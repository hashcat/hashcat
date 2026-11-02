/* SPDX-License-Identifier: BSD-2-Clause
 *
 * LitePCIe driver
 *
 * This file is part of LitePCIe.
 *
 * Copyright (C) 2018-2024 / EnjoyDigital  / florent@enjoy-digital.fr
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/mmtimer.h>
#include <linux/miscdevice.h>
#include <linux/posix-timers.h>
#include <linux/interrupt.h>
#include <linux/time.h>
#include <linux/math64.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/log2.h>
#include <linux/poll.h>
#include <linux/cdev.h>
#include <linux/kref.h>
#include <linux/idr.h>
#include <linux/rwsem.h>
#include <linux/platform_device.h>
#include <linux/version.h>
#include <linux/dma-mapping.h>

#if defined(__arm__) || defined(__aarch64__)
#include <linux/dma-direct.h>
#endif

#include "litepcie.h"
#include "csr.h"
#include "config.h"
#include "flags.h"
#include "soc.h"

//#define DEBUG_CSR
//#define DEBUG_MSI
//#define DEBUG_POLL
//#define DEBUG_READ
//#define DEBUG_WRITE

#define LITEPCIE_NAME "litepcie"
#define LITEPCIE_MINOR_COUNT 32

#ifndef CSR_BASE
#define CSR_BASE 0x00000000
#endif

struct litepcie_dma_chan {
	uint32_t base;
	uint32_t writer_interrupt;
	uint32_t reader_interrupt;
	dma_addr_t reader_handle[DMA_BUFFER_COUNT];
	dma_addr_t writer_handle[DMA_BUFFER_COUNT];
	uint32_t *reader_addr[DMA_BUFFER_COUNT];
	uint32_t *writer_addr[DMA_BUFFER_COUNT];
	int64_t reader_hw_count;
	int64_t reader_hw_count_last;
	int64_t reader_sw_count;
	int64_t writer_hw_count;
	int64_t writer_hw_count_last;
	int64_t writer_sw_count;
	uint8_t writer_enable;
	uint8_t reader_enable;
	uint8_t writer_lock;
	uint8_t reader_lock;
};

struct litepcie_chan {
	struct litepcie_device *litepcie_dev;
	struct litepcie_dma_chan dma;
	struct cdev cdev;
	uint32_t block_size;
	uint32_t core_base;
	wait_queue_head_t wait_rd; /* to wait for an ongoing read */
	wait_queue_head_t wait_wr; /* to wait for an ongoing write */

	int index;
	int minor;
	struct device device;              /* chardev; its release() drops a kref */
	struct address_space *mapping;     /* for unmap_mapping_range() on removal */
};

/* Structure to hold the LitePCIe device information */
struct litepcie_device {
	struct pci_dev *dev;                          /* PCI device */
	struct platform_device *uart;                 /* UART platform device */
	resource_size_t bar0_size;                    /* Size of BAR0 */
	phys_addr_t bar0_phys_addr;                   /* Physical address of BAR0 */
	uint8_t *bar0_addr;                           /* Virtual address of BAR0 */
	struct litepcie_chan chan[DMA_CHANNEL_COUNT]; /* DMA channel information */
	spinlock_t lock;                              /* Spinlock for synchronization */
	int minor_base;                               /* Base minor number for the device */
	int minor_idx;                                /* IDA allocated device index */
	int irqs;                                     /* Number of IRQs */
	int channels;                                 /* Number of DMA channels */
	struct kref ref;                              /* Allocation lifetime */
	struct rw_semaphore hw_lock;                  /* Hardware access gate */
	bool disconnected;                            /* Guarded by hw_lock */
};

struct litepcie_chan_priv {
	struct litepcie_chan *chan;
	bool reader;
	bool writer;
};

/*
 * A PCI device can be unbound while userspace still holds a file descriptor
 * open, so two things have to be kept apart: how long the allocation lives, and
 * how long the hardware behind it is usable.
 *
 * Lifetime is handled structurally. The device struct is refcounted and each
 * chardev holds one reference, dropped by its struct device release(). Since
 * cdev_add() takes a reference on its parent kobject, an open file descriptor
 * keeps that struct device -- and therefore this allocation -- alive on its
 * own, which is why open() and release() do no refcounting themselves.
 *
 * Usability is handled by the gate below. Every file operation that touches the
 * device runs between litepcie_enter() and litepcie_exit(); litepcie_pci_remove()
 * takes the same lock for writing once, to set `disconnected`. When that write
 * side returns, no file operation is in flight and none can start.
 */
static void litepcie_dev_free(struct kref *ref)
{
	kfree(container_of(ref, struct litepcie_device, ref));
}

static void litepcie_chan_device_release(struct device *dev)
{
	struct litepcie_chan *chan = container_of(dev, struct litepcie_chan, device);

	kref_put(&chan->litepcie_dev->ref, litepcie_dev_free);
}

/* Returns false with no lock held if the device is gone; the caller must then
 * fail with -ENODEV without touching anything device related.
 */
static bool litepcie_enter(struct litepcie_device *s)
{
	down_read(&s->hw_lock);
	if (s->disconnected) {
		up_read(&s->hw_lock);
		return false;
	}
	return true;
}

static void litepcie_exit(struct litepcie_device *s)
{
	up_read(&s->hw_lock);
}

static int litepcie_major;
static DEFINE_IDA(litepcie_ida);
static struct class *litepcie_class;
static dev_t litepcie_dev_t;

/* Function to read a 32-bit value from a LitePCIe device register */
static inline uint32_t litepcie_readl(struct litepcie_device *s, uint32_t addr)
{
	uint32_t val;

	val = readl(s->bar0_addr + addr - CSR_BASE);
#ifdef DEBUG_CSR
	dev_dbg(&s->dev->dev, "csr_read: 0x%08x @ 0x%08x", val, addr);
#endif
	return val;
}

/* Function to write a 32-bit value to a LitePCIe device register */
static inline void litepcie_writel(struct litepcie_device *s, uint32_t addr, uint32_t val)
{
#ifdef DEBUG_CSR
	dev_dbg(&s->dev->dev, "csr_write: 0x%08x @ 0x%08x", val, addr);
#endif
	return writel(val, s->bar0_addr + addr - CSR_BASE);
}

/* Function to enable a specific interrupt on a LitePCIe device */
static void litepcie_enable_interrupt(struct litepcie_device *s, int irq_num)
{
	uint32_t v;

	/* Read the current interrupt enable register value */
	v = litepcie_readl(s, CSR_PCIE_MSI_ENABLE_ADDR);

	/* Set the bit corresponding to the given interrupt number */
	v |= (1 << irq_num);

	/* Write the updated value back to the register */
	litepcie_writel(s, CSR_PCIE_MSI_ENABLE_ADDR, v);
}

/* Function to disable a specific interrupt on a LitePCIe device */
static void litepcie_disable_interrupt(struct litepcie_device *s, int irq_num)
{
	uint32_t v;

	/* Read the current interrupt enable register value */
	v = litepcie_readl(s, CSR_PCIE_MSI_ENABLE_ADDR);

	/* Clear the bit corresponding to the given interrupt number */
	v &= ~(1 << irq_num);

	/* Write the updated value back to the register */
	litepcie_writel(s, CSR_PCIE_MSI_ENABLE_ADDR, v);
}

static int litepcie_dma_init(struct litepcie_device *s)
{

	int i, j;
	struct litepcie_dma_chan *dmachan;

	if (!s)
		return -ENODEV;

	/* for each dma channel */
	for (i = 0; i < s->channels; i++) {
		dmachan = &s->chan[i].dma;
		/* for each dma buffer */
		for (j = 0; j < DMA_BUFFER_COUNT; j++) {
			/* allocate rd */
			dmachan->reader_addr[j] = dmam_alloc_coherent(
				&s->dev->dev,
				DMA_BUFFER_SIZE,
				&dmachan->reader_handle[j],
				GFP_KERNEL);
			/* allocate wr */
			dmachan->writer_addr[j] = dmam_alloc_coherent(
				&s->dev->dev,
				DMA_BUFFER_SIZE,
				&dmachan->writer_handle[j],
				GFP_KERNEL);
			/* check */
			if (!dmachan->writer_addr[j]
				|| !dmachan->reader_addr[j]) {
				dev_err(&s->dev->dev, "Failed to allocate dma buffers\n");
				return -ENOMEM;
			}
		}
	}

	return 0;
}

static void litepcie_dma_writer_start(struct litepcie_device *s, int chan_num)
{
	struct litepcie_dma_chan *dmachan;
	int i;

	dmachan = &s->chan[chan_num].dma;

	/* Fill DMA Writer descriptors. */
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_ENABLE_OFFSET, 0);
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_FLUSH_OFFSET, 1);
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_LOOP_PROG_N_OFFSET, 0);
	for (i = 0; i < DMA_BUFFER_COUNT; i++) {
		/* Fill buffer size + parameters. */
		litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_VALUE_OFFSET,
#ifndef DMA_BUFFER_ALIGNED
			DMA_LAST_DISABLE |
#endif
			(!(i%DMA_BUFFER_PER_IRQ == 0)) * DMA_IRQ_DISABLE | /* generate an msi */
			DMA_BUFFER_SIZE);                                  /* every n buffers */
		/* Fill 32-bit Address LSB. */
		litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_VALUE_OFFSET + 4, (dmachan->writer_handle[i] >>  0) & 0xffffffff);
		/* Write descriptor (and fill 32-bit Address MSB for 64-bit mode). */
		litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_WE_OFFSET,        (dmachan->writer_handle[i] >> 32) & 0xffffffff);
	}
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_LOOP_PROG_N_OFFSET, 1);

	/* Clear counters. */
	dmachan->writer_hw_count = 0;
	dmachan->writer_hw_count_last = 0;
	dmachan->writer_sw_count = 0;

	/* Start DMA Writer. */
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_ENABLE_OFFSET, 1);
}

static void litepcie_dma_writer_stop(struct litepcie_device *s, int chan_num)
{
	struct litepcie_dma_chan *dmachan;

	dmachan = &s->chan[chan_num].dma;

	/* Flush and stop DMA Writer. */
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_LOOP_PROG_N_OFFSET, 0);
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_FLUSH_OFFSET, 1);
	udelay(1000);
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_ENABLE_OFFSET, 0);
	litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_TABLE_FLUSH_OFFSET, 1);

	/* Clear counters. */
	dmachan->writer_hw_count = 0;
	dmachan->writer_hw_count_last = 0;
	dmachan->writer_sw_count = 0;
}

static void litepcie_dma_reader_start(struct litepcie_device *s, int chan_num)
{
	struct litepcie_dma_chan *dmachan;
	int i;

	dmachan = &s->chan[chan_num].dma;

	/* Fill DMA Reader descriptors. */
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_ENABLE_OFFSET, 0);
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_FLUSH_OFFSET, 1);
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_LOOP_PROG_N_OFFSET, 0);
	for (i = 0; i < DMA_BUFFER_COUNT; i++) {
		/* Fill buffer size + parameters. */
		litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_VALUE_OFFSET,
#ifndef DMA_BUFFER_ALIGNED
			DMA_LAST_DISABLE |
#endif
			(!(i%DMA_BUFFER_PER_IRQ == 0)) * DMA_IRQ_DISABLE | /* generate an msi */
			DMA_BUFFER_SIZE);                                  /* every n buffers */
		/* Fill 32-bit Address LSB. */
		litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_VALUE_OFFSET + 4, (dmachan->reader_handle[i] >>  0) & 0xffffffff);
		/* Write descriptor (and fill 32-bit Address MSB for 64-bit mode). */
		litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_WE_OFFSET, (dmachan->reader_handle[i] >> 32) & 0xffffffff);
	}
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_LOOP_PROG_N_OFFSET, 1);

	/* Clear counters */
	dmachan->reader_hw_count = 0;
	dmachan->reader_hw_count_last = 0;
	dmachan->reader_sw_count = 0;

	/* Start dma reader */
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_ENABLE_OFFSET, 1);
}

static void litepcie_dma_reader_stop(struct litepcie_device *s, int chan_num)
{
	struct litepcie_dma_chan *dmachan;

	dmachan = &s->chan[chan_num].dma;

	/* flush and stop dma reader */
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_LOOP_PROG_N_OFFSET, 0);
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_FLUSH_OFFSET, 1);
	udelay(1000);
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_ENABLE_OFFSET, 0);
	litepcie_writel(s, dmachan->base + PCIE_DMA_READER_TABLE_FLUSH_OFFSET, 1);

	/* clear counters */
	dmachan->reader_hw_count = 0;
	dmachan->reader_hw_count_last = 0;
	dmachan->reader_sw_count = 0;
}

static void litepcie_stop_dma(struct litepcie_device *s)
{
	struct litepcie_dma_chan *dmachan;
	int i;

	for (i = 0; i < s->channels; i++) {
		dmachan = &s->chan[i].dma;
		litepcie_writel(s, dmachan->base + PCIE_DMA_WRITER_ENABLE_OFFSET, 0b0);
		litepcie_writel(s, dmachan->base + PCIE_DMA_READER_ENABLE_OFFSET, 0b0);
	}
}

static irqreturn_t litepcie_interrupt(int irq, void *data)
{
	struct litepcie_device *s = (struct litepcie_device *) data;
	struct litepcie_chan *chan;
	uint32_t loop_status;
	uint32_t clear_mask, irq_vector, irq_enable;
	int i;

/* Single MSI */
#ifdef CSR_PCIE_MSI_CLEAR_ADDR
	irq_vector = litepcie_readl(s, CSR_PCIE_MSI_VECTOR_ADDR);
	irq_enable = litepcie_readl(s, CSR_PCIE_MSI_ENABLE_ADDR);
/* MSI MultiVector / MSI-X */
#else
	irq_vector = 0;
	for (i = 0; i < s->irqs; i++) {
		if (irq == pci_irq_vector(s->dev, i)) {
			irq_vector = (1 << i);
			break;
		}
	}
	irq_enable = litepcie_readl(s, CSR_PCIE_MSI_ENABLE_ADDR);
#endif

#ifdef DEBUG_MSI
	dev_dbg(&s->dev->dev, "MSI: 0x%x 0x%x\n", irq_vector, irq_enable);
#endif
	irq_vector &= irq_enable;
	clear_mask = 0;

	for (i = 0; i < s->channels; i++) {
		chan = &s->chan[i];
		/* dma reader interrupt handling */
		if (irq_vector & (1 << chan->dma.reader_interrupt)) {
			loop_status = litepcie_readl(s, chan->dma.base +
				PCIE_DMA_READER_TABLE_LOOP_STATUS_OFFSET);
			chan->dma.reader_hw_count &= ((~(DMA_BUFFER_COUNT - 1) << 16) & 0xffffffffffff0000);
			chan->dma.reader_hw_count |= (loop_status >> 16) * DMA_BUFFER_COUNT + (loop_status & 0xffff);
			if (chan->dma.reader_hw_count_last > chan->dma.reader_hw_count)
				chan->dma.reader_hw_count += (1 << (ilog2(DMA_BUFFER_COUNT) + 16));
			chan->dma.reader_hw_count_last = chan->dma.reader_hw_count;
#ifdef DEBUG_MSI
			dev_dbg(&s->dev->dev, "MSI DMA%d Reader buf: %lld\n", i,
				chan->dma.reader_hw_count);
#endif
			wake_up_interruptible(&chan->wait_wr);
			clear_mask |= (1 << chan->dma.reader_interrupt);
		}
		/* dma writer interrupt handling */
		if (irq_vector & (1 << chan->dma.writer_interrupt)) {
			loop_status = litepcie_readl(s, chan->dma.base +
				PCIE_DMA_WRITER_TABLE_LOOP_STATUS_OFFSET);
			chan->dma.writer_hw_count &= ((~(DMA_BUFFER_COUNT - 1) << 16) & 0xffffffffffff0000);
			chan->dma.writer_hw_count |= (loop_status >> 16) * DMA_BUFFER_COUNT + (loop_status & 0xffff);
			if (chan->dma.writer_hw_count_last > chan->dma.writer_hw_count)
				chan->dma.writer_hw_count += (1 << (ilog2(DMA_BUFFER_COUNT) + 16));
			chan->dma.writer_hw_count_last = chan->dma.writer_hw_count;
#ifdef DEBUG_MSI
			dev_dbg(&s->dev->dev, "MSI DMA%d Writer buf: %lld\n", i,
				chan->dma.writer_hw_count);
#endif
			wake_up_interruptible(&chan->wait_rd);
			clear_mask |= (1 << chan->dma.writer_interrupt);
		}
	}

#ifdef CSR_PCIE_MSI_CLEAR_ADDR
	litepcie_writel(s, CSR_PCIE_MSI_CLEAR_ADDR, clear_mask);
#endif

	return IRQ_HANDLED;
}

static int litepcie_open(struct inode *inode, struct file *file)
{
	struct litepcie_chan *chan = container_of(inode->i_cdev, struct litepcie_chan, cdev);
	struct litepcie_device *s = chan->litepcie_dev;
	struct litepcie_chan_priv *chan_priv;

	if (!litepcie_enter(s))
		return -ENODEV;

	chan_priv = kzalloc(sizeof(*chan_priv), GFP_KERNEL);
	if (!chan_priv) {
		litepcie_exit(s);
		return -ENOMEM;
	}

	chan_priv->chan = chan;
	file->private_data = chan_priv;

	/* Remembered so that removal can revoke any mmap of the DMA buffers. */
	chan->mapping = file->f_mapping;

	if (chan->dma.reader_enable == 0) { /* clear only if disabled */
		chan->dma.reader_hw_count = 0;
		chan->dma.reader_hw_count_last = 0;
		chan->dma.reader_sw_count = 0;
	}

	if (chan->dma.writer_enable == 0) { /* clear only if disabled */
		chan->dma.writer_hw_count = 0;
		chan->dma.writer_hw_count_last = 0;
		chan->dma.writer_sw_count = 0;
	}

	litepcie_exit(s);

	return 0;
}

static int litepcie_release(struct inode *inode, struct file *file)
{
	struct litepcie_chan_priv *chan_priv = file->private_data;
	struct litepcie_chan *chan = chan_priv->chan;
	struct litepcie_device *s = chan->litepcie_dev;

	/* If the device is already gone there is nothing left to quiesce, and the
	 * register writes below would touch an unmapped BAR.
	 */
	if (!litepcie_enter(s))
		goto out;

	if (chan_priv->reader) {
		/* disable interrupt */
		litepcie_disable_interrupt(chan->litepcie_dev, chan->dma.reader_interrupt);
		/* disable DMA */
		litepcie_dma_reader_stop(chan->litepcie_dev, chan->index);
		chan->dma.reader_lock = 0;
		chan->dma.reader_enable = 0;
	}

	if (chan_priv->writer) {
		/* disable interrupt */
		litepcie_disable_interrupt(chan->litepcie_dev, chan->dma.writer_interrupt);
		/* disable DMA */
		litepcie_dma_writer_stop(chan->litepcie_dev, chan->index);
		chan->dma.writer_lock = 0;
		chan->dma.writer_enable = 0;
	}

	litepcie_exit(s);
out:
	kfree(chan_priv);

	return 0;
}

static ssize_t litepcie_read(struct file *file, char __user *data, size_t size, loff_t *offset)
{
	size_t len;
	int i, ret;
	int overflows;

	struct litepcie_chan_priv *chan_priv = file->private_data;
	struct litepcie_chan *chan = chan_priv->chan;
	struct litepcie_device *s = chan->litepcie_dev;

	if (file->f_flags & O_NONBLOCK) {
		if (chan->dma.writer_hw_count == chan->dma.writer_sw_count)
			ret = -EAGAIN;
		else
			ret = 0;
	} else {
		/* Sleeps outside the gate: holding it across an unbounded wait would
		 * block removal. The condition tests disconnected so that the wake_up
		 * from litepcie_pci_remove() reliably ends the wait.
		 */
		ret = wait_event_interruptible(chan->wait_rd,
					       (chan->dma.writer_hw_count - chan->dma.writer_sw_count) > 0 ||
					       READ_ONCE(s->disconnected));
	}

	if (ret < 0)
		return ret;

	if (!litepcie_enter(s))
		return -ENODEV;

	i = 0;
	overflows = 0;
	len = size;
	while (len >= DMA_BUFFER_SIZE) {
		if ((chan->dma.writer_hw_count - chan->dma.writer_sw_count) > 0) {
			if ((chan->dma.writer_hw_count - chan->dma.writer_sw_count) > DMA_BUFFER_COUNT/2) {
				overflows++;
			} else {
				ret = copy_to_user(data + (chan->block_size * i),
						   chan->dma.writer_addr[chan->dma.writer_sw_count%DMA_BUFFER_COUNT],
						   DMA_BUFFER_SIZE);
				if (ret) {
					litepcie_exit(s);
					return -EFAULT;
				}
			}
			len -= DMA_BUFFER_SIZE;
			chan->dma.writer_sw_count += 1;
			i++;
		} else {
			break;
		}
	}

	if (overflows)
		dev_err(&s->dev->dev, "Reading too late, %d buffers lost\n", overflows);

#ifdef DEBUG_READ
	dev_dbg(&s->dev->dev, "read: read %ld bytes out of %ld\n", size - len, size);
#endif

	litepcie_exit(s);

	return size - len;
}

static ssize_t litepcie_write(struct file *file, const char __user *data, size_t size, loff_t *offset)
{
	size_t len;
	int i, ret;
	int underflows;

	struct litepcie_chan_priv *chan_priv = file->private_data;
	struct litepcie_chan *chan = chan_priv->chan;
	struct litepcie_device *s = chan->litepcie_dev;

	if (file->f_flags & O_NONBLOCK) {
		if (chan->dma.reader_hw_count == chan->dma.reader_sw_count)
			ret = -EAGAIN;
		else
			ret = 0;
	} else {
		/* Sleeps outside the gate, as in litepcie_read(). */
		ret = wait_event_interruptible(chan->wait_wr,
					       (chan->dma.reader_sw_count - chan->dma.reader_hw_count) < DMA_BUFFER_COUNT/2 ||
					       READ_ONCE(s->disconnected));
	}

	if (ret < 0)
		return ret;

	if (!litepcie_enter(s))
		return -ENODEV;

	i = 0;
	underflows = 0;
	len = size;
	while (len >= DMA_BUFFER_SIZE) {
		if ((chan->dma.reader_sw_count - chan->dma.reader_hw_count) < DMA_BUFFER_COUNT/2) {
			if ((chan->dma.reader_sw_count - chan->dma.reader_hw_count) < 0) {
				underflows++;
			} else {
				ret = copy_from_user(chan->dma.reader_addr[chan->dma.reader_sw_count%DMA_BUFFER_COUNT],
						     data + (chan->block_size * i), DMA_BUFFER_SIZE);
				if (ret) {
					litepcie_exit(s);
					return -EFAULT;
				}
			}
			len -= DMA_BUFFER_SIZE;
			chan->dma.reader_sw_count += 1;
			i++;
		} else {
			break;
		}
	}

	if (underflows)
		dev_err(&s->dev->dev, "Writing too late, %d buffers lost\n", underflows);

#ifdef DEBUG_WRITE
	dev_dbg(&s->dev->dev, "write: write %ld bytes out of %ld\n", size - len, size);
#endif

	litepcie_exit(s);

	return size - len;
}

static int litepcie_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct litepcie_chan_priv *chan_priv = file->private_data;
	struct litepcie_chan *chan = chan_priv->chan;
	struct litepcie_device *s = chan->litepcie_dev;
#if defined(__arm__) || defined(__aarch64__)
	unsigned long pfn;
#else
	int ret;
#endif
	int is_tx, i;

	if (vma->vm_end - vma->vm_start != DMA_BUFFER_TOTAL_SIZE)
		return -EINVAL;

	if (vma->vm_pgoff == 0)
		is_tx = 1;
	else if (vma->vm_pgoff == (DMA_BUFFER_TOTAL_SIZE >> PAGE_SHIFT))
		is_tx = 0;
	else
		return -EINVAL;

	if (!litepcie_enter(s))
		return -ENODEV;

	/* The ring is fixed-size device memory, not expandable or dumpable RAM. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
#else
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
#endif

	for (i = 0; i < DMA_BUFFER_COUNT; i++) {
#if defined(__arm__) || defined(__aarch64__)
		void *va;
		if (is_tx)
			va = phys_to_virt(dma_to_phys(&s->dev->dev, chan->dma.reader_handle[i]));
		else
			va = phys_to_virt(dma_to_phys(&s->dev->dev, chan->dma.writer_handle[i]));
		pfn = page_to_pfn(virt_to_page(va));
		/*
		 * Note: the memory is cached, so the user must explicitly
		 * flush the CPU caches on architectures which require it.
		 */
		if (remap_pfn_range(vma, vma->vm_start + i * DMA_BUFFER_SIZE, pfn,
				    DMA_BUFFER_SIZE, vma->vm_page_prot)) {
			dev_err(&s->dev->dev, "mmap remap_pfn_range failed\n");
			litepcie_exit(s);
			return -EAGAIN;
		}
#else
		void *cpu_addr;
		dma_addr_t dma_handle;
		struct vm_area_struct sub_vma = *vma;

		if (is_tx) {
			cpu_addr   = chan->dma.reader_addr[i];
			dma_handle = chan->dma.reader_handle[i];
		} else {
			cpu_addr   = chan->dma.writer_addr[i];
			dma_handle = chan->dma.writer_handle[i];
		}

		sub_vma.vm_start = vma->vm_start + i * DMA_BUFFER_SIZE;
		sub_vma.vm_end   = sub_vma.vm_start + DMA_BUFFER_SIZE;
		sub_vma.vm_pgoff = 0;

		ret = dma_mmap_coherent(&s->dev->dev, &sub_vma,
					cpu_addr, dma_handle, DMA_BUFFER_SIZE);
		/* DMA backends add PFNMAP or MIXEDMAP and may change protection.
		 * Retain that metadata on the real VMA, including partial failure. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
		vm_flags_set(vma, sub_vma.vm_flags);
#else
		vma->vm_flags |= sub_vma.vm_flags;
#endif
		vma->vm_page_prot = sub_vma.vm_page_prot;
		if (ret) {
			dev_err(&s->dev->dev,
				"dma_mmap_coherent failed for buffer %d (ret=%d)\n", i, ret);
			litepcie_exit(s);
			return ret;
		}
#endif
	}

	litepcie_exit(s);

	return 0;
}

static unsigned int litepcie_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;

	struct litepcie_chan_priv *chan_priv = file->private_data;
	struct litepcie_chan *chan = chan_priv->chan;
	struct litepcie_device *s = chan->litepcie_dev;

	if (!litepcie_enter(s))
		return POLLERR | POLLHUP;

	poll_wait(file, &chan->wait_rd, wait);
	poll_wait(file, &chan->wait_wr, wait);

#ifdef DEBUG_POLL
	dev_dbg(&s->dev->dev, "poll: writer hw_count: %10lld / sw_count %10lld\n",
	chan->dma.writer_hw_count, chan->dma.writer_sw_count);
	dev_dbg(&s->dev->dev, "poll: reader hw_count: %10lld / sw_count %10lld\n",
	chan->dma.reader_hw_count, chan->dma.reader_sw_count);
#endif

	if ((chan->dma.writer_hw_count - chan->dma.writer_sw_count) > 2)
		mask |= POLLIN | POLLRDNORM;

	if ((chan->dma.reader_sw_count - chan->dma.reader_hw_count) < DMA_BUFFER_COUNT/2)
		mask |= POLLOUT | POLLWRNORM;

	litepcie_exit(s);

	return mask;
}

#ifdef CSR_FLASH_SPI_CONTROL_ADDR
/* SPI */

#define SPI_TIMEOUT 100000 /* in us */

static int litepcie_flash_spi(struct litepcie_device *s, struct litepcie_ioctl_flash *m)
{
	int i;

	if (m->tx_len < 8 || m->tx_len > 40)
		return -EINVAL;

	litepcie_writel(s, CSR_FLASH_SPI_MOSI_ADDR, m->tx_data >> 32);
	litepcie_writel(s, CSR_FLASH_SPI_MOSI_ADDR + 4, m->tx_data);
	litepcie_writel(s, CSR_FLASH_SPI_CONTROL_ADDR,
		SPI_CTRL_START | (m->tx_len * SPI_CTRL_LENGTH));
	udelay(16);
	for (i = 0; i < SPI_TIMEOUT; i++) {
		if (litepcie_readl(s, CSR_FLASH_SPI_STATUS_ADDR) & SPI_STATUS_DONE)
			break;
		udelay(1);
	}
	m->rx_data = ((uint64_t)litepcie_readl(s, CSR_FLASH_SPI_MISO_ADDR) << 32) |
		litepcie_readl(s, CSR_FLASH_SPI_MISO_ADDR + 4);
	return 0;
}
#endif

static long litepcie_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	long ret = 0;

	struct litepcie_chan_priv *chan_priv = file->private_data;
	struct litepcie_chan *chan = chan_priv->chan;
	struct litepcie_device *dev = chan->litepcie_dev;

	if (!litepcie_enter(dev))
		return -ENODEV;

	switch (cmd) {
	case LITEPCIE_IOCTL_REG:
	{
		struct litepcie_ioctl_reg m;

		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

		/* m.addr is used unmodified as an offset into the BAR0 mapping, so it
		 * has to be checked against it. Without this the ioctl reads and
		 * writes up to 4 GiB past the end of a mapping that is typically a
		 * few hundred KiB, which on a node that init.sh chmods to 0666 hands
		 * every local user an arbitrary kernel read/write primitive.
		 */
		if ((m.addr & 3) || m.addr < CSR_BASE ||
		    (u64)(m.addr - CSR_BASE) + sizeof(m.val) > dev->bar0_size) {
			ret = -EINVAL;
			break;
		}

		if (m.is_write)
			litepcie_writel(dev, m.addr, m.val);
		else
			m.val = litepcie_readl(dev, m.addr);

		if (copy_to_user((void *)arg, &m, sizeof(m))) {
			ret = -EFAULT;
			break;
		}
	}
	break;
#ifdef CSR_FLASH_SPI_CONTROL_ADDR
	case LITEPCIE_IOCTL_FLASH:
	{
		struct litepcie_ioctl_flash m;

		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}
		ret = litepcie_flash_spi(dev, &m);
		if (ret == 0) {
			if (copy_to_user((void *)arg, &m, sizeof(m))) {
				ret = -EFAULT;
				break;
			}
		}
	}
	break;
#endif
#ifdef CSR_ICAP_BASE
	case LITEPCIE_IOCTL_ICAP:
	{
		struct litepcie_ioctl_icap m;

		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

		litepcie_writel(dev, CSR_ICAP_ADDR_ADDR, m.addr);
		litepcie_writel(dev, CSR_ICAP_DATA_ADDR, m.data);
		litepcie_writel(dev, CSR_ICAP_WRITE_ADDR, 1);
	}
	break;
#endif
	case LITEPCIE_IOCTL_DMA:
	{
		struct litepcie_ioctl_dma m;

		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

		/* loopback */
		litepcie_writel(chan->litepcie_dev, chan->dma.base + PCIE_DMA_LOOPBACK_ENABLE_OFFSET, m.loopback_enable);
	}
	break;
	case LITEPCIE_IOCTL_DMA_WRITER:
	{
		struct litepcie_ioctl_dma_writer m;

		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

		if (m.enable != chan->dma.writer_enable) {
			/* enable / disable DMA */
			if (m.enable) {
				litepcie_dma_writer_start(chan->litepcie_dev, chan->index);
				litepcie_enable_interrupt(chan->litepcie_dev, chan->dma.writer_interrupt);
			} else {
				litepcie_disable_interrupt(chan->litepcie_dev, chan->dma.writer_interrupt);
				litepcie_dma_writer_stop(chan->litepcie_dev, chan->index);
			}

		}

		chan->dma.writer_enable = m.enable;

		m.hw_count = chan->dma.writer_hw_count;
		m.sw_count = chan->dma.writer_sw_count;

		if (copy_to_user((void *)arg, &m, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

	}
	break;
	case LITEPCIE_IOCTL_DMA_READER:
	{
		struct litepcie_ioctl_dma_reader m;

		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

		if (m.enable != chan->dma.reader_enable) {
			/* enable / disable DMA */
			if (m.enable) {
				litepcie_dma_reader_start(chan->litepcie_dev, chan->index);
				litepcie_enable_interrupt(chan->litepcie_dev, chan->dma.reader_interrupt);
			} else {
				litepcie_disable_interrupt(chan->litepcie_dev, chan->dma.reader_interrupt);
				litepcie_dma_reader_stop(chan->litepcie_dev, chan->index);
			}
		}

		chan->dma.reader_enable = m.enable;

		m.hw_count = chan->dma.reader_hw_count;
		m.sw_count = chan->dma.reader_sw_count;

		if (copy_to_user((void *)arg, &m, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

	}
	break;
	case LITEPCIE_IOCTL_MMAP_DMA_INFO:
	{
		struct litepcie_ioctl_mmap_dma_info m;

		m.dma_tx_buf_offset = 0;
		m.dma_tx_buf_size = DMA_BUFFER_SIZE;
		m.dma_tx_buf_count = DMA_BUFFER_COUNT;

		m.dma_rx_buf_offset = DMA_BUFFER_TOTAL_SIZE;
		m.dma_rx_buf_size = DMA_BUFFER_SIZE;
		m.dma_rx_buf_count = DMA_BUFFER_COUNT;

		if (copy_to_user((void *)arg, &m, sizeof(m))) {
			ret = -EFAULT;
			break;
		}
	}
	break;
	case LITEPCIE_IOCTL_MMAP_DMA_WRITER_UPDATE:
	{
		struct litepcie_ioctl_mmap_dma_update m;

		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

		chan->dma.writer_sw_count = m.sw_count;
	}
	break;
	case LITEPCIE_IOCTL_MMAP_DMA_READER_UPDATE:
	{
		struct litepcie_ioctl_mmap_dma_update m;

		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

		chan->dma.reader_sw_count = m.sw_count;
	}
	break;
	case LITEPCIE_IOCTL_LOCK:
	{
		struct litepcie_ioctl_lock m;


		if (copy_from_user(&m, (void *)arg, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

		m.dma_reader_status = 1;
		if (m.dma_reader_request) {
			if (chan->dma.reader_lock) {
				m.dma_reader_status = 0;
			} else {
				chan->dma.reader_lock = 1;
				chan_priv->reader = 1;
			}
		}
		if (m.dma_reader_release) {
			chan->dma.reader_lock = 0;
			chan_priv->reader = 0;
		}

		m.dma_writer_status = 1;
		if (m.dma_writer_request) {
			if (chan->dma.writer_lock) {
				m.dma_writer_status = 0;
			} else {
				chan->dma.writer_lock = 1;
				chan_priv->writer = 1;
			}
		}
		if (m.dma_writer_release) {
			chan->dma.writer_lock = 0;
			chan_priv->writer = 0;
		}

		if (copy_to_user((void *)arg, &m, sizeof(m))) {
			ret = -EFAULT;
			break;
		}

	}
	break;
	default:
		ret = -ENOIOCTLCMD;
		break;
	}

	litepcie_exit(dev);

	return ret;
}

static const struct file_operations litepcie_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = litepcie_ioctl,
	.open = litepcie_open,
	.release = litepcie_release,
	.read = litepcie_read,
	.poll = litepcie_poll,
	.write = litepcie_write,
	.mmap = litepcie_mmap,
};

/* Reserve this device's minor range. Kept separate from litepcie_alloc_chdev()
 * so that the chardevs can be created at the end of probe.
 */
static int litepcie_reserve_minors(struct litepcie_device *s)
{
	int id = ida_alloc_max(&litepcie_ida,
			       LITEPCIE_MINOR_COUNT / s->channels - 1, GFP_KERNEL);

	if (id < 0)
		return id;

	s->minor_idx  = id;
	s->minor_base = MINOR(litepcie_dev_t) + id * s->channels;

	return 0;
}

static void litepcie_release_minors(struct litepcie_device *s)
{
	ida_free(&litepcie_ida, s->minor_idx);
}

static int litepcie_alloc_chdev(struct litepcie_device *s)
{
	int i, j, ret;

	for (i = 0; i < s->channels; i++) {
		struct litepcie_chan *chan = &s->chan[i];

		dev_info(&s->dev->dev, "Creating /dev/litepcie%d\n", chan->minor);

		device_initialize(&chan->device);
		chan->device.devt    = MKDEV(litepcie_major, chan->minor);
		chan->device.class   = litepcie_class;
		chan->device.parent  = &s->dev->dev;
		chan->device.release = litepcie_chan_device_release;

		/* The reference this chardev holds on the device struct. Taken before
		 * anything can call put_device(), dropped by the release() above.
		 */
		kref_get(&s->ref);

		ret = dev_set_name(&chan->device, "litepcie%d", chan->minor);
		if (ret)
			goto fail;

		cdev_init(&chan->cdev, &litepcie_fops);
		chan->cdev.owner = THIS_MODULE;

		ret = cdev_device_add(&chan->cdev, &chan->device);
		if (ret) {
			dev_err(&s->dev->dev, "Failed to add chardev %d\n", chan->minor);
			goto fail;
		}
	}

	return 0;

fail:
	put_device(&s->chan[i].device);
	for (j = 0; j < i; j++) {
		cdev_device_del(&s->chan[j].cdev, &s->chan[j].device);
		put_device(&s->chan[j].device);
	}
	return ret;
}

/* Stop handing the device out. After this returns no new open() reaches the
 * driver, but file descriptors that are already open still exist.
 */
static void litepcie_revoke_chdevs(struct litepcie_device *s)
{
	int i;

	for (i = 0; i < s->channels; i++)
		cdev_device_del(&s->chan[i].cdev, &s->chan[i].device);
}

/* Drop the chardevs' references. If a file descriptor is still open its
 * reference on the cdev holds the struct device alive, so the release() -- and
 * the kfree() behind it -- simply happens when that descriptor is closed.
 */
static void litepcie_release_chdevs(struct litepcie_device *s)
{
	int i;

	for (i = 0; i < s->channels; i++)
		put_device(&s->chan[i].device);
}

/* Function to probe the LitePCIe PCI device */
static int litepcie_pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int ret = 0;
	int irqs = 0;
	uint8_t rev_id;
	int i;
	char fpga_identifier[256];
	struct litepcie_device *litepcie_dev = NULL;
#ifdef CSR_UART_XOVER_RXTX_ADDR
	struct resource *tty_res = NULL;
#endif

	dev_info(&dev->dev, "\e[1m[Probing device]\e[0m\n");

	/* Allocate memory for the LitePCIe device structure */
	/* Not devm: this allocation holds the chardevs and has to outlive an
	 * unbind that happens while a file descriptor is still open. It is freed
	 * by the last kref_put().
	 */
	litepcie_dev = kzalloc(sizeof(struct litepcie_device), GFP_KERNEL);
	if (!litepcie_dev)
		return -ENOMEM;

	kref_init(&litepcie_dev->ref);
	init_rwsem(&litepcie_dev->hw_lock);

	pci_set_drvdata(dev, litepcie_dev);
	litepcie_dev->dev = dev;
	spin_lock_init(&litepcie_dev->lock);

	/* Enable the PCI device */
	ret = pcim_enable_device(dev);
	if (ret != 0) {
		dev_err(&dev->dev, "Cannot enable device\n");
		goto fail1;
	}

	ret = -EIO;

	/* Check the device version */
	pci_read_config_byte(dev, PCI_REVISION_ID, &rev_id);
	if (rev_id > 1) {
		dev_err(&dev->dev, "Unsupported device version %d\n", rev_id);
		goto fail1;
	}

	/* Check the BAR0 configuration */
	if (!(pci_resource_flags(dev, 0) & IORESOURCE_MEM)) {
		dev_err(&dev->dev, "Invalid BAR0 configuration\n");
		goto fail1;
	}

	/* Request and map BAR0 */
	if (pcim_iomap_regions(dev, BIT(0), LITEPCIE_NAME) < 0) {
		dev_err(&dev->dev, "Could not request regions\n");
		goto fail1;
	}

	litepcie_dev->bar0_size = pci_resource_len(dev, 0);
	litepcie_dev->bar0_addr = pcim_iomap_table(dev)[0];
	if (!litepcie_dev->bar0_addr) {
		dev_err(&dev->dev, "Could not map BAR0\n");
		goto fail1;
	}

	/* Reset LitePCIe core */
#ifdef CSR_CTRL_RESET_ADDR
	litepcie_writel(litepcie_dev, CSR_CTRL_RESET_ADDR, 1);
	msleep(10);
#endif

	/* Read and display the FPGA identifier */
	for (i = 0; i < 256; i++)
		fpga_identifier[i] = litepcie_readl(litepcie_dev, CSR_IDENTIFIER_MEM_BASE + i * 4);
	dev_info(&dev->dev, "Version %s\n", fpga_identifier);

	pci_set_master(dev);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 18, 0)
	ret = pci_set_dma_mask(dev, DMA_BIT_MASK(DMA_ADDR_WIDTH));
#else
	ret = dma_set_mask(&dev->dev, DMA_BIT_MASK(DMA_ADDR_WIDTH));
#endif
	if (ret) {
		dev_err(&dev->dev, "Failed to set DMA mask\n");
		goto fail1;
	}


/* MSI-X */
#ifdef CSR_PCIE_MSI_PBA_ADDR
	irqs = pci_alloc_irq_vectors(dev, 1, 32, PCI_IRQ_MSIX);
/* MSI Single / MultiVector */
#else
	irqs = pci_alloc_irq_vectors(dev, 1, 32, PCI_IRQ_MSI);
#endif
	if (irqs < 0) {
		dev_err(&dev->dev, "Failed to enable MSI\n");
		ret = irqs;
		goto fail1;
	}
/* MSI-X */
#ifdef CSR_PCIE_MSI_PBA_ADDR
	dev_info(&dev->dev, "%d MSI-X IRQs allocated.\n", irqs);
/* MSI Single / MultiVector */
#else
	dev_info(&dev->dev, "%d MSI IRQs allocated.\n", irqs);
#endif

	litepcie_dev->irqs = 0;
	for (i = 0; i < irqs; i++) {
		int irq = pci_irq_vector(dev, i);

		/* Request IRQ */
		ret = request_irq(irq, litepcie_interrupt, 0, LITEPCIE_NAME, litepcie_dev);
		if (ret < 0) {
			dev_err(&dev->dev, " Failed to allocate IRQ %d\n", dev->irq);
			while (--i >= 0) {
				irq = pci_irq_vector(dev, i);
				free_irq(irq, dev);
			}
			goto fail2;
		}
		litepcie_dev->irqs += 1;
	}

	litepcie_dev->channels = DMA_CHANNELS;

	ret = litepcie_reserve_minors(litepcie_dev);
	if (ret < 0) {
		dev_err(&dev->dev, "Failed to allocate a minor range\n");
		goto fail2;
	}

	for (i = 0; i < litepcie_dev->channels; i++) {
		litepcie_dev->chan[i].index = i;
		litepcie_dev->chan[i].block_size = DMA_BUFFER_SIZE;
		litepcie_dev->chan[i].minor = litepcie_dev->minor_base + i;
		litepcie_dev->chan[i].litepcie_dev = litepcie_dev;
		litepcie_dev->chan[i].dma.writer_lock = 0;
		litepcie_dev->chan[i].dma.reader_lock = 0;
		init_waitqueue_head(&litepcie_dev->chan[i].wait_rd);
		init_waitqueue_head(&litepcie_dev->chan[i].wait_wr);
		switch (i) {
#ifdef CSR_PCIE_DMA7_BASE
		case 7: {
		litepcie_dev->chan[i].dma.base = CSR_PCIE_DMA7_BASE;
		litepcie_dev->chan[i].dma.writer_interrupt = PCIE_DMA7_WRITER_INTERRUPT;
		litepcie_dev->chan[i].dma.reader_interrupt = PCIE_DMA7_READER_INTERRUPT;
	}
	break;
#endif
#ifdef CSR_PCIE_DMA6_BASE
		case 6: {
		litepcie_dev->chan[i].dma.base = CSR_PCIE_DMA6_BASE;
		litepcie_dev->chan[i].dma.writer_interrupt = PCIE_DMA6_WRITER_INTERRUPT;
		litepcie_dev->chan[i].dma.reader_interrupt = PCIE_DMA6_READER_INTERRUPT;
	}
	break;
#endif
#ifdef CSR_PCIE_DMA5_BASE
		case 5: {
		litepcie_dev->chan[i].dma.base = CSR_PCIE_DMA5_BASE;
		litepcie_dev->chan[i].dma.writer_interrupt = PCIE_DMA5_WRITER_INTERRUPT;
		litepcie_dev->chan[i].dma.reader_interrupt = PCIE_DMA5_READER_INTERRUPT;
	}
	break;
#endif
#ifdef CSR_PCIE_DMA4_BASE
		case 4: {
		litepcie_dev->chan[i].dma.base = CSR_PCIE_DMA4_BASE;
		litepcie_dev->chan[i].dma.writer_interrupt = PCIE_DMA4_WRITER_INTERRUPT;
		litepcie_dev->chan[i].dma.reader_interrupt = PCIE_DMA4_READER_INTERRUPT;
	}
	break;
#endif
#ifdef CSR_PCIE_DMA3_BASE
		case 3: {
		litepcie_dev->chan[i].dma.base = CSR_PCIE_DMA3_BASE;
		litepcie_dev->chan[i].dma.writer_interrupt = PCIE_DMA3_WRITER_INTERRUPT;
		litepcie_dev->chan[i].dma.reader_interrupt = PCIE_DMA3_READER_INTERRUPT;
	}
	break;
#endif
#ifdef CSR_PCIE_DMA2_BASE
		case 2: {
		litepcie_dev->chan[i].dma.base = CSR_PCIE_DMA2_BASE;
		litepcie_dev->chan[i].dma.writer_interrupt = PCIE_DMA2_WRITER_INTERRUPT;
		litepcie_dev->chan[i].dma.reader_interrupt = PCIE_DMA2_READER_INTERRUPT;
	}
	break;
#endif
#ifdef CSR_PCIE_DMA1_BASE
		case 1: {
		litepcie_dev->chan[i].dma.base = CSR_PCIE_DMA1_BASE;
		litepcie_dev->chan[i].dma.writer_interrupt = PCIE_DMA1_WRITER_INTERRUPT;
		litepcie_dev->chan[i].dma.reader_interrupt = PCIE_DMA1_READER_INTERRUPT;
	}
	break;
#endif
		default:
			{
				litepcie_dev->chan[i].dma.base = CSR_PCIE_DMA0_BASE;
				litepcie_dev->chan[i].dma.writer_interrupt = PCIE_DMA0_WRITER_INTERRUPT;
				litepcie_dev->chan[i].dma.reader_interrupt = PCIE_DMA0_READER_INTERRUPT;
			}
			break;
		}
	}

	/* allocate all dma buffers */
	ret = litepcie_dma_init(litepcie_dev);
	if (ret) {
		dev_err(&dev->dev, "Failed to allocate DMA\n");
		goto fail2;
	}

#ifdef CSR_UART_XOVER_RXTX_ADDR
	tty_res = devm_kzalloc(&dev->dev, sizeof(struct resource), GFP_KERNEL);
	if (!tty_res)
		return -ENOMEM;
	tty_res->start =
		(resource_size_t) litepcie_dev->bar0_addr +
		CSR_UART_XOVER_RXTX_ADDR - CSR_BASE;
	tty_res->flags = IORESOURCE_REG;
	litepcie_dev->uart = platform_device_register_simple("liteuart", litepcie_dev->minor_idx, tty_res, 1);
	if (IS_ERR(litepcie_dev->uart)) {
		ret = PTR_ERR(litepcie_dev->uart);
		goto fail2;
	}
#endif

	/* Create all chardev in /dev. This is the last step of probe: everything
	 * they expose to userspace is initialised above.
	 */
	ret = litepcie_alloc_chdev(litepcie_dev);
	if (ret) {
		dev_err(&dev->dev, "Failed to allocate character device\n");
		goto fail3;
	}

	return 0;

fail3:
#ifdef CSR_UART_XOVER_RXTX_ADDR
	platform_device_unregister(litepcie_dev->uart);
#endif
fail2:
	litepcie_release_minors(litepcie_dev);
	pci_free_irq_vectors(dev);
fail1:
	/* The chardevs were never created, so this drops the last reference. */
	kref_put(&litepcie_dev->ref, litepcie_dev_free);
	return ret;
}

/* Function to remove the LitePCIe PCI device */
static void litepcie_pci_remove(struct pci_dev *dev)
{
	int i, irq;
	struct litepcie_device *litepcie_dev;

	litepcie_dev = pci_get_drvdata(dev);

	dev_info(&dev->dev, "\e[1m[Removing device]\e[0m\n");

	/* Stop handing the device out first: no new open() gets through here. */
	litepcie_revoke_chdevs(litepcie_dev);

	/* Then close the gate. Taking hw_lock for writing waits for the file
	 * operations already between litepcie_enter() and litepcie_exit() to
	 * finish and keeps new ones out, so the teardown below has the hardware
	 * to itself.
	 */
	down_write(&litepcie_dev->hw_lock);
	litepcie_dev->disconnected = true;
	up_write(&litepcie_dev->hw_lock);

	for (i = 0; i < litepcie_dev->channels; i++) {
		/* read() and write() sleep outside the gate, so wake them up; their
		 * wait conditions test disconnected and they return -ENODEV.
		 */
		wake_up_interruptible(&litepcie_dev->chan[i].wait_rd);
		wake_up_interruptible(&litepcie_dev->chan[i].wait_wr);

		/* Drop userspace mappings of the DMA buffers before devres frees
		 * them, otherwise a process that mmap'd a ring keeps a read/write
		 * window onto pages that go back to the page allocator.
		 */
		if (litepcie_dev->chan[i].mapping)
			unmap_mapping_range(litepcie_dev->chan[i].mapping, 0, 0, 1);
	}

	/* Stop the DMAs */
	litepcie_stop_dma(litepcie_dev);

	/* Disable all interrupts */
	litepcie_writel(litepcie_dev, CSR_PCIE_MSI_ENABLE_ADDR, 0);

	/* Free all IRQs */
	for (i = 0; i < litepcie_dev->irqs; i++) {
		irq = pci_irq_vector(dev, i);
		free_irq(irq, litepcie_dev);
	}

	platform_device_unregister(litepcie_dev->uart);

	pci_free_irq_vectors(dev);

	/* Release the chardevs last. A file descriptor that is still open keeps
	 * the allocation alive through its reference on the cdev; every file
	 * operation it can still make is refused by the gate above.
	 */
	litepcie_release_chdevs(litepcie_dev);
	litepcie_release_minors(litepcie_dev);
	kref_put(&litepcie_dev->ref, litepcie_dev_free);
}

/* PCI device ID table */
static const struct pci_device_id litepcie_pci_ids[] = {
	/* Xilinx */
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_S7_GEN2_X1), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_S7_GEN2_X2), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_S7_GEN2_X4), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_S7_GEN2_X8), },

	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_US_GEN2_X1), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_US_GEN2_X2), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_US_GEN2_X4), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_US_GEN2_X8), },

	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_US_GEN3_X1), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_US_GEN3_X2), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_US_GEN3_X4), },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_US_GEN3_X8), },

	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN2_X1),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN2_X2),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN2_X4),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN2_X8),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN2_X16), },

	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN3_X1),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN3_X2),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN3_X4),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN3_X8),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN3_X16), },

	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN4_X1),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN4_X2),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN4_X4),  },
	{ PCI_DEVICE(PCIE_XILINX_VENDOR_ID, PCIE_XILINX_DEVICE_ID_USP_GEN4_X8),  },

	/* Lattice */
	{ PCI_DEVICE(PCIE_LATTICE_VENDOR_ID, PCIE_LATTICE_DEVICE_ID_CPNX_GEN3_X4),  },

	/* Gowin */
	{ PCI_DEVICE(PCIE_GOWIN_VENDOR_ID, PCIE_GOWIN_DEVICE_ID_GW5AT_GEN2_X4),  },

	{ 0, }
};
MODULE_DEVICE_TABLE(pci, litepcie_pci_ids);

/* PCI driver structure */
static struct pci_driver litepcie_pci_driver = {
	.name = LITEPCIE_NAME,
	.id_table = litepcie_pci_ids,
	.probe = litepcie_pci_probe,
	.remove = litepcie_pci_remove,
};

/* Module initialization function */
static int __init litepcie_module_init(void)
{
	int ret;

	#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
		litepcie_class = class_create(THIS_MODULE, LITEPCIE_NAME);
	#else
		litepcie_class = class_create(LITEPCIE_NAME);
	#endif
	if (!litepcie_class) {
		ret = -EEXIST;
		pr_err(" Failed to create class\n");
		goto fail_create_class;
	}

	ret = alloc_chrdev_region(&litepcie_dev_t, 0, LITEPCIE_MINOR_COUNT, LITEPCIE_NAME);
	if (ret < 0) {
		pr_err(" Could not allocate char device\n");
		goto fail_alloc_chrdev_region;
	}
	litepcie_major = MAJOR(litepcie_dev_t);

	ret = pci_register_driver(&litepcie_pci_driver);
	if (ret < 0) {
		pr_err(" Error while registering PCI driver\n");
		goto fail_register;
	}

	return 0;

fail_register:
	unregister_chrdev_region(litepcie_dev_t, LITEPCIE_MINOR_COUNT);
fail_alloc_chrdev_region:
	class_destroy(litepcie_class);
fail_create_class:
	return ret;
}

/* Module exit function */
static void __exit litepcie_module_exit(void)
{
	pci_unregister_driver(&litepcie_pci_driver);
	unregister_chrdev_region(litepcie_dev_t, LITEPCIE_MINOR_COUNT);
	ida_destroy(&litepcie_ida);
	class_destroy(litepcie_class);
}

module_init(litepcie_module_init);
module_exit(litepcie_module_exit);

MODULE_LICENSE("GPL");
