/* SPDX-License-Identifier: BSD-2-Clause
 *
 * LitePCIe driver
 *
 * This file is part of LitePCIe.
 *
 * Copyright (C) 2018-2024 / EnjoyDigital  / florent@enjoy-digital.fr
 *
 */

#ifndef _LINUX_LITEPCIE_H
#define _LINUX_LITEPCIE_H

#include <linux/types.h>

#include "csr.h"
#include "config.h"

struct litepcie_ioctl_reg {
	uint32_t addr;
	uint32_t val;
	uint8_t is_write;
};

struct litepcie_ioctl_flash {
	int tx_len; /* 8 to 40 */
	__u64 tx_data; /* 8 to 40 bits */
	__u64 rx_data; /* 40 bits */
};

struct litepcie_ioctl_icap {
	uint8_t addr;
	uint32_t data;
};

struct litepcie_ioctl_dma {
	uint8_t loopback_enable;
};

struct litepcie_ioctl_dma_writer {
	uint8_t enable;
	int64_t hw_count;
	int64_t sw_count;
};

struct litepcie_ioctl_dma_reader {
	uint8_t enable;
	int64_t hw_count;
	int64_t sw_count;
};

struct litepcie_ioctl_lock {
	uint8_t dma_reader_request;
	uint8_t dma_writer_request;
	uint8_t dma_reader_release;
	uint8_t dma_writer_release;
	uint8_t dma_reader_status;
	uint8_t dma_writer_status;
};

struct litepcie_ioctl_mmap_dma_info {
	uint64_t dma_tx_buf_offset;
	uint64_t dma_tx_buf_size;
	uint64_t dma_tx_buf_count;

	uint64_t dma_rx_buf_offset;
	uint64_t dma_rx_buf_size;
	uint64_t dma_rx_buf_count;
};

struct litepcie_ioctl_mmap_dma_update {
	int64_t sw_count;
};

#define LITEPCIE_IOCTL 'S'

#define LITEPCIE_IOCTL_REG               _IOWR(LITEPCIE_IOCTL,  0, struct litepcie_ioctl_reg)
#define LITEPCIE_IOCTL_FLASH             _IOWR(LITEPCIE_IOCTL,  1, struct litepcie_ioctl_flash)
#define LITEPCIE_IOCTL_ICAP              _IOWR(LITEPCIE_IOCTL,  2, struct litepcie_ioctl_icap)

#define LITEPCIE_IOCTL_DMA                       _IOW(LITEPCIE_IOCTL,  20, struct litepcie_ioctl_dma)
#define LITEPCIE_IOCTL_DMA_WRITER                _IOWR(LITEPCIE_IOCTL, 21, struct litepcie_ioctl_dma_writer)
#define LITEPCIE_IOCTL_DMA_READER                _IOWR(LITEPCIE_IOCTL, 22, struct litepcie_ioctl_dma_reader)
#define LITEPCIE_IOCTL_MMAP_DMA_INFO             _IOR(LITEPCIE_IOCTL,  24, struct litepcie_ioctl_mmap_dma_info)
#define LITEPCIE_IOCTL_LOCK                      _IOWR(LITEPCIE_IOCTL, 25, struct litepcie_ioctl_lock)
#define LITEPCIE_IOCTL_MMAP_DMA_WRITER_UPDATE    _IOW(LITEPCIE_IOCTL,  26, struct litepcie_ioctl_mmap_dma_update)
#define LITEPCIE_IOCTL_MMAP_DMA_READER_UPDATE    _IOW(LITEPCIE_IOCTL,  27, struct litepcie_ioctl_mmap_dma_update)

#endif /* _LINUX_LITEPCIE_H */
