/**
 * Author......: See docs/credits.txt
 * License.....: BSD-2-Clause
 *
 * Derived from LitePCIe, software/kernel/litepcie.h and config.h.
 * Copyright (C) 2018-2024 / EnjoyDigital / florent@enjoy-digital.fr
 * The hashcat additions in this file are released under the same terms.
 * See docs/license_libs/LITEPCIE_LICENSE.txt.
 */

#ifndef HC_FPGA_LITEPCIE_ABI_H
#define HC_FPGA_LITEPCIE_ABI_H

// Userspace ABI of the LitePCIe kernel driver, reproduced so the bridge can talk to a driver it does
// not build.
//
// The upstream header includes csr.h and config.h for driver translation units but does not use their
// definitions here. This copy is self-contained and independent of generated CSR maps.
//
// These structures and ioctl numbers are an ABI contract and must match the installed driver.

#if defined (__linux__)

#include <linux/types.h>
#include <sys/ioctl.h>

// Device identity used to distinguish an unprogrammed fabric from an unloaded driver through sysfs.

#define PCIE_XILINX_VENDOR_ID               0x10ee

// LiteX targets advertise PCI class 0B/80 (Processor/Other), allowing hashcat designs to be
// distinguished from other endpoints with the same vendor ID.

#define PCIE_HCFPGA_CLASS                   0x0b80

#define PCIE_XILINX_DEVICE_ID_S7_GEN2_X1    0x7021
#define PCIE_XILINX_DEVICE_ID_S7_GEN2_X2    0x7022
#define PCIE_XILINX_DEVICE_ID_S7_GEN2_X4    0x7024
#define PCIE_XILINX_DEVICE_ID_S7_GEN2_X8    0x7028

#define PCIE_XILINX_DEVICE_ID_US_GEN2_X1    0x8021
#define PCIE_XILINX_DEVICE_ID_US_GEN2_X2    0x8022
#define PCIE_XILINX_DEVICE_ID_US_GEN2_X4    0x8024
#define PCIE_XILINX_DEVICE_ID_US_GEN2_X8    0x8028

// DMA geometry. These are driver BUILD-TIME constants and the transport queries
// LITEPCIE_IOCTL_MMAP_DMA_INFO for what the driver actually built with, refusing to run on a
// mismatch rather than silently corrupting the candidate stream. So these are the expected defaults,
// and they have to track src/fpga/driver/patches/.
//
// The buffer size is not a contract with the gateware. The record carries a tag in every header and
// the feeder checks that, so a record may straddle a buffer boundary.
//
// 32768 rather than 8192 is worth 4x the candidates in a launch. Every one-shot batch fills and
// drains the core array once, so that fixed cost is amortised over four times as many candidates.

#define LITEPCIE_DMA_BUFFER_COUNT_EXPECTED  256
#define LITEPCIE_DMA_BUFFER_SIZE_EXPECTED   32768

struct litepcie_ioctl_reg
{
  uint32_t addr;
  uint32_t val;
  uint8_t  is_write;
};

struct litepcie_ioctl_icap
{
  uint8_t  addr;
  uint32_t data;
};

struct litepcie_ioctl_dma
{
  uint8_t loopback_enable;
};

struct litepcie_ioctl_dma_writer
{
  uint8_t enable;
  int64_t hw_count;
  int64_t sw_count;
};

struct litepcie_ioctl_dma_reader
{
  uint8_t enable;
  int64_t hw_count;
  int64_t sw_count;
};

struct litepcie_ioctl_lock
{
  uint8_t dma_reader_request;
  uint8_t dma_writer_request;
  uint8_t dma_reader_release;
  uint8_t dma_writer_release;
  uint8_t dma_reader_status;
  uint8_t dma_writer_status;
};

struct litepcie_ioctl_mmap_dma_info
{
  uint64_t dma_tx_buf_offset;
  uint64_t dma_tx_buf_size;
  uint64_t dma_tx_buf_count;

  uint64_t dma_rx_buf_offset;
  uint64_t dma_rx_buf_size;
  uint64_t dma_rx_buf_count;
};

struct litepcie_ioctl_mmap_dma_update
{
  int64_t sw_count;
};

// One-shot (Prog mode) DMA. The descriptor table has two modes. In Loop mode each consumed descriptor
// is refilled, so the device cycles the ring forever and re-reads records from previous batches. In
// Prog mode a descriptor executes once and the DMA stops when the table drains, so the device sees
// exactly what was armed and a result's position identifies it.
//
// This is NOT in upstream LitePCIe yet. The gateware mode is upstream and documented; what is ours is
// the driver reaching it. See src/fpga/driver/patches/0001-dma-one-shot-mode.patch for the change as
// it would be proposed.

struct litepcie_ioctl_dma_oneshot
{
  uint8_t enable;
};

struct litepcie_ioctl_dma_arm
{
  uint32_t count;
  uint32_t last_length;
};

#define LITEPCIE_IOCTL 'S'

#define LITEPCIE_IOCTL_REG                      _IOWR(LITEPCIE_IOCTL,  0, struct litepcie_ioctl_reg)
#define LITEPCIE_IOCTL_ICAP                     _IOWR(LITEPCIE_IOCTL,  2, struct litepcie_ioctl_icap)

#define LITEPCIE_IOCTL_DMA                      _IOW (LITEPCIE_IOCTL, 20, struct litepcie_ioctl_dma)
#define LITEPCIE_IOCTL_DMA_WRITER               _IOWR(LITEPCIE_IOCTL, 21, struct litepcie_ioctl_dma_writer)
#define LITEPCIE_IOCTL_DMA_READER               _IOWR(LITEPCIE_IOCTL, 22, struct litepcie_ioctl_dma_reader)
#define LITEPCIE_IOCTL_MMAP_DMA_INFO            _IOR (LITEPCIE_IOCTL, 24, struct litepcie_ioctl_mmap_dma_info)
#define LITEPCIE_IOCTL_LOCK                     _IOWR(LITEPCIE_IOCTL, 25, struct litepcie_ioctl_lock)
#define LITEPCIE_IOCTL_MMAP_DMA_WRITER_UPDATE   _IOW (LITEPCIE_IOCTL, 26, struct litepcie_ioctl_mmap_dma_update)
#define LITEPCIE_IOCTL_MMAP_DMA_READER_UPDATE   _IOW (LITEPCIE_IOCTL, 27, struct litepcie_ioctl_mmap_dma_update)
#define LITEPCIE_IOCTL_DMA_ONESHOT              _IOW (LITEPCIE_IOCTL, 28, struct litepcie_ioctl_dma_oneshot)
#define LITEPCIE_IOCTL_DMA_WRITER_ARM           _IOW (LITEPCIE_IOCTL, 29, struct litepcie_ioctl_dma_arm)
#define LITEPCIE_IOCTL_DMA_READER_ARM           _IOW (LITEPCIE_IOCTL, 30, struct litepcie_ioctl_dma_arm)

#endif // __linux__

#endif // HC_FPGA_LITEPCIE_ABI_H
