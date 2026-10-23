/* SPDX-License-Identifier: BSD-2-Clause
 *
 * LitePCIe driver
 *
 * This file is part of LitePCIe.
 *
 * Copyright (C) 2018-2024 / EnjoyDigital  / florent@enjoy-digital.fr
 *
 */

#ifndef __HW_FLAGS_H
#define __HW_FLAGS_H

/* SPI */
#define SPI_CTRL_START  (1 << 0)
#define SPI_CTRL_LENGTH (1 << 8)
#define SPI_STATUS_DONE (1 << 0)

/* PCIe */
#define DMA_TABLE_LOOP_INDEX (1 <<  0)
#define DMA_TABLE_LOOP_COUNT (1 << 16)

/* ICAP */
#define ICAP_CMD_REG   0b00100
#define ICAP_CMD_IPROG 0b01111

#define ICAP_IDCODE_REG   0b01100

#define ICAP_BOOTSTS_REG  0b10110
#define ICAP_BOOTSTS_VALID    (1 << 0)
#define ICAP_BOOTSTS_FALLBACK (1 << 1)


#endif /* __HW_FLAGS_H */
