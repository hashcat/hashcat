/* SPDX-License-Identifier: BSD-2-Clause
 *
 * LitePCIe library
 *
 * This file is part of LitePCIe.
 *
 * Copyright (C) 2018-2023 / EnjoyDigital  / florent@enjoy-digital.fr
 *
 */

#ifndef LITEPCIE_LIB_FLASH_H
#define LITEPCIE_LIB_FLASH_H

#include <stdint.h>

#define FLASH_READ_ID_REG 0x9F

#define FLASH_READ    0x03
#define FLASH_WREN    0x06
#define FLASH_WRDI    0x04
#define FLASH_PP      0x02
#define FLASH_SE      0xD8
#define FLASH_BE      0xC7
#define FLASH_RDSR    0x05
#define FLASH_WRSR    0x01
/* status */
#define FLASH_WIP     0x01

#define FLASH_SECTOR_SIZE (1 << 16)

/* BPI (Intel CFI) commands */
#define BPI_CMD_READ_ARRAY    0x00FF
#define BPI_CMD_READ_ID       0x0090
#define BPI_CMD_READ_STATUS   0x0070
#define BPI_CMD_CLEAR_STATUS  0x0050
#define BPI_CMD_PROGRAM       0x0041  /* Single-word program */
#define BPI_CMD_BUFFERED_PRG  0x00E9  /* Buffered program setup */
#define BPI_CMD_CONFIRM       0x00D0
#define BPI_CMD_BLOCK_ERASE   0x0020
#define BPI_CMD_UNLOCK_BLOCK  0x0060

/* BPI status register bits */
#define BPI_SR_READY      0x0080
#define BPI_SR_ERASE_ERR  0x0020
#define BPI_SR_PROG_ERR   0x0010

#define BPI_BLOCK_SIZE    (256 * 1024)  /* 256KB blocks */

/* BPI control/status bits */
#define BPI_CTRL_START  (1 << 0)
#define BPI_CTRL_RW     (1 << 1)
#define BPI_STATUS_DONE (1 << 0)

uint8_t litepcie_flash_read(int fd, uint32_t addr);
int litepcie_flash_get_erase_block_size(int fd);
int litepcie_flash_write(int fd,
                         uint8_t *buf, uint32_t base, uint32_t size,
                         void (*progress_cb)(void *opaque, const char *fmt, ...),
                         void *opaque);

#endif //LITEPCIE_LIB_FLASH_H
