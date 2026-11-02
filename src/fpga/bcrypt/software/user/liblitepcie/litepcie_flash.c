/* SPDX-License-Identifier: BSD-2-Clause
 *
 * LitePCIe library
 *
 * This file is part of LitePCIe.
 *
 * Copyright (C) 2018-2023 / EnjoyDigital  / florent@enjoy-digital.fr
 *
 */

#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "litepcie_flash.h"
#include "litepcie_helpers.h"
#include "litepcie.h"

#ifdef CSR_FLASH_BASE

#ifdef CSR_FLASH_SPI_CONTROL_ADDR
/* ─── SPI Flash Path ─── */

//#define FLASH_FULL_ERASE
#define FLASH_RETRIES 16

static void flash_spi_cs(int fd, uint8_t cs_n)
{
    litepcie_writel(fd, CSR_FLASH_CS_N_OUT_ADDR, cs_n);
}

static uint64_t flash_spi(int fd, int tx_len, uint8_t cmd,
                          uint32_t tx_data)
{
    struct litepcie_ioctl_flash m;
    flash_spi_cs(fd, 0);
    m.tx_len = tx_len;
    m.tx_data = tx_data | ((uint64_t)cmd << 32);
    checked_ioctl(fd, LITEPCIE_IOCTL_FLASH, &m);
    flash_spi_cs(fd, 1);
    return m.rx_data;
}

uint32_t flash_read_id(int fd, int reg)
{
    return flash_spi(fd, 32, reg, 0) & 0xffffff;
}

static void flash_write_enable(int fd)
{
    flash_spi(fd, 8, FLASH_WREN, 0);
}

static void flash_write_disable(int fd)
{
    flash_spi(fd, 8, FLASH_WRDI, 0);
}

static uint8_t flash_read_status(int fd)
{
    return flash_spi(fd, 16, FLASH_RDSR, 0) & 0xff;
}

static __attribute__((unused)) void flash_write_status(int fd, uint8_t value)
{
    flash_spi(fd, 16, FLASH_WRSR, value << 24);
}

static __attribute__((unused)) void flash_erase_sector(int fd, uint32_t addr)
{
    flash_spi(fd, 32, FLASH_SE, addr << 8);
}

static __attribute__((unused)) uint8_t flash_read_sector_lock(int fd, uint32_t addr)
{
    return flash_spi(fd, 40, FLASH_WRSR, addr << 8) & 0xff;
}

static __attribute__((unused)) void flash_write_sector_lock(int fd, uint32_t addr, uint8_t byte)
{
    flash_spi(fd, 40, FLASH_WRSR, (addr << 8) | byte);
}

static void flash_write(int fd, uint32_t addr, uint8_t byte)
{
    flash_spi(fd, 40, FLASH_PP, (addr << 8) | byte);
}

static void flash_write_buffer(int fd, uint32_t addr, uint8_t *buf, uint16_t size)
{
    if (size == 1) {
        flash_write(fd, addr, buf[0]);
    } else {
        int i;
        struct litepcie_ioctl_flash m;

        /* set cs_n */
        flash_spi_cs(fd, 0);

        /* send cmd */
        m.tx_len = 32;
        m.tx_data = ((uint64_t)FLASH_PP << 32) | ((uint64_t)addr << 8);
        checked_ioctl(fd, LITEPCIE_IOCTL_FLASH, &m);

        /* send bytes */
        for (i=0; i<size; i+=4) {
            m.tx_len = 32;
            m.tx_data = (
                ((uint64_t)buf[i+0] << 32) |
                ((uint64_t)buf[i+1] << 24) |
                ((uint64_t)buf[i+2] << 16) |
                ((uint64_t)buf[i+3] << 8));
            checked_ioctl(fd, LITEPCIE_IOCTL_FLASH, &m);
        }

        /* release cs_n */
        flash_spi_cs(fd, 1);
    }
}

uint8_t litepcie_flash_read(int fd, uint32_t addr)
{
    return flash_spi(fd, 40, FLASH_READ, addr << 8) & 0xff;
}

static void litepcie_flash_read_buffer(int fd, uint32_t addr, uint8_t *buf, uint16_t size)
{
    int i;

    struct litepcie_ioctl_flash m;

    if (size == 1) {
        buf[0] = litepcie_flash_read(fd, addr);

    } else {
        /* set cs_n */
        flash_spi_cs(fd, 0);

        /* send cmd */
        m.tx_len = 32;
        m.tx_data = ((uint64_t)FLASH_READ << 32) | ((uint64_t)addr << 8);
        checked_ioctl(fd, LITEPCIE_IOCTL_FLASH, &m);

        /* read bytes */
        for (i=0; i<size; i+=4) {
            m.tx_len = 32;
            checked_ioctl(fd, LITEPCIE_IOCTL_FLASH, &m);
            buf[i+0] = (m.rx_data >> 24 & 0xff);
            buf[i+1] = (m.rx_data >> 16 & 0xff);
            buf[i+2] = (m.rx_data >>  8 & 0xff);
            buf[i+3] = (m.rx_data >>  0 & 0xff);
        }

        /* release cs_n */
        flash_spi_cs(fd, 1);
    }
}

int litepcie_flash_get_erase_block_size(int fd)
{
    return FLASH_SECTOR_SIZE;
}

static int litepcie_flash_get_flash_program_size(int fd)
{
    int software_cs = 1;
    /* if software cs control, program in blocks to speed up update */
    litepcie_writel(fd, CSR_FLASH_CS_N_OUT_ADDR, 0);
    software_cs &= ((litepcie_readl(fd, CSR_FLASH_CS_N_OUT_ADDR) & 0x1) == 0);
    litepcie_writel(fd, CSR_FLASH_CS_N_OUT_ADDR, 1);
    software_cs &= ((litepcie_readl(fd, CSR_FLASH_CS_N_OUT_ADDR) & 0x1) == 1);
    if (software_cs)
        return 256;
    else
        return 1;
}

int litepcie_flash_write(int fd,
                     uint8_t *buf, uint32_t base, uint32_t size,
                     void (*progress_cb)(void *opaque, const char *fmt, ...),
                     void *opaque)
{
    int i;
    int retries;
    uint16_t flash_program_size;

    flash_program_size = litepcie_flash_get_flash_program_size(fd);
    printf("flash_program_size: %d\n", flash_program_size);

    uint8_t cmp_buf[256];

    /* dummy command because in some case the first erase does not
       work. */
    flash_read_id(fd, 0);

    /* disable write protection */
     flash_write_enable(fd);

#ifndef FLASH_FULL_ERASE
    /* erase */
    for(i = 0; i < size; i += FLASH_SECTOR_SIZE) {
        if (progress_cb) {
            progress_cb(opaque, "Erasing @%08x\r", base + i);
        }
        flash_write_enable(fd);
        flash_erase_sector(fd, base + i);
        while (flash_read_status(fd) & FLASH_WIP) {
            usleep(1000);
        }
    }
    if (progress_cb) {
        progress_cb(opaque, "\n");
    }
#else
    /* erase full flash */
    printf("Erasing...\n");
    flash_write_enable(fd);
    flash_spi(fd, 8, 0xC7, 0);
    while (flash_read_status(fd) & FLASH_WIP) {
        usleep(1000);
    }
#endif
    flash_write_disable(fd);

    i = 0;
    retries = 0;
    while (i < size) {
        if (progress_cb && (i % FLASH_SECTOR_SIZE) == 0) {
            progress_cb(opaque, "Writing @%08x\r", base + i);
        }

        /* wait flash to be ready */
        while (flash_read_status(fd) & FLASH_WIP)
            usleep(100);

        /* write flash page */
        flash_write_enable(fd);
        flash_write_buffer(fd, base + i, buf + i, flash_program_size);
        flash_write_disable(fd);

        /* wait flash to be ready*/
        while (flash_read_status(fd) & FLASH_WIP)
            usleep(100);

        /* verify flash page */
        litepcie_flash_read_buffer(fd, base + i, cmp_buf, flash_program_size);
        if (memcmp(buf + i, cmp_buf, flash_program_size) != 0) {
            retries += 1;
        } else {
            i += flash_program_size;
            retries = 0;
        }

        if (retries > FLASH_RETRIES) {
            printf("Not able to write page\n");
            return 1;
        }
    }

    if (progress_cb) {
        progress_cb(opaque, "\n");
    }

    return 0;
}

#endif /* CSR_FLASH_SPI_CONTROL_ADDR */

#ifdef CSR_FLASH_BPI_CONTROL_ADDR
/* ─── BPI Flash Path ─── */

#define BPI_BUFFER_WORDS 512  /* 512 words = 1KB programming region */

/* Low-level BPI word write via CSR registers. */
static void bpi_write_word(int fd, uint32_t word_addr, uint16_t data)
{
    litepcie_writel(fd, CSR_FLASH_BPI_ADDR_ADDR, word_addr);
    litepcie_writel(fd, CSR_FLASH_BPI_DATA_W_ADDR, data);
    litepcie_writel(fd, CSR_FLASH_BPI_CONTROL_ADDR,
        BPI_CTRL_RW | BPI_CTRL_START);  /* rw=1 (write), start=1 */
    while (!(litepcie_readl(fd, CSR_FLASH_BPI_STATUS_ADDR) & BPI_STATUS_DONE))
        ;
}

/* Low-level BPI word read via CSR registers. */
static uint16_t bpi_read_word(int fd, uint32_t word_addr)
{
    litepcie_writel(fd, CSR_FLASH_BPI_ADDR_ADDR, word_addr);
    litepcie_writel(fd, CSR_FLASH_BPI_CONTROL_ADDR,
        BPI_CTRL_START);  /* rw=0 (read), start=1 */
    while (!(litepcie_readl(fd, CSR_FLASH_BPI_STATUS_ADDR) & BPI_STATUS_DONE))
        ;
    return litepcie_readl(fd, CSR_FLASH_BPI_DATA_R_ADDR) & 0xFFFF;
}

/* Send a CFI command word to a BPI address. */
static void bpi_cmd(int fd, uint32_t word_addr, uint16_t cmd)
{
    bpi_write_word(fd, word_addr, cmd);
}

/* Read BPI status register and return it. */
static uint16_t bpi_read_status(int fd)
{
    bpi_cmd(fd, 0, BPI_CMD_READ_STATUS);
    return bpi_read_word(fd, 0);
}

/* Wait for BPI flash ready (SR bit 7 = 1).
 * On success, clears any errors and returns to READ_ARRAY mode. */
static int bpi_wait_ready(int fd, uint32_t timeout_ms)
{
    uint16_t sr;
    uint32_t elapsed = 0;

    while (elapsed < timeout_ms) {
        sr = bpi_read_status(fd);
        if (sr & BPI_SR_READY) {
            if (sr & (BPI_SR_ERASE_ERR | BPI_SR_PROG_ERR)) {
                printf("BPI: error status 0x%04x\n", sr);
                bpi_cmd(fd, 0, BPI_CMD_CLEAR_STATUS);
                return -1;
            }
            /* Return to read array mode. */
            bpi_cmd(fd, 0, BPI_CMD_READ_ARRAY);
            return 0;
        }
        usleep(1000);
        elapsed++;
    }
    printf("BPI: timeout waiting for ready (SR=0x%04x)\n", sr);
    return -1;
}

/* Unlock a BPI block at word_addr. */
static void bpi_unlock_block(int fd, uint32_t word_addr)
{
    bpi_cmd(fd, word_addr, BPI_CMD_UNLOCK_BLOCK);
    usleep(100);
    bpi_cmd(fd, word_addr, BPI_CMD_CONFIRM);
    usleep(100);
}

/* Erase a BPI block at word_addr. */
static int bpi_erase_block(int fd, uint32_t word_addr)
{
    bpi_unlock_block(fd, word_addr);
    bpi_cmd(fd, word_addr, BPI_CMD_BLOCK_ERASE);
    usleep(100);
    bpi_cmd(fd, word_addr, BPI_CMD_CONFIRM);
    return bpi_wait_ready(fd, 30000);
}

/* Read a single byte from flash (byte-addressed). */
uint8_t litepcie_flash_read(int fd, uint32_t addr)
{
    uint32_t word_addr = addr / 2;
    uint16_t word;

    /* Put flash in read-array mode. */
    bpi_cmd(fd, 0, BPI_CMD_READ_ARRAY);
    word = bpi_read_word(fd, word_addr);

    if (addr & 1)
        return (word >> 8) & 0xFF;  /* Odd byte = high byte. */
    else
        return word & 0xFF;         /* Even byte = low byte. */
}

int litepcie_flash_get_erase_block_size(int fd)
{
    return BPI_BLOCK_SIZE;
}

int litepcie_flash_write(int fd,
                     uint8_t *buf, uint32_t base, uint32_t size,
                     void (*progress_cb)(void *opaque, const char *fmt, ...),
                     void *opaque)
{
    uint32_t i;

    /* Read flash ID for sanity check. */
    bpi_cmd(fd, 0, BPI_CMD_READ_ID);
    uint16_t mfr = bpi_read_word(fd, 0);
    uint16_t dev = bpi_read_word(fd, 1);
    printf("BPI Flash ID: manufacturer=0x%04x device=0x%04x\n", mfr, dev);

    /* Erase blocks covering [base, base+size). */
    for (i = 0; i < size; i += BPI_BLOCK_SIZE) {
        uint32_t word_addr = (base + i) / 2;
        if (progress_cb)
            progress_cb(opaque, "Erasing @%08x\r", base + i);
        if (bpi_erase_block(fd, word_addr) != 0) {
            printf("BPI: erase failed at 0x%08x\n", base + i);
            return 1;
        }
    }
    if (progress_cb)
        progress_cb(opaque, "\n");

    /* Program using buffered programming (0xE9).
     * Per-chunk sequence:
     *   1. Clear status (0x50)
     *   2. Buffered program setup (0xE9) → block base word addr
     *   3. Word count (N-1) → block base word addr
     *   4. N data words → sequential word addresses
     *   5. Confirm (0xD0) → block base word addr
     *   6. Wait ready
     */
    uint32_t last_block = 0xFFFFFFFF;
    uint32_t offset = 0;

    while (offset < size) {
        uint32_t byte_addr = base + offset;
        uint32_t word_addr = byte_addr / 2;

        /* Block base word address. */
        uint32_t block_byte = (byte_addr / BPI_BLOCK_SIZE) * BPI_BLOCK_SIZE;
        uint32_t block_word_addr = block_byte / 2;

        /* Unlock when entering a new block. */
        uint32_t current_block = byte_addr / BPI_BLOCK_SIZE;
        if (current_block != last_block) {
            if (progress_cb)
                progress_cb(opaque, "Writing @%08x\r", byte_addr);
            bpi_unlock_block(fd, block_word_addr);
            last_block = current_block;
        }

        /* Calculate chunk size (up to 512 words = 1KB). */
        uint32_t remaining = size - offset;
        uint32_t chunk_bytes = (remaining > BPI_BUFFER_WORDS * 2)
            ? BPI_BUFFER_WORDS * 2 : remaining;

        /* Don't cross block boundaries. */
        uint32_t to_block_end = BPI_BLOCK_SIZE - (byte_addr % BPI_BLOCK_SIZE);
        if (chunk_bytes > to_block_end)
            chunk_bytes = to_block_end;

        uint32_t chunk_words = (chunk_bytes + 1) / 2;

        /* 1. Clear status. */
        bpi_cmd(fd, 0, BPI_CMD_CLEAR_STATUS);

        /* 2. Buffered program setup → block base. */
        bpi_cmd(fd, block_word_addr, BPI_CMD_BUFFERED_PRG);

        /* 3. Word count (N-1) → block base. */
        bpi_write_word(fd, block_word_addr, chunk_words - 1);

        /* 4. Write data words → sequential addresses. */
        for (uint32_t w = 0; w < chunk_words; w++) {
            uint16_t word;
            uint32_t d = offset + w * 2;
            word = buf[d];
            if (d + 1 < size)
                word |= ((uint16_t)buf[d + 1]) << 8;
            else
                word |= 0xFF00;  /* Pad odd trailing byte. */
            bpi_write_word(fd, word_addr + w, word);
        }

        /* 5. Confirm → block base. */
        bpi_cmd(fd, block_word_addr, BPI_CMD_CONFIRM);

        /* 6. Wait for program to complete. */
        if (bpi_wait_ready(fd, 5000) != 0) {
            printf("BPI: buffered program failed at 0x%08x\n", byte_addr);
            return 1;
        }

        offset += chunk_words * 2;
    }

    /* Return to read array mode. */
    bpi_cmd(fd, 0, BPI_CMD_READ_ARRAY);

    if (progress_cb)
        progress_cb(opaque, "\n");

    return 0;
}

#endif /* CSR_FLASH_BPI_CONTROL_ADDR */

#endif /* CSR_FLASH_BASE */
