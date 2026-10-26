/* SPDX-License-Identifier: BSD-2-Clause
 *
 * LitePCIe library
 *
 * This file is part of LitePCIe.
 *
 * Copyright (C) 2018-2023 / EnjoyDigital  / florent@enjoy-digital.fr
 *
 */

#ifndef LITEPCIE_LIB_HELPERS_H
#define LITEPCIE_LIB_HELPERS_H

#include <stdint.h>
#include <sys/ioctl.h>

int64_t get_time_ms(void);

uint32_t litepcie_readl(int fd, uint32_t addr);
void litepcie_writel(int fd, uint32_t addr, uint32_t val);
void litepcie_reload(int fd);

#define checked_ioctl(...) _check_ioctl(ioctl(__VA_ARGS__), __FILE__, __LINE__)
void _check_ioctl(int status, const char *file, int line);

#endif /* LITEPCIE_LIB_HELPERS_H */
