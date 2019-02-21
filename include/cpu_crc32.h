/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_CRC32_H
#define _CPU_CRC32_H

#include <stdio.h>
#include <errno.h>

int cpu_crc32        (const char *filename, u8 keytab[64]);
u32 cpu_crc32_buffer (const u8 *buf, const size_t length);

#endif // _CPU_CRC32_H
