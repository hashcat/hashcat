/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_CRC32_H
#define _CPU_CRC32_H

#include <stdio.h>
#include <errno.h>

void cpu_crc32 (const char *filename, u8 keytab[64]);

#endif // _CPU_CRC32_H
