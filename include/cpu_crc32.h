/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma once

#include <stdio.h>
#include <errno.h>

void cpu_crc32 (const char *filename, u8 keytab[64]);

