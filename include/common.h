/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#pragma once

#define _POSIX_SOURCE
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _CRT_SECURE_NO_WARNINGS

#define EXEC_CACHE    128

#define SPEED_CACHE   128
#define SPEED_MAXAGE  4096

#define HCBUFSIZ      0x50000 // general large space buffer size in case the size is unknown at compile-time

#define BLOCK_SIZE              64


#define EXPECTED_ITERATIONS 10000

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#define DEVICES_MAX   128

#define CEIL(a) ((a - (int) (a)) > 0 ? a + 1 : a)

#ifdef __APPLE__
#define __stdcall
#endif

#ifdef _WIN
#define WIN32_LEAN_AND_MEAN
#endif
