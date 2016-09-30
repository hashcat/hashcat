/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _COMMON_H
#define _COMMON_H

#define PROGNAME "hashcat"

#if   defined (__linux__)
#define _POSIX
#elif defined (__APPLE__)
#define _POSIX
#elif defined (__FreeBSD__)
#define _POSIX
#elif defined (_WIN32) || defined (_WIN64)
#define _WIN
#else
#error Your Operating System is not supported or detected
#endif

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

// don't try to simply change this, it will not work
#define PW_MIN      0
#define PW_MAX      54
#define PW_MAX1     (PW_MAX + 1)

#define PW_DICTMAX  31
#define PW_DICTMAX1 (PW_DICTMAX + 1)

#define EXEC_CACHE      128

#define SPEED_CACHE     128
#define SPEED_MAXAGE    4096

// general buffer size in case the size is unknown at compile-time
#define HCBUFSIZ_TINY   0x100
#define HCBUFSIZ_LARGE  0x50000

#define BLOCK_SIZE      64

#define EXPECTED_ITERATIONS 10000

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#define DEVICES_MAX   128

#define MAX_CUT_TRIES 4

#define CEIL(a) ((a - (int) (a)) > 0 ? a + 1 : a)

#if defined (__APPLE__)
#define __stdcall
#endif

#if defined (_WIN32) || defined (__WIN32__) || defined (__CYGWIN__)
#define HC_API_CALL __stdcall
#else
#define HC_API_CALL
#endif

#if defined (_WIN)
#define WIN32_LEAN_AND_MEAN
#endif

#if defined (_WIN)
#define EOL "\r\n"
#else
#define EOL "\n"
#endif

#endif // _COMMON_H
