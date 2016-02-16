/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifndef COMMON_H
#define COMMON_H

#define _POSIX_SOURCE
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _CRT_SECURE_NO_WARNINGS

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <math.h>
#include <ctype.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <search.h>
#include <fcntl.h>

#ifdef _POSIX
#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>
#include <dlfcn.h>
#include <pwd.h>

#ifdef LINUX
#include <termio.h>
#endif

#ifdef OSX
#include <termios.h>
#include <sys/ioctl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#endif

typedef void *OCL_LIB;

#ifdef HAVE_HWMON
typedef void *NV_LIB;
typedef void *AMD_LIB;
#ifdef OSX
#define __stdcall
#endif
#endif

#endif // _POSIX

#ifdef _WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#include <conio.h>
#include <tchar.h>
#include <psapi.h>
#include <io.h>

typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT8   int8_t;
typedef INT16  int16_t;
typedef INT32  int32_t;
typedef INT64  int64_t;

typedef UINT32 uint;
typedef UINT64 uint64_t;

typedef HINSTANCE OCL_LIB;

#ifdef HAVE_HWMON
typedef HINSTANCE NV_LIB;
typedef HINSTANCE AMD_LIB;
#endif

#define mkdir(name,mode) mkdir (name)

#endif // _WIN

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef uint32_t uint; // we need to get rid of this sooner or later, for consistency

#define EXEC_CACHE   128

#define SPEED_CACHE  128
#define SPEED_MAXAGE 4096

#undef  BUFSIZ
#define BUFSIZ 8192

/**
 * functions
 */

void log_out_nn (FILE *fp, const char *fmt, ...);
void log_info_nn (const char *fmt, ...);
void log_error_nn (const char *fmt, ...);

void log_out (FILE *fp, const char *fmt, ...);
void log_info (const char *fmt, ...);
void log_error (const char *fmt, ...);

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#endif // COMMON_H
