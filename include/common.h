#pragma once
/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               magnum <john.magnum@hushmail.com>
 *
 * License.....: MIT
 */

#ifndef COMMON_H
#define COMMON_H
#include "config.h"

#ifdef _WINDOWS
#define _WIN 1
#define WIN 1
#endif // _WINDOWS

#define _POSIX_SOURCE
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define _CRT_SECURE_NO_WARNINGS

#define NOMINMAX 1
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <search.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/time.h>

#include "numeric_types_abbreviations.h"

#ifndef __cplusplus
/* The C++ standard denies redefinition of keywords, 
but this is nededed for VS Ñ compiler which doesn't have inline keyword but has __inline
*/
#ifdef _MSC_VER
#define inline __inline
#endif
#endif

int hc_mkdir(char const* name, int mode);

#ifdef _POSIX

#include <pthread.h>
#include <semaphore.h>
#include <pwd.h>
#include <limits.h>

#ifdef __linux__
#include <termios.h>
#include <sys/ioctl.h>
#endif

#ifdef __APPLE__
#include <termios.h>
#include <sys/ioctl.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#endif

#ifdef __FreeBSD__
#include <termios.h>
#include <sys/ioctl.h>
#endif

typedef void *OCL_LIB;

#ifdef HAVE_HWMON
typedef void *ADL_LIB;
typedef void *NVAPI_LIB;
typedef void *NVML_LIB;
typedef void *XNVCTRL_LIB;
#ifdef __APPLE__
#define __stdcall
#endif
#endif

inline int hc_mkdir(char const* name, int mode) {
  return mkdir(name, mode);
}

#endif // _POSIX

#ifdef _WIN
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <process.h>
#include <conio.h>
#include <tchar.h>
#include <psapi.h>
#include <io.h>

typedef HINSTANCE OCL_LIB;

#ifdef HAVE_HWMON
typedef HINSTANCE ADL_LIB;
typedef HINSTANCE NVAPI_LIB;
typedef HINSTANCE NVML_LIB;
typedef HINSTANCE XNVCTRL_LIB;
#endif

inline int hc_mkdir(char const* name, int mode) {
  return _mkdir(name);
}
#endif // _WIN

/**
 * functions
 */

int log_out_nn(FILE *fp, const char *fmt, ...);
int log_info_nn(const char *fmt, ...);
int log_error_nn(const char *fmt, ...);

int log_out(FILE *fp, const char *fmt, ...);
int log_info(const char *fmt, ...);
int log_error(const char *fmt, ...);

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#define CEIL(a) ((a - (int) (a)) > 0 ? a + 1 : a)

#endif // COMMON_H
