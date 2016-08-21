/**
* Authors.....: Jens Steube <jens.steube@gmail.com>
*               magnum <john.magnum@hushmail.com>
*
* License.....: MIT
*/
#pragma once

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
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <search.h>
#include <fcntl.h>
#include <assert.h>

#define NOMINMAX
#include <unistd.h>
#include <sys/time.h>
#include "numeric_types_abbreviations.h"

#ifdef _MSC_VER
#define inline __inline
#endif

#ifdef _POSIX

#include <pthread.h>
#include <semaphore.h>
#include <dlfcn.h>
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

#ifdef WITH_HWMON
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

inline int hc_mkdir(char const* name, int mode) {
  return _mkdir(name);
}
#endif // _WIN

/**
* functions
*/

#define CEIL(a) ((a - (int) (a)) > 0 ? a + 1 : a)

#endif // COMMON_H
