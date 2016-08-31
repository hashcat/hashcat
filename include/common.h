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
#ifdef __cplusplus
#include <algorithm>
#endif
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

#ifdef HAVE_HWMON
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

///use this to disable c++ impl in favor of c ones
#define NO_CPP_MIN_MAX_VowdDc6V5vjFhdGy //it does not compile :(
//#define NO_CPP_CEIL_VowdDc6V5vjFhdGy

#ifndef MAX
  #if defined(__cplusplus) && ! defined(NO_CPP_MIN_MAX_VowdDc6V5vjFhdGy)
    template<typename T1, typename T2, typename T3> constexpr T3 MAX(T1 a, T2 b);//WTF, it doesn't work
    template<typename T1, typename T2, typename T3> constexpr inline T3 MAX(T1 a, T2 b) {
      return (a > b ? a : b);
    }
  #else
    #ifdef __max
      #define MAX(a,b) __max(a,b)
    #else
     #define MAX(a,b) ((a)>(b)?(a):(b))
    #endif
  #endif
#endif

#ifndef MIN
  #if defined(__cplusplus) && ! defined(NO_CPP_MIN_MAX_VowdDc6V5vjFhdGy)
    template<typename T1, typename T2, typename T3> constexpr T3 MIN(T1 a, T2 b);
    template<typename T1, typename T2, typename T3> constexpr inline T3 MIN(T1 a, T2 b) {
      return (T3)(a < b ? a : b);
    }
  #else
    #ifdef __min
      #define MIN(a,b) __min(a,b)
    #else
      #define MIN(a,b) ((a)<(b)?(a):(b))
    #endif
  #endif
#endif


#if defined(__cplusplus) && ! defined(NO_CPP_CEIL_VowdDc6V5vjFhdGy)
  template<typename T> T CEIL(T a);
  template<typename T> inline T CEIL(T a) {
    switch (sizeof(T)) {
    case sizeof(float) :
      return std::ceilf((float)a);
    case sizeof(double) :
      return std::ceill((double)a);
    default:
      return ((a - (int)(a)) > 0 ? a + 1 : a);
    }
  }
#else
  #define CEIL(a) ((a - (int) (a)) > 0 ? a + 1 : a)
#endif

#undef NO_CPP_MIN_MAX_VowdDc6V5vjFhdGy
#undef NO_CPP_CEIL_VowdDc6V5vjFhdGy

#endif // COMMON_H
