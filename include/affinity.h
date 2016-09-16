/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _AFFINITY_H
#define _AFFINITY_H

#include <stdlib.h>
#include <stdarg.h>

#if defined (_POSIX)
#include <pthread.h>
#include <sys/sysctl.h>
#endif // _POSIX

#if defined (__APPLE__)
#include <mach-o/dyld.h>
#include <mach/mach.h>
#endif // __APPLE__

#if defined (_WIN)
#include <windows.h>
#endif // _WIN

void set_cpu_affinity (char *cpu_affinity);

#endif // _AFFINITY_H
