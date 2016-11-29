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
#if defined (__linux__)
#include <sys/sysctl.h>
#endif // __linux__
#endif // _POSIX

#if defined (__APPLE__)
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <mach/thread_policy.h>
#endif // __APPLE__

#if defined (_WIN)
#include <windows.h>
#endif // _WIN

int set_cpu_affinity (hashcat_ctx_t *hashcat_ctx);

#endif // _AFFINITY_H
