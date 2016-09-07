/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _AFFINITY_H
#define _AFFINITY_H

#include <stdlib.h>

#ifdef _POSIX
#include <pthread.h>
#endif // _POSIX

#ifdef _WIN
#include <windows.h>
#endif // _WIN

#ifdef __APPLE__
typedef struct cpu_set
{
  uint32_t count;

} cpu_set_t;
#endif

void set_cpu_affinity (char *cpu_affinity);

#endif // _AFFINITY_H
