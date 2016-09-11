/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _TIMER_H
#define _TIMER_H

#if defined (_POSIX)
#include <sys/time.h>
#endif

#if defined (_WIN)
#include <windows.h>
#endif

#if defined (_WIN)
typedef LARGE_INTEGER  hc_timer_t;
#elif defined (_POSIX)
typedef struct timeval hc_timer_t;
#endif

#if defined (_WIN)

#define hc_timer_get(a,r) { hc_timer_t hr_freq; QueryPerformanceFrequency (&hr_freq); hc_timer_t hr_tmp; hc_timer_set (&hr_tmp); (r) = (double) ((double) (hr_tmp.QuadPart - (a).QuadPart) / (double) (hr_freq.QuadPart / 1000)); }
#define hc_timer_set(a)   { QueryPerformanceCounter ((a)); }

#elif defined (_POSIX)

#define hc_timer_get(a,r) { hc_timer_t hr_tmp; hc_timer_set (&hr_tmp); (r) = (double) (((hr_tmp.tv_sec - (a).tv_sec) * 1000) + ((double) (hr_tmp.tv_usec - (a).tv_usec) / 1000)); }
#define hc_timer_set(a)   { gettimeofday ((a), NULL); }

#endif

#endif // _TIMER_H
