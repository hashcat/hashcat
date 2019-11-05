/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "timer.h"

#if defined (_WIN)

void hc_timer_set (hc_timer_t *a)
{
  QueryPerformanceCounter (a);
}

double hc_timer_get (hc_timer_t a)
{
  hc_timer_t hr_freq;

  QueryPerformanceFrequency (&hr_freq);

  hc_timer_t hr_tmp;

  hc_timer_set (&hr_tmp);

  double r = ((double) hr_tmp.QuadPart - (double) a.QuadPart) / ((double) hr_freq.QuadPart / 1000);

  return r;
}

#else

void hc_timer_set (hc_timer_t* a)
{
  #if defined(__APPLE__) && defined(MISSING_CLOCK_GETTIME)
  gettimeofday (a, NULL);
  #else
  clock_gettime (CLOCK_MONOTONIC, a);
  #endif
}

double hc_timer_get (hc_timer_t a)
{
  hc_timer_t hr_tmp;

  hc_timer_set (&hr_tmp);

  #if defined(__APPLE__) && defined(MISSING_CLOCK_GETTIME)
  return (double) (((hr_tmp.tv_sec - (a).tv_sec) * 1000) + ((double) (hr_tmp.tv_usec - (a).tv_usec) / 1000));
  #else
  hc_timer_t s;

  s.tv_sec  = hr_tmp.tv_sec  - a.tv_sec;
  s.tv_nsec = hr_tmp.tv_nsec - a.tv_nsec;

  if (s.tv_nsec < 0)
  {
    s.tv_sec  -= 1;
    s.tv_nsec += 1000000000;
  }

  double r = ((double) s.tv_sec * 1000) + ((double) s.tv_nsec / 1000000);

  return r;
  #endif
}

#endif
