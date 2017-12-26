/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "timer.h"

#if defined (_WIN)

inline void hc_timer_set (hc_timer_t *a)
{
  QueryPerformanceCounter (a);
}

inline double hc_timer_get (hc_timer_t a)
{
  hc_timer_t hr_freq;

  QueryPerformanceFrequency (&hr_freq);

  hc_timer_t hr_tmp;

  hc_timer_set (&hr_tmp);

  double r = ((double) hr_tmp.QuadPart - (double) a.QuadPart) / ((double) hr_freq.QuadPart / 1000);

  return r;
}

#else

inline void hc_timer_set (hc_timer_t* a)
{
  #if defined(__APPLE__) && defined(MISSING_CLOCK_GETTIME)
  // taken from proxmark3/client/util_posix
  static uint64_t clock_start_time = 0;
  static mach_timebase_info_data_t timebase_info = {0, 0};
  uint64_t now = mach_absolute_time();

  if (clock_start_time == 0)
  {
    mach_timebase_info(&timebase_info);
    clock_start_time = now;
  }

  now = (uint64_t)((double)(now - clock_start_time) * (double)timebase_info.numer / (double)timebase_info.denom);

  a->tv_sec = now / 1000000000;
  a->tv_nsec = now % 1000000000;
  #else
  clock_gettime (CLOCK_MONOTONIC, a);
  #endif
}

inline double hc_timer_get (hc_timer_t a)
{
  hc_timer_t hr_tmp;

  hc_timer_set (&hr_tmp);

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
}

#endif
