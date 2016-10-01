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

  return (double) ((double) (hr_tmp.QuadPart - a.QuadPart) / (double) (hr_freq.QuadPart / 1000));
}

#elif defined(_POSIX)

inline void hc_timer_set (hc_timer_t* a)
{
  gettimeofday (a, NULL);
}

inline double hc_timer_get (hc_timer_t a)
{
  hc_timer_t hr_tmp;

  hc_timer_set (&hr_tmp);

  return (double) (((hr_tmp.tv_sec - (a).tv_sec) * 1000) + ((double) (hr_tmp.tv_usec - (a).tv_usec) / 1000));
}

#endif
