/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _TIMER_H
#define _TIMER_H

#if defined(__APPLE__) && defined(MISSING_CLOCK_GETTIME)
#include <sys/time.h>
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#endif

void   hc_timer_set (hc_timer_t *a);
double hc_timer_get (hc_timer_t a);

#endif // _TIMER_H
