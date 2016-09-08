/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef _STATUS_H
#define _STATUS_H

#include <stdio.h>
#include <inttypes.h>

#define STATUS       0
#define STATUS_TIMER 10

typedef enum status_rc
{
   STATUS_STARTING           = 0,
   STATUS_INIT               = 1,
   STATUS_RUNNING            = 2,
   STATUS_PAUSED             = 3,
   STATUS_EXHAUSTED          = 4,
   STATUS_CRACKED            = 5,
   STATUS_ABORTED            = 6,
   STATUS_QUIT               = 7,
   STATUS_BYPASS             = 8,
   STATUS_STOP_AT_CHECKPOINT = 9,
   STATUS_AUTOTUNE           = 10

} status_rc_t;

void status_display_machine_readable ();
void status_display ();
void status_benchmark_automate ();
void status_benchmark ();

#endif // _STATUS_H
