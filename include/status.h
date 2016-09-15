/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STATUS_H
#define _STATUS_H

#include <stdio.h>
#include <inttypes.h>

#define STATUS            0
#define STATUS_TIMER      10
#define MACHINE_READABLE  0

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

double get_avg_exec_time (hc_device_param_t *device_param, const int last_num_entries);

void status_display_machine_readable (opencl_ctx_t *opencl_ctx);
void status_display (opencl_ctx_t *opencl_ctx);
void status_benchmark_automate (opencl_ctx_t *opencl_ctx);
void status_benchmark (opencl_ctx_t *opencl_ctx);

#endif // _STATUS_H
