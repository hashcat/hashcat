/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STATUS_H
#define _STATUS_H

#include <stdio.h>
#include <time.h>
#include <inttypes.h>

double get_avg_exec_time (hc_device_param_t *device_param, const int last_num_entries);

void status_display_machine_readable (hashcat_ctx_t *hashcat_ctx);
void status_display                  (hashcat_ctx_t *hashcat_ctx);
void status_benchmark_automate       (hashcat_ctx_t *hashcat_ctx);
void status_benchmark                (hashcat_ctx_t *hashcat_ctx);

int  status_progress_init (status_ctx_t *status_ctx, const hashes_t *hashes);
void status_progress_destroy (status_ctx_t *status_ctx);
void status_progress_reset (status_ctx_t *status_ctx, const hashes_t *hashes);

int  status_ctx_init (status_ctx_t *status_ctx);
void status_ctx_destroy (status_ctx_t *status_ctx);

#endif // _STATUS_H
