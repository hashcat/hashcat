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

u64  status_words_base_calculate      (hashcat_ctx_t *hashcat_ctx, const u64 words_cnt);

void status_display_machine_readable  (hashcat_ctx_t *hashcat_ctx);
void status_display                   (hashcat_ctx_t *hashcat_ctx);
void status_benchmark_automate        (hashcat_ctx_t *hashcat_ctx);
void status_benchmark                 (hashcat_ctx_t *hashcat_ctx);

int  status_progress_init             (hashcat_ctx_t *hashcat_ctx);
void status_progress_destroy          (hashcat_ctx_t *hashcat_ctx);
void status_progress_reset            (hashcat_ctx_t *hashcat_ctx);

int  status_ctx_init                  (hashcat_ctx_t *hashcat_ctx);
void status_ctx_destroy               (hashcat_ctx_t *hashcat_ctx);

#endif // _STATUS_H
