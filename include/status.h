/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STATUS_H
#define _STATUS_H

#include <stdio.h>
#include <inttypes.h>

double get_avg_exec_time (hc_device_param_t *device_param, const int last_num_entries);

void status_display_machine_readable (status_ctx_t *status_ctx, opencl_ctx_t *opencl_ctx, const hwmon_ctx_t *hwmon_ctx, const hashes_t *hashes, const restore_ctx_t *restore_ctx, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const straight_ctx_t *straight_ctx, const combinator_ctx_t *combinator_ctx, const mask_ctx_t *mask_ctx);
void status_display                  (status_ctx_t *status_ctx, opencl_ctx_t *opencl_ctx, const hwmon_ctx_t *hwmon_ctx, const hashconfig_t *hashconfig, const hashes_t *hashes, const cpt_ctx_t *cpt_ctx, const restore_ctx_t *restore_ctx, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const straight_ctx_t *straight_ctx, const combinator_ctx_t *combinator_ctx, const mask_ctx_t *mask_ctx);
void status_benchmark_automate       (status_ctx_t *status_ctx, opencl_ctx_t *opencl_ctx, const hashconfig_t *hashconfig);
void status_benchmark                (status_ctx_t *status_ctx, opencl_ctx_t *opencl_ctx, const hashconfig_t *hashconfig, const user_options_t *user_options);

int  status_ctx_init    (status_ctx_t *status_ctx, const hashes_t *hashes);
void status_ctx_destroy (status_ctx_t *status_ctx);
void status_ctx_reset   (status_ctx_t *status_ctx, const hashes_t *hashes);

#endif // _STATUS_H
