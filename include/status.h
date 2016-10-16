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

char *status_get_session              (const hashcat_ctx_t *hashcat_ctx);
char *status_get_status_string        (const hashcat_ctx_t *hashcat_ctx);
char *status_get_hash_type            (const hashcat_ctx_t *hashcat_ctx);
char *status_get_hash_target          (const hashcat_ctx_t *hashcat_ctx);

int   status_get_input_mode           (const hashcat_ctx_t *hashcat_ctx);
char *status_get_input_base           (const hashcat_ctx_t *hashcat_ctx);
char *status_get_input_mod            (const hashcat_ctx_t *hashcat_ctx);
char *status_get_input_charset        (const hashcat_ctx_t *hashcat_ctx);
int   status_get_input_masks_pos      (const hashcat_ctx_t *hashcat_ctx);
int   status_get_input_masks_cnt      (const hashcat_ctx_t *hashcat_ctx);

int   status_progress_init            (hashcat_ctx_t *hashcat_ctx);
void  status_progress_destroy         (hashcat_ctx_t *hashcat_ctx);
void  status_progress_reset           (hashcat_ctx_t *hashcat_ctx);

int   status_ctx_init                 (hashcat_ctx_t *hashcat_ctx);
void  status_ctx_destroy              (hashcat_ctx_t *hashcat_ctx);

#endif // _STATUS_H
