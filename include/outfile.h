/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _OUTFILE_H
#define _OUTFILE_H

#include <stdio.h>
#include <time.h>
#include <inttypes.h>

void build_plain     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u32 *plain_buf, int *out_len);
void build_crackpos  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u64 *out_pos);
void build_debugdata (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u8 *debug_rule_buf, int *debug_rule_len, u8 *debug_plain_ptr, int *debug_plain_len);

void outfile_init           (outfile_ctx_t *outfile_ctx, const user_options_t *user_options);
void outfile_destroy        (outfile_ctx_t *outfile_ctx);
void outfile_format_plain   (outfile_ctx_t *outfile_ctx, const unsigned char *plain_ptr, const u32 plain_len);
void outfile_write_open     (outfile_ctx_t *outfile_ctx);
void outfile_write_close    (outfile_ctx_t *outfile_ctx);
void outfile_write          (outfile_ctx_t *outfile_ctx, const char *out_buf, const unsigned char *plain_ptr, const u32 plain_len, const u64 crackpos, const unsigned char *username, const u32 user_len, const hashconfig_t *hashconfig);
int  outfile_and_hashfile   (outfile_ctx_t *outfile_ctx, const char *hashfile);

#endif // _OUTFILE_H
