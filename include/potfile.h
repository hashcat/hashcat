/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _POTFILE_H
#define _POTFILE_H

#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#define INCR_POT 1000

int sort_by_pot               (const void *v1, const void *v2, void *v3);
int sort_by_salt_buf          (const void *v1, const void *v2, void *v3);
int sort_by_hash_t_salt       (const void *v1, const void *v2);
int sort_by_hash_t_salt_hccap (const void *v1, const void *v2);

void  hc_qsort_r (void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg);
void *hc_bsearch_r (const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg);

void potfile_init             (potfile_ctx_t *potfile_ctx, const user_options_t *user_options, const folder_config_t *folder_config);
void potfile_format_plain     (potfile_ctx_t *potfile_ctx, const unsigned char *plain_ptr, const u32 plain_len);
int  potfile_read_open        (potfile_ctx_t *potfile_ctx);
void potfile_read_parse       (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig);
void potfile_read_close       (potfile_ctx_t *potfile_ctx);
int  potfile_write_open       (potfile_ctx_t *potfile_ctx);
void potfile_write_close      (potfile_ctx_t *potfile_ctx);
void potfile_write_append     (potfile_ctx_t *potfile_ctx, const char *out_buf, u8 *plain_ptr, unsigned int plain_len);
void potfile_hash_alloc       (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, const u32 num);
void potfile_hash_free        (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig);
void potfile_show_request     (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, outfile_ctx_t *outfile_ctx, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *, void *));
void potfile_left_request     (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, outfile_ctx_t *outfile_ctx, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *, void *));
void potfile_show_request_lm  (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, outfile_ctx_t *outfile_ctx, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *, void *));
void potfile_left_request_lm  (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, outfile_ctx_t *outfile_ctx, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *, void *));
int  potfile_remove_parse     (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, const hashes_t *hashes);
void potfile_destroy          (potfile_ctx_t *potfile_ctx);

#endif // _POTFILE_H
