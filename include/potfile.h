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

int sort_by_pot               (const void *v1, const void *v2, MAYBE_UNUSED void *v3);
int sort_by_salt_buf          (const void *v1, const void *v2, MAYBE_UNUSED void *v3);
int sort_by_hash_t_salt       (const void *v1, const void *v2);
int sort_by_hash_t_salt_hccap (const void *v1, const void *v2);

void  hc_qsort_r (void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg);
void *hc_bsearch_r (const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg);

int  potfile_init             (hashcat_ctx_t *hashcat_ctx);
int  potfile_read_open        (hashcat_ctx_t *hashcat_ctx);
//int  potfile_read_parse       (hashcat_ctx_t *hashcat_ctx);
void potfile_read_close       (hashcat_ctx_t *hashcat_ctx);
int  potfile_write_open       (hashcat_ctx_t *hashcat_ctx);
void potfile_write_close      (hashcat_ctx_t *hashcat_ctx);
void potfile_write_append     (hashcat_ctx_t *hashcat_ctx, const char *out_buf, u8 *plain_ptr, unsigned int plain_len);
//void potfile_show_request     (hashcat_ctx_t *hashcat_ctx, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *, void *));
//void potfile_left_request     (hashcat_ctx_t *hashcat_ctx, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *, void *));
//int  potfile_show_request_lm  (hashcat_ctx_t *hashcat_ctx, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *, void *));
//int  potfile_left_request_lm  (hashcat_ctx_t *hashcat_ctx, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *, void *));
int  potfile_remove_parse     (hashcat_ctx_t *hashcat_ctx);
void potfile_destroy          (hashcat_ctx_t *hashcat_ctx);
int  potfile_handle_show      (hashcat_ctx_t *hashcat_ctx);
int  potfile_handle_left      (hashcat_ctx_t *hashcat_ctx);

#endif // _POTFILE_H
