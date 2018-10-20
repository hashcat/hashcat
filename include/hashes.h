/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HASH_MANAGEMENT_H
#define _HASH_MANAGEMENT_H

int sort_by_string       (const void *v1, const void *v2);
int sort_by_digest_p0p1  (const void *v1, const void *v2, void *v3);
int sort_by_salt         (const void *v1, const void *v2);
int sort_by_salt_buf     (const void *v1, const void *v2, MAYBE_UNUSED void * v3);
int sort_by_hash         (const void *v1, const void *v2, void *v3);
int sort_by_hash_no_salt (const void *v1, const void *v2, void *v3);

int save_hash (hashcat_ctx_t *hashcat_ctx);

void check_hash (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain);

int check_cracked (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 salt_pos);

void hashes_init_filename (hashcat_ctx_t *hashcat_ctx);

int hashes_init_stage1 (hashcat_ctx_t *hashcat_ctx);
int hashes_init_stage2 (hashcat_ctx_t *hashcat_ctx);
int hashes_init_stage3 (hashcat_ctx_t *hashcat_ctx);
int hashes_init_stage4 (hashcat_ctx_t *hashcat_ctx);

int hashes_init_selftest (hashcat_ctx_t *hashcat_ctx);

void hashes_destroy (hashcat_ctx_t *hashcat_ctx);

void hashes_logger (hashcat_ctx_t *hashcat_ctx);

#endif // _HASH_MANAGEMENT_H
