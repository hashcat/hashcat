/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HASH_MANAGEMENT_H
#define _HASH_MANAGEMENT_H

int sort_by_digest_p0p1  (const void *v1, const void *v2);
int sort_by_salt         (const void *v1, const void *v2);
int sort_by_hash         (const void *v1, const void *v2);
int sort_by_hash_no_salt (const void *v1, const void *v2);

void save_hash (const user_options_t *user_options, const hashconfig_t *hashconfig, const hashes_t *hashes);

void check_hash (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const user_options_t *user_options, const user_options_extra_t *user_options_extra, plain_t *plain);

int check_cracked (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const user_options_t *user_options, const user_options_extra_t *user_options_extra, hashconfig_t *hashconfig, hashes_t *hashes, const uint salt_pos);

int hashes_init_stage1 (hashes_t *hashes, const hashconfig_t *hashconfig, potfile_ctx_t *potfile_ctx, outfile_ctx_t *outfile_ctx, user_options_t *user_options, char *hash_or_file);
int hashes_init_stage2 (hashes_t *hashes, const hashconfig_t *hashconfig, opencl_ctx_t *opencl_ctx, user_options_t *user_options);

void hashes_destroy (hashes_t *hashes);

#endif // _HASH_MANAGEMENT_H
