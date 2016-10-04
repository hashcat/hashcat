/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _HASH_MANAGEMENT_H
#define _HASH_MANAGEMENT_H

int sort_by_digest_p0p1  (const void *v1, const void *v2, void *v3);
int sort_by_salt         (const void *v1, const void *v2);
int sort_by_hash         (const void *v1, const void *v2, void *v3);
int sort_by_hash_no_salt (const void *v1, const void *v2, void *v3);

void build_plain     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u32 *plain_buf, int *out_len);
void build_crackpos  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u64 *out_pos);
void build_debugdata (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u8 *debug_rule_buf, int *debug_rule_len, u8 *debug_plain_ptr, int *debug_plain_len);

void save_hash (const user_options_t *user_options, const hashconfig_t *hashconfig, const hashes_t *hashes);

void check_hash (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain);

int check_cracked (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 salt_pos);

int hashes_init_stage1 (hashes_t *hashes, const hashconfig_t *hashconfig, potfile_ctx_t *potfile_ctx, outfile_ctx_t *outfile_ctx, user_options_t *user_options, char *hash_or_file);
int hashes_init_stage2 (hashes_t *hashes, const hashconfig_t *hashconfig, user_options_t *user_options, status_ctx_t *status_ctx);
int hashes_init_stage3 (hashes_t *hashes, hashconfig_t *hashconfig, user_options_t *user_options);

void hashes_destroy (hashes_t *hashes);

void hashes_logger (const hashes_t *hashes, const logfile_ctx_t *logfile_ctx);

#endif // _HASH_MANAGEMENT_H
