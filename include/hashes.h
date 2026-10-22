/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_HASHES_H
#define HC_HASHES_H

int sort_by_digest_p0p1  (const void *v1, const void *v2, void *v3);
int sort_by_salt         (const void *v1, const void *v2);
int sort_by_hash         (const void *v1, const void *v2, void *v3);
int sort_by_hash_no_salt (const void *v1, const void *v2, void *v3);

int hash_encode (const user_options_t *user_options, const hashconfig_t *hashconfig, const hashes_t *hashes, const module_ctx_t *module_ctx, char *out_buf, const int out_size, const u32 salt_pos, const u32 digest_pos);

int save_hash (hashcat_ctx_t *hashcat_ctx);

int check_hash (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain);

//int check_cracked (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 salt_pos);
int check_cracked (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);

int hashes_init_filename  (hashcat_ctx_t *hashcat_ctx);
int hashes_init_stage1    (hashcat_ctx_t *hashcat_ctx);
int hashes_init_stage2    (hashcat_ctx_t *hashcat_ctx);
int hashes_init_stage3    (hashcat_ctx_t *hashcat_ctx);
int hashes_init_stage4    (hashcat_ctx_t *hashcat_ctx);
int hashes_init_stage5    (hashcat_ctx_t *hashcat_ctx);
int hashes_init_selftest  (hashcat_ctx_t *hashcat_ctx);
int hashes_init_benchmark (hashcat_ctx_t *hashcat_ctx);
int hashes_init_zerohash  (hashcat_ctx_t *hashcat_ctx);

void hash_info_destroy (hashinfo_t *hash_info);

// How many non-empty lines each probe reads. Autodetect and the wordlist read as many as the format
// detection does. With -m the question is narrower and a little more of the hash file is read, so a
// block of junk at its top cannot decide it. HASHES_PROBE_LOAD is far beyond any header a real hash
// file carries, and parsing that many lines still costs milliseconds with any parser.

#define HASHES_PROBE_AUTODETECT 100
#define HASHES_PROBE_HASHFILE   500
#define HASHES_PROBE_WORDLIST   100
#define HASHES_PROBE_LOAD       10000

// HASHES_PROBE_SPLIT reads a split hash the way the loader does, and HASHES_PROBE_REGULAR reads nothing
// but a regular file

typedef enum hashes_probe_flags
{
  HASHES_PROBE_SPLIT   = (1 << 0),
  HASHES_PROBE_REGULAR = (1 << 1),

} hashes_probe_flags_t;

// what a probe read: the non-empty lines, those of them that are not a placeholder, and those of
// them that parsed

typedef struct hashes_probe
{
  u32 lines;
  u32 tried;
  u32 hit;

} hashes_probe_t;

void hashes_probe_file      (hashcat_ctx_t *hashcat_ctx, const char *path, const u32 lines_max, const u32 hits_max, const u32 probe_flags, u8 *hit_map, hashes_probe_t *probe);
void hashes_probe_wordlists (hashcat_ctx_t *hashcat_ctx, const u32 lines_max, const u32 probe_flags, const char **best_file, hashes_probe_t *best);

bool hashes_probe_has_wordlist (hashcat_ctx_t *hashcat_ctx);

bool hashes_probe_wordlike (const hashconfig_t *hashconfig);

bool hashes_probe_few  (const u32 lines_hit, const u32 lines_tried, const bool wordlike);
bool hashes_probe_most (const u32 lines_hit, const u32 lines_tried);

void hashes_destroy (hashcat_ctx_t *hashcat_ctx);

void hashes_logger (hashcat_ctx_t *hashcat_ctx);

#endif // HC_HASHES_H
