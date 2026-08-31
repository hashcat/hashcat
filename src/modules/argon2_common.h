/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_ARGON2_COMMON_H
#define HC_ARGON2_COMMON_H

#define ARGON2_SYNC_POINTS  4
#define ARGON2_BLOCK_SIZE   1024

typedef struct argon2_options
{
  u32 type;
  u32 version;

  u32 iterations;
  u32 parallelism;
  u32 memory_usage_in_kib;

  u32 segment_length;
  u32 lane_length;
  u32 memory_block_count;

  u32 digest_len;

} argon2_options_t;

u64 get_largest_memory_block_count  (const hashconfig_t *hashconfig, const hashes_t *hashes);
u64 get_selftest_memory_block_count (const hashconfig_t *hashconfig, const hashes_t *hashes);

#endif //  HC_ARGON2_COMMON_H
