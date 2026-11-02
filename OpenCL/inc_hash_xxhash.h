/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_XXHASH_H
#define INC_HASH_XXHASH_H

// XXH64 and XXH32. The seed sets the initial state of the four lanes, so it is not the same as
// hashing a prefix. The context buffers one stripe of input, 32 bytes for XXH64 and 16 for XXH32,
// and final () leaves the digest in h.

typedef struct xxh64_ctx
{
  u64 v[4];
  u64 seed;
  u64 h;

  u32 buf[8];

  int len;

} xxh64_ctx_t;

typedef struct xxh64_ctx_vector
{
  u64x v[4];
  u64x seed;
  u64x h;

  u32x buf[8];

  int len;

} xxh64_ctx_vector_t;

typedef struct xxh32_ctx
{
  u32 v[4];
  u32 seed;
  u32 h;

  u32 buf[4];

  int len;

} xxh32_ctx_t;

typedef struct xxh32_ctx_vector
{
  u32x v[4];
  u32x seed;
  u32x h;

  u32x buf[4];

  int len;

} xxh32_ctx_vector_t;

DECLSPEC void xxh64_init           (PRIVATE_AS xxh64_ctx_t *ctx, const u64 seed);
DECLSPEC void xxh64_update         (PRIVATE_AS xxh64_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void xxh64_update_global  (PRIVATE_AS xxh64_ctx_t *ctx, GLOBAL_AS  const u32 *w, const int len);
DECLSPEC void xxh64_final          (PRIVATE_AS xxh64_ctx_t *ctx);

DECLSPEC void xxh64_init_vector    (PRIVATE_AS xxh64_ctx_vector_t *ctx, const u64x seed);
DECLSPEC void xxh64_update_vector  (PRIVATE_AS xxh64_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void xxh64_final_vector   (PRIVATE_AS xxh64_ctx_vector_t *ctx);

DECLSPEC void xxh32_init           (PRIVATE_AS xxh32_ctx_t *ctx, const u32 seed);
DECLSPEC void xxh32_update         (PRIVATE_AS xxh32_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void xxh32_update_global  (PRIVATE_AS xxh32_ctx_t *ctx, GLOBAL_AS  const u32 *w, const int len);
DECLSPEC void xxh32_final          (PRIVATE_AS xxh32_ctx_t *ctx);

DECLSPEC void xxh32_init_vector    (PRIVATE_AS xxh32_ctx_vector_t *ctx, const u32x seed);
DECLSPEC void xxh32_update_vector  (PRIVATE_AS xxh32_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void xxh32_final_vector   (PRIVATE_AS xxh32_ctx_vector_t *ctx);

// The whole candidate at once, for the optimized kernels.

DECLSPEC u64 xxh64_opti (PRIVATE_AS const u32 *w, const u32 len, const u64 seed);
DECLSPEC u32 xxh32_opti (PRIVATE_AS const u32 *w, const u32 len, const u32 seed);

#endif // INC_HASH_XXHASH_H
