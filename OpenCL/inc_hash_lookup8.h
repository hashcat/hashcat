/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_LOOKUP8_H
#define INC_HASH_LOOKUP8_H

// Bob Jenkins' lookup8 hash (), the 64 bit form of lookup2. The level starts a and b, and the
// length of the whole input is added to c before the tail, so the context buffers one block of 24
// bytes and counts every byte. final () leaves the hash in c.

typedef struct lookup8_ctx
{
  u64 a;
  u64 b;
  u64 c;

  u32 buf[6];

  int len;

} lookup8_ctx_t;

typedef struct lookup8_ctx_vector
{
  u64x a;
  u64x b;
  u64x c;

  u32x buf[6];

  int len;

} lookup8_ctx_vector_t;

DECLSPEC void lookup8_init          (PRIVATE_AS lookup8_ctx_t *ctx, const u64 level);
DECLSPEC void lookup8_update        (PRIVATE_AS lookup8_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void lookup8_update_global (PRIVATE_AS lookup8_ctx_t *ctx, GLOBAL_AS  const u32 *w, const int len);
DECLSPEC void lookup8_final         (PRIVATE_AS lookup8_ctx_t *ctx);

DECLSPEC void lookup8_init_vector   (PRIVATE_AS lookup8_ctx_vector_t *ctx, const u64x level);
DECLSPEC void lookup8_update_vector (PRIVATE_AS lookup8_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void lookup8_final_vector  (PRIVATE_AS lookup8_ctx_vector_t *ctx);

// The whole candidate at once, for the optimized kernels.

DECLSPEC u64 lookup8_opti (PRIVATE_AS const u32 *w, const u32 len, const u64 level);

#endif // INC_HASH_LOOKUP8_H
