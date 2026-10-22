/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_RIPEMD256_H
#define INC_HASH_RIPEMD256_H

// RIPEMD-256 uses 2 RIPEMD-128 lines that remain separate, with one register swapped after each
// round. Input consists of little endian words, as for MD5, in blocks of 64 bytes. After
// ripemd256_final (), the digest is h in little endian word order.

typedef struct ripemd256_ctx
{
  u32 h[8];
  u32 w[16];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

} ripemd256_ctx_t;

typedef struct ripemd256_ctx_vector
{
  u32x h[8];
  u32x w[16];

  int pos;
  int len;

} ripemd256_ctx_vector_t;

DECLSPEC void ripemd256_transform (PRIVATE_AS u32 *dgst, PRIVATE_AS const u32 *w);
DECLSPEC void ripemd256_init (PRIVATE_AS ripemd256_ctx_t *ctx);
DECLSPEC void ripemd256_block (PRIVATE_AS ripemd256_ctx_t *ctx);
DECLSPEC void ripemd256_absorb (PRIVATE_AS ripemd256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void ripemd256_update (PRIVATE_AS ripemd256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd256_update_utf16le (PRIVATE_AS ripemd256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd256_update_global (PRIVATE_AS ripemd256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd256_update_global_utf16le (PRIVATE_AS ripemd256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd256_final (PRIVATE_AS ripemd256_ctx_t *ctx);

DECLSPEC void ripemd256_transform_vector (PRIVATE_AS u32x *dgst, PRIVATE_AS const u32x *w);
DECLSPEC void ripemd256_init_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx);
DECLSPEC void ripemd256_block_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx);
DECLSPEC void ripemd256_absorb_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void ripemd256_update_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd256_update_vector_utf16le (PRIVATE_AS ripemd256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd256_final_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx);

#endif // INC_HASH_RIPEMD256_H
