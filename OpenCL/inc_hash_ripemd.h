/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_RIPEMD_H
#define INC_HASH_RIPEMD_H

// The original RIPEMD of 1992 with its 128 bit output, which is not RIPEMD-128. It uses 3 rounds
// on 2 lines of 4 words, combined at the end. Input consists of little endian words, as for MD5,
// in blocks of 64 bytes. After ripemd_final (), h[0] to h[3] contain the digest as little endian
// words, so h[i] holds digest bytes 4i to 4i+3.

typedef struct ripemd_ctx
{
  u32 h[4];
  u32 w[16];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

} ripemd_ctx_t;

typedef struct ripemd_ctx_vector
{
  u32x h[4];
  u32x w[16];

  int pos;
  int len;

} ripemd_ctx_vector_t;

DECLSPEC void ripemd_transform (PRIVATE_AS u32 *dgst, PRIVATE_AS const u32 *w);
DECLSPEC void ripemd_init (PRIVATE_AS ripemd_ctx_t *ctx);
DECLSPEC void ripemd_block (PRIVATE_AS ripemd_ctx_t *ctx);
DECLSPEC void ripemd_absorb (PRIVATE_AS ripemd_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void ripemd_update (PRIVATE_AS ripemd_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd_update_utf16le (PRIVATE_AS ripemd_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd_update_global (PRIVATE_AS ripemd_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd_update_global_utf16le (PRIVATE_AS ripemd_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd_final (PRIVATE_AS ripemd_ctx_t *ctx);

DECLSPEC void ripemd_transform_vector (PRIVATE_AS u32x *dgst, PRIVATE_AS const u32x *w);
DECLSPEC void ripemd_init_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx);
DECLSPEC void ripemd_block_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx);
DECLSPEC void ripemd_absorb_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void ripemd_update_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd_update_vector_utf16le (PRIVATE_AS ripemd_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd_final_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx);

#endif // INC_HASH_RIPEMD_H
