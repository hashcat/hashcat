/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_CUBEHASH_H
#define INC_HASH_CUBEHASH_H

// CubeHash16/32 with a digest of 28, 32, 48 or 64 bytes, one context type for all 4. These are
// what hx calls cube224 to cube512, sphlib's CubeHash-224 to CubeHash-512: 16 rounds per block of
// 32 bytes, and 160 rounds after the last block. Input consists of little endian words, as for
// MD5. After cubehash_final (), x[0] to x[dlen / 4 - 1] contain the digest, little endian.

typedef struct cubehash_ctx
{
  // The state. The block being filled is XORed into its first 8 words as it arrives.

  u32 x[32];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

  int dlen;

} cubehash_ctx_t;

typedef struct cubehash_ctx_vector
{
  u32x x[32];

  int pos;
  int len;

  int dlen;

} cubehash_ctx_vector_t;

DECLSPEC void cubehash_rounds (PRIVATE_AS u32 *x, const int n);
DECLSPEC void cubehash_init (PRIVATE_AS cubehash_ctx_t *ctx, const int dlen);
DECLSPEC void cubehash_absorb (PRIVATE_AS cubehash_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void cubehash_update (PRIVATE_AS cubehash_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void cubehash_update_utf16le (PRIVATE_AS cubehash_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void cubehash_update_global (PRIVATE_AS cubehash_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void cubehash_update_global_utf16le (PRIVATE_AS cubehash_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void cubehash_final (PRIVATE_AS cubehash_ctx_t *ctx);

DECLSPEC void cubehash_rounds_vector (PRIVATE_AS u32x *x, const int n);
DECLSPEC void cubehash_init_vector (PRIVATE_AS cubehash_ctx_vector_t *ctx, const int dlen);
DECLSPEC void cubehash_absorb_vector (PRIVATE_AS cubehash_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void cubehash_update_vector (PRIVATE_AS cubehash_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void cubehash_update_vector_utf16le (PRIVATE_AS cubehash_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void cubehash_final_vector (PRIVATE_AS cubehash_ctx_vector_t *ctx);

#endif // INC_HASH_CUBEHASH_H
