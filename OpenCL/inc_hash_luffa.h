/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_LUFFA_H
#define INC_HASH_LUFFA_H

// Luffa with a digest of 28, 32, 48 or 64 bytes, one context type for all 4, as sphlib
// implements it. These are what hx calls luffa224 to luffa512. Luffa-224 and Luffa-256 use 3 lanes
// of 8 words, Luffa-384 uses 4 and Luffa-512 uses 5. Luffa-224 is Luffa-256 cut to 28 bytes. The
// block is 32 bytes. Input consists of little endian words, as for MD5, and Luffa reads its blocks
// as big endian words, so the include swaps them internally. After luffa_final () or
// luffa_final_vector (), h[0] to h[dlen / 4 - 1] contain the digest as big endian words: digest
// byte 4i is the high byte of h[i].

typedef struct luffa_ctx
{
  // The chaining value, 1 row of 8 words per lane. Rows beyond the lane count stay unused.

  u32 v[5][8];

  // The block being filled, in memory byte order like the input, and the digest after
  // luffa_final ().

  u32 m[8];
  u32 h[16];

  // Bytes in m and in the whole message. The second count is -1 after invalid UTF-8.

  int pos;
  int len;

  int lanes;
  int dlen;

} luffa_ctx_t;

typedef struct luffa_ctx_vector
{
  u32x v[5][8];

  u32x m[8];
  u32x h[16];

  int pos;
  int len;

  int lanes;
  int dlen;

} luffa_ctx_vector_t;

DECLSPEC void luffa_round (PRIVATE_AS luffa_ctx_t *ctx);
DECLSPEC void luffa_init (PRIVATE_AS luffa_ctx_t *ctx, const int dlen);
DECLSPEC void luffa_absorb (PRIVATE_AS luffa_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void luffa_update (PRIVATE_AS luffa_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void luffa_update_utf16le (PRIVATE_AS luffa_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void luffa_update_global (PRIVATE_AS luffa_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void luffa_update_global_utf16le (PRIVATE_AS luffa_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void luffa_final (PRIVATE_AS luffa_ctx_t *ctx);

DECLSPEC void luffa_round_vector (PRIVATE_AS luffa_ctx_vector_t *ctx);
DECLSPEC void luffa_init_vector (PRIVATE_AS luffa_ctx_vector_t *ctx, const int dlen);
DECLSPEC void luffa_absorb_vector (PRIVATE_AS luffa_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void luffa_update_vector (PRIVATE_AS luffa_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void luffa_update_vector_utf16le (PRIVATE_AS luffa_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void luffa_final_vector (PRIVATE_AS luffa_ctx_vector_t *ctx);

#endif // INC_HASH_LUFFA_H
