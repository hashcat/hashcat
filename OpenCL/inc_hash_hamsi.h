/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_HAMSI_H
#define INC_HASH_HAMSI_H

// Hamsi, as in sphlib, which is what hx calls hamsi224 to hamsi512. Hamsi-224 and Hamsi-256 share
// the hamsi256 functions, with 4 byte blocks and 8 state words. Hamsi-384 and Hamsi-512 share the
// hamsi512 functions, with 8 byte blocks and 16 state words. The init functions take the digest
// size in bytes: 28 or 32 for hamsi256, 48 or 64 for hamsi512. Input consists of little endian
// words, as for MD5. After the final functions, h[0] to h[dlen / 4 - 1] contain the digest as
// little endian words in digest byte order, so the first digest byte is the low byte of h[0].

typedef struct hamsi256_ctx
{
  u32 h[8];

  // The block being filled, and the bytes in it.

  u32 m;

  int pos;

  // Bytes in the blocks already processed and bytes in the whole message. The second count is -1
  // after invalid UTF-8.

  u64 cnt;

  int len;

  int dlen;

} hamsi256_ctx_t;

typedef struct hamsi256_ctx_vector
{
  u32x h[8];

  u32x m;

  int pos;

  u64 cnt;

  int len;

  int dlen;

} hamsi256_ctx_vector_t;

typedef struct hamsi512_ctx
{
  u32 h[16];

  u32 m[2];

  int pos;

  u64 cnt;

  int len;

  int dlen;

} hamsi512_ctx_t;

typedef struct hamsi512_ctx_vector
{
  u32x h[16];

  u32x m[2];

  int pos;

  u64 cnt;

  int len;

  int dlen;

} hamsi512_ctx_vector_t;

DECLSPEC void hamsi256_transform (PRIVATE_AS u32 *h, const u32 x);
DECLSPEC void hamsi256_transform_final (PRIVATE_AS u32 *h, const u32 x);
DECLSPEC void hamsi256_init (PRIVATE_AS hamsi256_ctx_t *ctx, const int dlen);
DECLSPEC void hamsi256_absorb (PRIVATE_AS hamsi256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void hamsi256_update (PRIVATE_AS hamsi256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void hamsi256_update_utf16le (PRIVATE_AS hamsi256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void hamsi256_update_global (PRIVATE_AS hamsi256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void hamsi256_update_global_utf16le (PRIVATE_AS hamsi256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void hamsi256_final (PRIVATE_AS hamsi256_ctx_t *ctx);

DECLSPEC void hamsi256_transform_vector (PRIVATE_AS u32x *h, const u32x x);
DECLSPEC void hamsi256_transform_final_vector (PRIVATE_AS u32x *h, const u32x x);
DECLSPEC void hamsi256_init_vector (PRIVATE_AS hamsi256_ctx_vector_t *ctx, const int dlen);
DECLSPEC void hamsi256_absorb_vector (PRIVATE_AS hamsi256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void hamsi256_update_vector (PRIVATE_AS hamsi256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void hamsi256_update_vector_utf16le (PRIVATE_AS hamsi256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void hamsi256_final_vector (PRIVATE_AS hamsi256_ctx_vector_t *ctx);

DECLSPEC void hamsi512_transform (PRIVATE_AS u32 *h, const u32 x0, const u32 x1);
DECLSPEC void hamsi512_transform_final (PRIVATE_AS u32 *h, const u32 x0, const u32 x1);
DECLSPEC void hamsi512_init (PRIVATE_AS hamsi512_ctx_t *ctx, const int dlen);
DECLSPEC void hamsi512_absorb (PRIVATE_AS hamsi512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void hamsi512_update (PRIVATE_AS hamsi512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void hamsi512_update_utf16le (PRIVATE_AS hamsi512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void hamsi512_update_global (PRIVATE_AS hamsi512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void hamsi512_update_global_utf16le (PRIVATE_AS hamsi512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void hamsi512_final (PRIVATE_AS hamsi512_ctx_t *ctx);

DECLSPEC void hamsi512_transform_vector (PRIVATE_AS u32x *h, const u32x x0, const u32x x1);
DECLSPEC void hamsi512_transform_final_vector (PRIVATE_AS u32x *h, const u32x x0, const u32x x1);
DECLSPEC void hamsi512_init_vector (PRIVATE_AS hamsi512_ctx_vector_t *ctx, const int dlen);
DECLSPEC void hamsi512_absorb_vector (PRIVATE_AS hamsi512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void hamsi512_update_vector (PRIVATE_AS hamsi512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void hamsi512_update_vector_utf16le (PRIVATE_AS hamsi512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void hamsi512_final_vector (PRIVATE_AS hamsi512_ctx_vector_t *ctx);

#endif // INC_HASH_HAMSI_H
