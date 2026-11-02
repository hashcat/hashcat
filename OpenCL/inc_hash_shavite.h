/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SHAVITE_H
#define INC_HASH_SHAVITE_H

// SHAvite-3 as tweaked for round 2 of the SHA-3 competition, which is what sphlib and hx call
// shavite224 to shavite512. The shavite256 functions serve digests of 28 and 32 bytes with 64 byte
// blocks, the shavite512 functions digests of 48 and 64 bytes with 128 byte blocks. Input consists
// of little endian words, as for MD5. The AES rounds read the tables te0 to te3 of
// inc_cipher_aes.cl through the pointers given to init. After final, h[0] to h[dlen / 4 - 1]
// contain the digest as little endian words.

typedef struct shavite256_ctx
{
  // The chaining value, byte swapped until final

  u32 h[8];

  u32 m[16];

  // Bytes in the blocks already processed, bytes in m and bytes in the whole message. The last
  // count is -1 after invalid UTF-8.

  u32 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE const u32 *s_te0;
  SHM_TYPE const u32 *s_te1;
  SHM_TYPE const u32 *s_te2;
  SHM_TYPE const u32 *s_te3;

} shavite256_ctx_t;

typedef struct shavite256_ctx_vector
{
  u32x h[8];

  u32x m[16];

  u32 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE const u32 *s_te0;
  SHM_TYPE const u32 *s_te1;
  SHM_TYPE const u32 *s_te2;
  SHM_TYPE const u32 *s_te3;

} shavite256_ctx_vector_t;

typedef struct shavite512_ctx
{
  u32 h[16];

  u32 m[32];

  u32 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE const u32 *s_te0;
  SHM_TYPE const u32 *s_te1;
  SHM_TYPE const u32 *s_te2;
  SHM_TYPE const u32 *s_te3;

} shavite512_ctx_t;

typedef struct shavite512_ctx_vector
{
  u32x h[16];

  u32x m[32];

  u32 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE const u32 *s_te0;
  SHM_TYPE const u32 *s_te1;
  SHM_TYPE const u32 *s_te2;
  SHM_TYPE const u32 *s_te3;

} shavite512_ctx_vector_t;

DECLSPEC HC_NOINLINE_ALWAYS void shavite256_transform (PRIVATE_AS shavite256_ctx_t *ctx, const u32 cnt0, const u32 cnt1);
DECLSPEC void shavite256_init (PRIVATE_AS shavite256_ctx_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void shavite256_block (PRIVATE_AS shavite256_ctx_t *ctx);
DECLSPEC void shavite256_absorb (PRIVATE_AS shavite256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void shavite256_update (PRIVATE_AS shavite256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void shavite256_update_utf16le (PRIVATE_AS shavite256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void shavite256_update_global (PRIVATE_AS shavite256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void shavite256_update_global_utf16le (PRIVATE_AS shavite256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void shavite256_final (PRIVATE_AS shavite256_ctx_t *ctx);

DECLSPEC HC_NOINLINE_ALWAYS void shavite256_transform_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx, const u32 cnt0, const u32 cnt1);
DECLSPEC void shavite256_init_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void shavite256_block_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx);
DECLSPEC void shavite256_absorb_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void shavite256_update_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void shavite256_update_vector_utf16le (PRIVATE_AS shavite256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void shavite256_final_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx);

DECLSPEC HC_NOINLINE_ALWAYS void shavite512_transform (PRIVATE_AS shavite512_ctx_t *ctx, const u32 cnt0, const u32 cnt1);
DECLSPEC void shavite512_init (PRIVATE_AS shavite512_ctx_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void shavite512_block (PRIVATE_AS shavite512_ctx_t *ctx);
DECLSPEC void shavite512_absorb (PRIVATE_AS shavite512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void shavite512_update (PRIVATE_AS shavite512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void shavite512_update_utf16le (PRIVATE_AS shavite512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void shavite512_update_global (PRIVATE_AS shavite512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void shavite512_update_global_utf16le (PRIVATE_AS shavite512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void shavite512_final (PRIVATE_AS shavite512_ctx_t *ctx);

DECLSPEC HC_NOINLINE_ALWAYS void shavite512_transform_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx, const u32 cnt0, const u32 cnt1);
DECLSPEC void shavite512_init_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void shavite512_block_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx);
DECLSPEC void shavite512_absorb_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void shavite512_update_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void shavite512_update_vector_utf16le (PRIVATE_AS shavite512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void shavite512_final_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx);

#endif // INC_HASH_SHAVITE_H
