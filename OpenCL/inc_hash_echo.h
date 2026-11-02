/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_ECHO_H
#define INC_HASH_ECHO_H

// ECHO, the SHA-3 candidate, as sphlib, hx and John the Ripper implement it. The echo256 functions
// serve digests of 28 and 32 bytes (echo224, echo256) with blocks of 192 bytes, the echo512
// functions digests of 48 and 64 bytes (echo384, echo512) with blocks of 128 bytes. Input consists
// of little endian words, as for MD5. The AES rounds read the tables te0 to te3 of
// inc_cipher_aes.cl through the pointers given to init. After final, v[0] to v[dlen / 4 - 1]
// contain the digest as little endian words.

typedef struct echo256_ctx
{
  // The chaining value of 4 128 bit words, as 16 words, byte swapped until final

  u32 v[16];

  // The block being filled, and the message bits in the blocks already processed.

  u32 m[48];

  u64 cnt;

  // Bytes in m and in the whole message. The second count is -1 after invalid UTF-8.

  int pos;
  int len;

  int dlen;

  SHM_TYPE const u32 *s_te0;
  SHM_TYPE const u32 *s_te1;
  SHM_TYPE const u32 *s_te2;
  SHM_TYPE const u32 *s_te3;

} echo256_ctx_t;

typedef struct echo256_ctx_vector
{
  u32x v[16];

  u32x m[48];

  u64 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE const u32 *s_te0;
  SHM_TYPE const u32 *s_te1;
  SHM_TYPE const u32 *s_te2;
  SHM_TYPE const u32 *s_te3;

} echo256_ctx_vector_t;

typedef struct echo512_ctx
{
  // The chaining value of 8 128 bit words, as 32 words, byte swapped until final

  u32 v[32];

  u32 m[32];

  u64 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE const u32 *s_te0;
  SHM_TYPE const u32 *s_te1;
  SHM_TYPE const u32 *s_te2;
  SHM_TYPE const u32 *s_te3;

} echo512_ctx_t;

typedef struct echo512_ctx_vector
{
  u32x v[32];

  u32x m[32];

  u64 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE const u32 *s_te0;
  SHM_TYPE const u32 *s_te1;
  SHM_TYPE const u32 *s_te2;
  SHM_TYPE const u32 *s_te3;

} echo512_ctx_vector_t;

DECLSPEC void echo256_transform (PRIVATE_AS u32 *v, PRIVATE_AS const u32 *m, const u64 cnt, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void echo256_init (PRIVATE_AS echo256_ctx_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void echo256_block (PRIVATE_AS echo256_ctx_t *ctx);
DECLSPEC void echo256_absorb (PRIVATE_AS echo256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void echo256_update (PRIVATE_AS echo256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void echo256_update_utf16le (PRIVATE_AS echo256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void echo256_update_global (PRIVATE_AS echo256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void echo256_update_global_utf16le (PRIVATE_AS echo256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void echo256_final (PRIVATE_AS echo256_ctx_t *ctx);

DECLSPEC void echo256_transform_vector (PRIVATE_AS u32x *v, PRIVATE_AS const u32x *m, const u64 cnt, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void echo256_init_vector (PRIVATE_AS echo256_ctx_vector_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void echo256_block_vector (PRIVATE_AS echo256_ctx_vector_t *ctx);
DECLSPEC void echo256_absorb_vector (PRIVATE_AS echo256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void echo256_update_vector (PRIVATE_AS echo256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void echo256_update_vector_utf16le (PRIVATE_AS echo256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void echo256_final_vector (PRIVATE_AS echo256_ctx_vector_t *ctx);

DECLSPEC void echo512_transform (PRIVATE_AS u32 *v, PRIVATE_AS const u32 *m, const u64 cnt, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void echo512_init (PRIVATE_AS echo512_ctx_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void echo512_block (PRIVATE_AS echo512_ctx_t *ctx);
DECLSPEC void echo512_absorb (PRIVATE_AS echo512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void echo512_update (PRIVATE_AS echo512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void echo512_update_utf16le (PRIVATE_AS echo512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void echo512_update_global (PRIVATE_AS echo512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void echo512_update_global_utf16le (PRIVATE_AS echo512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void echo512_final (PRIVATE_AS echo512_ctx_t *ctx);

DECLSPEC void echo512_transform_vector (PRIVATE_AS u32x *v, PRIVATE_AS const u32x *m, const u64 cnt, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void echo512_init_vector (PRIVATE_AS echo512_ctx_vector_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3);
DECLSPEC void echo512_block_vector (PRIVATE_AS echo512_ctx_vector_t *ctx);
DECLSPEC void echo512_absorb_vector (PRIVATE_AS echo512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void echo512_update_vector (PRIVATE_AS echo512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void echo512_update_vector_utf16le (PRIVATE_AS echo512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void echo512_final_vector (PRIVATE_AS echo512_ctx_vector_t *ctx);

#endif // INC_HASH_ECHO_H
