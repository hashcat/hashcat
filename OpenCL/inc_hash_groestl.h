/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_GROESTL_H
#define INC_HASH_GROESTL_H

// Groestl, the SHA-3 finalist, in the version that sphlib, hx and John the Ripper call groestl.
// groestl256 serves digests of 28 and 32 bytes with the 512 bit permutations and 64 byte blocks.
// groestl512 serves digests of 48 and 64 bytes with the 1024 bit permutations and 128 byte blocks.
// The init functions take the digest size in bytes and the table groestl_t0, or a copy of it in
// shared memory. Input consists of little endian words, as for MD5. The state words hold the
// state bytes in the same little endian order, so the input needs no swap. After the final
// function, the digest is the first dlen bytes of h, little endian, as for Skein: digest word 2i
// is the low half of h[i] and digest word 2i + 1 its high half.

typedef struct groestl256_ctx
{
  u64 h[8];
  u32 w[16];

  // Blocks already processed. Bytes in the current block and in the whole message. The last
  // count is -1 after invalid UTF-8.

  u32 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE u64a *s_groestl;

} groestl256_ctx_t;

typedef struct groestl256_ctx_vector
{
  u64x h[8];
  u32x w[16];

  u32 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE u64a *s_groestl;

} groestl256_ctx_vector_t;

typedef struct groestl512_ctx
{
  u64 h[16];
  u32 w[32];

  u32 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE u64a *s_groestl;

} groestl512_ctx_t;

typedef struct groestl512_ctx_vector
{
  u64x h[16];
  u32x w[32];

  u32 cnt;

  int pos;
  int len;

  int dlen;

  SHM_TYPE u64a *s_groestl;

} groestl512_ctx_vector_t;

DECLSPEC void groestl256_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u32 *w, SHM_TYPE u64a *s_groestl);
DECLSPEC void groestl256_init (PRIVATE_AS groestl256_ctx_t *ctx, const int dlen, SHM_TYPE u64a *s_groestl);
DECLSPEC void groestl256_block (PRIVATE_AS groestl256_ctx_t *ctx);
DECLSPEC void groestl256_absorb (PRIVATE_AS groestl256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void groestl256_update (PRIVATE_AS groestl256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void groestl256_update_utf16le (PRIVATE_AS groestl256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void groestl256_update_global (PRIVATE_AS groestl256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void groestl256_update_global_utf16le (PRIVATE_AS groestl256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void groestl256_final (PRIVATE_AS groestl256_ctx_t *ctx);

DECLSPEC void groestl256_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u32x *w, SHM_TYPE u64a *s_groestl);
DECLSPEC void groestl256_init_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx, const int dlen, SHM_TYPE u64a *s_groestl);
DECLSPEC void groestl256_block_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx);
DECLSPEC void groestl256_absorb_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void groestl256_update_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void groestl256_update_vector_utf16le (PRIVATE_AS groestl256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void groestl256_final_vector (PRIVATE_AS groestl256_ctx_vector_t *ctx);

DECLSPEC void groestl512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u32 *w, SHM_TYPE u64a *s_groestl);
DECLSPEC void groestl512_init (PRIVATE_AS groestl512_ctx_t *ctx, const int dlen, SHM_TYPE u64a *s_groestl);
DECLSPEC void groestl512_block (PRIVATE_AS groestl512_ctx_t *ctx);
DECLSPEC void groestl512_absorb (PRIVATE_AS groestl512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void groestl512_update (PRIVATE_AS groestl512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void groestl512_update_utf16le (PRIVATE_AS groestl512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void groestl512_update_global (PRIVATE_AS groestl512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void groestl512_update_global_utf16le (PRIVATE_AS groestl512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void groestl512_final (PRIVATE_AS groestl512_ctx_t *ctx);

DECLSPEC void groestl512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u32x *w, SHM_TYPE u64a *s_groestl);
DECLSPEC void groestl512_init_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx, const int dlen, SHM_TYPE u64a *s_groestl);
DECLSPEC void groestl512_block_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx);
DECLSPEC void groestl512_absorb_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void groestl512_update_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void groestl512_update_vector_utf16le (PRIVATE_AS groestl512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void groestl512_final_vector (PRIVATE_AS groestl512_ctx_vector_t *ctx);

#endif // INC_HASH_GROESTL_H
