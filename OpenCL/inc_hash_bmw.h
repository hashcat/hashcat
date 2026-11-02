/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_BMW_H
#define INC_HASH_BMW_H

// Blue Midnight Wish with the tweak of the second SHA-3 round, as sphlib implements it, which is
// what hx calls bmw224 to bmw512. The 32 bit core bmw256 produces digests of 28 or 32 bytes from
// 64 byte blocks, and the 64 bit core bmw512 digests of 48 or 64 bytes from 128 byte blocks.
// Input consists of little endian words, as for MD5. After bmw256_final () and bmw512_final (),
// and after their vector forms, h holds the digest in its first dlen bytes, little endian. These
// are 7 or 8 u32 words for bmw256, and 6 or 8 u64 words for bmw512, whose low 32 bits come first.

typedef struct bmw256_ctx
{
  u32 h[16];

  // The block being filled. Bytes in the blocks already processed, bytes in m and bytes in the
  // whole message. The last count is -1 after invalid UTF-8.

  u32 m[16];

  u64 cnt;

  int pos;
  int len;

  int dlen;

} bmw256_ctx_t;

typedef struct bmw256_ctx_vector
{
  u32x h[16];

  u32x m[16];

  u64 cnt;

  int pos;
  int len;

  int dlen;

} bmw256_ctx_vector_t;

typedef struct bmw512_ctx
{
  u64 h[16];

  u64 m[16];

  u64 cnt;

  int pos;
  int len;

  int dlen;

} bmw512_ctx_t;

typedef struct bmw512_ctx_vector
{
  u64x h[16];

  u64x m[16];

  u64 cnt;

  int pos;
  int len;

  int dlen;

} bmw512_ctx_vector_t;

DECLSPEC void bmw256_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m);
DECLSPEC void bmw256_init (PRIVATE_AS bmw256_ctx_t *ctx, const int dlen);
DECLSPEC void bmw256_absorb (PRIVATE_AS bmw256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void bmw256_update (PRIVATE_AS bmw256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void bmw256_absorb_utf16le (PRIVATE_AS bmw256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void bmw256_update_utf16le (PRIVATE_AS bmw256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void bmw256_update_global (PRIVATE_AS bmw256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void bmw256_update_global_utf16le (PRIVATE_AS bmw256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void bmw256_final (PRIVATE_AS bmw256_ctx_t *ctx);

DECLSPEC void bmw256_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m);
DECLSPEC void bmw256_init_vector (PRIVATE_AS bmw256_ctx_vector_t *ctx, const int dlen);
DECLSPEC void bmw256_absorb_vector (PRIVATE_AS bmw256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void bmw256_update_vector (PRIVATE_AS bmw256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void bmw256_update_vector_utf16le (PRIVATE_AS bmw256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void bmw256_final_vector (PRIVATE_AS bmw256_ctx_vector_t *ctx);

DECLSPEC void bmw512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m);
DECLSPEC void bmw512_init (PRIVATE_AS bmw512_ctx_t *ctx, const int dlen);
DECLSPEC void bmw512_absorb (PRIVATE_AS bmw512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void bmw512_update (PRIVATE_AS bmw512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void bmw512_absorb_utf16le (PRIVATE_AS bmw512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void bmw512_update_utf16le (PRIVATE_AS bmw512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void bmw512_update_global (PRIVATE_AS bmw512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void bmw512_update_global_utf16le (PRIVATE_AS bmw512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void bmw512_final (PRIVATE_AS bmw512_ctx_t *ctx);

DECLSPEC void bmw512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m);
DECLSPEC void bmw512_init_vector (PRIVATE_AS bmw512_ctx_vector_t *ctx, const int dlen);
DECLSPEC void bmw512_absorb_vector (PRIVATE_AS bmw512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void bmw512_update_vector (PRIVATE_AS bmw512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void bmw512_update_vector_utf16le (PRIVATE_AS bmw512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void bmw512_final_vector (PRIVATE_AS bmw512_ctx_vector_t *ctx);

#endif // INC_HASH_BMW_H
