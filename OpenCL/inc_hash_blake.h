/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_BLAKE_H
#define INC_HASH_BLAKE_H

// BLAKE, the SHA-3 finalist with 14 rounds of the 32 bit core and 16 rounds of the 64 bit core, as
// sphlib and hx implement it. This is not BLAKE2. blake256 computes BLAKE-224 and BLAKE-256 with
// 64 byte blocks, blake512 computes BLAKE-384 and BLAKE-512 with 128 byte blocks. The init takes
// the digest length in bytes: 28 or 32 for blake256, 48 or 64 for blake512. The salt is zero.
//
// Input consists of little endian words, as for MD5. BLAKE reads its blocks as big endian words,
// so the block being filled is kept in big endian words.
//
// After blake256_final (), h[0] to h[6] (BLAKE-224) or h[0] to h[7] (BLAKE-256) contain the
// digest as big endian words, so digest word i in little endian is hc_swap32_S (h[i]).
//
// After blake512_final (), h[0] to h[5] (BLAKE-384) or h[0] to h[7] (BLAKE-512) contain the
// digest as big endian 64 bit words, so digest words 2i and 2i + 1 in little endian are
// hc_swap32_S (h32_from_64_S (h[i])) and hc_swap32_S (l32_from_64_S (h[i])).

typedef struct blake256_ctx
{
  u32 h[8];

  // The block being filled, in big endian words. Bytes in the blocks already processed, bytes in
  // m and bytes in the whole message. The last count is -1 after invalid UTF-8.

  u32 m[16];

  u32 cnt;

  int pos;
  int len;

  int dlen;

} blake256_ctx_t;

typedef struct blake256_ctx_vector
{
  u32x h[8];

  u32x m[16];

  u32 cnt;

  int pos;
  int len;

  int dlen;

} blake256_ctx_vector_t;

typedef struct blake512_ctx
{
  u64 h[8];

  // The block being filled, in big endian 32 bit words, 2 of which make one 64 bit word of
  // the block, the high half first.

  u32 m[32];

  u32 cnt;

  int pos;
  int len;

  int dlen;

} blake512_ctx_t;

typedef struct blake512_ctx_vector
{
  u64x h[8];

  u32x m[32];

  u32 cnt;

  int pos;
  int len;

  int dlen;

} blake512_ctx_vector_t;

DECLSPEC void blake256_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m, const u32 t0, const u32 t1);
DECLSPEC void blake256_init (PRIVATE_AS blake256_ctx_t *ctx, const int dlen);
DECLSPEC void blake256_block (PRIVATE_AS blake256_ctx_t *ctx, const u32 t0, const u32 t1);
DECLSPEC void blake256_absorb (PRIVATE_AS blake256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void blake256_absorb_utf16le (PRIVATE_AS blake256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void blake256_update (PRIVATE_AS blake256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void blake256_update_utf16le (PRIVATE_AS blake256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void blake256_update_global (PRIVATE_AS blake256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void blake256_update_global_utf16le (PRIVATE_AS blake256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void blake256_final (PRIVATE_AS blake256_ctx_t *ctx);

DECLSPEC void blake256_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m, const u32 t0, const u32 t1);
DECLSPEC void blake256_init_vector (PRIVATE_AS blake256_ctx_vector_t *ctx, const int dlen);
DECLSPEC void blake256_block_vector (PRIVATE_AS blake256_ctx_vector_t *ctx, const u32 t0, const u32 t1);
DECLSPEC void blake256_absorb_vector (PRIVATE_AS blake256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void blake256_update_vector (PRIVATE_AS blake256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void blake256_update_vector_utf16le (PRIVATE_AS blake256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void blake256_final_vector (PRIVATE_AS blake256_ctx_vector_t *ctx);

DECLSPEC void blake512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m, const u64 t0, const u64 t1);
DECLSPEC void blake512_init (PRIVATE_AS blake512_ctx_t *ctx, const int dlen);
DECLSPEC void blake512_block (PRIVATE_AS blake512_ctx_t *ctx, const u64 t0);
DECLSPEC void blake512_absorb (PRIVATE_AS blake512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void blake512_absorb_utf16le (PRIVATE_AS blake512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void blake512_update (PRIVATE_AS blake512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void blake512_update_utf16le (PRIVATE_AS blake512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void blake512_update_global (PRIVATE_AS blake512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void blake512_update_global_utf16le (PRIVATE_AS blake512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void blake512_final (PRIVATE_AS blake512_ctx_t *ctx);

DECLSPEC void blake512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, const u64 t0, const u64 t1);
DECLSPEC void blake512_init_vector (PRIVATE_AS blake512_ctx_vector_t *ctx, const int dlen);
DECLSPEC void blake512_block_vector (PRIVATE_AS blake512_ctx_vector_t *ctx, const u64 t0);
DECLSPEC void blake512_absorb_vector (PRIVATE_AS blake512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void blake512_update_vector (PRIVATE_AS blake512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void blake512_update_vector_utf16le (PRIVATE_AS blake512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void blake512_final_vector (PRIVATE_AS blake512_ctx_vector_t *ctx);

#endif // INC_HASH_BLAKE_H
