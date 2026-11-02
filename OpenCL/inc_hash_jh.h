/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_JH_H
#define INC_HASH_JH_H

// JH (the SHA-3 finalist, round 3 version) with a digest of 28, 32, 48 or 64 bytes, one context
// type for all 4. These are what hx and sphlib call jh224 to jh512. The block is 64 bytes and
// input consists of little endian words, as for MD5. The 128 byte state h holds 64 bit words in
// sphlib's little endian bitslice order. After jh_final (), the digest is the last dlen bytes of
// the state, in byte order: viewed as 32 little endian words, where word 2k is the low half of h[k]
// and word 2k + 1 its high half, digest word i is state word 32 - (dlen / 4) + i.

typedef struct jh_ctx
{
  u64 h[16];

  // The block being filled, and the number of blocks already processed, for the length that ends
  // the padding.

  u64 m[8];

  u64 cnt;

  // Bytes in m and in the whole message. The second count is -1 after invalid UTF-8.

  int pos;
  int len;

  int dlen;

} jh_ctx_t;

typedef struct jh_ctx_vector
{
  u64x h[16];

  u64x m[8];

  u64 cnt;

  int pos;
  int len;

  int dlen;

} jh_ctx_vector_t;

DECLSPEC void jh_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m);
DECLSPEC void jh_init (PRIVATE_AS jh_ctx_t *ctx, const int dlen);
DECLSPEC void jh_block (PRIVATE_AS jh_ctx_t *ctx);
DECLSPEC void jh_absorb (PRIVATE_AS jh_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void jh_update (PRIVATE_AS jh_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void jh_update_utf16le (PRIVATE_AS jh_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void jh_update_global (PRIVATE_AS jh_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void jh_update_global_utf16le (PRIVATE_AS jh_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void jh_final (PRIVATE_AS jh_ctx_t *ctx);

DECLSPEC void jh_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m);
DECLSPEC void jh_init_vector (PRIVATE_AS jh_ctx_vector_t *ctx, const int dlen);
DECLSPEC void jh_block_vector (PRIVATE_AS jh_ctx_vector_t *ctx);
DECLSPEC void jh_absorb_vector (PRIVATE_AS jh_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void jh_update_vector (PRIVATE_AS jh_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void jh_update_vector_utf16le (PRIVATE_AS jh_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void jh_final_vector (PRIVATE_AS jh_ctx_vector_t *ctx);

#endif // INC_HASH_JH_H
