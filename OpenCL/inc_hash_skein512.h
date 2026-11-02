/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SKEIN512_H
#define INC_HASH_SKEIN512_H

// Skein-512 (Skein 1.3) with a digest of 28, 32, 48 or 64 bytes, one context type for all four.
// These are what hx calls skein224 to skein512, sphlib's Skein-224 to Skein-512, which the Skein
// paper calls Skein-512-224 to Skein-512-512. The block is 64 bytes. The state holds the digest in
// its first bytes, little endian, after skein512_final ().

typedef struct skein512_ctx
{
  u64 h[8];

  // The block being filled, which is processed only once more input arrives, because the last
  // block of the message is processed with the final flag set.

  u64 m[8];

  // Bytes in the blocks already processed, bytes in m and bytes in the whole message. The last
  // count is -1 after invalid UTF-8.

  u64 cnt;

  int pos;
  int len;

  int dlen;

} skein512_ctx_t;

typedef struct skein512_ctx_vector
{
  u64x h[8];

  u64x m[8];

  u64 cnt;

  int pos;
  int len;

  int dlen;

} skein512_ctx_vector_t;

DECLSPEC void skein512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m, const u64 t0, const u64 t1);
DECLSPEC void skein512_init (PRIVATE_AS skein512_ctx_t *ctx, const int dlen);
DECLSPEC void skein512_block (PRIVATE_AS skein512_ctx_t *ctx);
DECLSPEC void skein512_absorb (PRIVATE_AS skein512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void skein512_update (PRIVATE_AS skein512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void skein512_update_utf16le (PRIVATE_AS skein512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void skein512_update_global (PRIVATE_AS skein512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void skein512_update_global_utf16le (PRIVATE_AS skein512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void skein512_final (PRIVATE_AS skein512_ctx_t *ctx);

DECLSPEC void skein512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, const u64 t0, const u64 t1);
DECLSPEC void skein512_init_vector (PRIVATE_AS skein512_ctx_vector_t *ctx, const int dlen);
DECLSPEC void skein512_block_vector (PRIVATE_AS skein512_ctx_vector_t *ctx);
DECLSPEC void skein512_absorb_vector (PRIVATE_AS skein512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void skein512_update_vector (PRIVATE_AS skein512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void skein512_update_vector_utf16le (PRIVATE_AS skein512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void skein512_final_vector (PRIVATE_AS skein512_ctx_vector_t *ctx);

#endif // INC_HASH_SKEIN512_H
