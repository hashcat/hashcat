/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_EDONR_H
#define INC_HASH_EDONR_H

// EDON-R 256 and EDON-R 512, as RHash implements them, which is what hx calls edon256 and edon512.
// Input is little endian words, as for MD5. EDON-R 256 reads its 64 byte blocks as little endian
// 32 bit words and EDON-R 512 its 128 byte blocks as little endian 64 bit words. The padding is
// that of MD5, with the bit length in the last 8 bytes of the block.
//
// The digest is the second half of the chaining state. After edonr256_final () h[8] to h[15]
// contain the 32 byte digest, little endian. After edonr512_final () h[8] to h[15] contain the 64
// byte digest, little endian 64 bit words: the low half of h[8] holds digest bytes 0 to 3.

typedef struct edonr256_ctx
{
  u32 h[16];
  u32 w[16];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

} edonr256_ctx_t;

typedef struct edonr256_ctx_vector
{
  u32x h[16];
  u32x w[16];

  int pos;
  int len;

} edonr256_ctx_vector_t;

typedef struct edonr512_ctx
{
  u64 h[16];
  u64 w[16];

  int pos;
  int len;

} edonr512_ctx_t;

typedef struct edonr512_ctx_vector
{
  u64x h[16];
  u64x w[16];

  int pos;
  int len;

} edonr512_ctx_vector_t;

DECLSPEC void edonr256_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w);
DECLSPEC void edonr256_init (PRIVATE_AS edonr256_ctx_t *ctx);
DECLSPEC void edonr256_block (PRIVATE_AS edonr256_ctx_t *ctx);
DECLSPEC void edonr256_absorb (PRIVATE_AS edonr256_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void edonr256_update (PRIVATE_AS edonr256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void edonr256_update_utf16le (PRIVATE_AS edonr256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void edonr256_update_global (PRIVATE_AS edonr256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void edonr256_update_global_utf16le (PRIVATE_AS edonr256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void edonr256_final (PRIVATE_AS edonr256_ctx_t *ctx);

DECLSPEC void edonr256_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w);
DECLSPEC void edonr256_init_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx);
DECLSPEC void edonr256_block_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx);
DECLSPEC void edonr256_absorb_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void edonr256_update_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void edonr256_update_vector_utf16le (PRIVATE_AS edonr256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void edonr256_final_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx);

DECLSPEC void edonr512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *w);
DECLSPEC void edonr512_init (PRIVATE_AS edonr512_ctx_t *ctx);
DECLSPEC void edonr512_block (PRIVATE_AS edonr512_ctx_t *ctx);
DECLSPEC void edonr512_absorb (PRIVATE_AS edonr512_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void edonr512_update (PRIVATE_AS edonr512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void edonr512_update_utf16le (PRIVATE_AS edonr512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void edonr512_update_global (PRIVATE_AS edonr512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void edonr512_update_global_utf16le (PRIVATE_AS edonr512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void edonr512_final (PRIVATE_AS edonr512_ctx_t *ctx);

DECLSPEC void edonr512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *w);
DECLSPEC void edonr512_init_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx);
DECLSPEC void edonr512_block_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx);
DECLSPEC void edonr512_absorb_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void edonr512_update_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void edonr512_update_vector_utf16le (PRIVATE_AS edonr512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void edonr512_final_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx);

#endif // INC_HASH_EDONR_H
