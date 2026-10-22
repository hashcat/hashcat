/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SHA0_H
#define INC_HASH_SHA0_H

// SHA-0 is the 1993 version of SHA. Input consists of little endian words, as for MD5, in
// blocks of 64 bytes. After sha0_final (), the digest is h in the same layout as SHA-1, with
// each word in big endian order.

typedef struct sha0_ctx
{
  u32 h[5];
  u32 w[16];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

} sha0_ctx_t;

typedef struct sha0_ctx_vector
{
  u32x h[5];
  u32x w[16];

  int pos;
  int len;

} sha0_ctx_vector_t;

DECLSPEC void sha0_transform (PRIVATE_AS u32 *dgst, PRIVATE_AS const u32 *w);
DECLSPEC void sha0_init (PRIVATE_AS sha0_ctx_t *ctx);
DECLSPEC void sha0_block (PRIVATE_AS sha0_ctx_t *ctx);
DECLSPEC void sha0_absorb (PRIVATE_AS sha0_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void sha0_update (PRIVATE_AS sha0_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha0_update_utf16le (PRIVATE_AS sha0_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha0_update_global (PRIVATE_AS sha0_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha0_update_global_utf16le (PRIVATE_AS sha0_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha0_final (PRIVATE_AS sha0_ctx_t *ctx);

DECLSPEC void sha0_transform_vector (PRIVATE_AS u32x *dgst, PRIVATE_AS const u32x *w);
DECLSPEC void sha0_init_vector (PRIVATE_AS sha0_ctx_vector_t *ctx);
DECLSPEC void sha0_block_vector (PRIVATE_AS sha0_ctx_vector_t *ctx);
DECLSPEC void sha0_absorb_vector (PRIVATE_AS sha0_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void sha0_update_vector (PRIVATE_AS sha0_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha0_update_vector_utf16le (PRIVATE_AS sha0_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha0_final_vector (PRIVATE_AS sha0_ctx_vector_t *ctx);

#endif // INC_HASH_SHA0_H
