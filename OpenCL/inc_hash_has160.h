/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_HAS160_H
#define INC_HASH_HAS160_H

// HAS-160, the Korean KCDSA hash, as RHash implements it. Input is little endian words, as for
// MD5, in blocks of 64 bytes, with the same padding and bit length as MD5. After has160_final ()
// h[0] to h[4] contain the 20 byte digest, little endian.

typedef struct has160_ctx
{
  u32 h[5];
  u32 w[16];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

} has160_ctx_t;

typedef struct has160_ctx_vector
{
  u32x h[5];
  u32x w[16];

  int pos;
  int len;

} has160_ctx_vector_t;

DECLSPEC void has160_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w);
DECLSPEC void has160_init (PRIVATE_AS has160_ctx_t *ctx);
DECLSPEC void has160_block (PRIVATE_AS has160_ctx_t *ctx);
DECLSPEC void has160_absorb (PRIVATE_AS has160_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void has160_update (PRIVATE_AS has160_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void has160_update_utf16le (PRIVATE_AS has160_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void has160_update_global (PRIVATE_AS has160_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void has160_update_global_utf16le (PRIVATE_AS has160_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void has160_final (PRIVATE_AS has160_ctx_t *ctx);

DECLSPEC void has160_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w);
DECLSPEC void has160_init_vector (PRIVATE_AS has160_ctx_vector_t *ctx);
DECLSPEC void has160_block_vector (PRIVATE_AS has160_ctx_vector_t *ctx);
DECLSPEC void has160_absorb_vector (PRIVATE_AS has160_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void has160_update_vector (PRIVATE_AS has160_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void has160_update_vector_utf16le (PRIVATE_AS has160_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void has160_final_vector (PRIVATE_AS has160_ctx_vector_t *ctx);

#endif // INC_HASH_HAS160_H
