/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_MD2_H
#define INC_HASH_MD2_H

// MD2, RFC 1319, with the checksum as corrected in its errata. Input is little endian words, as for
// MD5, in blocks of 16 bytes. After md2_final () the digest is h, little endian.

typedef struct md2_ctx
{
  u32 h[4];
  u32 c[4];
  u32 w[4];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

  SHM_TYPE u32a *s_md2;

} md2_ctx_t;

typedef struct md2_ctx_vector
{
  u32x h[4];
  u32x c[4];
  u32x w[4];

  int pos;
  int len;

  SHM_TYPE u32a *s_md2;

} md2_ctx_vector_t;

DECLSPEC void md2_transform (PRIVATE_AS u32 *h, PRIVATE_AS u32 *c, PRIVATE_AS const u32 *w, SHM_TYPE u32a *s_md2);
DECLSPEC void md2_init (PRIVATE_AS md2_ctx_t *ctx, SHM_TYPE u32a *s_md2);
DECLSPEC void md2_block (PRIVATE_AS md2_ctx_t *ctx);
DECLSPEC void md2_absorb (PRIVATE_AS md2_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void md2_update (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void md2_update_utf16le (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void md2_update_global (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md2_update_global_utf16le (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md2_final (PRIVATE_AS md2_ctx_t *ctx);

DECLSPEC void md2_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS u32x *c, PRIVATE_AS const u32x *w, SHM_TYPE u32a *s_md2);
DECLSPEC void md2_init_vector (PRIVATE_AS md2_ctx_vector_t *ctx, SHM_TYPE u32a *s_md2);
DECLSPEC void md2_block_vector (PRIVATE_AS md2_ctx_vector_t *ctx);
DECLSPEC void md2_absorb_vector (PRIVATE_AS md2_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void md2_update_vector (PRIVATE_AS md2_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void md2_update_vector_utf16le (PRIVATE_AS md2_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void md2_final_vector (PRIVATE_AS md2_ctx_vector_t *ctx);

#endif // INC_HASH_MD2_H
