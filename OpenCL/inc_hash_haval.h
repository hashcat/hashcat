/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_HAVAL_H
#define INC_HASH_HAVAL_H

// HAVAL with 3, 4 or 5 passes and a digest of 4 to 8 words, one context type for all 15 variants.
// Input is little endian words, as for MD5, in blocks of 128 bytes. After haval_final () the digest
// is the first olen words of h, little endian.

typedef struct haval_ctx
{
  u32 h[8];
  u32 w[32];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

  int passes;
  int olen;

} haval_ctx_t;

typedef struct haval_ctx_vector
{
  u32x h[8];
  u32x w[32];

  int pos;
  int len;

  int passes;
  int olen;

} haval_ctx_vector_t;

DECLSPEC void haval_transform3 (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w);
DECLSPEC void haval_transform4 (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w);
DECLSPEC void haval_transform5 (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w);
DECLSPEC void haval_init (PRIVATE_AS haval_ctx_t *ctx, const int passes, const int olen);
DECLSPEC void haval_block (PRIVATE_AS haval_ctx_t *ctx);
DECLSPEC void haval_absorb (PRIVATE_AS haval_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void haval_update (PRIVATE_AS haval_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void haval_update_utf16le (PRIVATE_AS haval_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void haval_update_global (PRIVATE_AS haval_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void haval_update_global_utf16le (PRIVATE_AS haval_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void haval_final (PRIVATE_AS haval_ctx_t *ctx);

DECLSPEC void haval_transform3_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w);
DECLSPEC void haval_transform4_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w);
DECLSPEC void haval_transform5_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w);
DECLSPEC void haval_init_vector (PRIVATE_AS haval_ctx_vector_t *ctx, const int passes, const int olen);
DECLSPEC void haval_block_vector (PRIVATE_AS haval_ctx_vector_t *ctx);
DECLSPEC void haval_absorb_vector (PRIVATE_AS haval_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void haval_update_vector (PRIVATE_AS haval_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void haval_update_vector_utf16le (PRIVATE_AS haval_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void haval_final_vector (PRIVATE_AS haval_ctx_vector_t *ctx);

#endif // INC_HASH_HAVAL_H
