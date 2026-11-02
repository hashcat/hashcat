/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SNEFRU_H
#define INC_HASH_SNEFRU_H

// Snefru uses 8 rounds. The dlen value is 16 for Snefru-128 and 32 for Snefru-256, whose
// blocks contain 48 and 32 bytes. Input consists of little endian words, as for MD5.
// After snefru_final (), the first dlen / 4 words of h contain the digest, with each
// word in big endian order.

typedef struct snefru_ctx
{
  u32 h[8];
  u32 w[12];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

  // bytes per block

  int blk;

  SHM_TYPE u32a (*s_snefru)[256];

} snefru_ctx_t;

typedef struct snefru_ctx_vector
{
  u32x h[8];
  u32x w[12];

  int pos;
  int len;

  int blk;

  SHM_TYPE u32a (*s_snefru)[256];

} snefru_ctx_vector_t;

DECLSPEC void snefru_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w, const int blk, SHM_TYPE u32a (*s_snefru)[256]);
DECLSPEC void snefru_init (PRIVATE_AS snefru_ctx_t *ctx, SHM_TYPE u32a (*s_snefru)[256], const int dlen);
DECLSPEC void snefru_block (PRIVATE_AS snefru_ctx_t *ctx);
DECLSPEC void snefru_absorb (PRIVATE_AS snefru_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void snefru_update (PRIVATE_AS snefru_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void snefru_update_utf16le (PRIVATE_AS snefru_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void snefru_update_global (PRIVATE_AS snefru_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void snefru_update_global_utf16le (PRIVATE_AS snefru_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void snefru_final (PRIVATE_AS snefru_ctx_t *ctx);

DECLSPEC void snefru_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w, const int blk, SHM_TYPE u32a (*s_snefru)[256]);
DECLSPEC void snefru_init_vector (PRIVATE_AS snefru_ctx_vector_t *ctx, SHM_TYPE u32a (*s_snefru)[256], const int dlen);
DECLSPEC void snefru_block_vector (PRIVATE_AS snefru_ctx_vector_t *ctx);
DECLSPEC void snefru_absorb_vector (PRIVATE_AS snefru_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void snefru_update_vector (PRIVATE_AS snefru_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void snefru_update_vector_utf16le (PRIVATE_AS snefru_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void snefru_final_vector (PRIVATE_AS snefru_ctx_vector_t *ctx);

#endif // INC_HASH_SNEFRU_H
