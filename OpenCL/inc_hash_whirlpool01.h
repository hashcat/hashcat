/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_WHIRLPOOL01_H
#define INC_HASH_WHIRLPOOL01_H

// The 2 predecessors of Whirlpool: Whirlpool-0, as first submitted to NESSIE, and Whirlpool-T,
// its revision with a new S-box. sphlib calls them whirlpool0 and whirlpool1, hx calls them wrl0
// and wrl1. They have the structure of Whirlpool and differ from it and from each other only in
// the table and the round constants, so one set of functions serves both, selected by the variant
// that the init function takes. It also takes whirlpool01_t0, the tables of both variants.
// Input consists of little endian words, as for MD5, in blocks of 64 bytes. After the final
// function, the 64 byte digest is h[0] to h[7], each in little endian order: digest bytes 8i to
// 8i+3 are the low half of h[i], bytes 8i+4 to 8i+7 its high half.

#define WHIRLPOOL01_WRL0 0
#define WHIRLPOOL01_WRL1 1

typedef struct whirlpool01_ctx
{
  u64 h[8];
  u32 w[16];

  // Bytes in the current block and in the whole message. The second count is -1 after invalid
  // UTF-8.

  int pos;
  int len;

  // The variant, which selects the round constants, and the table of that variant.

  int var;

  SHM_TYPE u64a *s_wrl;

} whirlpool01_ctx_t;

typedef struct whirlpool01_ctx_vector
{
  u64x h[8];
  u32x w[16];

  int pos;
  int len;

  int var;

  SHM_TYPE u64a *s_wrl;

} whirlpool01_ctx_vector_t;

DECLSPEC void whirlpool01_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u32 *w, SHM_TYPE u64a *s_wrl, const int var);
DECLSPEC void whirlpool01_init (PRIVATE_AS whirlpool01_ctx_t *ctx, SHM_TYPE u64a (*s_whirlpool01)[256], const int var);
DECLSPEC void whirlpool01_block (PRIVATE_AS whirlpool01_ctx_t *ctx);
DECLSPEC void whirlpool01_absorb (PRIVATE_AS whirlpool01_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void whirlpool01_update (PRIVATE_AS whirlpool01_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool01_absorb_utf16le (PRIVATE_AS whirlpool01_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void whirlpool01_update_utf16le (PRIVATE_AS whirlpool01_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool01_update_global (PRIVATE_AS whirlpool01_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool01_update_global_utf16le (PRIVATE_AS whirlpool01_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool01_final (PRIVATE_AS whirlpool01_ctx_t *ctx);

DECLSPEC void whirlpool01_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u32x *w, SHM_TYPE u64a *s_wrl, const int var);
DECLSPEC void whirlpool01_init_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx, SHM_TYPE u64a (*s_whirlpool01)[256], const int var);
DECLSPEC void whirlpool01_block_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx);
DECLSPEC void whirlpool01_absorb_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void whirlpool01_update_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void whirlpool01_update_vector_utf16le (PRIVATE_AS whirlpool01_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void whirlpool01_final_vector (PRIVATE_AS whirlpool01_ctx_vector_t *ctx);

#endif // INC_HASH_WHIRLPOOL01_H
