/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_RADIOGATUN_H
#define INC_HASH_RADIOGATUN_H

// RadioGatun[32] and RadioGatun[64], in the little endian convention of sphlib, which is what hx
// calls radiogatun32 and radiogatun64. Its radiogatun32 keeps only the first 16 bytes of the
// digest, the length hashpipe registers for it. Both take input as little endian words, as MD5
// does, in blocks of 3 words: 12 bytes for RadioGatun[32] and 24 bytes for RadioGatun[64]. Both
// produce 32 bytes. After radiogatun32_final (), h[0] to h[7] contain the digest as little endian
// words, so h[i] holds digest bytes 4i to 4i+3. After radiogatun64_final (), h[0] to h[3] contain
// it as little endian 64 bit words, so h[i] holds digest bytes 8i to 8i+7: its low half is digest
// word 2i and its high half digest word 2i+1.

typedef struct radiogatun32_ctx
{
  // The mill of 19 words and the belt of 13 stages of 3 words

  u32 a[19];
  u32 b[13][3];

  // The block being filled. Bytes in it and in the whole message. The second count is -1 after
  // invalid UTF-8.

  u32 m[3];

  int pos;
  int len;

  // The digest, which radiogatun32_final () collects from the output rounds

  u32 h[8];

} radiogatun32_ctx_t;

typedef struct radiogatun32_ctx_vector
{
  u32x a[19];
  u32x b[13][3];

  u32x m[3];

  int pos;
  int len;

  u32x h[8];

} radiogatun32_ctx_vector_t;

typedef struct radiogatun64_ctx
{
  u64 a[19];
  u64 b[13][3];

  u64 m[3];

  int pos;
  int len;

  u64 h[4];

} radiogatun64_ctx_t;

typedef struct radiogatun64_ctx_vector
{
  u64x a[19];
  u64x b[13][3];

  u64x m[3];

  int pos;
  int len;

  u64x h[4];

} radiogatun64_ctx_vector_t;

DECLSPEC void radiogatun32_round (PRIVATE_AS radiogatun32_ctx_t *ctx);
DECLSPEC void radiogatun32_init (PRIVATE_AS radiogatun32_ctx_t *ctx);
DECLSPEC void radiogatun32_block (PRIVATE_AS radiogatun32_ctx_t *ctx);
DECLSPEC void radiogatun32_absorb (PRIVATE_AS radiogatun32_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void radiogatun32_update (PRIVATE_AS radiogatun32_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void radiogatun32_update_utf16le (PRIVATE_AS radiogatun32_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void radiogatun32_update_global (PRIVATE_AS radiogatun32_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void radiogatun32_update_global_utf16le (PRIVATE_AS radiogatun32_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void radiogatun32_final (PRIVATE_AS radiogatun32_ctx_t *ctx);

DECLSPEC void radiogatun32_round_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx);
DECLSPEC void radiogatun32_init_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx);
DECLSPEC void radiogatun32_block_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx);
DECLSPEC void radiogatun32_absorb_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void radiogatun32_update_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void radiogatun32_update_vector_utf16le (PRIVATE_AS radiogatun32_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void radiogatun32_final_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx);

DECLSPEC void radiogatun64_round (PRIVATE_AS radiogatun64_ctx_t *ctx);
DECLSPEC void radiogatun64_init (PRIVATE_AS radiogatun64_ctx_t *ctx);
DECLSPEC void radiogatun64_block (PRIVATE_AS radiogatun64_ctx_t *ctx);
DECLSPEC void radiogatun64_absorb (PRIVATE_AS radiogatun64_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void radiogatun64_update (PRIVATE_AS radiogatun64_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void radiogatun64_update_utf16le (PRIVATE_AS radiogatun64_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void radiogatun64_update_global (PRIVATE_AS radiogatun64_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void radiogatun64_update_global_utf16le (PRIVATE_AS radiogatun64_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void radiogatun64_final (PRIVATE_AS radiogatun64_ctx_t *ctx);

DECLSPEC void radiogatun64_round_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx);
DECLSPEC void radiogatun64_init_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx);
DECLSPEC void radiogatun64_block_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx);
DECLSPEC void radiogatun64_absorb_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void radiogatun64_update_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void radiogatun64_update_vector_utf16le (PRIVATE_AS radiogatun64_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void radiogatun64_final_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx);

#endif // INC_HASH_RADIOGATUN_H
