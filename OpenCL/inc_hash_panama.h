/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_PANAMA_H
#define INC_HASH_PANAMA_H

// PANAMA as a hash function, in the little endian convention of sphlib, which is what hx and John
// the Ripper call panama. The block is 32 bytes. Input consists of little endian words, as for MD5.
// After panama_final (), st[9] to st[16] contain the 32 byte digest, little endian.

typedef struct panama_ctx
{
  // The buffer of 32 stages of 8 words, which turns by moving ptr rather than its contents, and
  // the 17 word state.

  u32 b[32][8];
  u32 st[17];

  int ptr;

  // The block being filled. Bytes in it and in the whole message. The second count is -1 after
  // invalid UTF-8.

  u32 m[8];

  int pos;
  int len;

} panama_ctx_t;

typedef struct panama_ctx_vector
{
  u32x b[32][8];
  u32x st[17];

  int ptr;

  u32x m[8];

  int pos;
  int len;

} panama_ctx_vector_t;

DECLSPEC void panama_step (PRIVATE_AS panama_ctx_t *ctx, PRIVATE_AS const u32 *x1, PRIVATE_AS const u32 *x2);
DECLSPEC void panama_init (PRIVATE_AS panama_ctx_t *ctx);
DECLSPEC void panama_absorb (PRIVATE_AS panama_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void panama_update (PRIVATE_AS panama_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void panama_update_utf16le (PRIVATE_AS panama_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void panama_update_global (PRIVATE_AS panama_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void panama_update_global_utf16le (PRIVATE_AS panama_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void panama_final (PRIVATE_AS panama_ctx_t *ctx);

DECLSPEC void panama_step_vector (PRIVATE_AS panama_ctx_vector_t *ctx, PRIVATE_AS const u32x *x1, PRIVATE_AS const u32x *x2);
DECLSPEC void panama_init_vector (PRIVATE_AS panama_ctx_vector_t *ctx);
DECLSPEC void panama_absorb_vector (PRIVATE_AS panama_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void panama_update_vector (PRIVATE_AS panama_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void panama_update_vector_utf16le (PRIVATE_AS panama_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void panama_final_vector (PRIVATE_AS panama_ctx_vector_t *ctx);

#endif // INC_HASH_PANAMA_H
