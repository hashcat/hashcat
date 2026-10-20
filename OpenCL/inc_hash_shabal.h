/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SHABAL_H
#define INC_HASH_SHABAL_H

// Shabal with a digest of 28, 32, 48 or 64 bytes, one context type for all 4. These are what hx
// and sphlib call shabal224 to shabal512. Each size starts from its own initial state. The block
// is 64 bytes. Input consists of little endian words, as for MD5. After shabal_final (), the
// digest is the last dlen / 4 words of b, b[16 - dlen / 4] to b[15], little endian.

typedef struct shabal_ctx
{
  u32 a[12];
  u32 b[16];
  u32 c[16];

  // The block counter W, which starts at 1.

  u64 cnt;

  // The block being filled. Bytes in it and in the whole message. The second count is -1 after
  // invalid UTF-8.

  u32 m[16];

  int pos;
  int len;

  int dlen;

} shabal_ctx_t;

typedef struct shabal_ctx_vector
{
  u32x a[12];
  u32x b[16];
  u32x c[16];

  u64 cnt;

  u32x m[16];

  int pos;
  int len;

  int dlen;

} shabal_ctx_vector_t;

DECLSPEC void shabal_perm (PRIVATE_AS shabal_ctx_t *ctx);
DECLSPEC void shabal_init (PRIVATE_AS shabal_ctx_t *ctx, const int dlen);
DECLSPEC void shabal_block (PRIVATE_AS shabal_ctx_t *ctx);
DECLSPEC void shabal_absorb (PRIVATE_AS shabal_ctx_t *ctx, const u32 v, const int n);
DECLSPEC void shabal_update (PRIVATE_AS shabal_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void shabal_update_utf16le (PRIVATE_AS shabal_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void shabal_update_global (PRIVATE_AS shabal_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void shabal_update_global_utf16le (PRIVATE_AS shabal_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void shabal_final (PRIVATE_AS shabal_ctx_t *ctx);

DECLSPEC void shabal_perm_vector (PRIVATE_AS shabal_ctx_vector_t *ctx);
DECLSPEC void shabal_init_vector (PRIVATE_AS shabal_ctx_vector_t *ctx, const int dlen);
DECLSPEC void shabal_block_vector (PRIVATE_AS shabal_ctx_vector_t *ctx);
DECLSPEC void shabal_absorb_vector (PRIVATE_AS shabal_ctx_vector_t *ctx, const u32x v, const int n);
DECLSPEC void shabal_update_vector (PRIVATE_AS shabal_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void shabal_update_vector_utf16le (PRIVATE_AS shabal_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void shabal_final_vector (PRIVATE_AS shabal_ctx_vector_t *ctx);

#endif // INC_HASH_SHABAL_H
