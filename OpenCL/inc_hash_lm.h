/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_LM_H
#define INC_HASH_LM_H

// The LM hash. It keeps the first 14 bytes of its input, converts ASCII letters to uppercase and
// pads with zero bytes. Each half of 7 bytes becomes a DES key that encrypts the string KGS!@#$%.
// Input is little endian words, as for MD5. After lm_final (), the 16 byte digest is in h, as
// little endian words in memory order. The DES tables come from inc_cipher_des.cl, which the
// caller includes.

typedef struct lm_ctx
{
  u32 w[4];
  u32 h[4];

  // Number of bytes kept, up to 14, or -1 if the input contains invalid UTF-8.

  int len;

  SHM_TYPE u32 (*s_skb)[64];
  SHM_TYPE u32 (*s_sptrans)[64];

} lm_ctx_t;

typedef struct lm_ctx_vector
{
  u32x w[4];
  u32x h[4];

  int len;

  SHM_TYPE u32 (*s_skb)[64];
  SHM_TYPE u32 (*s_sptrans)[64];

} lm_ctx_vector_t;

DECLSPEC void lm_key (const u32 w0, const u32 w1, PRIVATE_AS u32 *key);
DECLSPEC void lm_init (PRIVATE_AS lm_ctx_t *ctx, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_sptrans)[64]);
DECLSPEC void lm_byte (PRIVATE_AS lm_ctx_t *ctx, const u32 c);
DECLSPEC void lm_update (PRIVATE_AS lm_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void lm_update_utf16le (PRIVATE_AS lm_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void lm_update_global (PRIVATE_AS lm_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void lm_update_global_utf16le (PRIVATE_AS lm_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void lm_final (PRIVATE_AS lm_ctx_t *ctx);

DECLSPEC void lm_key_vector (const u32x w0, const u32x w1, PRIVATE_AS u32x *key);
DECLSPEC void lm_init_vector (PRIVATE_AS lm_ctx_vector_t *ctx, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_sptrans)[64]);
DECLSPEC void lm_byte_vector (PRIVATE_AS lm_ctx_vector_t *ctx, const u32x c);
DECLSPEC void lm_update_vector (PRIVATE_AS lm_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void lm_update_vector_utf16le (PRIVATE_AS lm_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void lm_final_vector (PRIVATE_AS lm_ctx_vector_t *ctx);

#endif // INC_HASH_LM_H
