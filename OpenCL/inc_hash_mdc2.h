/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_MDC2_H
#define INC_HASH_MDC2_H

// MDC-2 with DES, as OpenSSL computes it: blocks of 8 bytes, a last partial block padded with zero
// bytes and no length padding. Input is little endian words, as for MD5. After mdc2_final (), the
// 16 byte digest is h followed by hh, as little endian words in memory order. The DES tables come
// from inc_cipher_des.cl, which the caller includes.

typedef struct mdc2_ctx
{
  u32 h[2];
  u32 hh[2];
  u32 w[2];

  // Bytes in the current block, and in the whole message or -1 after invalid UTF-8.

  int pos;
  int len;

  SHM_TYPE u32 (*s_skb)[64];
  SHM_TYPE u32 (*s_sptrans)[64];

} mdc2_ctx_t;

typedef struct mdc2_ctx_vector
{
  u32x h[2];
  u32x hh[2];
  u32x w[2];

  int pos;
  int len;

  SHM_TYPE u32 (*s_skb)[64];
  SHM_TYPE u32 (*s_sptrans)[64];

} mdc2_ctx_vector_t;

DECLSPEC void mdc2_init (PRIVATE_AS mdc2_ctx_t *ctx, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_sptrans)[64]);
DECLSPEC void mdc2_block (PRIVATE_AS mdc2_ctx_t *ctx);
DECLSPEC void mdc2_byte (PRIVATE_AS mdc2_ctx_t *ctx, const u32 c);
DECLSPEC void mdc2_update (PRIVATE_AS mdc2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void mdc2_update_utf16le (PRIVATE_AS mdc2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void mdc2_update_global (PRIVATE_AS mdc2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void mdc2_update_global_utf16le (PRIVATE_AS mdc2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void mdc2_final (PRIVATE_AS mdc2_ctx_t *ctx);

DECLSPEC void mdc2_init_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx, SHM_TYPE u32 (*s_skb)[64], SHM_TYPE u32 (*s_sptrans)[64]);
DECLSPEC void mdc2_block_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx);
DECLSPEC void mdc2_byte_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx, const u32x c);
DECLSPEC void mdc2_update_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void mdc2_update_vector_utf16le (PRIVATE_AS mdc2_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void mdc2_final_vector (PRIVATE_AS mdc2_ctx_vector_t *ctx);

#endif // INC_HASH_MDC2_H
