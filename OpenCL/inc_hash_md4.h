/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_MD4_H
#define _INC_HASH_MD4_H

#define MD4_F_S(x,y,z)  (((x) & (y)) | ((~(x)) & (z)))
#define MD4_G_S(x,y,z)  (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H_S(x,y,z)  ((x) ^ (y) ^ (z))

#ifdef IS_NV
#define MD4_F(x,y,z)    (((x) & (y)) | ((~(x)) & (z)))
#define MD4_G(x,y,z)    (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD4_Fo(x,y,z)   (bitselect ((z), (y), (x)))
#define MD4_Go(x,y,z)   (bitselect ((x), (y), ((x) ^ (z))))
#endif

#ifdef IS_AMD
#define MD4_F(x,y,z)    (((x) & (y)) | ((~(x)) & (z)))
#define MD4_G(x,y,z)    (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD4_Fo(x,y,z)   (bitselect ((z), (y), (x)))
#define MD4_Go(x,y,z)   (bitselect ((x), (y), ((x) ^ (z))))
#endif

#ifdef IS_GENERIC
#define MD4_F(x,y,z)    (((x) & (y)) | ((~(x)) & (z)))
#define MD4_G(x,y,z)    (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD4_Fo(x,y,z)   (MD4_F((x), (y), (z)))
#define MD4_Go(x,y,z)   (MD4_G((x), (y), (z)))
#endif

#define MD4_STEP_S(f,a,b,c,d,x,K,s)   \
{                                     \
  a += K;                             \
  a  = hc_add3_S (a, x, f (b, c, d)); \
  a  = hc_rotl32_S (a, s);            \
}

#define MD4_STEP(f,a,b,c,d,x,K,s)     \
{                                     \
  a += K;                             \
  a  = hc_add3 (a, x, f (b, c, d));   \
  a  = hc_rotl32 (a, s);              \
}

#define MD4_STEP0(f,a,b,c,d,K,s)      \
{                                     \
  a  = hc_add3 (a, K, f (b, c, d));   \
  a  = hc_rotl32 (a, s);              \
}

typedef struct md4_ctx
{
  u32 h[4];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} md4_ctx_t;

typedef struct md4_hmac_ctx
{
  md4_ctx_t ipad;
  md4_ctx_t opad;

} md4_hmac_ctx_t;

typedef struct md4_ctx_vector
{
  u32x h[4];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} md4_ctx_vector_t;

typedef struct md4_hmac_ctx_vector
{
  md4_ctx_vector_t ipad;
  md4_ctx_vector_t opad;

} md4_hmac_ctx_vector_t;

DECLSPEC void md4_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void md4_init (md4_ctx_t *ctx);
DECLSPEC void md4_update_64 (md4_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void md4_update (md4_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_update_swap (md4_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_update_utf16le (md4_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_update_utf16le_swap (md4_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_update_global (md4_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_update_global_swap (md4_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_update_global_utf16le (md4_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_update_global_utf16le_swap (md4_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_final (md4_ctx_t *ctx);
DECLSPEC void md4_hmac_init_64 (md4_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void md4_hmac_init (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_init_swap (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_init_global (md4_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_hmac_init_global_swap (md4_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_hmac_update_64 (md4_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void md4_hmac_update (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_update_swap (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_update_utf16le (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_update_utf16le_swap (md4_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md4_hmac_update_global (md4_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_hmac_update_global_swap (md4_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_hmac_update_global_utf16le (md4_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_hmac_update_global_utf16le_swap (md4_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md4_hmac_final (md4_hmac_ctx_t *ctx);
DECLSPEC void md4_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void md4_init_vector (md4_ctx_vector_t *ctx);
DECLSPEC void md4_init_vector_from_scalar (md4_ctx_vector_t *ctx, md4_ctx_t *ctx0);
DECLSPEC void md4_update_vector_64 (md4_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void md4_update_vector (md4_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_update_vector_swap (md4_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_update_vector_utf16le (md4_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_update_vector_utf16le_swap (md4_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_final_vector (md4_ctx_vector_t *ctx);
DECLSPEC void md4_hmac_init_vector_64 (md4_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void md4_hmac_init_vector (md4_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_hmac_update_vector_64 (md4_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void md4_hmac_update_vector (md4_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md4_hmac_final_vector (md4_hmac_ctx_vector_t *ctx);

#endif
