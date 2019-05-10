/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_MD5_H
#define _INC_HASH_MD5_H

#define MD5_F_S(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G_S(x,y,z)  ((y) ^ ((z) & ((x) ^ (y))))
#define MD5_H_S(x,y,z)  ((x) ^ (y) ^ (z))
#define MD5_I_S(x,y,z)  ((y) ^ ((x) | ~(z)))

#ifdef IS_NV
#define MD5_F(x,y,z)    ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G(x,y,z)    ((y) ^ ((z) & ((x) ^ (y))))
#define MD5_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD5_H1(x,y,z)   ((t = (x) ^ (y)) ^ (z))
#define MD5_H2(x,y,z)   ((x) ^ t)
#define MD5_I(x,y,z)    ((y) ^ ((x) | ~(z)))
#define MD5_Fo(x,y,z)   (MD5_F((x), (y), (z)))
#define MD5_Go(x,y,z)   (MD5_G((x), (y), (z)))
#endif

#ifdef IS_AMD
#define MD5_F(x,y,z)    ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G(x,y,z)    ((y) ^ ((z) & ((x) ^ (y))))
#define MD5_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD5_H1(x,y,z)   ((t = (x) ^ (y)) ^ (z))
#define MD5_H2(x,y,z)   ((x) ^ t)
#define MD5_I(x,y,z)    ((y) ^ ((x) | ~(z)))
#define MD5_Fo(x,y,z)   (bitselect ((z), (y), (x)))
#define MD5_Go(x,y,z)   (bitselect ((y), (x), (z)))
#endif

#ifdef IS_GENERIC
#define MD5_F(x,y,z)    ((z) ^ ((x) & ((y) ^ (z))))
#define MD5_G(x,y,z)    ((y) ^ ((z) & ((x) ^ (y))))
#define MD5_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD5_H1(x,y,z)   ((t = (x) ^ (y)) ^ (z))
#define MD5_H2(x,y,z)   ((x) ^ t)
#define MD5_I(x,y,z)    ((y) ^ ((x) | ~(z)))
#define MD5_Fo(x,y,z)   (MD5_F((x), (y), (z)))
#define MD5_Go(x,y,z)   (MD5_G((x), (y), (z)))
#endif

#define MD5_STEP_S(f,a,b,c,d,x,K,s)   \
{                                     \
  a += K;                             \
  a  = hc_add3_S (a, x, f (b, c, d)); \
  a  = hc_rotl32_S (a, s);            \
  a += b;                             \
}

#define MD5_STEP(f,a,b,c,d,x,K,s)   \
{                                   \
  a += K;                           \
  a  = hc_add3 (a, x, f (b, c, d)); \
  a  = hc_rotl32 (a, s);            \
  a += b;                           \
}

#define MD5_STEP0(f,a,b,c,d,K,s)    \
{                                   \
  a  = hc_add3 (a, K, f (b, c, d)); \
  a  = hc_rotl32 (a, s);            \
  a += b;                           \
}

typedef struct md5_ctx
{
  u32 h[4];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} md5_ctx_t;

typedef struct md5_hmac_ctx
{
  md5_ctx_t ipad;
  md5_ctx_t opad;

} md5_hmac_ctx_t;

typedef struct md5_ctx_vector
{
  u32x h[4];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} md5_ctx_vector_t;

typedef struct md5_hmac_ctx_vector
{
  md5_ctx_vector_t ipad;
  md5_ctx_vector_t opad;

} md5_hmac_ctx_vector_t;

DECLSPEC void md5_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void md5_init (md5_ctx_t *ctx);
DECLSPEC void md5_update_64 (md5_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void md5_update (md5_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_update_swap (md5_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_update_utf16le (md5_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_update_utf16le_swap (md5_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_update_global (md5_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_update_global_swap (md5_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_update_global_utf16le (md5_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_update_global_utf16le_swap (md5_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_final (md5_ctx_t *ctx);
DECLSPEC void md5_hmac_init_64 (md5_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void md5_hmac_init (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_init_swap (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_init_global (md5_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_hmac_init_global_swap (md5_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_hmac_update_64 (md5_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void md5_hmac_update (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_update_swap (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_update_utf16le (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_update_utf16le_swap (md5_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void md5_hmac_update_global (md5_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_hmac_update_global_swap (md5_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_hmac_update_global_utf16le (md5_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_hmac_update_global_utf16le_swap (md5_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void md5_hmac_final (md5_hmac_ctx_t *ctx);
DECLSPEC void md5_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void md5_init_vector (md5_ctx_vector_t *ctx);
DECLSPEC void md5_init_vector_from_scalar (md5_ctx_vector_t *ctx, md5_ctx_t *ctx0);
DECLSPEC void md5_update_vector_64 (md5_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void md5_update_vector (md5_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_update_vector_swap (md5_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_update_vector_utf16le (md5_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_update_vector_utf16le_swap (md5_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_final_vector (md5_ctx_vector_t *ctx);
DECLSPEC void md5_hmac_init_vector_64 (md5_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void md5_hmac_init_vector (md5_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_hmac_update_vector_64 (md5_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void md5_hmac_update_vector (md5_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void md5_hmac_final_vector (md5_hmac_ctx_vector_t *ctx);

#endif
