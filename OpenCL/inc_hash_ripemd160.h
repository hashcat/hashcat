/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_RIPEMD160_H
#define _INC_HASH_RIPEMD160_H

#ifdef IS_NV
#define RIPEMD160_F(x,y,z)    ((x) ^ (y) ^ (z))
#define RIPEMD160_G(x,y,z)    ((z) ^ ((x) & ((y) ^ (z)))) /* x ? y : z */
#define RIPEMD160_H(x,y,z)    (((x) | ~(y)) ^ (z))
#define RIPEMD160_I(x,y,z)    ((y) ^ ((z) & ((x) ^ (y)))) /* z ? x : y */
#define RIPEMD160_J(x,y,z)    ((x) ^ ((y) | ~(z)))
#define RIPEMD160_Go(x,y,z)   (bitselect ((z), (y), (x)))
#define RIPEMD160_Io(x,y,z)   (bitselect ((y), (x), (z)))
#endif

#ifdef IS_AMD
#define RIPEMD160_F(x,y,z)    ((x) ^ (y) ^ (z))
#define RIPEMD160_G(x,y,z)    ((z) ^ ((x) & ((y) ^ (z)))) /* x ? y : z */
#define RIPEMD160_H(x,y,z)    (((x) | ~(y)) ^ (z))
#define RIPEMD160_I(x,y,z)    ((y) ^ ((z) & ((x) ^ (y)))) /* z ? x : y */
#define RIPEMD160_J(x,y,z)    ((x) ^ ((y) | ~(z)))
#define RIPEMD160_Go(x,y,z)   (bitselect ((z), (y), (x)))
#define RIPEMD160_Io(x,y,z)   (bitselect ((y), (x), (z)))
#endif

#ifdef IS_GENERIC
#define RIPEMD160_F(x,y,z)    ((x) ^ (y) ^ (z))
#define RIPEMD160_G(x,y,z)    ((z) ^ ((x) & ((y) ^ (z)))) /* x ? y : z */
#define RIPEMD160_H(x,y,z)    (((x) | ~(y)) ^ (z))
#define RIPEMD160_I(x,y,z)    ((y) ^ ((z) & ((x) ^ (y)))) /* z ? x : y */
#define RIPEMD160_J(x,y,z)    ((x) ^ ((y) | ~(z)))
#define RIPEMD160_Go(x,y,z)   (RIPEMD160_G ((x), (y), (z)))
#define RIPEMD160_Io(x,y,z)   (RIPEMD160_I ((x), (y), (z)))
#endif

#define RIPEMD160_STEP_S(f,a,b,c,d,e,x,K,s) \
{                                           \
  a += K;                                   \
  a += x;                                   \
  a += f (b, c, d);                         \
  a  = hc_rotl32_S (a, s);                  \
  a += e;                                   \
  c  = hc_rotl32_S (c, 10u);                \
}

#define RIPEMD160_STEP(f,a,b,c,d,e,x,K,s) \
{                                         \
  a += K;                                 \
  a += x;                                 \
  a += f (b, c, d);                       \
  a  = hc_rotl32 (a, s);                  \
  a += e;                                 \
  c  = hc_rotl32 (c, 10u);                \
}

#define ROTATE_LEFT_WORKAROUND_BUG(a,n) ((a << n) | (a >> (32 - n)))

#define RIPEMD160_STEP_S_WORKAROUND_BUG(f,a,b,c,d,e,x,K,s)  \
{                                           \
  a += K;                                   \
  a += x;                                   \
  a += f (b, c, d);                         \
  a  = ROTATE_LEFT_WORKAROUND_BUG (a, s);   \
  a += e;                                   \
  c  = hc_rotl32_S (c, 10u);                \
}

#define RIPEMD160_STEP_WORKAROUND_BUG(f,a,b,c,d,e,x,K,s)  \
{                                         \
  a += K;                                 \
  a += x;                                 \
  a += f (b, c, d);                       \
  a  = ROTATE_LEFT_WORKAROUND_BUG (a, s); \
  a += e;                                 \
  c  = hc_rotl32 (c, 10u);                \
}

typedef struct ripemd160_ctx
{
  u32 h[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} ripemd160_ctx_t;

typedef struct ripemd160_hmac_ctx
{
  ripemd160_ctx_t ipad;
  ripemd160_ctx_t opad;

} ripemd160_hmac_ctx_t;

typedef struct ripemd160_ctx_vector
{
  u32x h[5];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} ripemd160_ctx_vector_t;

typedef struct ripemd160_hmac_ctx_vector
{
  ripemd160_ctx_vector_t ipad;
  ripemd160_ctx_vector_t opad;

} ripemd160_hmac_ctx_vector_t;

DECLSPEC void ripemd160_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void ripemd160_init (ripemd160_ctx_t *ctx);
DECLSPEC void ripemd160_update_64 (ripemd160_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void ripemd160_update (ripemd160_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_update_swap (ripemd160_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_update_utf16le (ripemd160_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_update_utf16le_swap (ripemd160_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_update_global (ripemd160_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_update_global_swap (ripemd160_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_update_global_utf16le (ripemd160_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_update_global_utf16le_swap (ripemd160_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_final (ripemd160_ctx_t *ctx);
DECLSPEC void ripemd160_hmac_init_64 (ripemd160_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void ripemd160_hmac_init (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_init_swap (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_init_global (ripemd160_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_init_global_swap (ripemd160_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_update_64 (ripemd160_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void ripemd160_hmac_update (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_update_swap (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_update_utf16le (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_update_utf16le_swap (ripemd160_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_update_global (ripemd160_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_update_global_swap (ripemd160_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_update_global_utf16le (ripemd160_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_update_global_utf16le_swap (ripemd160_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd160_hmac_final (ripemd160_hmac_ctx_t *ctx);
DECLSPEC void ripemd160_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void ripemd160_init_vector (ripemd160_ctx_vector_t *ctx);
DECLSPEC void ripemd160_init_vector_from_scalar (ripemd160_ctx_vector_t *ctx, ripemd160_ctx_t *ctx0);
DECLSPEC void ripemd160_update_vector_64 (ripemd160_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void ripemd160_update_vector (ripemd160_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void ripemd160_update_vector_swap (ripemd160_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void ripemd160_update_vector_utf16le (ripemd160_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void ripemd160_update_vector_utf16le_swap (ripemd160_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void ripemd160_final_vector (ripemd160_ctx_vector_t *ctx);
DECLSPEC void ripemd160_hmac_init_vector_64 (ripemd160_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void ripemd160_hmac_init_vector (ripemd160_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void ripemd160_hmac_update_vector_64 (ripemd160_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void ripemd160_hmac_update_vector (ripemd160_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void ripemd160_hmac_final_vector (ripemd160_hmac_ctx_vector_t *ctx);

#endif // _INC_HASH_RIPEMD160_H
