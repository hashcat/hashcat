/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_RIPEMD320_H
#define INC_HASH_RIPEMD320_H

#define RIPEMD320_F(x,y,z)    ((x) ^ (y) ^ (z))
#define RIPEMD320_G(x,y,z)    ((z) ^ ((x) & ((y) ^ (z)))) /* x ? y : z */
#define RIPEMD320_H(x,y,z)    (((x) | ~(y)) ^ (z))
#define RIPEMD320_I(x,y,z)    ((y) ^ ((z) & ((x) ^ (y)))) /* z ? x : y */
#define RIPEMD320_J(x,y,z)    ((x) ^ ((y) | ~(z)))

#ifdef USE_BITSELECT
#define RIPEMD320_Go(x,y,z)   (bitselect ((z), (y), (x)))
#define RIPEMD320_Io(x,y,z)   (bitselect ((y), (x), (z)))
#else
#define RIPEMD320_Go(x,y,z)   (RIPEMD320_G ((x), (y), (z)))
#define RIPEMD320_Io(x,y,z)   (RIPEMD320_I ((x), (y), (z)))
#endif

#define RIPEMD320_STEP_S(f,a,b,c,d,e,x,K,s) \
{                                           \
  a += K;                                   \
  a += x;                                   \
  a += f (b, c, d);                         \
  a  = hc_rotl32_S (a, s);                  \
  a += e;                                   \
  c  = hc_rotl32_S (c, 10u);                \
}

#define RIPEMD320_STEP(f,a,b,c,d,e,x,K,s) \
{                                         \
  a += make_u32x (K);                     \
  a += x;                                 \
  a += f (b, c, d);                       \
  a  = hc_rotl32 (a, s);                  \
  a += e;                                 \
  c  = hc_rotl32 (c, 10u);                \
}

#define ROTATE_LEFT_WORKAROUND_BUG(a,n) ((a << n) | (a >> (32 - n)))

#define RIPEMD320_STEP_S_WORKAROUND_BUG(f,a,b,c,d,e,x,K,s)  \
{                                           \
  a += K;                                   \
  a += x;                                   \
  a += f (b, c, d);                         \
  a  = ROTATE_LEFT_WORKAROUND_BUG (a, s);   \
  a += e;                                   \
  c  = hc_rotl32_S (c, 10u);                \
}

#define RIPEMD320_STEP_WORKAROUND_BUG(f,a,b,c,d,e,x,K,s)  \
{                                         \
  a += make_u32x (K);                     \
  a += x;                                 \
  a += f (b, c, d);                       \
  a  = ROTATE_LEFT_WORKAROUND_BUG (a, s); \
  a += e;                                 \
  c  = hc_rotl32 (c, 10u);                \
}

typedef struct ripemd320_ctx
{
  u32 h[10];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} ripemd320_ctx_t;

typedef struct ripemd320_hmac_ctx
{
  ripemd320_ctx_t ipad;
  ripemd320_ctx_t opad;

} ripemd320_hmac_ctx_t;

typedef struct ripemd320_ctx_vector
{
  u32x h[10];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} ripemd320_ctx_vector_t;

typedef struct ripemd320_hmac_ctx_vector
{
  ripemd320_ctx_vector_t ipad;
  ripemd320_ctx_vector_t opad;

} ripemd320_hmac_ctx_vector_t;

DECLSPEC void ripemd320_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest);
DECLSPEC void ripemd320_init (PRIVATE_AS ripemd320_ctx_t *ctx);
DECLSPEC void ripemd320_update_64 (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void ripemd320_update (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_update_swap (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_update_utf16le (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_update_utf16le_swap (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_update_global (PRIVATE_AS ripemd320_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_update_global_swap (PRIVATE_AS ripemd320_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_update_global_utf16le (PRIVATE_AS ripemd320_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_update_global_utf16le_swap (PRIVATE_AS ripemd320_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_final (PRIVATE_AS ripemd320_ctx_t *ctx);
DECLSPEC void ripemd320_hmac_init_64 (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3);
DECLSPEC void ripemd320_hmac_init (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_init_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_init_global (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_init_global_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_update_64 (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void ripemd320_hmac_update (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_update_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_update_utf16le (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_update_utf16le_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_update_global (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_update_global_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_update_global_utf16le (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_update_global_utf16le_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void ripemd320_hmac_final (PRIVATE_AS ripemd320_hmac_ctx_t *ctx);
DECLSPEC void ripemd320_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u32x *digest);
DECLSPEC void ripemd320_init_vector (PRIVATE_AS ripemd320_ctx_vector_t *ctx);
DECLSPEC void ripemd320_init_vector_from_scalar (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS ripemd320_ctx_t *ctx0);
DECLSPEC void ripemd320_update_vector_64 (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void ripemd320_update_vector (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd320_update_vector_swap (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd320_update_vector_utf16le (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd320_update_vector_utf16le_swap (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd320_final_vector (PRIVATE_AS ripemd320_ctx_vector_t *ctx);
DECLSPEC void ripemd320_hmac_init_vector_64 (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3);
DECLSPEC void ripemd320_hmac_init_vector (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd320_hmac_update_vector_64 (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void ripemd320_hmac_update_vector (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void ripemd320_hmac_final_vector (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx);

#endif // INC_HASH_RIPEMD320_H
