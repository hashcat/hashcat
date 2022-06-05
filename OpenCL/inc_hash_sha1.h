/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_SHA1_H
#define _INC_HASH_SHA1_H

#define SHA1_F0(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA1_F1(x,y,z)  ((x) ^ (y) ^ (z))
#define SHA1_F2(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))

#ifdef USE_BITSELECT
#define SHA1_F0o(x,y,z) (bitselect ((z), (y), (x)))
#define SHA1_F2o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#else
#define SHA1_F0o(x,y,z) (SHA1_F0 ((x), (y), (z)))
#define SHA1_F2o(x,y,z) (SHA1_F2 ((x), (y), (z)))
#endif

#define SHA1_STEP_S(f,a,b,c,d,e,x)    \
{                                     \
  e += K;                             \
  e  = hc_add3_S (e, x, f (b, c, d)); \
  e += hc_rotl32_S (a,  5u);          \
  b  = hc_rotl32_S (b, 30u);          \
}

#define SHA1_STEP(f,a,b,c,d,e,x)    \
{                                   \
  e += make_u32x (K);               \
  e  = hc_add3 (e, x, f (b, c, d)); \
  e += hc_rotl32 (a,  5u);          \
  b  = hc_rotl32 (b, 30u);          \
}

/*
#define SHA1_STEP0(f,a,b,c,d,e,x)   \
{                                   \
  e  = hc_add3 (e, K, f (b, c, d)); \
  e += hc_rotl32 (a,  5u);          \
  b  = hc_rotl32 (b, 30u);          \
}
*/

#define SHA1_STEPX(f,a,b,c,d,e,x)   \
{                                   \
  e  = hc_add3 (e, x, f (b, c, d)); \
  e += hc_rotl32 (a,  5u);          \
  b  = hc_rotl32 (b, 30u);          \
}

typedef struct sha1_ctx
{
  u32 h[5];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} sha1_ctx_t;

typedef struct sha1_hmac_ctx
{
  sha1_ctx_t ipad;
  sha1_ctx_t opad;

} sha1_hmac_ctx_t;

typedef struct sha1_ctx_vector
{
  u32x h[5];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} sha1_ctx_vector_t;

typedef struct sha1_hmac_ctx_vector
{
  sha1_ctx_vector_t ipad;
  sha1_ctx_vector_t opad;

} sha1_hmac_ctx_vector_t;

DECLSPEC void sha1_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest);
DECLSPEC void sha1_init (PRIVATE_AS sha1_ctx_t *ctx);
DECLSPEC void sha1_update_64 (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void sha1_update (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_update_swap (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_update_utf16le (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_update_utf16le_swap (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_update_utf16be (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_update_utf16be_swap (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_update_utf16beN (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_update_global (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_update_global_swap (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_update_global_utf16le (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_update_global_utf16le_swap (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_update_global_utf16be (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_update_global_utf16be_swap (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_final (PRIVATE_AS sha1_ctx_t *ctx);
DECLSPEC void sha1_hmac_init_64 (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3);
DECLSPEC void sha1_hmac_init (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_init_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_init_global (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_init_global_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_update_64 (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void sha1_hmac_update (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_update_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_update_utf16le (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_update_utf16le_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_update_global (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_update_global_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_update_global_utf16le (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_update_global_utf16le_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha1_hmac_final (PRIVATE_AS  sha1_hmac_ctx_t *ctx);
DECLSPEC void sha1_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u32x *digest);
DECLSPEC void sha1_init_vector (PRIVATE_AS sha1_ctx_vector_t *ctx);
DECLSPEC void sha1_init_vector_from_scalar (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS sha1_ctx_t *ctx0);
DECLSPEC void sha1_update_vector_64 (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void sha1_update_vector (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha1_update_vector_swap (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha1_update_vector_utf16le (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha1_update_vector_utf16le_swap (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha1_update_vector_utf16leN (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha1_update_vector_utf16beN (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha1_final_vector (PRIVATE_AS sha1_ctx_vector_t *ctx);
DECLSPEC void sha1_hmac_init_vector_64 (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3);
DECLSPEC void sha1_hmac_init_vector (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha1_hmac_update_vector_64 (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void sha1_hmac_update_vector (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha1_hmac_final_vector (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx);

#endif
