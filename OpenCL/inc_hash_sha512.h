/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_SHA512_H
#define _INC_HASH_SHA512_H

#define SHIFT_RIGHT_64(x,n) ((x) >> (n))

#define SHA512_S0_S(x) (hc_rotr64_S ((x), 28) ^ hc_rotr64_S ((x), 34) ^ hc_rotr64_S ((x), 39))
#define SHA512_S1_S(x) (hc_rotr64_S ((x), 14) ^ hc_rotr64_S ((x), 18) ^ hc_rotr64_S ((x), 41))
#define SHA512_S2_S(x) (hc_rotr64_S ((x),  1) ^ hc_rotr64_S ((x),  8) ^ SHIFT_RIGHT_64 ((x), 7))
#define SHA512_S3_S(x) (hc_rotr64_S ((x), 19) ^ hc_rotr64_S ((x), 61) ^ SHIFT_RIGHT_64 ((x), 6))

#define SHA512_S0(x) (hc_rotr64 ((x), 28) ^ hc_rotr64 ((x), 34) ^ hc_rotr64 ((x), 39))
#define SHA512_S1(x) (hc_rotr64 ((x), 14) ^ hc_rotr64 ((x), 18) ^ hc_rotr64 ((x), 41))
#define SHA512_S2(x) (hc_rotr64 ((x),  1) ^ hc_rotr64 ((x),  8) ^ SHIFT_RIGHT_64 ((x), 7))
#define SHA512_S3(x) (hc_rotr64 ((x), 19) ^ hc_rotr64 ((x), 61) ^ SHIFT_RIGHT_64 ((x), 6))

#define SHA512_F0(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define SHA512_F1(x,y,z) (((x) & (y)) | ((z) & ((x) ^ (y))))

#ifdef USE_BITSELECT
#define SHA512_F0o(x,y,z) (bitselect ((z), (y), (x)))
#define SHA512_F1o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#else
#define SHA512_F0o(x,y,z) (SHA512_F0 ((x), (y), (z)))
#define SHA512_F1o(x,y,z) (SHA512_F1 ((x), (y), (z)))
#endif

#define SHA512_STEP_S(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                                 \
  h += K;                                         \
  h += x;                                         \
  h += SHA512_S1_S (e);                           \
  h += F0 (e, f, g);                              \
  d += h;                                         \
  h += SHA512_S0_S (a);                           \
  h += F1 (a, b, c);                              \
}

#define SHA512_EXPAND_S(x,y,z,w) (SHA512_S3_S (x) + y + SHA512_S2_S (z) + w)

#define SHA512_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                               \
  h += make_u64x (K);                           \
  h += x;                                       \
  h += SHA512_S1 (e);                           \
  h += F0 (e, f, g);                            \
  d += h;                                       \
  h += SHA512_S0 (a);                           \
  h += F1 (a, b, c);                            \
}

#define SHA512_EXPAND(x,y,z,w) (SHA512_S3 (x) + y + SHA512_S2 (z) + w)

typedef struct sha512_ctx
{
  u64 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int len;

} sha512_ctx_t;

typedef struct sha512_hmac_ctx
{
  sha512_ctx_t ipad;
  sha512_ctx_t opad;

} sha512_hmac_ctx_t;

typedef struct sha512_ctx_vector
{
  u64x h[8];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  int  len;

} sha512_ctx_vector_t;

typedef struct sha512_hmac_ctx_vector
{
  sha512_ctx_vector_t ipad;
  sha512_ctx_vector_t opad;

} sha512_hmac_ctx_vector_t;

DECLSPEC void sha512_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS const u32 *w4, PRIVATE_AS const u32 *w5, PRIVATE_AS const u32 *w6, PRIVATE_AS const u32 *w7, PRIVATE_AS u64 *digest);
DECLSPEC void sha512_init (PRIVATE_AS sha512_ctx_t *ctx);
DECLSPEC void sha512_update_128 (PRIVATE_AS sha512_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, const int len);
DECLSPEC void sha512_update (PRIVATE_AS sha512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_update_swap (PRIVATE_AS sha512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_update_utf16le (PRIVATE_AS sha512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_update_utf16le_swap (PRIVATE_AS sha512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_update_global (PRIVATE_AS sha512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_update_global_swap (PRIVATE_AS sha512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_update_global_utf16le (PRIVATE_AS sha512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_update_global_utf16le_swap (PRIVATE_AS sha512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_final (PRIVATE_AS sha512_ctx_t *ctx);
DECLSPEC void sha512_hmac_init_128 (PRIVATE_AS sha512_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS const u32 *w4, PRIVATE_AS const u32 *w5, PRIVATE_AS const u32 *w6, PRIVATE_AS const u32 *w7);
DECLSPEC void sha512_hmac_init (PRIVATE_AS sha512_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_init_swap (PRIVATE_AS sha512_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_init_global (PRIVATE_AS sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_init_global_swap (PRIVATE_AS sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_init_global_utf16le_swap (PRIVATE_AS sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_128 (PRIVATE_AS sha512_hmac_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, PRIVATE_AS u32 *w4, PRIVATE_AS u32 *w5, PRIVATE_AS u32 *w6, PRIVATE_AS u32 *w7, const int len);
DECLSPEC void sha512_hmac_update (PRIVATE_AS sha512_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_swap (PRIVATE_AS sha512_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_utf16le (PRIVATE_AS sha512_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_utf16le_swap (PRIVATE_AS sha512_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_global (PRIVATE_AS sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_global_swap (PRIVATE_AS sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_global_utf16le (PRIVATE_AS sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_global_utf16le_swap (PRIVATE_AS sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_final (PRIVATE_AS sha512_hmac_ctx_t *ctx);
DECLSPEC void sha512_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS const u32x *w4, PRIVATE_AS const u32x *w5, PRIVATE_AS const u32x *w6, PRIVATE_AS const u32x *w7, PRIVATE_AS u64x *digest);
DECLSPEC void sha512_init_vector (PRIVATE_AS sha512_ctx_vector_t *ctx);
DECLSPEC void sha512_init_vector_from_scalar (PRIVATE_AS sha512_ctx_vector_t *ctx, PRIVATE_AS sha512_ctx_t *ctx0);
DECLSPEC void sha512_update_vector_128 (PRIVATE_AS sha512_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const int len);
DECLSPEC void sha512_update_vector (PRIVATE_AS sha512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha512_update_vector_swap (PRIVATE_AS sha512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha512_update_vector_utf16le (PRIVATE_AS sha512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha512_update_vector_utf16le_swap (PRIVATE_AS sha512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha512_update_vector_utf16beN (PRIVATE_AS sha512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha512_final_vector (PRIVATE_AS sha512_ctx_vector_t *ctx);
DECLSPEC void sha512_hmac_init_vector_128 (PRIVATE_AS sha512_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS const u32x *w4, PRIVATE_AS const u32x *w5, PRIVATE_AS const u32x *w6, PRIVATE_AS const u32x *w7);
DECLSPEC void sha512_hmac_init_vector (PRIVATE_AS sha512_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha512_hmac_update_vector_128 (PRIVATE_AS sha512_hmac_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, const int len);
DECLSPEC void sha512_hmac_update_vector (PRIVATE_AS sha512_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha512_hmac_final_vector (PRIVATE_AS sha512_hmac_ctx_vector_t *ctx);

#endif // _INC_HASH_SHA512_H
