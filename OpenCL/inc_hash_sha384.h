/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_SHA384_H
#define _INC_HASH_SHA384_H

#define SHIFT_RIGHT_64(x,n) ((x) >> (n))

#define SHA384_S0_S(x) (hc_rotr64_S ((x), 28) ^ hc_rotr64_S ((x), 34) ^ hc_rotr64_S ((x), 39))
#define SHA384_S1_S(x) (hc_rotr64_S ((x), 14) ^ hc_rotr64_S ((x), 18) ^ hc_rotr64_S ((x), 41))
#define SHA384_S2_S(x) (hc_rotr64_S ((x),  1) ^ hc_rotr64_S ((x),  8) ^ SHIFT_RIGHT_64 ((x), 7))
#define SHA384_S3_S(x) (hc_rotr64_S ((x), 19) ^ hc_rotr64_S ((x), 61) ^ SHIFT_RIGHT_64 ((x), 6))

#define SHA384_S0(x) (hc_rotr64 ((x), 28) ^ hc_rotr64 ((x), 34) ^ hc_rotr64 ((x), 39))
#define SHA384_S1(x) (hc_rotr64 ((x), 14) ^ hc_rotr64 ((x), 18) ^ hc_rotr64 ((x), 41))
#define SHA384_S2(x) (hc_rotr64 ((x),  1) ^ hc_rotr64 ((x),  8) ^ SHIFT_RIGHT_64 ((x), 7))
#define SHA384_S3(x) (hc_rotr64 ((x), 19) ^ hc_rotr64 ((x), 61) ^ SHIFT_RIGHT_64 ((x), 6))

#define SHA384_F0(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define SHA384_F1(x,y,z) (((x) & (y)) | ((z) & ((x) ^ (y))))

#ifdef IS_NV
#define SHA384_F0o(x,y,z) (bitselect ((z), (y), (x)))
#define SHA384_F1o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#endif

#ifdef IS_AMD
#define SHA384_F0o(x,y,z) (bitselect ((z), (y), (x)))
#define SHA384_F1o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#endif

#ifdef IS_GENERIC
#define SHA384_F0o(x,y,z) (SHA384_F0 ((x), (y), (z)))
#define SHA384_F1o(x,y,z) (SHA384_F1 ((x), (y), (z)))
#endif

#define SHA384_STEP_S(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                                 \
  h += K;                                         \
  h += x;                                         \
  h += SHA384_S1_S (e);                           \
  h += F0 (e, f, g);                              \
  d += h;                                         \
  h += SHA384_S0_S (a);                           \
  h += F1 (a, b, c);                              \
}

#define SHA384_EXPAND_S(x,y,z,w) (SHA384_S3_S (x) + y + SHA384_S2_S (z) + w)

#define SHA384_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                               \
  h += K;                                       \
  h += x;                                       \
  h += SHA384_S1 (e);                           \
  h += F0 (e, f, g);                            \
  d += h;                                       \
  h += SHA384_S0 (a);                           \
  h += F1 (a, b, c);                            \
}

#define SHA384_EXPAND(x,y,z,w) (SHA384_S3 (x) + y + SHA384_S2 (z) + w)

typedef struct sha384_ctx
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

} sha384_ctx_t;

typedef struct sha384_hmac_ctx
{
  sha384_ctx_t ipad;
  sha384_ctx_t opad;

} sha384_hmac_ctx_t;

typedef struct sha384_ctx_vector
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

} sha384_ctx_vector_t;

typedef struct sha384_hmac_ctx_vector
{
  sha384_ctx_vector_t ipad;
  sha384_ctx_vector_t opad;

} sha384_hmac_ctx_vector_t;

DECLSPEC void sha384_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, const u32 *w4, const u32 *w5, const u32 *w6, const u32 *w7, u64 *digest);
DECLSPEC void sha384_init (sha384_ctx_t *ctx);
DECLSPEC void sha384_update_128 (sha384_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len);
DECLSPEC void sha384_update (sha384_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_update_swap (sha384_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_update_utf16le (sha384_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_update_utf16le_swap (sha384_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_update_global (sha384_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_update_global_swap (sha384_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_update_global_utf16le (sha384_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_update_global_utf16le_swap (sha384_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_final (sha384_ctx_t *ctx);
DECLSPEC void sha384_hmac_init_128 (sha384_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, const u32 *w4, const u32 *w5, const u32 *w6, const u32 *w7);
DECLSPEC void sha384_hmac_init (sha384_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_hmac_init_swap (sha384_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_hmac_init_global (sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_hmac_init_global_swap (sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_hmac_update_128 (sha384_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len);
DECLSPEC void sha384_hmac_update (sha384_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_hmac_update_swap (sha384_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_hmac_update_utf16le (sha384_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_hmac_update_utf16le_swap (sha384_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha384_hmac_update_global (sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_hmac_update_global_swap (sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_hmac_update_global_utf16le (sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_hmac_update_global_utf16le_swap (sha384_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha384_hmac_final (sha384_hmac_ctx_t *ctx);
DECLSPEC void sha384_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, const u32x *w4, const u32x *w5, const u32x *w6, const u32x *w7, u64x *digest);
DECLSPEC void sha384_init_vector (sha384_ctx_vector_t *ctx);
DECLSPEC void sha384_init_vector_from_scalar (sha384_ctx_vector_t *ctx, sha384_ctx_t *ctx0);
DECLSPEC void sha384_update_vector_128 (sha384_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const int len);
DECLSPEC void sha384_update_vector (sha384_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha384_update_vector_swap (sha384_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha384_update_vector_utf16le (sha384_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha384_update_vector_utf16le_swap (sha384_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha384_update_vector_utf16beN (sha384_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha384_final_vector (sha384_ctx_vector_t *ctx);
DECLSPEC void sha384_hmac_init_vector_128 (sha384_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, const u32x *w4, const u32x *w5, const u32x *w6, const u32x *w7);
DECLSPEC void sha384_hmac_init_vector (sha384_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha384_hmac_update_vector_128 (sha384_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const int len);
DECLSPEC void sha384_hmac_update_vector (sha384_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha384_hmac_final_vector (sha384_hmac_ctx_vector_t *ctx);

#endif // _INC_HASH_SHA384_H
