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

#ifdef IS_NV
#define SHA512_F0o(x,y,z) (bitselect ((z), (y), (x)))
#define SHA512_F1o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#endif

#ifdef IS_AMD
#define SHA512_F0o(x,y,z) (bitselect ((z), (y), (x)))
#define SHA512_F1o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#endif

#ifdef IS_GENERIC
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
  h += K;                                       \
  h += x;                                       \
  h += SHA512_S1 (e);                           \
  h += F0 (e, f, g);                            \
  d += h;                                       \
  h += SHA512_S0 (a);                           \
  h += F1 (a, b, c);                            \
}

#define SHA512_EXPAND(x,y,z,w) (SHA512_S3 (x) + y + SHA512_S2 (z) + w)

CONSTANT_AS u64a k_sha512[80] =
{
  SHA512C00, SHA512C01, SHA512C02, SHA512C03,
  SHA512C04, SHA512C05, SHA512C06, SHA512C07,
  SHA512C08, SHA512C09, SHA512C0a, SHA512C0b,
  SHA512C0c, SHA512C0d, SHA512C0e, SHA512C0f,
  SHA512C10, SHA512C11, SHA512C12, SHA512C13,
  SHA512C14, SHA512C15, SHA512C16, SHA512C17,
  SHA512C18, SHA512C19, SHA512C1a, SHA512C1b,
  SHA512C1c, SHA512C1d, SHA512C1e, SHA512C1f,
  SHA512C20, SHA512C21, SHA512C22, SHA512C23,
  SHA512C24, SHA512C25, SHA512C26, SHA512C27,
  SHA512C28, SHA512C29, SHA512C2a, SHA512C2b,
  SHA512C2c, SHA512C2d, SHA512C2e, SHA512C2f,
  SHA512C30, SHA512C31, SHA512C32, SHA512C33,
  SHA512C34, SHA512C35, SHA512C36, SHA512C37,
  SHA512C38, SHA512C39, SHA512C3a, SHA512C3b,
  SHA512C3c, SHA512C3d, SHA512C3e, SHA512C3f,
  SHA512C40, SHA512C41, SHA512C42, SHA512C43,
  SHA512C44, SHA512C45, SHA512C46, SHA512C47,
  SHA512C48, SHA512C49, SHA512C4a, SHA512C4b,
  SHA512C4c, SHA512C4d, SHA512C4e, SHA512C4f,
};

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

DECLSPEC void sha512_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, const u32 *w4, const u32 *w5, const u32 *w6, const u32 *w7, u64 *digest);
DECLSPEC void sha512_init (sha512_ctx_t *ctx);
DECLSPEC void sha512_update_128 (sha512_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len);
DECLSPEC void sha512_update (sha512_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_update_swap (sha512_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_update_utf16le (sha512_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_update_utf16le_swap (sha512_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_update_global (sha512_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha512_update_global_swap (sha512_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha512_update_global_utf16le (sha512_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha512_update_global_utf16le_swap (sha512_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha512_final (sha512_ctx_t *ctx);
DECLSPEC void sha512_hmac_init_128 (sha512_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, const u32 *w4, const u32 *w5, const u32 *w6, const u32 *w7);
DECLSPEC void sha512_hmac_init (sha512_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_hmac_init_swap (sha512_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_hmac_init_global (sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_init_global_swap (sha512_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_128 (sha512_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len);
DECLSPEC void sha512_hmac_update (sha512_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_swap (sha512_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_utf16le (sha512_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_utf16le_swap (sha512_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha512_hmac_update_global (sha512_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha512_hmac_update_global_swap (sha512_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha512_hmac_update_global_utf16le (sha512_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha512_hmac_update_global_utf16le_swap (sha512_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha512_hmac_final (sha512_hmac_ctx_t *ctx);
DECLSPEC void sha512_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, const u32x *w4, const u32x *w5, const u32x *w6, const u32x *w7, u64x *digest);
DECLSPEC void sha512_init_vector (sha512_ctx_vector_t *ctx);
DECLSPEC void sha512_init_vector_from_scalar (sha512_ctx_vector_t *ctx, sha512_ctx_t *ctx0);
DECLSPEC void sha512_update_vector_128 (sha512_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const int len);
DECLSPEC void sha512_update_vector (sha512_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha512_update_vector_swap (sha512_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha512_update_vector_utf16le (sha512_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha512_update_vector_utf16le_swap (sha512_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha512_update_vector_utf16beN (sha512_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha512_final_vector (sha512_ctx_vector_t *ctx);
DECLSPEC void sha512_hmac_init_vector_128 (sha512_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, const u32x *w4, const u32x *w5, const u32x *w6, const u32x *w7);
DECLSPEC void sha512_hmac_init_vector (sha512_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha512_hmac_update_vector_128 (sha512_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const int len);
DECLSPEC void sha512_hmac_update_vector (sha512_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha512_hmac_final_vector (sha512_hmac_ctx_vector_t *ctx);

#endif // _INC_HASH_SHA512_H
