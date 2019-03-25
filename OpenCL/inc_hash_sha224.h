/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_SHA224_H
#define _INC_HASH_SHA224_H

#define SHIFT_RIGHT_32(x,n) ((x) >> (n))

#define SHA224_S0_S(x) (hc_rotl32_S ((x), 25u) ^ hc_rotl32_S ((x), 14u) ^ SHIFT_RIGHT_32 ((x),  3u))
#define SHA224_S1_S(x) (hc_rotl32_S ((x), 15u) ^ hc_rotl32_S ((x), 13u) ^ SHIFT_RIGHT_32 ((x), 10u))
#define SHA224_S2_S(x) (hc_rotl32_S ((x), 30u) ^ hc_rotl32_S ((x), 19u) ^ hc_rotl32_S ((x), 10u))
#define SHA224_S3_S(x) (hc_rotl32_S ((x), 26u) ^ hc_rotl32_S ((x), 21u) ^ hc_rotl32_S ((x),  7u))

#define SHA224_S0(x) (hc_rotl32 ((x), 25u) ^ hc_rotl32 ((x), 14u) ^ SHIFT_RIGHT_32 ((x),  3u))
#define SHA224_S1(x) (hc_rotl32 ((x), 15u) ^ hc_rotl32 ((x), 13u) ^ SHIFT_RIGHT_32 ((x), 10u))
#define SHA224_S2(x) (hc_rotl32 ((x), 30u) ^ hc_rotl32 ((x), 19u) ^ hc_rotl32 ((x), 10u))
#define SHA224_S3(x) (hc_rotl32 ((x), 26u) ^ hc_rotl32 ((x), 21u) ^ hc_rotl32 ((x),  7u))

#ifdef IS_NV
#define SHA224_F0(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA224_F1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA224_F0o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#define SHA224_F1o(x,y,z) (bitselect ((z), (y), (x)))
#endif

#ifdef IS_AMD
#define SHA224_F0(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA224_F1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA224_F0o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#define SHA224_F1o(x,y,z) (bitselect ((z), (y), (x)))
#endif

#ifdef IS_GENERIC
#define SHA224_F0(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA224_F1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA224_F0o(x,y,z) (SHA224_F0 ((x), (y), (z)))
#define SHA224_F1o(x,y,z) (SHA224_F1 ((x), (y), (z)))
#endif

#define SHA224_STEP_S(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                                 \
  h = hc_add3_S (h, K, x);                        \
  h = hc_add3_S (h, SHA224_S3_S (e), F1 (e,f,g)); \
  d += h;                                         \
  h = hc_add3_S (h, SHA224_S2_S (a), F0 (a,b,c)); \
}

#define SHA224_EXPAND_S(x,y,z,w) (SHA224_S1_S (x) + y + SHA224_S0_S (z) + w)

#define SHA224_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)    \
{                                                 \
  h = hc_add3 (h, K, x);                          \
  h = hc_add3 (h, SHA224_S3 (e), F1 (e,f,g));     \
  d += h;                                         \
  h = hc_add3 (h, SHA224_S2 (a), F0 (a,b,c));     \
}

#define SHA224_EXPAND(x,y,z,w) (SHA224_S1 (x) + y + SHA224_S0 (z) + w)

CONSTANT_AS CONSTSPEC u32a k_sha224[64] =
{
  SHA224C00, SHA224C01, SHA224C02, SHA224C03,
  SHA224C04, SHA224C05, SHA224C06, SHA224C07,
  SHA224C08, SHA224C09, SHA224C0a, SHA224C0b,
  SHA224C0c, SHA224C0d, SHA224C0e, SHA224C0f,
  SHA224C10, SHA224C11, SHA224C12, SHA224C13,
  SHA224C14, SHA224C15, SHA224C16, SHA224C17,
  SHA224C18, SHA224C19, SHA224C1a, SHA224C1b,
  SHA224C1c, SHA224C1d, SHA224C1e, SHA224C1f,
  SHA224C20, SHA224C21, SHA224C22, SHA224C23,
  SHA224C24, SHA224C25, SHA224C26, SHA224C27,
  SHA224C28, SHA224C29, SHA224C2a, SHA224C2b,
  SHA224C2c, SHA224C2d, SHA224C2e, SHA224C2f,
  SHA224C30, SHA224C31, SHA224C32, SHA224C33,
  SHA224C34, SHA224C35, SHA224C36, SHA224C37,
  SHA224C38, SHA224C39, SHA224C3a, SHA224C3b,
  SHA224C3c, SHA224C3d, SHA224C3e, SHA224C3f,
};

typedef struct sha224_ctx
{
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} sha224_ctx_t;

typedef struct sha224_hmac_ctx
{
  sha224_ctx_t ipad;
  sha224_ctx_t opad;

} sha224_hmac_ctx_t;

typedef struct sha224_ctx_vector
{
  u32x h[8];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} sha224_ctx_vector_t;

typedef struct sha224_hmac_ctx_vector
{
  sha224_ctx_vector_t ipad;
  sha224_ctx_vector_t opad;

} sha224_hmac_ctx_vector_t;

DECLSPEC void sha224_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void sha224_init (sha224_ctx_t *ctx);
DECLSPEC void sha224_update_64 (sha224_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void sha224_update (sha224_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_update_swap (sha224_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_update_utf16le (sha224_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_update_utf16le_swap (sha224_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_update_global (sha224_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_update_global_swap (sha224_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_update_global_utf16le (sha224_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_update_global_utf16le_swap (sha224_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_final (sha224_ctx_t *ctx);
DECLSPEC void sha224_hmac_init_64 (sha224_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void sha224_hmac_init (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_init_swap (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_init_global (sha224_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_hmac_init_global_swap (sha224_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_64 (sha224_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void sha224_hmac_update (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_swap (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_utf16le (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_utf16le_swap (sha224_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_global (sha224_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_global_swap (sha224_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_global_utf16le (sha224_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_hmac_update_global_utf16le_swap (sha224_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha224_hmac_final (sha224_hmac_ctx_t *ctx);
DECLSPEC void sha224_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void sha224_init_vector (sha224_ctx_vector_t *ctx);
DECLSPEC void sha224_init_vector_from_scalar (sha224_ctx_vector_t *ctx, sha224_ctx_t *ctx0);
DECLSPEC void sha224_update_vector_64 (sha224_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void sha224_update_vector (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_update_vector_swap (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_update_vector_utf16le (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_update_vector_utf16le_swap (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_update_vector_utf16beN (sha224_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_final_vector (sha224_ctx_vector_t *ctx);
DECLSPEC void sha224_hmac_init_vector_64 (sha224_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void sha224_hmac_init_vector (sha224_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_hmac_update_vector_64 (sha224_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void sha224_hmac_update_vector (sha224_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha224_hmac_final_vector (sha224_hmac_ctx_vector_t *ctx);

#endif // _INC_HASH_SHA224_H
