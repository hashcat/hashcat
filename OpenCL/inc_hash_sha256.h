/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_SHA256_H
#define _INC_HASH_SHA256_H

#define SHIFT_RIGHT_32(x,n) ((x) >> (n))

#define SHA256_S0_S(x) (hc_rotl32_S ((x), 25u) ^ hc_rotl32_S ((x), 14u) ^ SHIFT_RIGHT_32 ((x),  3u))
#define SHA256_S1_S(x) (hc_rotl32_S ((x), 15u) ^ hc_rotl32_S ((x), 13u) ^ SHIFT_RIGHT_32 ((x), 10u))
#define SHA256_S2_S(x) (hc_rotl32_S ((x), 30u) ^ hc_rotl32_S ((x), 19u) ^ hc_rotl32_S ((x), 10u))
#define SHA256_S3_S(x) (hc_rotl32_S ((x), 26u) ^ hc_rotl32_S ((x), 21u) ^ hc_rotl32_S ((x),  7u))

#define SHA256_S0(x) (hc_rotl32 ((x), 25u) ^ hc_rotl32 ((x), 14u) ^ SHIFT_RIGHT_32 ((x),  3u))
#define SHA256_S1(x) (hc_rotl32 ((x), 15u) ^ hc_rotl32 ((x), 13u) ^ SHIFT_RIGHT_32 ((x), 10u))
#define SHA256_S2(x) (hc_rotl32 ((x), 30u) ^ hc_rotl32 ((x), 19u) ^ hc_rotl32 ((x), 10u))
#define SHA256_S3(x) (hc_rotl32 ((x), 26u) ^ hc_rotl32 ((x), 21u) ^ hc_rotl32 ((x),  7u))

#ifdef IS_NV
#define SHA256_F0(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA256_F1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA256_F0o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#define SHA256_F1o(x,y,z) (bitselect ((z), (y), (x)))
#endif

#ifdef IS_AMD
#define SHA256_F0(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA256_F1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA256_F0o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#define SHA256_F1o(x,y,z) (bitselect ((z), (y), (x)))
#endif

#ifdef IS_GENERIC
#define SHA256_F0(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA256_F1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SHA256_F0o(x,y,z) (SHA256_F0 ((x), (y), (z)))
#define SHA256_F1o(x,y,z) (SHA256_F1 ((x), (y), (z)))
#endif

#define SHA256_STEP_S(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                                 \
  h = hc_add3_S (h, K, x);                        \
  h = hc_add3_S (h, SHA256_S3_S (e), F1 (e,f,g)); \
  d += h;                                         \
  h = hc_add3_S (h, SHA256_S2_S (a), F0 (a,b,c)); \
}

#define SHA256_EXPAND_S(x,y,z,w) (SHA256_S1_S (x) + y + SHA256_S0_S (z) + w)

#define SHA256_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)    \
{                                                 \
  h = hc_add3 (h, K, x);                          \
  h = hc_add3 (h, SHA256_S3 (e), F1 (e,f,g));     \
  d += h;                                         \
  h = hc_add3 (h, SHA256_S2 (a), F0 (a,b,c));     \
}

#define SHA256_EXPAND(x,y,z,w) (SHA256_S1 (x) + y + SHA256_S0 (z) + w)

typedef struct sha256_ctx
{
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} sha256_ctx_t;

typedef struct sha256_hmac_ctx
{
  sha256_ctx_t ipad;
  sha256_ctx_t opad;

} sha256_hmac_ctx_t;

typedef struct sha256_ctx_vector
{
  u32x h[8];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} sha256_ctx_vector_t;

typedef struct sha256_hmac_ctx_vector
{
  sha256_ctx_vector_t ipad;
  sha256_ctx_vector_t opad;

} sha256_hmac_ctx_vector_t;

CONSTANT_AS u32a k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

DECLSPEC void sha256_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest);
DECLSPEC void sha256_init (sha256_ctx_t *ctx);
DECLSPEC void sha256_update_64 (sha256_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void sha256_update (sha256_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_update_swap (sha256_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_update_utf16le (sha256_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_update_utf16le_swap (sha256_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_update_global (sha256_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_update_global_swap (sha256_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_update_global_utf16le (sha256_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_update_global_utf16le_swap (sha256_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_final (sha256_ctx_t *ctx);
DECLSPEC void sha256_hmac_init_64 (sha256_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3);
DECLSPEC void sha256_hmac_init (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_swap (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_global (sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_global_swap (sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_64 (sha256_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void sha256_hmac_update (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_swap (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_utf16le (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_utf16le_swap (sha256_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global (sha256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_swap (sha256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_utf16le (sha256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_utf16le_swap (sha256_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len);
DECLSPEC void sha256_hmac_final (sha256_hmac_ctx_t *ctx);
DECLSPEC void sha256_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest);
DECLSPEC void sha256_init_vector (sha256_ctx_vector_t *ctx);
DECLSPEC void sha256_init_vector_from_scalar (sha256_ctx_vector_t *ctx, sha256_ctx_t *ctx0);
DECLSPEC void sha256_update_vector_64 (sha256_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void sha256_update_vector (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_update_vector_swap (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16le (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16le_swap (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16beN (sha256_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_final_vector (sha256_ctx_vector_t *ctx);
DECLSPEC void sha256_hmac_init_vector_64 (sha256_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3);
DECLSPEC void sha256_hmac_init_vector (sha256_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_hmac_update_vector_64 (sha256_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void sha256_hmac_update_vector (sha256_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void sha256_hmac_final_vector (sha256_hmac_ctx_vector_t *ctx);

#endif
