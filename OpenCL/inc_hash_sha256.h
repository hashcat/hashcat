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

#define SHA256_F0(x,y,z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA256_F1(x,y,z)  ((z) ^ ((x) & ((y) ^ (z))))

#ifdef USE_BITSELECT
#define SHA256_F0o(x,y,z) (bitselect ((x), (y), ((x) ^ (z))))
#define SHA256_F1o(x,y,z) (bitselect ((z), (y), (x)))
#else
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
  h = hc_add3 (h, make_u32x (K), x);              \
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

DECLSPEC void sha256_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest);
DECLSPEC void sha256_init (PRIVATE_AS sha256_ctx_t *ctx);
DECLSPEC void sha256_update_64 (PRIVATE_AS sha256_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void sha256_update (PRIVATE_AS sha256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_update_swap (PRIVATE_AS sha256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_update_utf16le (PRIVATE_AS sha256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_update_utf16le_swap (PRIVATE_AS sha256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_update_global (PRIVATE_AS sha256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_update_global_swap (PRIVATE_AS sha256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_update_global_utf16le (PRIVATE_AS sha256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_update_global_utf16le_swap (PRIVATE_AS sha256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_final (PRIVATE_AS sha256_ctx_t *ctx);
DECLSPEC void sha256_hmac_init_64 (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3);
DECLSPEC void sha256_hmac_init (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_swap (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_global (PRIVATE_AS sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_init_global_swap (PRIVATE_AS sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_64 (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void sha256_hmac_update (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_swap (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_utf16le (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_utf16le_swap (PRIVATE_AS sha256_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global (PRIVATE_AS sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_swap (PRIVATE_AS sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_utf16le (PRIVATE_AS sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_update_global_utf16le_swap (PRIVATE_AS sha256_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sha256_hmac_final (PRIVATE_AS sha256_hmac_ctx_t *ctx);
DECLSPEC void sha256_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u32x *digest);
DECLSPEC void sha256_init_vector (PRIVATE_AS sha256_ctx_vector_t *ctx);
DECLSPEC void sha256_init_vector_from_scalar (PRIVATE_AS sha256_ctx_vector_t *ctx, PRIVATE_AS sha256_ctx_t *ctx0);
DECLSPEC void sha256_update_vector_64 (PRIVATE_AS sha256_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void sha256_update_vector (PRIVATE_AS sha256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha256_update_vector_swap (PRIVATE_AS sha256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16le (PRIVATE_AS sha256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16le_swap (PRIVATE_AS sha256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha256_update_vector_utf16beN (PRIVATE_AS sha256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha256_final_vector (PRIVATE_AS sha256_ctx_vector_t *ctx);
DECLSPEC void sha256_hmac_init_vector_64 (PRIVATE_AS sha256_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3);
DECLSPEC void sha256_hmac_init_vector (PRIVATE_AS sha256_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha256_hmac_update_vector_64 (PRIVATE_AS sha256_hmac_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void sha256_hmac_update_vector (PRIVATE_AS sha256_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sha256_hmac_final_vector (PRIVATE_AS sha256_hmac_ctx_vector_t *ctx);

#endif
