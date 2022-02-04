/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_WHIRLPOOL_H
#define _INC_HASH_WHIRLPOOL_H

#if   VECT_SIZE == 1
#define BOX(S,i)   (S)[(i)]
#define BOX64(S,i) (S)[(i)]
#elif VECT_SIZE == 2
#define BOX(S,i)   make_u32x ((S)[(i).s0], (S)[(i).s1])
#define BOX64(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define BOX(S,i)   make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#define BOX64(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define BOX(S,i)   make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#define BOX64(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define BOX(S,i)   make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#define BOX64(S,i) make_u64x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

#define BOX_S(S,i)   (S)[(i)]
#define BOX64_S(S,i) (S)[(i)]

typedef struct whirlpool_ctx
{
  u32 h[16];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

  SHM_TYPE u64 *s_MT0;
  SHM_TYPE u64 *s_MT1;
  SHM_TYPE u64 *s_MT2;
  SHM_TYPE u64 *s_MT3;
  SHM_TYPE u64 *s_MT4;
  SHM_TYPE u64 *s_MT5;
  SHM_TYPE u64 *s_MT6;
  SHM_TYPE u64 *s_MT7;

} whirlpool_ctx_t;

typedef struct whirlpool_hmac_ctx
{
  whirlpool_ctx_t ipad;
  whirlpool_ctx_t opad;

} whirlpool_hmac_ctx_t;

typedef struct whirlpool_ctx_vector
{
  u32x h[16];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

  SHM_TYPE u64 *s_MT0;
  SHM_TYPE u64 *s_MT1;
  SHM_TYPE u64 *s_MT2;
  SHM_TYPE u64 *s_MT3;
  SHM_TYPE u64 *s_MT4;
  SHM_TYPE u64 *s_MT5;
  SHM_TYPE u64 *s_MT6;
  SHM_TYPE u64 *s_MT7;

} whirlpool_ctx_vector_t;

typedef struct whirlpool_hmac_ctx_vector
{
  whirlpool_ctx_vector_t ipad;
  whirlpool_ctx_vector_t opad;

} whirlpool_hmac_ctx_vector_t;

DECLSPEC void whirlpool_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_init (PRIVATE_AS whirlpool_ctx_t *ctx, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_update_64 (PRIVATE_AS whirlpool_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void whirlpool_update (PRIVATE_AS whirlpool_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_swap (PRIVATE_AS whirlpool_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_utf16le (PRIVATE_AS whirlpool_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_utf16le_swap (PRIVATE_AS whirlpool_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_global (PRIVATE_AS whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_global_swap (PRIVATE_AS whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_global_utf16le (PRIVATE_AS whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_global_utf16le_swap (PRIVATE_AS whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_final (PRIVATE_AS whirlpool_ctx_t *ctx);
DECLSPEC void whirlpool_hmac_init_64 (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init_swap (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init_global (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init_global_swap (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_update_64 (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void whirlpool_hmac_update (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_swap (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_utf16le (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_utf16le_swap (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_swap (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_utf16le (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_utf16le_swap (PRIVATE_AS whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_final (PRIVATE_AS whirlpool_hmac_ctx_t *ctx);
DECLSPEC void whirlpool_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u32x *digest, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_init_vector (PRIVATE_AS whirlpool_ctx_vector_t *ctx, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_init_vector_from_scalar (PRIVATE_AS whirlpool_ctx_vector_t *ctx, PRIVATE_AS whirlpool_ctx_t *ctx0);
DECLSPEC void whirlpool_update_vector_64 (PRIVATE_AS whirlpool_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void whirlpool_update_vector (PRIVATE_AS whirlpool_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_swap (PRIVATE_AS whirlpool_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_utf16le (PRIVATE_AS whirlpool_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_utf16le_swap (PRIVATE_AS whirlpool_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void whirlpool_final_vector (PRIVATE_AS whirlpool_ctx_vector_t *ctx);
DECLSPEC void whirlpool_hmac_init_vector_64 (PRIVATE_AS whirlpool_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init_vector (PRIVATE_AS whirlpool_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_update_vector_64 (PRIVATE_AS whirlpool_hmac_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void whirlpool_hmac_update_vector (PRIVATE_AS whirlpool_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void whirlpool_hmac_final_vector (PRIVATE_AS whirlpool_hmac_ctx_vector_t *ctx);

#endif // _INC_HASH_WHIRLPOOL_H
