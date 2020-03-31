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

DECLSPEC void whirlpool_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_init (whirlpool_ctx_t *ctx, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_update_64 (whirlpool_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void whirlpool_update (whirlpool_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_update_swap (whirlpool_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_update_utf16le (whirlpool_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_update_utf16le_swap (whirlpool_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_update_global (whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_global_swap (whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_global_utf16le (whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_update_global_utf16le_swap (whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_final (whirlpool_ctx_t *ctx);
DECLSPEC void whirlpool_hmac_init_64 (whirlpool_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init_global (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init_global_swap (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_update_64 (whirlpool_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len);
DECLSPEC void whirlpool_hmac_update (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_utf16le (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_utf16le_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_swap (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_utf16le (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_update_global_utf16le_swap (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void whirlpool_hmac_final (whirlpool_hmac_ctx_t *ctx);
DECLSPEC void whirlpool_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_init_vector (whirlpool_ctx_vector_t *ctx, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_init_vector_from_scalar (whirlpool_ctx_vector_t *ctx, whirlpool_ctx_t *ctx0);
DECLSPEC void whirlpool_update_vector_64 (whirlpool_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void whirlpool_update_vector (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_swap (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_utf16le (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_utf16le_swap (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_final_vector (whirlpool_ctx_vector_t *ctx);
DECLSPEC void whirlpool_hmac_init_vector_64 (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_init_vector (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7);
DECLSPEC void whirlpool_hmac_update_vector_64 (whirlpool_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void whirlpool_hmac_update_vector (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_hmac_final_vector (whirlpool_hmac_ctx_vector_t *ctx);

#endif // _INC_HASH_WHIRLPOOL_H
