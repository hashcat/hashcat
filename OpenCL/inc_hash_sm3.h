/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_SM3_H
#define INC_HASH_SM3_H

#define SM3_P0_S(x)       ((x) ^ hc_rotl32_S((x),  9) ^ hc_rotl32_S((x), 17))
#define SM3_P1_S(x)       ((x) ^ hc_rotl32_S((x), 15) ^ hc_rotl32_S((x), 23))

#define SM3_P0(x)         ((x) ^ hc_rotl32((x),  9) ^ hc_rotl32((x), 17))
#define SM3_P1(x)         ((x) ^ hc_rotl32((x), 15) ^ hc_rotl32((x), 23))

#define SM3_FF0(x, y, z)  ((x) ^ (y) ^ (z))
#define SM3_GG0(x, y, z)  ((x) ^ (y) ^ (z))

#ifdef USE_BITSELECT
#define SM3_FF1(x, y, z)  (bitselect ((x), (y), ((x) ^ (z))))
#define SM3_GG1(x, y, z)  (bitselect ((z), (y), (x)))
#else
#define SM3_FF1(x, y, z)  (((x) & (y)) | ((z) & ((x) ^ (y))))
#define SM3_GG1(x, y, z)  (((z) ^ ((x) & ((y) ^ (z)))))
#endif

#define SM3_EXPAND_S(a, b, c, d, e)   (SM3_P1_S(a ^ b ^ hc_rotl32_S(c, 15)) ^ hc_rotl32_S(d, 7) ^ e)
#define SM3_EXPAND(a, b, c, d, e)     (SM3_P1(a ^ b ^ hc_rotl32(c, 15)) ^ hc_rotl32(d, 7) ^ e)

// Only Wj need to be parenthesis because of operator priority
// (Wj = Wi ^ Wi+4)
#define SM3_ROUND_S(a, b, c, d, e, f, g, h, Tj, Wi, Wj, FF, GG)  \
{                                                                \
  const u32 A_ROTL12 = hc_rotl32_S(a, 12);                       \
  const u32 SS1 = hc_rotl32_S(A_ROTL12 + e + Tj, 7);             \
  const u32 TT1 = FF(a, b, c) + d + (SS1 ^ A_ROTL12) + (Wj);     \
  const u32 TT2 = GG(e, f, g) + h + SS1 + Wi;                    \
  b = hc_rotl32_S(b, 9);                                         \
  d = TT1;                                                       \
  f = hc_rotl32_S(f, 19);                                        \
  h = SM3_P0_S(TT2);                                             \
}

#define SM3_ROUND(a, b, c, d, e, f, g, h, Tj, Wi, Wj, FF, GG)    \
{                                                                \
  const u32x A_ROTL12 = hc_rotl32(a, 12);                        \
  const u32x SS1 = hc_rotl32(A_ROTL12 + e + make_u32x(Tj), 7);   \
  const u32x TT1 = FF(a, b, c) + d + (SS1 ^ A_ROTL12) + (Wj);    \
  const u32x TT2 = GG(e, f, g) + h + SS1 + Wi;                   \
  b = hc_rotl32(b, 9);                                           \
  d = TT1;                                                       \
  f = hc_rotl32(f, 19);                                          \
  h = SM3_P0(TT2);                                               \
}

#define SM3_ROUND1_S(a, b, c, d, e, f, g, h, Tj, Wi, Wj)  SM3_ROUND_S(a, b, c, d, e, f, g, h, Tj, Wi, Wj, SM3_FF0, SM3_GG0)
#define SM3_ROUND1(a, b, c, d, e, f, g, h, Tj, Wi, Wj)    SM3_ROUND(a, b, c, d, e, f, g, h, Tj, Wi, Wj, SM3_FF0, SM3_GG0)
#define SM3_ROUND2_S(a, b, c, d, e, f, g, h, Tj, Wi, Wj)  SM3_ROUND_S(a, b, c, d, e, f, g, h, Tj, Wi, Wj, SM3_FF1, SM3_GG1)
#define SM3_ROUND2(a, b, c, d, e, f, g, h, Tj, Wi, Wj)    SM3_ROUND(a, b, c, d, e, f, g, h, Tj, Wi, Wj, SM3_FF1, SM3_GG1)

typedef struct sm3_ctx
{
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} sm3_ctx_t;

typedef struct sm3_ctx_vector
{
  u32x h[8];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} sm3_ctx_vector_t;

DECLSPEC void sm3_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest);
DECLSPEC void sm3_init (PRIVATE_AS sm3_ctx_t *ctx);
DECLSPEC void sm3_update_64 (PRIVATE_AS sm3_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len);
DECLSPEC void sm3_update (PRIVATE_AS sm3_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sm3_update_swap (PRIVATE_AS sm3_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sm3_update_utf16le (PRIVATE_AS sm3_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sm3_update_utf16le_swap (PRIVATE_AS sm3_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void sm3_update_global (PRIVATE_AS sm3_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sm3_update_global_swap (PRIVATE_AS sm3_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sm3_update_global_utf16le (PRIVATE_AS sm3_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sm3_update_global_utf16le_swap (PRIVATE_AS sm3_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void sm3_final (PRIVATE_AS sm3_ctx_t *ctx);

DECLSPEC void sm3_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u32x *digest);
DECLSPEC void sm3_init_vector (PRIVATE_AS sm3_ctx_vector_t *ctx);
DECLSPEC void sm3_init_vector_from_scalar (PRIVATE_AS sm3_ctx_vector_t *ctx, PRIVATE_AS sm3_ctx_t *ctx0);
DECLSPEC void sm3_update_vector_64 (PRIVATE_AS sm3_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len);
DECLSPEC void sm3_update_vector (PRIVATE_AS sm3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sm3_update_vector_swap (PRIVATE_AS sm3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sm3_update_vector_utf16le (PRIVATE_AS sm3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sm3_update_vector_utf16le_swap (PRIVATE_AS sm3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sm3_update_vector_utf16beN (PRIVATE_AS sm3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void sm3_final_vector (PRIVATE_AS sm3_ctx_vector_t *ctx);

#endif
