/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_WHIRLPOOL_H
#define _INC_HASH_WHIRLPOOL_H

#define R 10

#if   VECT_SIZE == 1
#define BOX(S,n,i) (S)[(n)][(i)]
#elif VECT_SIZE == 2
#define BOX(S,n,i) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1])
#elif VECT_SIZE == 4
#define BOX(S,n,i) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3])
#elif VECT_SIZE == 8
#define BOX(S,n,i) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3], (S)[(n)][(i).s4], (S)[(n)][(i).s5], (S)[(n)][(i).s6], (S)[(n)][(i).s7])
#elif VECT_SIZE == 16
#define BOX(S,n,i) make_u32x ((S)[(n)][(i).s0], (S)[(n)][(i).s1], (S)[(n)][(i).s2], (S)[(n)][(i).s3], (S)[(n)][(i).s4], (S)[(n)][(i).s5], (S)[(n)][(i).s6], (S)[(n)][(i).s7], (S)[(n)][(i).s8], (S)[(n)][(i).s9], (S)[(n)][(i).sa], (S)[(n)][(i).sb], (S)[(n)][(i).sc], (S)[(n)][(i).sd], (S)[(n)][(i).se], (S)[(n)][(i).sf])
#endif

#define BOX_S(S,n,i) (S)[(n)][(i)]

typedef struct whirlpool_ctx
{
  u32 h[16];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

  SHM_TYPE u32 (*s_Ch)[256];
  SHM_TYPE u32 (*s_Cl)[256];

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

  SHM_TYPE u32 (*s_Ch)[256];
  SHM_TYPE u32 (*s_Cl)[256];

} whirlpool_ctx_vector_t;

typedef struct whirlpool_hmac_ctx_vector
{
  whirlpool_ctx_vector_t ipad;
  whirlpool_ctx_vector_t opad;

} whirlpool_hmac_ctx_vector_t;

DECLSPEC void whirlpool_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_init (whirlpool_ctx_t *ctx, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
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
DECLSPEC void whirlpool_hmac_init_64 (whirlpool_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init_global (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init_global_swap (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
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
DECLSPEC void whirlpool_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_init_vector (whirlpool_ctx_vector_t *ctx, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_init_vector_from_scalar (whirlpool_ctx_vector_t *ctx, whirlpool_ctx_t *ctx0);
DECLSPEC void whirlpool_update_vector_64 (whirlpool_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void whirlpool_update_vector (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_swap (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_utf16le (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_update_vector_utf16le_swap (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_final_vector (whirlpool_ctx_vector_t *ctx);
DECLSPEC void whirlpool_hmac_init_vector_64 (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_init_vector (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256]);
DECLSPEC void whirlpool_hmac_update_vector_64 (whirlpool_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len);
DECLSPEC void whirlpool_hmac_update_vector (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w, const int len);
DECLSPEC void whirlpool_hmac_final_vector (whirlpool_hmac_ctx_vector_t *ctx);

#endif // _INC_HASH_WHIRLPOOL_H
