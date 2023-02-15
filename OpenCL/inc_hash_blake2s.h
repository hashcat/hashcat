/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_HASH_BLAKE2S_H
#define INC_HASH_BLAKE2S_H

#define BLAKE2S_UPDATE  0
#define BLAKE2S_FINAL  -1

DECLSPEC u32  blake2s_rot16_S (const u32  a);
DECLSPEC u32x blake2s_rot16   (const u32x a);

DECLSPEC u32  blake2s_rot08_S (const u32  a);
DECLSPEC u32x blake2s_rot08   (const u32x a);

#define BLAKE2S_G(k0,k1,a,b,c,d) \
{                                \
  a = a + b + m[k0];             \
  d = blake2s_rot16_S (d ^ a);   \
  c = c + d;                     \
  b = hc_rotr32_S (b ^ c, 12);   \
  a = a + b + m[k1];             \
  d = blake2s_rot08_S (d ^ a);   \
  c = c + d;                     \
  b = hc_rotr32_S (b ^ c, 7);    \
}

#define BLAKE2S_ROUND(c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf) \
{                                                                      \
  BLAKE2S_G (c0, c1, v[0], v[4], v[ 8], v[12]);                        \
  BLAKE2S_G (c2, c3, v[1], v[5], v[ 9], v[13]);                        \
  BLAKE2S_G (c4, c5, v[2], v[6], v[10], v[14]);                        \
  BLAKE2S_G (c6, c7, v[3], v[7], v[11], v[15]);                        \
  BLAKE2S_G (c8, c9, v[0], v[5], v[10], v[15]);                        \
  BLAKE2S_G (ca, cb, v[1], v[6], v[11], v[12]);                        \
  BLAKE2S_G (cc, cd, v[2], v[7], v[ 8], v[13]);                        \
  BLAKE2S_G (ce, cf, v[3], v[4], v[ 9], v[14]);                        \
}

#define BLAKE2S_G_VECTOR(k0,k1,a,b,c,d) \
{                                       \
  a = a + b + m[k0];                    \
  d = blake2s_rot16 (d ^ a);            \
  c = c + d;                            \
  b = hc_rotr32 (b ^ c, 12);            \
  a = a + b + m[k1];                    \
  d = blake2s_rot08 (d ^ a);            \
  c = c + d;                            \
  b = hc_rotr32 (b ^ c, 7);             \
}

#define BLAKE2S_ROUND_VECTOR(c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf) \
{                                                                             \
  BLAKE2S_G_VECTOR (c0, c1, v[0], v[4], v[ 8], v[12]);                        \
  BLAKE2S_G_VECTOR (c2, c3, v[1], v[5], v[ 9], v[13]);                        \
  BLAKE2S_G_VECTOR (c4, c5, v[2], v[6], v[10], v[14]);                        \
  BLAKE2S_G_VECTOR (c6, c7, v[3], v[7], v[11], v[15]);                        \
  BLAKE2S_G_VECTOR (c8, c9, v[0], v[5], v[10], v[15]);                        \
  BLAKE2S_G_VECTOR (ca, cb, v[1], v[6], v[11], v[12]);                        \
  BLAKE2S_G_VECTOR (cc, cd, v[2], v[7], v[ 8], v[13]);                        \
  BLAKE2S_G_VECTOR (ce, cf, v[3], v[4], v[ 9], v[14]);                        \
}

typedef struct blake2s_ctx
{
  u32 m[16]; // buffer
  u32 h[ 8]; // digest

  int len;

} blake2s_ctx_t;

typedef struct blake2s_ctx_vector
{
  u32x m[16]; // buffer
  u32x h[ 8]; // digest

  int len;

} blake2s_ctx_vector_t;

DECLSPEC void blake2s_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m, const int len, const u32 f0);
DECLSPEC void blake2s_init (PRIVATE_AS blake2s_ctx_t *ctx);
DECLSPEC void blake2s_update (PRIVATE_AS blake2s_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len);
DECLSPEC void blake2s_update_global (PRIVATE_AS blake2s_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len);
DECLSPEC void blake2s_final (PRIVATE_AS blake2s_ctx_t *ctx);

DECLSPEC void blake2s_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m, const u32x len, const u32 f0);
DECLSPEC void blake2s_init_vector (PRIVATE_AS blake2s_ctx_vector_t *ctx);
DECLSPEC void blake2s_init_vector_from_scalar (PRIVATE_AS blake2s_ctx_vector_t *ctx, PRIVATE_AS blake2s_ctx_t *ctx0);
DECLSPEC void blake2s_update_vector (PRIVATE_AS blake2s_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len);
DECLSPEC void blake2s_final_vector (PRIVATE_AS blake2s_ctx_vector_t *ctx);

#endif // INC_HASH_BLAKE2S_H
