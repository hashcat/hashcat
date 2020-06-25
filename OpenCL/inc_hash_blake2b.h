/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_BLAKE2B_H
#define _INC_HASH_BLAKE2B_H

#define BLAKE2B_UPDATE  0
#define BLAKE2B_FINAL  -1

#define BLAKE2B_G(k0,k1,a,b,c,d) \
{                                \
  a = a + b + m[k0];             \
  d = hc_rotr64_S (d ^ a, 32);   \
  c = c + d;                     \
  b = hc_rotr64_S (b ^ c, 24);   \
  a = a + b + m[k1];             \
  d = hc_rotr64_S (d ^ a, 16);   \
  c = c + d;                     \
  b = hc_rotr64_S (b ^ c, 63);   \
}

#define BLAKE2B_ROUND(c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf) \
{                                                                      \
  BLAKE2B_G (c0, c1, v[0], v[4], v[ 8], v[12]);                        \
  BLAKE2B_G (c2, c3, v[1], v[5], v[ 9], v[13]);                        \
  BLAKE2B_G (c4, c5, v[2], v[6], v[10], v[14]);                        \
  BLAKE2B_G (c6, c7, v[3], v[7], v[11], v[15]);                        \
  BLAKE2B_G (c8, c9, v[0], v[5], v[10], v[15]);                        \
  BLAKE2B_G (ca, cb, v[1], v[6], v[11], v[12]);                        \
  BLAKE2B_G (cc, cd, v[2], v[7], v[ 8], v[13]);                        \
  BLAKE2B_G (ce, cf, v[3], v[4], v[ 9], v[14]);                        \
}

#define BLAKE2B_G_VECTOR(k0,k1,a,b,c,d) \
{                                       \
  a = a + b + m[k0];                    \
  d = hc_rotr64 (d ^ a, 32);            \
  c = c + d;                            \
  b = hc_rotr64 (b ^ c, 24);            \
  a = a + b + m[k1];                    \
  d = hc_rotr64 (d ^ a, 16);            \
  c = c + d;                            \
  b = hc_rotr64 (b ^ c, 63);            \
}

#define BLAKE2B_ROUND_VECTOR(c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf) \
{                                                                             \
  BLAKE2B_G_VECTOR (c0, c1, v[0], v[4], v[ 8], v[12]);                        \
  BLAKE2B_G_VECTOR (c2, c3, v[1], v[5], v[ 9], v[13]);                        \
  BLAKE2B_G_VECTOR (c4, c5, v[2], v[6], v[10], v[14]);                        \
  BLAKE2B_G_VECTOR (c6, c7, v[3], v[7], v[11], v[15]);                        \
  BLAKE2B_G_VECTOR (c8, c9, v[0], v[5], v[10], v[15]);                        \
  BLAKE2B_G_VECTOR (ca, cb, v[1], v[6], v[11], v[12]);                        \
  BLAKE2B_G_VECTOR (cc, cd, v[2], v[7], v[ 8], v[13]);                        \
  BLAKE2B_G_VECTOR (ce, cf, v[3], v[4], v[ 9], v[14]);                        \
}

typedef struct blake2b_ctx
{
  u64 m[16]; // buffer
  u64 h[ 8]; // digest

  u32 len;

} blake2b_ctx_t;

typedef struct blake2b_ctx_vector
{
  u64x m[16]; // buffer
  u64x h[ 8]; // digest

  u32 len;

} blake2b_ctx_vector_t;

DECLSPEC void blake2b_transform (u64 *h, const u64 *m, const u32 len, const u64 f0);
DECLSPEC void blake2b_init (blake2b_ctx_t *ctx);
DECLSPEC void blake2b_update (blake2b_ctx_t *ctx, const u32 *w, const u32 len);
DECLSPEC void blake2b_update_global (blake2b_ctx_t *ctx, GLOBAL_AS const u32 *w, const u32 len);
DECLSPEC void blake2b_final (blake2b_ctx_t *ctx);

DECLSPEC void blake2b_transform_vector (u64x *h, const u64x *m, const u32x len, const u64 f0);
DECLSPEC void blake2b_init_vector (blake2b_ctx_vector_t *ctx);
DECLSPEC void blake2b_update_vector (blake2b_ctx_vector_t *ctx, const u32x *w, const u32 len);
DECLSPEC void blake2b_final_vector (blake2b_ctx_vector_t *ctx);

#endif // _INC_HASH_BLAKE2B_H
