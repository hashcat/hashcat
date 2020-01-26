/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_HASH_BLAKE2_H
#define _INC_HASH_BLAKE2_H

typedef struct blake2
{
  u64 h[8];
  u64 t[2];
  u64 f[2];
  u32 buflen;
  u32 outlen;

} blake2_t;

#define BLAKE2B_FINAL   1
#define BLAKE2B_UPDATE  0

#define BLAKE2B_G(r,i,a,b,c,d)                \
  do {                                        \
    a = a + b + m[blake2b_sigma[r][2*i+0]];   \
    d = hc_rotr64 (d ^ a, 32);                   \
    c = c + d;                                \
    b = hc_rotr64 (b ^ c, 24);                   \
    a = a + b + m[blake2b_sigma[r][2*i+1]];   \
    d = hc_rotr64 (d ^ a, 16);                   \
    c = c + d;                                \
    b = hc_rotr64 (b ^ c, 63);                   \
  } while(0)

#define BLAKE2B_ROUND(r)                     \
  do {                                       \
    BLAKE2B_G (r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    BLAKE2B_G (r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    BLAKE2B_G (r,2,v[ 2],v[ 6],v[10],v[14]); \
    BLAKE2B_G (r,3,v[ 3],v[ 7],v[11],v[15]); \
    BLAKE2B_G (r,4,v[ 0],v[ 5],v[10],v[15]); \
    BLAKE2B_G (r,5,v[ 1],v[ 6],v[11],v[12]); \
    BLAKE2B_G (r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    BLAKE2B_G (r,7,v[ 3],v[ 4],v[ 9],v[14]); \
} while(0)

DECLSPEC void blake2b_transform (u64x *h, u64x *t, u64x *f, u64x *m, u64x *v, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, const u32x out_len, const u8 isFinal);


#endif
