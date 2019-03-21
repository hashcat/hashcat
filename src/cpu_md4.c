/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"

#define MD4_F(x,y,z)    (((x) & (y)) | ((~(x)) & (z)))
#define MD4_G(x,y,z)    (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x,y,z)    ((x) ^ (y) ^ (z))
#define MD4_Fo(x,y,z)   (MD4_F((x), (y), (z)))
#define MD4_Go(x,y,z)   (MD4_G((x), (y), (z)))

#define MD4_STEP_S(f,a,b,c,d,x,K,s)   \
{                                     \
  a += K;                             \
  a  = hc_add3_S (a, x, f (b, c, d)); \
  a  = rotl32_S (a, s);               \
}

#define MD4_STEP(f,a,b,c,d,x,K,s)     \
{                                     \
  a += K;                             \
  a  = hc_add3 (a, x, f (b, c, d));   \
  a  = rotl32 (a, s);                 \
}

#define MD4_STEP0(f,a,b,c,d,K,s)      \
{                                     \
  a  = hc_add3 (a, K, f (b, c, d));   \
  a  = rotl32 (a, s);                 \
}

void md4_64 (const u32 block[16], u32 digest[4])
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = block[ 0];
  w0[1] = block[ 1];
  w0[2] = block[ 2];
  w0[3] = block[ 3];
  w1[0] = block[ 4];
  w1[1] = block[ 5];
  w1[2] = block[ 6];
  w1[3] = block[ 7];
  w2[0] = block[ 8];
  w2[1] = block[ 9];
  w2[2] = block[10];
  w2[3] = block[11];
  w3[0] = block[12];
  w3[1] = block[13];
  w3[2] = block[14];
  w3[3] = block[15];

  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];

  MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
  MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
  MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
  MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
  MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
  MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
  MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
  MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
  MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
  MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
  MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
  MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
  MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
  MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
  MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
  MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

  MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
  MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
  MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
  MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
  MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
  MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
  MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
  MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
  MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
  MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
  MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
  MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
  MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
  MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
  MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
  MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

  MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
  MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
  MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
  MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
  MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
  MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
  MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
  MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
  MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
  MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
  MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
  MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
  MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);
  MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
  MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
  MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}
