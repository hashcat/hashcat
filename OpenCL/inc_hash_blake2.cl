/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_blake2.h"

DECLSPEC void blake2b_transform (u64x *h, u64x *t, u64x *f, u64x *m, u64x *v, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, const u32x out_len, const u8 isFinal)
{
  if (isFinal)
    f[0] = 0xFFFFFFFFFFFFFFFF;

  t[0] += hl32_to_64 (0, out_len);

  m[ 0] = hl32_to_64 (w0[1], w0[0]);
  m[ 1] = hl32_to_64 (w0[3], w0[2]);
  m[ 2] = hl32_to_64 (w1[1], w1[0]);
  m[ 3] = hl32_to_64 (w1[3], w1[2]);
  m[ 4] = hl32_to_64 (w2[1], w2[0]);
  m[ 5] = hl32_to_64 (w2[3], w2[2]);
  m[ 6] = hl32_to_64 (w3[1], w3[0]);
  m[ 7] = hl32_to_64 (w3[3], w3[2]);
  m[ 8] = 0;
  m[ 9] = 0;
  m[10] = 0;
  m[11] = 0;
  m[12] = 0;
  m[13] = 0;
  m[14] = 0;
  m[15] = 0;

  v[ 0] = h[0];
  v[ 1] = h[1];
  v[ 2] = h[2];
  v[ 3] = h[3];
  v[ 4] = h[4];
  v[ 5] = h[5];
  v[ 6] = h[6];
  v[ 7] = h[7];
  v[ 8] = BLAKE2B_IV_00;
  v[ 9] = BLAKE2B_IV_01;
  v[10] = BLAKE2B_IV_02;
  v[11] = BLAKE2B_IV_03;
  v[12] = BLAKE2B_IV_04 ^ t[0];
  v[13] = BLAKE2B_IV_05 ^ t[1];
  v[14] = BLAKE2B_IV_06 ^ f[0];
  v[15] = BLAKE2B_IV_07 ^ f[1];

  const int blake2b_sigma[12][16] =
  {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
  };

  BLAKE2B_ROUND ( 0);
  BLAKE2B_ROUND ( 1);
  BLAKE2B_ROUND ( 2);
  BLAKE2B_ROUND ( 3);
  BLAKE2B_ROUND ( 4);
  BLAKE2B_ROUND ( 5);
  BLAKE2B_ROUND ( 6);
  BLAKE2B_ROUND ( 7);
  BLAKE2B_ROUND ( 8);
  BLAKE2B_ROUND ( 9);
  BLAKE2B_ROUND (10);
  BLAKE2B_ROUND (11);

  h[0] = h[0] ^ v[0] ^ v[ 8];
  h[1] = h[1] ^ v[1] ^ v[ 9];
  h[2] = h[2] ^ v[2] ^ v[10];
  h[3] = h[3] ^ v[3] ^ v[11];
  h[4] = h[4] ^ v[4] ^ v[12];
  h[5] = h[5] ^ v[5] ^ v[13];
  h[6] = h[6] ^ v[6] ^ v[14];
  h[7] = h[7] ^ v[7] ^ v[15];
}
