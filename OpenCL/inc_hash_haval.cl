/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_haval.h"

// The boolean functions from the reference paper, in the forms used by sphlib, with the input order
// for each pass of the variants with 3, 4 or 5 passes in total.

#define HAVAL_F1(x6,x5,x4,x3,x2,x1,x0) (((x1) & ((x0) ^ (x4))) ^ ((x2) & (x5)) ^ ((x3) & (x6)) ^ (x0))
#define HAVAL_F2(x6,x5,x4,x3,x2,x1,x0) (((x2) & (((x1) & ~(x3)) ^ ((x4) & (x5)) ^ (x6) ^ (x0))) ^ ((x4) & ((x1) ^ (x5))) ^ (((x3) & (x5)) ^ (x0)))
#define HAVAL_F3(x6,x5,x4,x3,x2,x1,x0) (((x3) & (((x1) & (x2)) ^ (x6) ^ (x0))) ^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ (x0))
#define HAVAL_F4(x6,x5,x4,x3,x2,x1,x0) (((x3) & (((x1) & (x2)) ^ ((x4) | (x6)) ^ (x5))) ^ ((x4) & ((~(x2) & (x5)) ^ (x1) ^ (x6) ^ (x0))) ^ ((x2) & (x6)) ^ (x0))
#define HAVAL_F5(x6,x5,x4,x3,x2,x1,x0) (((x0) & ~(((x1) & (x2) & (x3)) ^ (x5))) ^ ((x1) & (x4)) ^ ((x2) & (x5)) ^ ((x3) & (x6)))

#define HAVAL_FP3_1(x6,x5,x4,x3,x2,x1,x0) HAVAL_F1 (x1, x0, x3, x5, x6, x2, x4)
#define HAVAL_FP3_2(x6,x5,x4,x3,x2,x1,x0) HAVAL_F2 (x4, x2, x1, x0, x5, x3, x6)
#define HAVAL_FP3_3(x6,x5,x4,x3,x2,x1,x0) HAVAL_F3 (x6, x1, x2, x3, x4, x5, x0)

#define HAVAL_FP4_1(x6,x5,x4,x3,x2,x1,x0) HAVAL_F1 (x2, x6, x1, x4, x5, x3, x0)
#define HAVAL_FP4_2(x6,x5,x4,x3,x2,x1,x0) HAVAL_F2 (x3, x5, x2, x0, x1, x6, x4)
#define HAVAL_FP4_3(x6,x5,x4,x3,x2,x1,x0) HAVAL_F3 (x1, x4, x3, x6, x0, x2, x5)
#define HAVAL_FP4_4(x6,x5,x4,x3,x2,x1,x0) HAVAL_F4 (x6, x4, x0, x5, x2, x1, x3)

#define HAVAL_FP5_1(x6,x5,x4,x3,x2,x1,x0) HAVAL_F1 (x3, x4, x1, x0, x5, x2, x6)
#define HAVAL_FP5_2(x6,x5,x4,x3,x2,x1,x0) HAVAL_F2 (x6, x2, x1, x0, x3, x4, x5)
#define HAVAL_FP5_3(x6,x5,x4,x3,x2,x1,x0) HAVAL_F3 (x2, x6, x0, x4, x3, x1, x5)
#define HAVAL_FP5_4(x6,x5,x4,x3,x2,x1,x0) HAVAL_F4 (x1, x5, x3, x2, x0, x4, x6)
#define HAVAL_FP5_5(x6,x5,x4,x3,x2,x1,x0) HAVAL_F5 (x2, x5, x0, x6, x4, x3, x1)

// One step: the input word w, the constant c and state registers named for their
// positions in this step.

#define HAVAL_STEP_S(FP,x7,x6,x5,x4,x3,x2,x1,x0,w,c)                  \
{                                                                     \
  const u32 t = FP ((x6), (x5), (x4), (x3), (x2), (x1), (x0));        \
                                                                      \
  (x7) = hc_rotr32_S (t, 7) + hc_rotr32_S ((x7), 11) + (w) + (c);     \
}

#define HAVAL_STEP(FP,x7,x6,x5,x4,x3,x2,x1,x0,w,c)                    \
{                                                                     \
  const u32x t = FP ((x6), (x5), (x4), (x3), (x2), (x1), (x0));       \
                                                                      \
  (x7) = hc_rotr32 (t, 7) + hc_rotr32 ((x7), 11) + (w) + (c);         \
}

DECLSPEC void haval_transform3 (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w)
{
  u32 s0 = h[0];
  u32 s1 = h[1];
  u32 s2 = h[2];
  u32 s3 = h[3];
  u32 s4 = h[4];
  u32 s5 = h[5];
  u32 s6 = h[6];
  u32 s7 = h[7];

  // pass 1

  HAVAL_STEP_S (HAVAL_FP3_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 1], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s5, s4, s3, s2, s1, s0, s7, s6, w[ 2], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s3, s2, s1, s0, s7, s6, s5, s4, w[ 4], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s2, s1, s0, s7, s6, s5, s4, s3, w[ 5], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s1, s0, s7, s6, s5, s4, s3, s2, w[ 6], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s0, s7, s6, s5, s4, s3, s2, s1, w[ 7], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 8], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s5, s4, s3, s2, s1, s0, s7, s6, w[10], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s4, s3, s2, s1, s0, s7, s6, s5, w[11], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s3, s2, s1, s0, s7, s6, s5, s4, w[12], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s2, s1, s0, s7, s6, s5, s4, s3, w[13], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s1, s0, s7, s6, s5, s4, s3, s2, w[14], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s0, s7, s6, s5, s4, s3, s2, s1, w[15], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s7, s6, s5, s4, s3, s2, s1, s0, w[16], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s6, s5, s4, s3, s2, s1, s0, s7, w[17], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s5, s4, s3, s2, s1, s0, s7, s6, w[18], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s4, s3, s2, s1, s0, s7, s6, s5, w[19], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s3, s2, s1, s0, s7, s6, s5, s4, w[20], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s2, s1, s0, s7, s6, s5, s4, s3, w[21], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s1, s0, s7, s6, s5, s4, s3, s2, w[22], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s6, s5, s4, s3, s2, s1, s0, s7, w[25], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s4, s3, s2, s1, s0, s7, s6, s5, w[27], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s2, s1, s0, s7, s6, s5, s4, s3, w[29], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s1, s0, s7, s6, s5, s4, s3, s2, w[30], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP3_1, s0, s7, s6, s5, s4, s3, s2, s1, w[31], 0x00000000);

  // pass 2

  HAVAL_STEP_S (HAVAL_FP3_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 5], 0x452821e6);
  HAVAL_STEP_S (HAVAL_FP3_2, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0x38d01377);
  HAVAL_STEP_S (HAVAL_FP3_2, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0xbe5466cf);
  HAVAL_STEP_S (HAVAL_FP3_2, s4, s3, s2, s1, s0, s7, s6, s5, w[18], 0x34e90c6c);
  HAVAL_STEP_S (HAVAL_FP3_2, s3, s2, s1, s0, s7, s6, s5, s4, w[11], 0xc0ac29b7);
  HAVAL_STEP_S (HAVAL_FP3_2, s2, s1, s0, s7, s6, s5, s4, s3, w[28], 0xc97c50dd);
  HAVAL_STEP_S (HAVAL_FP3_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 7], 0x3f84d5b5);
  HAVAL_STEP_S (HAVAL_FP3_2, s0, s7, s6, s5, s4, s3, s2, s1, w[16], 0xb5470917);
  HAVAL_STEP_S (HAVAL_FP3_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x9216d5d9);
  HAVAL_STEP_S (HAVAL_FP3_2, s6, s5, s4, s3, s2, s1, s0, s7, w[23], 0x8979fb1b);
  HAVAL_STEP_S (HAVAL_FP3_2, s5, s4, s3, s2, s1, s0, s7, s6, w[20], 0xd1310ba6);
  HAVAL_STEP_S (HAVAL_FP3_2, s4, s3, s2, s1, s0, s7, s6, s5, w[22], 0x98dfb5ac);
  HAVAL_STEP_S (HAVAL_FP3_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0x2ffd72db);
  HAVAL_STEP_S (HAVAL_FP3_2, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xd01adfb7);
  HAVAL_STEP_S (HAVAL_FP3_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 4], 0xb8e1afed);
  HAVAL_STEP_S (HAVAL_FP3_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 8], 0x6a267e96);
  HAVAL_STEP_S (HAVAL_FP3_2, s7, s6, s5, s4, s3, s2, s1, s0, w[30], 0xba7c9045);
  HAVAL_STEP_S (HAVAL_FP3_2, s6, s5, s4, s3, s2, s1, s0, s7, w[ 3], 0xf12c7f99);
  HAVAL_STEP_S (HAVAL_FP3_2, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x24a19947);
  HAVAL_STEP_S (HAVAL_FP3_2, s4, s3, s2, s1, s0, s7, s6, s5, w[ 9], 0xb3916cf7);
  HAVAL_STEP_S (HAVAL_FP3_2, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x0801f2e2);
  HAVAL_STEP_S (HAVAL_FP3_2, s2, s1, s0, s7, s6, s5, s4, s3, w[24], 0x858efc16);
  HAVAL_STEP_S (HAVAL_FP3_2, s1, s0, s7, s6, s5, s4, s3, s2, w[29], 0x636920d8);
  HAVAL_STEP_S (HAVAL_FP3_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 6], 0x71574e69);
  HAVAL_STEP_S (HAVAL_FP3_2, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0xa458fea3);
  HAVAL_STEP_S (HAVAL_FP3_2, s6, s5, s4, s3, s2, s1, s0, s7, w[12], 0xf4933d7e);
  HAVAL_STEP_S (HAVAL_FP3_2, s5, s4, s3, s2, s1, s0, s7, s6, w[15], 0x0d95748f);
  HAVAL_STEP_S (HAVAL_FP3_2, s4, s3, s2, s1, s0, s7, s6, s5, w[13], 0x728eb658);
  HAVAL_STEP_S (HAVAL_FP3_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0x718bcd58);
  HAVAL_STEP_S (HAVAL_FP3_2, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0x82154aee);
  HAVAL_STEP_S (HAVAL_FP3_2, s1, s0, s7, s6, s5, s4, s3, s2, w[31], 0x7b54a41d);
  HAVAL_STEP_S (HAVAL_FP3_2, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0xc25a59b5);

  // pass 3

  HAVAL_STEP_S (HAVAL_FP3_3, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0x9c30d539);
  HAVAL_STEP_S (HAVAL_FP3_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x2af26013);
  HAVAL_STEP_S (HAVAL_FP3_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 4], 0xc5d1b023);
  HAVAL_STEP_S (HAVAL_FP3_3, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0x286085f0);
  HAVAL_STEP_S (HAVAL_FP3_3, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0xca417918);
  HAVAL_STEP_S (HAVAL_FP3_3, s2, s1, s0, s7, s6, s5, s4, s3, w[17], 0xb8db38ef);
  HAVAL_STEP_S (HAVAL_FP3_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 8], 0x8e79dcb0);
  HAVAL_STEP_S (HAVAL_FP3_3, s0, s7, s6, s5, s4, s3, s2, s1, w[22], 0x603a180e);
  HAVAL_STEP_S (HAVAL_FP3_3, s7, s6, s5, s4, s3, s2, s1, s0, w[29], 0x6c9e0e8b);
  HAVAL_STEP_S (HAVAL_FP3_3, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0xb01e8a3e);
  HAVAL_STEP_S (HAVAL_FP3_3, s5, s4, s3, s2, s1, s0, s7, s6, w[25], 0xd71577c1);
  HAVAL_STEP_S (HAVAL_FP3_3, s4, s3, s2, s1, s0, s7, s6, s5, w[12], 0xbd314b27);
  HAVAL_STEP_S (HAVAL_FP3_3, s3, s2, s1, s0, s7, s6, s5, s4, w[24], 0x78af2fda);
  HAVAL_STEP_S (HAVAL_FP3_3, s2, s1, s0, s7, s6, s5, s4, s3, w[30], 0x55605c60);
  HAVAL_STEP_S (HAVAL_FP3_3, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0xe65525f3);
  HAVAL_STEP_S (HAVAL_FP3_3, s0, s7, s6, s5, s4, s3, s2, s1, w[26], 0xaa55ab94);
  HAVAL_STEP_S (HAVAL_FP3_3, s7, s6, s5, s4, s3, s2, s1, s0, w[31], 0x57489862);
  HAVAL_STEP_S (HAVAL_FP3_3, s6, s5, s4, s3, s2, s1, s0, s7, w[15], 0x63e81440);
  HAVAL_STEP_S (HAVAL_FP3_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 7], 0x55ca396a);
  HAVAL_STEP_S (HAVAL_FP3_3, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x2aab10b6);
  HAVAL_STEP_S (HAVAL_FP3_3, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0xb4cc5c34);
  HAVAL_STEP_S (HAVAL_FP3_3, s2, s1, s0, s7, s6, s5, s4, s3, w[ 0], 0x1141e8ce);
  HAVAL_STEP_S (HAVAL_FP3_3, s1, s0, s7, s6, s5, s4, s3, s2, w[18], 0xa15486af);
  HAVAL_STEP_S (HAVAL_FP3_3, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0x7c72e993);
  HAVAL_STEP_S (HAVAL_FP3_3, s7, s6, s5, s4, s3, s2, s1, s0, w[13], 0xb3ee1411);
  HAVAL_STEP_S (HAVAL_FP3_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x636fbc2a);
  HAVAL_STEP_S (HAVAL_FP3_3, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x2ba9c55d);
  HAVAL_STEP_S (HAVAL_FP3_3, s4, s3, s2, s1, s0, s7, s6, s5, w[10], 0x741831f6);
  HAVAL_STEP_S (HAVAL_FP3_3, s3, s2, s1, s0, s7, s6, s5, s4, w[23], 0xce5c3e16);
  HAVAL_STEP_S (HAVAL_FP3_3, s2, s1, s0, s7, s6, s5, s4, s3, w[11], 0x9b87931e);
  HAVAL_STEP_S (HAVAL_FP3_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 5], 0xafd6ba33);
  HAVAL_STEP_S (HAVAL_FP3_3, s0, s7, s6, s5, s4, s3, s2, s1, w[ 2], 0x6c24cf5c);

  h[0] += s0;
  h[1] += s1;
  h[2] += s2;
  h[3] += s3;
  h[4] += s4;
  h[5] += s5;
  h[6] += s6;
  h[7] += s7;
}

DECLSPEC void haval_transform4 (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w)
{
  u32 s0 = h[0];
  u32 s1 = h[1];
  u32 s2 = h[2];
  u32 s3 = h[3];
  u32 s4 = h[4];
  u32 s5 = h[5];
  u32 s6 = h[6];
  u32 s7 = h[7];

  // pass 1

  HAVAL_STEP_S (HAVAL_FP4_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 1], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s5, s4, s3, s2, s1, s0, s7, s6, w[ 2], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s3, s2, s1, s0, s7, s6, s5, s4, w[ 4], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s2, s1, s0, s7, s6, s5, s4, s3, w[ 5], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s1, s0, s7, s6, s5, s4, s3, s2, w[ 6], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s0, s7, s6, s5, s4, s3, s2, s1, w[ 7], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 8], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s5, s4, s3, s2, s1, s0, s7, s6, w[10], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s4, s3, s2, s1, s0, s7, s6, s5, w[11], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s3, s2, s1, s0, s7, s6, s5, s4, w[12], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s2, s1, s0, s7, s6, s5, s4, s3, w[13], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s1, s0, s7, s6, s5, s4, s3, s2, w[14], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s0, s7, s6, s5, s4, s3, s2, s1, w[15], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s7, s6, s5, s4, s3, s2, s1, s0, w[16], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s6, s5, s4, s3, s2, s1, s0, s7, w[17], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s5, s4, s3, s2, s1, s0, s7, s6, w[18], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s4, s3, s2, s1, s0, s7, s6, s5, w[19], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s3, s2, s1, s0, s7, s6, s5, s4, w[20], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s2, s1, s0, s7, s6, s5, s4, s3, w[21], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s1, s0, s7, s6, s5, s4, s3, s2, w[22], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s6, s5, s4, s3, s2, s1, s0, s7, w[25], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s4, s3, s2, s1, s0, s7, s6, s5, w[27], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s2, s1, s0, s7, s6, s5, s4, s3, w[29], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s1, s0, s7, s6, s5, s4, s3, s2, w[30], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP4_1, s0, s7, s6, s5, s4, s3, s2, s1, w[31], 0x00000000);

  // pass 2

  HAVAL_STEP_S (HAVAL_FP4_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 5], 0x452821e6);
  HAVAL_STEP_S (HAVAL_FP4_2, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0x38d01377);
  HAVAL_STEP_S (HAVAL_FP4_2, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0xbe5466cf);
  HAVAL_STEP_S (HAVAL_FP4_2, s4, s3, s2, s1, s0, s7, s6, s5, w[18], 0x34e90c6c);
  HAVAL_STEP_S (HAVAL_FP4_2, s3, s2, s1, s0, s7, s6, s5, s4, w[11], 0xc0ac29b7);
  HAVAL_STEP_S (HAVAL_FP4_2, s2, s1, s0, s7, s6, s5, s4, s3, w[28], 0xc97c50dd);
  HAVAL_STEP_S (HAVAL_FP4_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 7], 0x3f84d5b5);
  HAVAL_STEP_S (HAVAL_FP4_2, s0, s7, s6, s5, s4, s3, s2, s1, w[16], 0xb5470917);
  HAVAL_STEP_S (HAVAL_FP4_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x9216d5d9);
  HAVAL_STEP_S (HAVAL_FP4_2, s6, s5, s4, s3, s2, s1, s0, s7, w[23], 0x8979fb1b);
  HAVAL_STEP_S (HAVAL_FP4_2, s5, s4, s3, s2, s1, s0, s7, s6, w[20], 0xd1310ba6);
  HAVAL_STEP_S (HAVAL_FP4_2, s4, s3, s2, s1, s0, s7, s6, s5, w[22], 0x98dfb5ac);
  HAVAL_STEP_S (HAVAL_FP4_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0x2ffd72db);
  HAVAL_STEP_S (HAVAL_FP4_2, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xd01adfb7);
  HAVAL_STEP_S (HAVAL_FP4_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 4], 0xb8e1afed);
  HAVAL_STEP_S (HAVAL_FP4_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 8], 0x6a267e96);
  HAVAL_STEP_S (HAVAL_FP4_2, s7, s6, s5, s4, s3, s2, s1, s0, w[30], 0xba7c9045);
  HAVAL_STEP_S (HAVAL_FP4_2, s6, s5, s4, s3, s2, s1, s0, s7, w[ 3], 0xf12c7f99);
  HAVAL_STEP_S (HAVAL_FP4_2, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x24a19947);
  HAVAL_STEP_S (HAVAL_FP4_2, s4, s3, s2, s1, s0, s7, s6, s5, w[ 9], 0xb3916cf7);
  HAVAL_STEP_S (HAVAL_FP4_2, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x0801f2e2);
  HAVAL_STEP_S (HAVAL_FP4_2, s2, s1, s0, s7, s6, s5, s4, s3, w[24], 0x858efc16);
  HAVAL_STEP_S (HAVAL_FP4_2, s1, s0, s7, s6, s5, s4, s3, s2, w[29], 0x636920d8);
  HAVAL_STEP_S (HAVAL_FP4_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 6], 0x71574e69);
  HAVAL_STEP_S (HAVAL_FP4_2, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0xa458fea3);
  HAVAL_STEP_S (HAVAL_FP4_2, s6, s5, s4, s3, s2, s1, s0, s7, w[12], 0xf4933d7e);
  HAVAL_STEP_S (HAVAL_FP4_2, s5, s4, s3, s2, s1, s0, s7, s6, w[15], 0x0d95748f);
  HAVAL_STEP_S (HAVAL_FP4_2, s4, s3, s2, s1, s0, s7, s6, s5, w[13], 0x728eb658);
  HAVAL_STEP_S (HAVAL_FP4_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0x718bcd58);
  HAVAL_STEP_S (HAVAL_FP4_2, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0x82154aee);
  HAVAL_STEP_S (HAVAL_FP4_2, s1, s0, s7, s6, s5, s4, s3, s2, w[31], 0x7b54a41d);
  HAVAL_STEP_S (HAVAL_FP4_2, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0xc25a59b5);

  // pass 3

  HAVAL_STEP_S (HAVAL_FP4_3, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0x9c30d539);
  HAVAL_STEP_S (HAVAL_FP4_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x2af26013);
  HAVAL_STEP_S (HAVAL_FP4_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 4], 0xc5d1b023);
  HAVAL_STEP_S (HAVAL_FP4_3, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0x286085f0);
  HAVAL_STEP_S (HAVAL_FP4_3, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0xca417918);
  HAVAL_STEP_S (HAVAL_FP4_3, s2, s1, s0, s7, s6, s5, s4, s3, w[17], 0xb8db38ef);
  HAVAL_STEP_S (HAVAL_FP4_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 8], 0x8e79dcb0);
  HAVAL_STEP_S (HAVAL_FP4_3, s0, s7, s6, s5, s4, s3, s2, s1, w[22], 0x603a180e);
  HAVAL_STEP_S (HAVAL_FP4_3, s7, s6, s5, s4, s3, s2, s1, s0, w[29], 0x6c9e0e8b);
  HAVAL_STEP_S (HAVAL_FP4_3, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0xb01e8a3e);
  HAVAL_STEP_S (HAVAL_FP4_3, s5, s4, s3, s2, s1, s0, s7, s6, w[25], 0xd71577c1);
  HAVAL_STEP_S (HAVAL_FP4_3, s4, s3, s2, s1, s0, s7, s6, s5, w[12], 0xbd314b27);
  HAVAL_STEP_S (HAVAL_FP4_3, s3, s2, s1, s0, s7, s6, s5, s4, w[24], 0x78af2fda);
  HAVAL_STEP_S (HAVAL_FP4_3, s2, s1, s0, s7, s6, s5, s4, s3, w[30], 0x55605c60);
  HAVAL_STEP_S (HAVAL_FP4_3, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0xe65525f3);
  HAVAL_STEP_S (HAVAL_FP4_3, s0, s7, s6, s5, s4, s3, s2, s1, w[26], 0xaa55ab94);
  HAVAL_STEP_S (HAVAL_FP4_3, s7, s6, s5, s4, s3, s2, s1, s0, w[31], 0x57489862);
  HAVAL_STEP_S (HAVAL_FP4_3, s6, s5, s4, s3, s2, s1, s0, s7, w[15], 0x63e81440);
  HAVAL_STEP_S (HAVAL_FP4_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 7], 0x55ca396a);
  HAVAL_STEP_S (HAVAL_FP4_3, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x2aab10b6);
  HAVAL_STEP_S (HAVAL_FP4_3, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0xb4cc5c34);
  HAVAL_STEP_S (HAVAL_FP4_3, s2, s1, s0, s7, s6, s5, s4, s3, w[ 0], 0x1141e8ce);
  HAVAL_STEP_S (HAVAL_FP4_3, s1, s0, s7, s6, s5, s4, s3, s2, w[18], 0xa15486af);
  HAVAL_STEP_S (HAVAL_FP4_3, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0x7c72e993);
  HAVAL_STEP_S (HAVAL_FP4_3, s7, s6, s5, s4, s3, s2, s1, s0, w[13], 0xb3ee1411);
  HAVAL_STEP_S (HAVAL_FP4_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x636fbc2a);
  HAVAL_STEP_S (HAVAL_FP4_3, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x2ba9c55d);
  HAVAL_STEP_S (HAVAL_FP4_3, s4, s3, s2, s1, s0, s7, s6, s5, w[10], 0x741831f6);
  HAVAL_STEP_S (HAVAL_FP4_3, s3, s2, s1, s0, s7, s6, s5, s4, w[23], 0xce5c3e16);
  HAVAL_STEP_S (HAVAL_FP4_3, s2, s1, s0, s7, s6, s5, s4, s3, w[11], 0x9b87931e);
  HAVAL_STEP_S (HAVAL_FP4_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 5], 0xafd6ba33);
  HAVAL_STEP_S (HAVAL_FP4_3, s0, s7, s6, s5, s4, s3, s2, s1, w[ 2], 0x6c24cf5c);

  // pass 4

  HAVAL_STEP_S (HAVAL_FP4_4, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x7a325381);
  HAVAL_STEP_S (HAVAL_FP4_4, s6, s5, s4, s3, s2, s1, s0, s7, w[ 4], 0x28958677);
  HAVAL_STEP_S (HAVAL_FP4_4, s5, s4, s3, s2, s1, s0, s7, s6, w[ 0], 0x3b8f4898);
  HAVAL_STEP_S (HAVAL_FP4_4, s4, s3, s2, s1, s0, s7, s6, s5, w[14], 0x6b4bb9af);
  HAVAL_STEP_S (HAVAL_FP4_4, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0xc4bfe81b);
  HAVAL_STEP_S (HAVAL_FP4_4, s2, s1, s0, s7, s6, s5, s4, s3, w[ 7], 0x66282193);
  HAVAL_STEP_S (HAVAL_FP4_4, s1, s0, s7, s6, s5, s4, s3, s2, w[28], 0x61d809cc);
  HAVAL_STEP_S (HAVAL_FP4_4, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0xfb21a991);
  HAVAL_STEP_S (HAVAL_FP4_4, s7, s6, s5, s4, s3, s2, s1, s0, w[26], 0x487cac60);
  HAVAL_STEP_S (HAVAL_FP4_4, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x5dec8032);
  HAVAL_STEP_S (HAVAL_FP4_4, s5, s4, s3, s2, s1, s0, s7, s6, w[30], 0xef845d5d);
  HAVAL_STEP_S (HAVAL_FP4_4, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0xe98575b1);
  HAVAL_STEP_S (HAVAL_FP4_4, s3, s2, s1, s0, s7, s6, s5, s4, w[18], 0xdc262302);
  HAVAL_STEP_S (HAVAL_FP4_4, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0xeb651b88);
  HAVAL_STEP_S (HAVAL_FP4_4, s1, s0, s7, s6, s5, s4, s3, s2, w[19], 0x23893e81);
  HAVAL_STEP_S (HAVAL_FP4_4, s0, s7, s6, s5, s4, s3, s2, s1, w[ 3], 0xd396acc5);
  HAVAL_STEP_S (HAVAL_FP4_4, s7, s6, s5, s4, s3, s2, s1, s0, w[22], 0x0f6d6ff3);
  HAVAL_STEP_S (HAVAL_FP4_4, s6, s5, s4, s3, s2, s1, s0, s7, w[11], 0x83f44239);
  HAVAL_STEP_S (HAVAL_FP4_4, s5, s4, s3, s2, s1, s0, s7, s6, w[31], 0x2e0b4482);
  HAVAL_STEP_S (HAVAL_FP4_4, s4, s3, s2, s1, s0, s7, s6, s5, w[21], 0xa4842004);
  HAVAL_STEP_S (HAVAL_FP4_4, s3, s2, s1, s0, s7, s6, s5, s4, w[ 8], 0x69c8f04a);
  HAVAL_STEP_S (HAVAL_FP4_4, s2, s1, s0, s7, s6, s5, s4, s3, w[27], 0x9e1f9b5e);
  HAVAL_STEP_S (HAVAL_FP4_4, s1, s0, s7, s6, s5, s4, s3, s2, w[12], 0x21c66842);
  HAVAL_STEP_S (HAVAL_FP4_4, s0, s7, s6, s5, s4, s3, s2, s1, w[ 9], 0xf6e96c9a);
  HAVAL_STEP_S (HAVAL_FP4_4, s7, s6, s5, s4, s3, s2, s1, s0, w[ 1], 0x670c9c61);
  HAVAL_STEP_S (HAVAL_FP4_4, s6, s5, s4, s3, s2, s1, s0, s7, w[29], 0xabd388f0);
  HAVAL_STEP_S (HAVAL_FP4_4, s5, s4, s3, s2, s1, s0, s7, s6, w[ 5], 0x6a51a0d2);
  HAVAL_STEP_S (HAVAL_FP4_4, s4, s3, s2, s1, s0, s7, s6, s5, w[15], 0xd8542f68);
  HAVAL_STEP_S (HAVAL_FP4_4, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x960fa728);
  HAVAL_STEP_S (HAVAL_FP4_4, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xab5133a3);
  HAVAL_STEP_S (HAVAL_FP4_4, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0x6eef0b6c);
  HAVAL_STEP_S (HAVAL_FP4_4, s0, s7, s6, s5, s4, s3, s2, s1, w[13], 0x137a3be4);

  h[0] += s0;
  h[1] += s1;
  h[2] += s2;
  h[3] += s3;
  h[4] += s4;
  h[5] += s5;
  h[6] += s6;
  h[7] += s7;
}

DECLSPEC void haval_transform5 (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w)
{
  u32 s0 = h[0];
  u32 s1 = h[1];
  u32 s2 = h[2];
  u32 s3 = h[3];
  u32 s4 = h[4];
  u32 s5 = h[5];
  u32 s6 = h[6];
  u32 s7 = h[7];

  // pass 1

  HAVAL_STEP_S (HAVAL_FP5_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 1], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s5, s4, s3, s2, s1, s0, s7, s6, w[ 2], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s3, s2, s1, s0, s7, s6, s5, s4, w[ 4], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s2, s1, s0, s7, s6, s5, s4, s3, w[ 5], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s1, s0, s7, s6, s5, s4, s3, s2, w[ 6], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s0, s7, s6, s5, s4, s3, s2, s1, w[ 7], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 8], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s5, s4, s3, s2, s1, s0, s7, s6, w[10], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s4, s3, s2, s1, s0, s7, s6, s5, w[11], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s3, s2, s1, s0, s7, s6, s5, s4, w[12], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s2, s1, s0, s7, s6, s5, s4, s3, w[13], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s1, s0, s7, s6, s5, s4, s3, s2, w[14], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s0, s7, s6, s5, s4, s3, s2, s1, w[15], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s7, s6, s5, s4, s3, s2, s1, s0, w[16], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s6, s5, s4, s3, s2, s1, s0, s7, w[17], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s5, s4, s3, s2, s1, s0, s7, s6, w[18], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s4, s3, s2, s1, s0, s7, s6, s5, w[19], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s3, s2, s1, s0, s7, s6, s5, s4, w[20], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s2, s1, s0, s7, s6, s5, s4, s3, w[21], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s1, s0, s7, s6, s5, s4, s3, s2, w[22], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s6, s5, s4, s3, s2, s1, s0, s7, w[25], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s4, s3, s2, s1, s0, s7, s6, s5, w[27], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s2, s1, s0, s7, s6, s5, s4, s3, w[29], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s1, s0, s7, s6, s5, s4, s3, s2, w[30], 0x00000000);
  HAVAL_STEP_S (HAVAL_FP5_1, s0, s7, s6, s5, s4, s3, s2, s1, w[31], 0x00000000);

  // pass 2

  HAVAL_STEP_S (HAVAL_FP5_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 5], 0x452821e6);
  HAVAL_STEP_S (HAVAL_FP5_2, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0x38d01377);
  HAVAL_STEP_S (HAVAL_FP5_2, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0xbe5466cf);
  HAVAL_STEP_S (HAVAL_FP5_2, s4, s3, s2, s1, s0, s7, s6, s5, w[18], 0x34e90c6c);
  HAVAL_STEP_S (HAVAL_FP5_2, s3, s2, s1, s0, s7, s6, s5, s4, w[11], 0xc0ac29b7);
  HAVAL_STEP_S (HAVAL_FP5_2, s2, s1, s0, s7, s6, s5, s4, s3, w[28], 0xc97c50dd);
  HAVAL_STEP_S (HAVAL_FP5_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 7], 0x3f84d5b5);
  HAVAL_STEP_S (HAVAL_FP5_2, s0, s7, s6, s5, s4, s3, s2, s1, w[16], 0xb5470917);
  HAVAL_STEP_S (HAVAL_FP5_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x9216d5d9);
  HAVAL_STEP_S (HAVAL_FP5_2, s6, s5, s4, s3, s2, s1, s0, s7, w[23], 0x8979fb1b);
  HAVAL_STEP_S (HAVAL_FP5_2, s5, s4, s3, s2, s1, s0, s7, s6, w[20], 0xd1310ba6);
  HAVAL_STEP_S (HAVAL_FP5_2, s4, s3, s2, s1, s0, s7, s6, s5, w[22], 0x98dfb5ac);
  HAVAL_STEP_S (HAVAL_FP5_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0x2ffd72db);
  HAVAL_STEP_S (HAVAL_FP5_2, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xd01adfb7);
  HAVAL_STEP_S (HAVAL_FP5_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 4], 0xb8e1afed);
  HAVAL_STEP_S (HAVAL_FP5_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 8], 0x6a267e96);
  HAVAL_STEP_S (HAVAL_FP5_2, s7, s6, s5, s4, s3, s2, s1, s0, w[30], 0xba7c9045);
  HAVAL_STEP_S (HAVAL_FP5_2, s6, s5, s4, s3, s2, s1, s0, s7, w[ 3], 0xf12c7f99);
  HAVAL_STEP_S (HAVAL_FP5_2, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x24a19947);
  HAVAL_STEP_S (HAVAL_FP5_2, s4, s3, s2, s1, s0, s7, s6, s5, w[ 9], 0xb3916cf7);
  HAVAL_STEP_S (HAVAL_FP5_2, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x0801f2e2);
  HAVAL_STEP_S (HAVAL_FP5_2, s2, s1, s0, s7, s6, s5, s4, s3, w[24], 0x858efc16);
  HAVAL_STEP_S (HAVAL_FP5_2, s1, s0, s7, s6, s5, s4, s3, s2, w[29], 0x636920d8);
  HAVAL_STEP_S (HAVAL_FP5_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 6], 0x71574e69);
  HAVAL_STEP_S (HAVAL_FP5_2, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0xa458fea3);
  HAVAL_STEP_S (HAVAL_FP5_2, s6, s5, s4, s3, s2, s1, s0, s7, w[12], 0xf4933d7e);
  HAVAL_STEP_S (HAVAL_FP5_2, s5, s4, s3, s2, s1, s0, s7, s6, w[15], 0x0d95748f);
  HAVAL_STEP_S (HAVAL_FP5_2, s4, s3, s2, s1, s0, s7, s6, s5, w[13], 0x728eb658);
  HAVAL_STEP_S (HAVAL_FP5_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0x718bcd58);
  HAVAL_STEP_S (HAVAL_FP5_2, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0x82154aee);
  HAVAL_STEP_S (HAVAL_FP5_2, s1, s0, s7, s6, s5, s4, s3, s2, w[31], 0x7b54a41d);
  HAVAL_STEP_S (HAVAL_FP5_2, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0xc25a59b5);

  // pass 3

  HAVAL_STEP_S (HAVAL_FP5_3, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0x9c30d539);
  HAVAL_STEP_S (HAVAL_FP5_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x2af26013);
  HAVAL_STEP_S (HAVAL_FP5_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 4], 0xc5d1b023);
  HAVAL_STEP_S (HAVAL_FP5_3, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0x286085f0);
  HAVAL_STEP_S (HAVAL_FP5_3, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0xca417918);
  HAVAL_STEP_S (HAVAL_FP5_3, s2, s1, s0, s7, s6, s5, s4, s3, w[17], 0xb8db38ef);
  HAVAL_STEP_S (HAVAL_FP5_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 8], 0x8e79dcb0);
  HAVAL_STEP_S (HAVAL_FP5_3, s0, s7, s6, s5, s4, s3, s2, s1, w[22], 0x603a180e);
  HAVAL_STEP_S (HAVAL_FP5_3, s7, s6, s5, s4, s3, s2, s1, s0, w[29], 0x6c9e0e8b);
  HAVAL_STEP_S (HAVAL_FP5_3, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0xb01e8a3e);
  HAVAL_STEP_S (HAVAL_FP5_3, s5, s4, s3, s2, s1, s0, s7, s6, w[25], 0xd71577c1);
  HAVAL_STEP_S (HAVAL_FP5_3, s4, s3, s2, s1, s0, s7, s6, s5, w[12], 0xbd314b27);
  HAVAL_STEP_S (HAVAL_FP5_3, s3, s2, s1, s0, s7, s6, s5, s4, w[24], 0x78af2fda);
  HAVAL_STEP_S (HAVAL_FP5_3, s2, s1, s0, s7, s6, s5, s4, s3, w[30], 0x55605c60);
  HAVAL_STEP_S (HAVAL_FP5_3, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0xe65525f3);
  HAVAL_STEP_S (HAVAL_FP5_3, s0, s7, s6, s5, s4, s3, s2, s1, w[26], 0xaa55ab94);
  HAVAL_STEP_S (HAVAL_FP5_3, s7, s6, s5, s4, s3, s2, s1, s0, w[31], 0x57489862);
  HAVAL_STEP_S (HAVAL_FP5_3, s6, s5, s4, s3, s2, s1, s0, s7, w[15], 0x63e81440);
  HAVAL_STEP_S (HAVAL_FP5_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 7], 0x55ca396a);
  HAVAL_STEP_S (HAVAL_FP5_3, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x2aab10b6);
  HAVAL_STEP_S (HAVAL_FP5_3, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0xb4cc5c34);
  HAVAL_STEP_S (HAVAL_FP5_3, s2, s1, s0, s7, s6, s5, s4, s3, w[ 0], 0x1141e8ce);
  HAVAL_STEP_S (HAVAL_FP5_3, s1, s0, s7, s6, s5, s4, s3, s2, w[18], 0xa15486af);
  HAVAL_STEP_S (HAVAL_FP5_3, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0x7c72e993);
  HAVAL_STEP_S (HAVAL_FP5_3, s7, s6, s5, s4, s3, s2, s1, s0, w[13], 0xb3ee1411);
  HAVAL_STEP_S (HAVAL_FP5_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x636fbc2a);
  HAVAL_STEP_S (HAVAL_FP5_3, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x2ba9c55d);
  HAVAL_STEP_S (HAVAL_FP5_3, s4, s3, s2, s1, s0, s7, s6, s5, w[10], 0x741831f6);
  HAVAL_STEP_S (HAVAL_FP5_3, s3, s2, s1, s0, s7, s6, s5, s4, w[23], 0xce5c3e16);
  HAVAL_STEP_S (HAVAL_FP5_3, s2, s1, s0, s7, s6, s5, s4, s3, w[11], 0x9b87931e);
  HAVAL_STEP_S (HAVAL_FP5_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 5], 0xafd6ba33);
  HAVAL_STEP_S (HAVAL_FP5_3, s0, s7, s6, s5, s4, s3, s2, s1, w[ 2], 0x6c24cf5c);

  // pass 4

  HAVAL_STEP_S (HAVAL_FP5_4, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x7a325381);
  HAVAL_STEP_S (HAVAL_FP5_4, s6, s5, s4, s3, s2, s1, s0, s7, w[ 4], 0x28958677);
  HAVAL_STEP_S (HAVAL_FP5_4, s5, s4, s3, s2, s1, s0, s7, s6, w[ 0], 0x3b8f4898);
  HAVAL_STEP_S (HAVAL_FP5_4, s4, s3, s2, s1, s0, s7, s6, s5, w[14], 0x6b4bb9af);
  HAVAL_STEP_S (HAVAL_FP5_4, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0xc4bfe81b);
  HAVAL_STEP_S (HAVAL_FP5_4, s2, s1, s0, s7, s6, s5, s4, s3, w[ 7], 0x66282193);
  HAVAL_STEP_S (HAVAL_FP5_4, s1, s0, s7, s6, s5, s4, s3, s2, w[28], 0x61d809cc);
  HAVAL_STEP_S (HAVAL_FP5_4, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0xfb21a991);
  HAVAL_STEP_S (HAVAL_FP5_4, s7, s6, s5, s4, s3, s2, s1, s0, w[26], 0x487cac60);
  HAVAL_STEP_S (HAVAL_FP5_4, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x5dec8032);
  HAVAL_STEP_S (HAVAL_FP5_4, s5, s4, s3, s2, s1, s0, s7, s6, w[30], 0xef845d5d);
  HAVAL_STEP_S (HAVAL_FP5_4, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0xe98575b1);
  HAVAL_STEP_S (HAVAL_FP5_4, s3, s2, s1, s0, s7, s6, s5, s4, w[18], 0xdc262302);
  HAVAL_STEP_S (HAVAL_FP5_4, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0xeb651b88);
  HAVAL_STEP_S (HAVAL_FP5_4, s1, s0, s7, s6, s5, s4, s3, s2, w[19], 0x23893e81);
  HAVAL_STEP_S (HAVAL_FP5_4, s0, s7, s6, s5, s4, s3, s2, s1, w[ 3], 0xd396acc5);
  HAVAL_STEP_S (HAVAL_FP5_4, s7, s6, s5, s4, s3, s2, s1, s0, w[22], 0x0f6d6ff3);
  HAVAL_STEP_S (HAVAL_FP5_4, s6, s5, s4, s3, s2, s1, s0, s7, w[11], 0x83f44239);
  HAVAL_STEP_S (HAVAL_FP5_4, s5, s4, s3, s2, s1, s0, s7, s6, w[31], 0x2e0b4482);
  HAVAL_STEP_S (HAVAL_FP5_4, s4, s3, s2, s1, s0, s7, s6, s5, w[21], 0xa4842004);
  HAVAL_STEP_S (HAVAL_FP5_4, s3, s2, s1, s0, s7, s6, s5, s4, w[ 8], 0x69c8f04a);
  HAVAL_STEP_S (HAVAL_FP5_4, s2, s1, s0, s7, s6, s5, s4, s3, w[27], 0x9e1f9b5e);
  HAVAL_STEP_S (HAVAL_FP5_4, s1, s0, s7, s6, s5, s4, s3, s2, w[12], 0x21c66842);
  HAVAL_STEP_S (HAVAL_FP5_4, s0, s7, s6, s5, s4, s3, s2, s1, w[ 9], 0xf6e96c9a);
  HAVAL_STEP_S (HAVAL_FP5_4, s7, s6, s5, s4, s3, s2, s1, s0, w[ 1], 0x670c9c61);
  HAVAL_STEP_S (HAVAL_FP5_4, s6, s5, s4, s3, s2, s1, s0, s7, w[29], 0xabd388f0);
  HAVAL_STEP_S (HAVAL_FP5_4, s5, s4, s3, s2, s1, s0, s7, s6, w[ 5], 0x6a51a0d2);
  HAVAL_STEP_S (HAVAL_FP5_4, s4, s3, s2, s1, s0, s7, s6, s5, w[15], 0xd8542f68);
  HAVAL_STEP_S (HAVAL_FP5_4, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x960fa728);
  HAVAL_STEP_S (HAVAL_FP5_4, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xab5133a3);
  HAVAL_STEP_S (HAVAL_FP5_4, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0x6eef0b6c);
  HAVAL_STEP_S (HAVAL_FP5_4, s0, s7, s6, s5, s4, s3, s2, s1, w[13], 0x137a3be4);

  // pass 5

  HAVAL_STEP_S (HAVAL_FP5_5, s7, s6, s5, s4, s3, s2, s1, s0, w[27], 0xba3bf050);
  HAVAL_STEP_S (HAVAL_FP5_5, s6, s5, s4, s3, s2, s1, s0, s7, w[ 3], 0x7efb2a98);
  HAVAL_STEP_S (HAVAL_FP5_5, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0xa1f1651d);
  HAVAL_STEP_S (HAVAL_FP5_5, s4, s3, s2, s1, s0, s7, s6, s5, w[26], 0x39af0176);
  HAVAL_STEP_S (HAVAL_FP5_5, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x66ca593e);
  HAVAL_STEP_S (HAVAL_FP5_5, s2, s1, s0, s7, s6, s5, s4, s3, w[11], 0x82430e88);
  HAVAL_STEP_S (HAVAL_FP5_5, s1, s0, s7, s6, s5, s4, s3, s2, w[20], 0x8cee8619);
  HAVAL_STEP_S (HAVAL_FP5_5, s0, s7, s6, s5, s4, s3, s2, s1, w[29], 0x456f9fb4);
  HAVAL_STEP_S (HAVAL_FP5_5, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0x7d84a5c3);
  HAVAL_STEP_S (HAVAL_FP5_5, s6, s5, s4, s3, s2, s1, s0, s7, w[ 0], 0x3b8b5ebe);
  HAVAL_STEP_S (HAVAL_FP5_5, s5, s4, s3, s2, s1, s0, s7, s6, w[12], 0xe06f75d8);
  HAVAL_STEP_S (HAVAL_FP5_5, s4, s3, s2, s1, s0, s7, s6, s5, w[ 7], 0x85c12073);
  HAVAL_STEP_S (HAVAL_FP5_5, s3, s2, s1, s0, s7, s6, s5, s4, w[13], 0x401a449f);
  HAVAL_STEP_S (HAVAL_FP5_5, s2, s1, s0, s7, s6, s5, s4, s3, w[ 8], 0x56c16aa6);
  HAVAL_STEP_S (HAVAL_FP5_5, s1, s0, s7, s6, s5, s4, s3, s2, w[31], 0x4ed3aa62);
  HAVAL_STEP_S (HAVAL_FP5_5, s0, s7, s6, s5, s4, s3, s2, s1, w[10], 0x363f7706);
  HAVAL_STEP_S (HAVAL_FP5_5, s7, s6, s5, s4, s3, s2, s1, s0, w[ 5], 0x1bfedf72);
  HAVAL_STEP_S (HAVAL_FP5_5, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x429b023d);
  HAVAL_STEP_S (HAVAL_FP5_5, s5, s4, s3, s2, s1, s0, s7, s6, w[14], 0x37d0d724);
  HAVAL_STEP_S (HAVAL_FP5_5, s4, s3, s2, s1, s0, s7, s6, s5, w[30], 0xd00a1248);
  HAVAL_STEP_S (HAVAL_FP5_5, s3, s2, s1, s0, s7, s6, s5, s4, w[18], 0xdb0fead3);
  HAVAL_STEP_S (HAVAL_FP5_5, s2, s1, s0, s7, s6, s5, s4, s3, w[ 6], 0x49f1c09b);
  HAVAL_STEP_S (HAVAL_FP5_5, s1, s0, s7, s6, s5, s4, s3, s2, w[28], 0x075372c9);
  HAVAL_STEP_S (HAVAL_FP5_5, s0, s7, s6, s5, s4, s3, s2, s1, w[24], 0x80991b7b);
  HAVAL_STEP_S (HAVAL_FP5_5, s7, s6, s5, s4, s3, s2, s1, s0, w[ 2], 0x25d479d8);
  HAVAL_STEP_S (HAVAL_FP5_5, s6, s5, s4, s3, s2, s1, s0, s7, w[23], 0xf6e8def7);
  HAVAL_STEP_S (HAVAL_FP5_5, s5, s4, s3, s2, s1, s0, s7, s6, w[16], 0xe3fe501a);
  HAVAL_STEP_S (HAVAL_FP5_5, s4, s3, s2, s1, s0, s7, s6, s5, w[22], 0xb6794c3b);
  HAVAL_STEP_S (HAVAL_FP5_5, s3, s2, s1, s0, s7, s6, s5, s4, w[ 4], 0x976ce0bd);
  HAVAL_STEP_S (HAVAL_FP5_5, s2, s1, s0, s7, s6, s5, s4, s3, w[ 1], 0x04c006ba);
  HAVAL_STEP_S (HAVAL_FP5_5, s1, s0, s7, s6, s5, s4, s3, s2, w[25], 0xc1a94fb6);
  HAVAL_STEP_S (HAVAL_FP5_5, s0, s7, s6, s5, s4, s3, s2, s1, w[15], 0x409f60c4);

  h[0] += s0;
  h[1] += s1;
  h[2] += s2;
  h[3] += s3;
  h[4] += s4;
  h[5] += s5;
  h[6] += s6;
  h[7] += s7;
}

DECLSPEC void haval_transform3_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w)
{
  u32x s0 = h[0];
  u32x s1 = h[1];
  u32x s2 = h[2];
  u32x s3 = h[3];
  u32x s4 = h[4];
  u32x s5 = h[5];
  u32x s6 = h[6];
  u32x s7 = h[7];

  // pass 1

  HAVAL_STEP (HAVAL_FP3_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 1], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s5, s4, s3, s2, s1, s0, s7, s6, w[ 2], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s3, s2, s1, s0, s7, s6, s5, s4, w[ 4], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s2, s1, s0, s7, s6, s5, s4, s3, w[ 5], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s1, s0, s7, s6, s5, s4, s3, s2, w[ 6], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s0, s7, s6, s5, s4, s3, s2, s1, w[ 7], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 8], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s5, s4, s3, s2, s1, s0, s7, s6, w[10], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s4, s3, s2, s1, s0, s7, s6, s5, w[11], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s3, s2, s1, s0, s7, s6, s5, s4, w[12], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s2, s1, s0, s7, s6, s5, s4, s3, w[13], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s1, s0, s7, s6, s5, s4, s3, s2, w[14], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s0, s7, s6, s5, s4, s3, s2, s1, w[15], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s7, s6, s5, s4, s3, s2, s1, s0, w[16], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s6, s5, s4, s3, s2, s1, s0, s7, w[17], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s5, s4, s3, s2, s1, s0, s7, s6, w[18], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s4, s3, s2, s1, s0, s7, s6, s5, w[19], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s3, s2, s1, s0, s7, s6, s5, s4, w[20], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s2, s1, s0, s7, s6, s5, s4, s3, w[21], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s1, s0, s7, s6, s5, s4, s3, s2, w[22], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s6, s5, s4, s3, s2, s1, s0, s7, w[25], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s4, s3, s2, s1, s0, s7, s6, s5, w[27], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s2, s1, s0, s7, s6, s5, s4, s3, w[29], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s1, s0, s7, s6, s5, s4, s3, s2, w[30], 0x00000000);
  HAVAL_STEP (HAVAL_FP3_1, s0, s7, s6, s5, s4, s3, s2, s1, w[31], 0x00000000);

  // pass 2

  HAVAL_STEP (HAVAL_FP3_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 5], 0x452821e6);
  HAVAL_STEP (HAVAL_FP3_2, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0x38d01377);
  HAVAL_STEP (HAVAL_FP3_2, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0xbe5466cf);
  HAVAL_STEP (HAVAL_FP3_2, s4, s3, s2, s1, s0, s7, s6, s5, w[18], 0x34e90c6c);
  HAVAL_STEP (HAVAL_FP3_2, s3, s2, s1, s0, s7, s6, s5, s4, w[11], 0xc0ac29b7);
  HAVAL_STEP (HAVAL_FP3_2, s2, s1, s0, s7, s6, s5, s4, s3, w[28], 0xc97c50dd);
  HAVAL_STEP (HAVAL_FP3_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 7], 0x3f84d5b5);
  HAVAL_STEP (HAVAL_FP3_2, s0, s7, s6, s5, s4, s3, s2, s1, w[16], 0xb5470917);
  HAVAL_STEP (HAVAL_FP3_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x9216d5d9);
  HAVAL_STEP (HAVAL_FP3_2, s6, s5, s4, s3, s2, s1, s0, s7, w[23], 0x8979fb1b);
  HAVAL_STEP (HAVAL_FP3_2, s5, s4, s3, s2, s1, s0, s7, s6, w[20], 0xd1310ba6);
  HAVAL_STEP (HAVAL_FP3_2, s4, s3, s2, s1, s0, s7, s6, s5, w[22], 0x98dfb5ac);
  HAVAL_STEP (HAVAL_FP3_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0x2ffd72db);
  HAVAL_STEP (HAVAL_FP3_2, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xd01adfb7);
  HAVAL_STEP (HAVAL_FP3_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 4], 0xb8e1afed);
  HAVAL_STEP (HAVAL_FP3_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 8], 0x6a267e96);
  HAVAL_STEP (HAVAL_FP3_2, s7, s6, s5, s4, s3, s2, s1, s0, w[30], 0xba7c9045);
  HAVAL_STEP (HAVAL_FP3_2, s6, s5, s4, s3, s2, s1, s0, s7, w[ 3], 0xf12c7f99);
  HAVAL_STEP (HAVAL_FP3_2, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x24a19947);
  HAVAL_STEP (HAVAL_FP3_2, s4, s3, s2, s1, s0, s7, s6, s5, w[ 9], 0xb3916cf7);
  HAVAL_STEP (HAVAL_FP3_2, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x0801f2e2);
  HAVAL_STEP (HAVAL_FP3_2, s2, s1, s0, s7, s6, s5, s4, s3, w[24], 0x858efc16);
  HAVAL_STEP (HAVAL_FP3_2, s1, s0, s7, s6, s5, s4, s3, s2, w[29], 0x636920d8);
  HAVAL_STEP (HAVAL_FP3_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 6], 0x71574e69);
  HAVAL_STEP (HAVAL_FP3_2, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0xa458fea3);
  HAVAL_STEP (HAVAL_FP3_2, s6, s5, s4, s3, s2, s1, s0, s7, w[12], 0xf4933d7e);
  HAVAL_STEP (HAVAL_FP3_2, s5, s4, s3, s2, s1, s0, s7, s6, w[15], 0x0d95748f);
  HAVAL_STEP (HAVAL_FP3_2, s4, s3, s2, s1, s0, s7, s6, s5, w[13], 0x728eb658);
  HAVAL_STEP (HAVAL_FP3_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0x718bcd58);
  HAVAL_STEP (HAVAL_FP3_2, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0x82154aee);
  HAVAL_STEP (HAVAL_FP3_2, s1, s0, s7, s6, s5, s4, s3, s2, w[31], 0x7b54a41d);
  HAVAL_STEP (HAVAL_FP3_2, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0xc25a59b5);

  // pass 3

  HAVAL_STEP (HAVAL_FP3_3, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0x9c30d539);
  HAVAL_STEP (HAVAL_FP3_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x2af26013);
  HAVAL_STEP (HAVAL_FP3_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 4], 0xc5d1b023);
  HAVAL_STEP (HAVAL_FP3_3, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0x286085f0);
  HAVAL_STEP (HAVAL_FP3_3, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0xca417918);
  HAVAL_STEP (HAVAL_FP3_3, s2, s1, s0, s7, s6, s5, s4, s3, w[17], 0xb8db38ef);
  HAVAL_STEP (HAVAL_FP3_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 8], 0x8e79dcb0);
  HAVAL_STEP (HAVAL_FP3_3, s0, s7, s6, s5, s4, s3, s2, s1, w[22], 0x603a180e);
  HAVAL_STEP (HAVAL_FP3_3, s7, s6, s5, s4, s3, s2, s1, s0, w[29], 0x6c9e0e8b);
  HAVAL_STEP (HAVAL_FP3_3, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0xb01e8a3e);
  HAVAL_STEP (HAVAL_FP3_3, s5, s4, s3, s2, s1, s0, s7, s6, w[25], 0xd71577c1);
  HAVAL_STEP (HAVAL_FP3_3, s4, s3, s2, s1, s0, s7, s6, s5, w[12], 0xbd314b27);
  HAVAL_STEP (HAVAL_FP3_3, s3, s2, s1, s0, s7, s6, s5, s4, w[24], 0x78af2fda);
  HAVAL_STEP (HAVAL_FP3_3, s2, s1, s0, s7, s6, s5, s4, s3, w[30], 0x55605c60);
  HAVAL_STEP (HAVAL_FP3_3, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0xe65525f3);
  HAVAL_STEP (HAVAL_FP3_3, s0, s7, s6, s5, s4, s3, s2, s1, w[26], 0xaa55ab94);
  HAVAL_STEP (HAVAL_FP3_3, s7, s6, s5, s4, s3, s2, s1, s0, w[31], 0x57489862);
  HAVAL_STEP (HAVAL_FP3_3, s6, s5, s4, s3, s2, s1, s0, s7, w[15], 0x63e81440);
  HAVAL_STEP (HAVAL_FP3_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 7], 0x55ca396a);
  HAVAL_STEP (HAVAL_FP3_3, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x2aab10b6);
  HAVAL_STEP (HAVAL_FP3_3, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0xb4cc5c34);
  HAVAL_STEP (HAVAL_FP3_3, s2, s1, s0, s7, s6, s5, s4, s3, w[ 0], 0x1141e8ce);
  HAVAL_STEP (HAVAL_FP3_3, s1, s0, s7, s6, s5, s4, s3, s2, w[18], 0xa15486af);
  HAVAL_STEP (HAVAL_FP3_3, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0x7c72e993);
  HAVAL_STEP (HAVAL_FP3_3, s7, s6, s5, s4, s3, s2, s1, s0, w[13], 0xb3ee1411);
  HAVAL_STEP (HAVAL_FP3_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x636fbc2a);
  HAVAL_STEP (HAVAL_FP3_3, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x2ba9c55d);
  HAVAL_STEP (HAVAL_FP3_3, s4, s3, s2, s1, s0, s7, s6, s5, w[10], 0x741831f6);
  HAVAL_STEP (HAVAL_FP3_3, s3, s2, s1, s0, s7, s6, s5, s4, w[23], 0xce5c3e16);
  HAVAL_STEP (HAVAL_FP3_3, s2, s1, s0, s7, s6, s5, s4, s3, w[11], 0x9b87931e);
  HAVAL_STEP (HAVAL_FP3_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 5], 0xafd6ba33);
  HAVAL_STEP (HAVAL_FP3_3, s0, s7, s6, s5, s4, s3, s2, s1, w[ 2], 0x6c24cf5c);

  h[0] += s0;
  h[1] += s1;
  h[2] += s2;
  h[3] += s3;
  h[4] += s4;
  h[5] += s5;
  h[6] += s6;
  h[7] += s7;
}

DECLSPEC void haval_transform4_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w)
{
  u32x s0 = h[0];
  u32x s1 = h[1];
  u32x s2 = h[2];
  u32x s3 = h[3];
  u32x s4 = h[4];
  u32x s5 = h[5];
  u32x s6 = h[6];
  u32x s7 = h[7];

  // pass 1

  HAVAL_STEP (HAVAL_FP4_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 1], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s5, s4, s3, s2, s1, s0, s7, s6, w[ 2], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s3, s2, s1, s0, s7, s6, s5, s4, w[ 4], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s2, s1, s0, s7, s6, s5, s4, s3, w[ 5], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s1, s0, s7, s6, s5, s4, s3, s2, w[ 6], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s0, s7, s6, s5, s4, s3, s2, s1, w[ 7], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 8], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s5, s4, s3, s2, s1, s0, s7, s6, w[10], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s4, s3, s2, s1, s0, s7, s6, s5, w[11], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s3, s2, s1, s0, s7, s6, s5, s4, w[12], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s2, s1, s0, s7, s6, s5, s4, s3, w[13], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s1, s0, s7, s6, s5, s4, s3, s2, w[14], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s0, s7, s6, s5, s4, s3, s2, s1, w[15], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s7, s6, s5, s4, s3, s2, s1, s0, w[16], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s6, s5, s4, s3, s2, s1, s0, s7, w[17], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s5, s4, s3, s2, s1, s0, s7, s6, w[18], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s4, s3, s2, s1, s0, s7, s6, s5, w[19], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s3, s2, s1, s0, s7, s6, s5, s4, w[20], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s2, s1, s0, s7, s6, s5, s4, s3, w[21], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s1, s0, s7, s6, s5, s4, s3, s2, w[22], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s6, s5, s4, s3, s2, s1, s0, s7, w[25], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s4, s3, s2, s1, s0, s7, s6, s5, w[27], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s2, s1, s0, s7, s6, s5, s4, s3, w[29], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s1, s0, s7, s6, s5, s4, s3, s2, w[30], 0x00000000);
  HAVAL_STEP (HAVAL_FP4_1, s0, s7, s6, s5, s4, s3, s2, s1, w[31], 0x00000000);

  // pass 2

  HAVAL_STEP (HAVAL_FP4_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 5], 0x452821e6);
  HAVAL_STEP (HAVAL_FP4_2, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0x38d01377);
  HAVAL_STEP (HAVAL_FP4_2, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0xbe5466cf);
  HAVAL_STEP (HAVAL_FP4_2, s4, s3, s2, s1, s0, s7, s6, s5, w[18], 0x34e90c6c);
  HAVAL_STEP (HAVAL_FP4_2, s3, s2, s1, s0, s7, s6, s5, s4, w[11], 0xc0ac29b7);
  HAVAL_STEP (HAVAL_FP4_2, s2, s1, s0, s7, s6, s5, s4, s3, w[28], 0xc97c50dd);
  HAVAL_STEP (HAVAL_FP4_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 7], 0x3f84d5b5);
  HAVAL_STEP (HAVAL_FP4_2, s0, s7, s6, s5, s4, s3, s2, s1, w[16], 0xb5470917);
  HAVAL_STEP (HAVAL_FP4_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x9216d5d9);
  HAVAL_STEP (HAVAL_FP4_2, s6, s5, s4, s3, s2, s1, s0, s7, w[23], 0x8979fb1b);
  HAVAL_STEP (HAVAL_FP4_2, s5, s4, s3, s2, s1, s0, s7, s6, w[20], 0xd1310ba6);
  HAVAL_STEP (HAVAL_FP4_2, s4, s3, s2, s1, s0, s7, s6, s5, w[22], 0x98dfb5ac);
  HAVAL_STEP (HAVAL_FP4_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0x2ffd72db);
  HAVAL_STEP (HAVAL_FP4_2, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xd01adfb7);
  HAVAL_STEP (HAVAL_FP4_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 4], 0xb8e1afed);
  HAVAL_STEP (HAVAL_FP4_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 8], 0x6a267e96);
  HAVAL_STEP (HAVAL_FP4_2, s7, s6, s5, s4, s3, s2, s1, s0, w[30], 0xba7c9045);
  HAVAL_STEP (HAVAL_FP4_2, s6, s5, s4, s3, s2, s1, s0, s7, w[ 3], 0xf12c7f99);
  HAVAL_STEP (HAVAL_FP4_2, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x24a19947);
  HAVAL_STEP (HAVAL_FP4_2, s4, s3, s2, s1, s0, s7, s6, s5, w[ 9], 0xb3916cf7);
  HAVAL_STEP (HAVAL_FP4_2, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x0801f2e2);
  HAVAL_STEP (HAVAL_FP4_2, s2, s1, s0, s7, s6, s5, s4, s3, w[24], 0x858efc16);
  HAVAL_STEP (HAVAL_FP4_2, s1, s0, s7, s6, s5, s4, s3, s2, w[29], 0x636920d8);
  HAVAL_STEP (HAVAL_FP4_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 6], 0x71574e69);
  HAVAL_STEP (HAVAL_FP4_2, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0xa458fea3);
  HAVAL_STEP (HAVAL_FP4_2, s6, s5, s4, s3, s2, s1, s0, s7, w[12], 0xf4933d7e);
  HAVAL_STEP (HAVAL_FP4_2, s5, s4, s3, s2, s1, s0, s7, s6, w[15], 0x0d95748f);
  HAVAL_STEP (HAVAL_FP4_2, s4, s3, s2, s1, s0, s7, s6, s5, w[13], 0x728eb658);
  HAVAL_STEP (HAVAL_FP4_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0x718bcd58);
  HAVAL_STEP (HAVAL_FP4_2, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0x82154aee);
  HAVAL_STEP (HAVAL_FP4_2, s1, s0, s7, s6, s5, s4, s3, s2, w[31], 0x7b54a41d);
  HAVAL_STEP (HAVAL_FP4_2, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0xc25a59b5);

  // pass 3

  HAVAL_STEP (HAVAL_FP4_3, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0x9c30d539);
  HAVAL_STEP (HAVAL_FP4_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x2af26013);
  HAVAL_STEP (HAVAL_FP4_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 4], 0xc5d1b023);
  HAVAL_STEP (HAVAL_FP4_3, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0x286085f0);
  HAVAL_STEP (HAVAL_FP4_3, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0xca417918);
  HAVAL_STEP (HAVAL_FP4_3, s2, s1, s0, s7, s6, s5, s4, s3, w[17], 0xb8db38ef);
  HAVAL_STEP (HAVAL_FP4_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 8], 0x8e79dcb0);
  HAVAL_STEP (HAVAL_FP4_3, s0, s7, s6, s5, s4, s3, s2, s1, w[22], 0x603a180e);
  HAVAL_STEP (HAVAL_FP4_3, s7, s6, s5, s4, s3, s2, s1, s0, w[29], 0x6c9e0e8b);
  HAVAL_STEP (HAVAL_FP4_3, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0xb01e8a3e);
  HAVAL_STEP (HAVAL_FP4_3, s5, s4, s3, s2, s1, s0, s7, s6, w[25], 0xd71577c1);
  HAVAL_STEP (HAVAL_FP4_3, s4, s3, s2, s1, s0, s7, s6, s5, w[12], 0xbd314b27);
  HAVAL_STEP (HAVAL_FP4_3, s3, s2, s1, s0, s7, s6, s5, s4, w[24], 0x78af2fda);
  HAVAL_STEP (HAVAL_FP4_3, s2, s1, s0, s7, s6, s5, s4, s3, w[30], 0x55605c60);
  HAVAL_STEP (HAVAL_FP4_3, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0xe65525f3);
  HAVAL_STEP (HAVAL_FP4_3, s0, s7, s6, s5, s4, s3, s2, s1, w[26], 0xaa55ab94);
  HAVAL_STEP (HAVAL_FP4_3, s7, s6, s5, s4, s3, s2, s1, s0, w[31], 0x57489862);
  HAVAL_STEP (HAVAL_FP4_3, s6, s5, s4, s3, s2, s1, s0, s7, w[15], 0x63e81440);
  HAVAL_STEP (HAVAL_FP4_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 7], 0x55ca396a);
  HAVAL_STEP (HAVAL_FP4_3, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x2aab10b6);
  HAVAL_STEP (HAVAL_FP4_3, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0xb4cc5c34);
  HAVAL_STEP (HAVAL_FP4_3, s2, s1, s0, s7, s6, s5, s4, s3, w[ 0], 0x1141e8ce);
  HAVAL_STEP (HAVAL_FP4_3, s1, s0, s7, s6, s5, s4, s3, s2, w[18], 0xa15486af);
  HAVAL_STEP (HAVAL_FP4_3, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0x7c72e993);
  HAVAL_STEP (HAVAL_FP4_3, s7, s6, s5, s4, s3, s2, s1, s0, w[13], 0xb3ee1411);
  HAVAL_STEP (HAVAL_FP4_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x636fbc2a);
  HAVAL_STEP (HAVAL_FP4_3, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x2ba9c55d);
  HAVAL_STEP (HAVAL_FP4_3, s4, s3, s2, s1, s0, s7, s6, s5, w[10], 0x741831f6);
  HAVAL_STEP (HAVAL_FP4_3, s3, s2, s1, s0, s7, s6, s5, s4, w[23], 0xce5c3e16);
  HAVAL_STEP (HAVAL_FP4_3, s2, s1, s0, s7, s6, s5, s4, s3, w[11], 0x9b87931e);
  HAVAL_STEP (HAVAL_FP4_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 5], 0xafd6ba33);
  HAVAL_STEP (HAVAL_FP4_3, s0, s7, s6, s5, s4, s3, s2, s1, w[ 2], 0x6c24cf5c);

  // pass 4

  HAVAL_STEP (HAVAL_FP4_4, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x7a325381);
  HAVAL_STEP (HAVAL_FP4_4, s6, s5, s4, s3, s2, s1, s0, s7, w[ 4], 0x28958677);
  HAVAL_STEP (HAVAL_FP4_4, s5, s4, s3, s2, s1, s0, s7, s6, w[ 0], 0x3b8f4898);
  HAVAL_STEP (HAVAL_FP4_4, s4, s3, s2, s1, s0, s7, s6, s5, w[14], 0x6b4bb9af);
  HAVAL_STEP (HAVAL_FP4_4, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0xc4bfe81b);
  HAVAL_STEP (HAVAL_FP4_4, s2, s1, s0, s7, s6, s5, s4, s3, w[ 7], 0x66282193);
  HAVAL_STEP (HAVAL_FP4_4, s1, s0, s7, s6, s5, s4, s3, s2, w[28], 0x61d809cc);
  HAVAL_STEP (HAVAL_FP4_4, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0xfb21a991);
  HAVAL_STEP (HAVAL_FP4_4, s7, s6, s5, s4, s3, s2, s1, s0, w[26], 0x487cac60);
  HAVAL_STEP (HAVAL_FP4_4, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x5dec8032);
  HAVAL_STEP (HAVAL_FP4_4, s5, s4, s3, s2, s1, s0, s7, s6, w[30], 0xef845d5d);
  HAVAL_STEP (HAVAL_FP4_4, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0xe98575b1);
  HAVAL_STEP (HAVAL_FP4_4, s3, s2, s1, s0, s7, s6, s5, s4, w[18], 0xdc262302);
  HAVAL_STEP (HAVAL_FP4_4, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0xeb651b88);
  HAVAL_STEP (HAVAL_FP4_4, s1, s0, s7, s6, s5, s4, s3, s2, w[19], 0x23893e81);
  HAVAL_STEP (HAVAL_FP4_4, s0, s7, s6, s5, s4, s3, s2, s1, w[ 3], 0xd396acc5);
  HAVAL_STEP (HAVAL_FP4_4, s7, s6, s5, s4, s3, s2, s1, s0, w[22], 0x0f6d6ff3);
  HAVAL_STEP (HAVAL_FP4_4, s6, s5, s4, s3, s2, s1, s0, s7, w[11], 0x83f44239);
  HAVAL_STEP (HAVAL_FP4_4, s5, s4, s3, s2, s1, s0, s7, s6, w[31], 0x2e0b4482);
  HAVAL_STEP (HAVAL_FP4_4, s4, s3, s2, s1, s0, s7, s6, s5, w[21], 0xa4842004);
  HAVAL_STEP (HAVAL_FP4_4, s3, s2, s1, s0, s7, s6, s5, s4, w[ 8], 0x69c8f04a);
  HAVAL_STEP (HAVAL_FP4_4, s2, s1, s0, s7, s6, s5, s4, s3, w[27], 0x9e1f9b5e);
  HAVAL_STEP (HAVAL_FP4_4, s1, s0, s7, s6, s5, s4, s3, s2, w[12], 0x21c66842);
  HAVAL_STEP (HAVAL_FP4_4, s0, s7, s6, s5, s4, s3, s2, s1, w[ 9], 0xf6e96c9a);
  HAVAL_STEP (HAVAL_FP4_4, s7, s6, s5, s4, s3, s2, s1, s0, w[ 1], 0x670c9c61);
  HAVAL_STEP (HAVAL_FP4_4, s6, s5, s4, s3, s2, s1, s0, s7, w[29], 0xabd388f0);
  HAVAL_STEP (HAVAL_FP4_4, s5, s4, s3, s2, s1, s0, s7, s6, w[ 5], 0x6a51a0d2);
  HAVAL_STEP (HAVAL_FP4_4, s4, s3, s2, s1, s0, s7, s6, s5, w[15], 0xd8542f68);
  HAVAL_STEP (HAVAL_FP4_4, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x960fa728);
  HAVAL_STEP (HAVAL_FP4_4, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xab5133a3);
  HAVAL_STEP (HAVAL_FP4_4, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0x6eef0b6c);
  HAVAL_STEP (HAVAL_FP4_4, s0, s7, s6, s5, s4, s3, s2, s1, w[13], 0x137a3be4);

  h[0] += s0;
  h[1] += s1;
  h[2] += s2;
  h[3] += s3;
  h[4] += s4;
  h[5] += s5;
  h[6] += s6;
  h[7] += s7;
}

DECLSPEC void haval_transform5_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w)
{
  u32x s0 = h[0];
  u32x s1 = h[1];
  u32x s2 = h[2];
  u32x s3 = h[3];
  u32x s4 = h[4];
  u32x s5 = h[5];
  u32x s6 = h[6];
  u32x s7 = h[7];

  // pass 1

  HAVAL_STEP (HAVAL_FP5_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 1], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s5, s4, s3, s2, s1, s0, s7, s6, w[ 2], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s3, s2, s1, s0, s7, s6, s5, s4, w[ 4], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s2, s1, s0, s7, s6, s5, s4, s3, w[ 5], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s1, s0, s7, s6, s5, s4, s3, s2, w[ 6], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s0, s7, s6, s5, s4, s3, s2, s1, w[ 7], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s7, s6, s5, s4, s3, s2, s1, s0, w[ 8], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s5, s4, s3, s2, s1, s0, s7, s6, w[10], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s4, s3, s2, s1, s0, s7, s6, s5, w[11], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s3, s2, s1, s0, s7, s6, s5, s4, w[12], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s2, s1, s0, s7, s6, s5, s4, s3, w[13], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s1, s0, s7, s6, s5, s4, s3, s2, w[14], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s0, s7, s6, s5, s4, s3, s2, s1, w[15], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s7, s6, s5, s4, s3, s2, s1, s0, w[16], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s6, s5, s4, s3, s2, s1, s0, s7, w[17], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s5, s4, s3, s2, s1, s0, s7, s6, w[18], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s4, s3, s2, s1, s0, s7, s6, s5, w[19], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s3, s2, s1, s0, s7, s6, s5, s4, w[20], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s2, s1, s0, s7, s6, s5, s4, s3, w[21], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s1, s0, s7, s6, s5, s4, s3, s2, w[22], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s6, s5, s4, s3, s2, s1, s0, s7, w[25], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s4, s3, s2, s1, s0, s7, s6, s5, w[27], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s2, s1, s0, s7, s6, s5, s4, s3, w[29], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s1, s0, s7, s6, s5, s4, s3, s2, w[30], 0x00000000);
  HAVAL_STEP (HAVAL_FP5_1, s0, s7, s6, s5, s4, s3, s2, s1, w[31], 0x00000000);

  // pass 2

  HAVAL_STEP (HAVAL_FP5_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 5], 0x452821e6);
  HAVAL_STEP (HAVAL_FP5_2, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0x38d01377);
  HAVAL_STEP (HAVAL_FP5_2, s5, s4, s3, s2, s1, s0, s7, s6, w[26], 0xbe5466cf);
  HAVAL_STEP (HAVAL_FP5_2, s4, s3, s2, s1, s0, s7, s6, s5, w[18], 0x34e90c6c);
  HAVAL_STEP (HAVAL_FP5_2, s3, s2, s1, s0, s7, s6, s5, s4, w[11], 0xc0ac29b7);
  HAVAL_STEP (HAVAL_FP5_2, s2, s1, s0, s7, s6, s5, s4, s3, w[28], 0xc97c50dd);
  HAVAL_STEP (HAVAL_FP5_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 7], 0x3f84d5b5);
  HAVAL_STEP (HAVAL_FP5_2, s0, s7, s6, s5, s4, s3, s2, s1, w[16], 0xb5470917);
  HAVAL_STEP (HAVAL_FP5_2, s7, s6, s5, s4, s3, s2, s1, s0, w[ 0], 0x9216d5d9);
  HAVAL_STEP (HAVAL_FP5_2, s6, s5, s4, s3, s2, s1, s0, s7, w[23], 0x8979fb1b);
  HAVAL_STEP (HAVAL_FP5_2, s5, s4, s3, s2, s1, s0, s7, s6, w[20], 0xd1310ba6);
  HAVAL_STEP (HAVAL_FP5_2, s4, s3, s2, s1, s0, s7, s6, s5, w[22], 0x98dfb5ac);
  HAVAL_STEP (HAVAL_FP5_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0x2ffd72db);
  HAVAL_STEP (HAVAL_FP5_2, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xd01adfb7);
  HAVAL_STEP (HAVAL_FP5_2, s1, s0, s7, s6, s5, s4, s3, s2, w[ 4], 0xb8e1afed);
  HAVAL_STEP (HAVAL_FP5_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 8], 0x6a267e96);
  HAVAL_STEP (HAVAL_FP5_2, s7, s6, s5, s4, s3, s2, s1, s0, w[30], 0xba7c9045);
  HAVAL_STEP (HAVAL_FP5_2, s6, s5, s4, s3, s2, s1, s0, s7, w[ 3], 0xf12c7f99);
  HAVAL_STEP (HAVAL_FP5_2, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x24a19947);
  HAVAL_STEP (HAVAL_FP5_2, s4, s3, s2, s1, s0, s7, s6, s5, w[ 9], 0xb3916cf7);
  HAVAL_STEP (HAVAL_FP5_2, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x0801f2e2);
  HAVAL_STEP (HAVAL_FP5_2, s2, s1, s0, s7, s6, s5, s4, s3, w[24], 0x858efc16);
  HAVAL_STEP (HAVAL_FP5_2, s1, s0, s7, s6, s5, s4, s3, s2, w[29], 0x636920d8);
  HAVAL_STEP (HAVAL_FP5_2, s0, s7, s6, s5, s4, s3, s2, s1, w[ 6], 0x71574e69);
  HAVAL_STEP (HAVAL_FP5_2, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0xa458fea3);
  HAVAL_STEP (HAVAL_FP5_2, s6, s5, s4, s3, s2, s1, s0, s7, w[12], 0xf4933d7e);
  HAVAL_STEP (HAVAL_FP5_2, s5, s4, s3, s2, s1, s0, s7, s6, w[15], 0x0d95748f);
  HAVAL_STEP (HAVAL_FP5_2, s4, s3, s2, s1, s0, s7, s6, s5, w[13], 0x728eb658);
  HAVAL_STEP (HAVAL_FP5_2, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0x718bcd58);
  HAVAL_STEP (HAVAL_FP5_2, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0x82154aee);
  HAVAL_STEP (HAVAL_FP5_2, s1, s0, s7, s6, s5, s4, s3, s2, w[31], 0x7b54a41d);
  HAVAL_STEP (HAVAL_FP5_2, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0xc25a59b5);

  // pass 3

  HAVAL_STEP (HAVAL_FP5_3, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0x9c30d539);
  HAVAL_STEP (HAVAL_FP5_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x2af26013);
  HAVAL_STEP (HAVAL_FP5_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 4], 0xc5d1b023);
  HAVAL_STEP (HAVAL_FP5_3, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0x286085f0);
  HAVAL_STEP (HAVAL_FP5_3, s3, s2, s1, s0, s7, s6, s5, s4, w[28], 0xca417918);
  HAVAL_STEP (HAVAL_FP5_3, s2, s1, s0, s7, s6, s5, s4, s3, w[17], 0xb8db38ef);
  HAVAL_STEP (HAVAL_FP5_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 8], 0x8e79dcb0);
  HAVAL_STEP (HAVAL_FP5_3, s0, s7, s6, s5, s4, s3, s2, s1, w[22], 0x603a180e);
  HAVAL_STEP (HAVAL_FP5_3, s7, s6, s5, s4, s3, s2, s1, s0, w[29], 0x6c9e0e8b);
  HAVAL_STEP (HAVAL_FP5_3, s6, s5, s4, s3, s2, s1, s0, s7, w[14], 0xb01e8a3e);
  HAVAL_STEP (HAVAL_FP5_3, s5, s4, s3, s2, s1, s0, s7, s6, w[25], 0xd71577c1);
  HAVAL_STEP (HAVAL_FP5_3, s4, s3, s2, s1, s0, s7, s6, s5, w[12], 0xbd314b27);
  HAVAL_STEP (HAVAL_FP5_3, s3, s2, s1, s0, s7, s6, s5, s4, w[24], 0x78af2fda);
  HAVAL_STEP (HAVAL_FP5_3, s2, s1, s0, s7, s6, s5, s4, s3, w[30], 0x55605c60);
  HAVAL_STEP (HAVAL_FP5_3, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0xe65525f3);
  HAVAL_STEP (HAVAL_FP5_3, s0, s7, s6, s5, s4, s3, s2, s1, w[26], 0xaa55ab94);
  HAVAL_STEP (HAVAL_FP5_3, s7, s6, s5, s4, s3, s2, s1, s0, w[31], 0x57489862);
  HAVAL_STEP (HAVAL_FP5_3, s6, s5, s4, s3, s2, s1, s0, s7, w[15], 0x63e81440);
  HAVAL_STEP (HAVAL_FP5_3, s5, s4, s3, s2, s1, s0, s7, s6, w[ 7], 0x55ca396a);
  HAVAL_STEP (HAVAL_FP5_3, s4, s3, s2, s1, s0, s7, s6, s5, w[ 3], 0x2aab10b6);
  HAVAL_STEP (HAVAL_FP5_3, s3, s2, s1, s0, s7, s6, s5, s4, w[ 1], 0xb4cc5c34);
  HAVAL_STEP (HAVAL_FP5_3, s2, s1, s0, s7, s6, s5, s4, s3, w[ 0], 0x1141e8ce);
  HAVAL_STEP (HAVAL_FP5_3, s1, s0, s7, s6, s5, s4, s3, s2, w[18], 0xa15486af);
  HAVAL_STEP (HAVAL_FP5_3, s0, s7, s6, s5, s4, s3, s2, s1, w[27], 0x7c72e993);
  HAVAL_STEP (HAVAL_FP5_3, s7, s6, s5, s4, s3, s2, s1, s0, w[13], 0xb3ee1411);
  HAVAL_STEP (HAVAL_FP5_3, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x636fbc2a);
  HAVAL_STEP (HAVAL_FP5_3, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0x2ba9c55d);
  HAVAL_STEP (HAVAL_FP5_3, s4, s3, s2, s1, s0, s7, s6, s5, w[10], 0x741831f6);
  HAVAL_STEP (HAVAL_FP5_3, s3, s2, s1, s0, s7, s6, s5, s4, w[23], 0xce5c3e16);
  HAVAL_STEP (HAVAL_FP5_3, s2, s1, s0, s7, s6, s5, s4, s3, w[11], 0x9b87931e);
  HAVAL_STEP (HAVAL_FP5_3, s1, s0, s7, s6, s5, s4, s3, s2, w[ 5], 0xafd6ba33);
  HAVAL_STEP (HAVAL_FP5_3, s0, s7, s6, s5, s4, s3, s2, s1, w[ 2], 0x6c24cf5c);

  // pass 4

  HAVAL_STEP (HAVAL_FP5_4, s7, s6, s5, s4, s3, s2, s1, s0, w[24], 0x7a325381);
  HAVAL_STEP (HAVAL_FP5_4, s6, s5, s4, s3, s2, s1, s0, s7, w[ 4], 0x28958677);
  HAVAL_STEP (HAVAL_FP5_4, s5, s4, s3, s2, s1, s0, s7, s6, w[ 0], 0x3b8f4898);
  HAVAL_STEP (HAVAL_FP5_4, s4, s3, s2, s1, s0, s7, s6, s5, w[14], 0x6b4bb9af);
  HAVAL_STEP (HAVAL_FP5_4, s3, s2, s1, s0, s7, s6, s5, s4, w[ 2], 0xc4bfe81b);
  HAVAL_STEP (HAVAL_FP5_4, s2, s1, s0, s7, s6, s5, s4, s3, w[ 7], 0x66282193);
  HAVAL_STEP (HAVAL_FP5_4, s1, s0, s7, s6, s5, s4, s3, s2, w[28], 0x61d809cc);
  HAVAL_STEP (HAVAL_FP5_4, s0, s7, s6, s5, s4, s3, s2, s1, w[23], 0xfb21a991);
  HAVAL_STEP (HAVAL_FP5_4, s7, s6, s5, s4, s3, s2, s1, s0, w[26], 0x487cac60);
  HAVAL_STEP (HAVAL_FP5_4, s6, s5, s4, s3, s2, s1, s0, s7, w[ 6], 0x5dec8032);
  HAVAL_STEP (HAVAL_FP5_4, s5, s4, s3, s2, s1, s0, s7, s6, w[30], 0xef845d5d);
  HAVAL_STEP (HAVAL_FP5_4, s4, s3, s2, s1, s0, s7, s6, s5, w[20], 0xe98575b1);
  HAVAL_STEP (HAVAL_FP5_4, s3, s2, s1, s0, s7, s6, s5, s4, w[18], 0xdc262302);
  HAVAL_STEP (HAVAL_FP5_4, s2, s1, s0, s7, s6, s5, s4, s3, w[25], 0xeb651b88);
  HAVAL_STEP (HAVAL_FP5_4, s1, s0, s7, s6, s5, s4, s3, s2, w[19], 0x23893e81);
  HAVAL_STEP (HAVAL_FP5_4, s0, s7, s6, s5, s4, s3, s2, s1, w[ 3], 0xd396acc5);
  HAVAL_STEP (HAVAL_FP5_4, s7, s6, s5, s4, s3, s2, s1, s0, w[22], 0x0f6d6ff3);
  HAVAL_STEP (HAVAL_FP5_4, s6, s5, s4, s3, s2, s1, s0, s7, w[11], 0x83f44239);
  HAVAL_STEP (HAVAL_FP5_4, s5, s4, s3, s2, s1, s0, s7, s6, w[31], 0x2e0b4482);
  HAVAL_STEP (HAVAL_FP5_4, s4, s3, s2, s1, s0, s7, s6, s5, w[21], 0xa4842004);
  HAVAL_STEP (HAVAL_FP5_4, s3, s2, s1, s0, s7, s6, s5, s4, w[ 8], 0x69c8f04a);
  HAVAL_STEP (HAVAL_FP5_4, s2, s1, s0, s7, s6, s5, s4, s3, w[27], 0x9e1f9b5e);
  HAVAL_STEP (HAVAL_FP5_4, s1, s0, s7, s6, s5, s4, s3, s2, w[12], 0x21c66842);
  HAVAL_STEP (HAVAL_FP5_4, s0, s7, s6, s5, s4, s3, s2, s1, w[ 9], 0xf6e96c9a);
  HAVAL_STEP (HAVAL_FP5_4, s7, s6, s5, s4, s3, s2, s1, s0, w[ 1], 0x670c9c61);
  HAVAL_STEP (HAVAL_FP5_4, s6, s5, s4, s3, s2, s1, s0, s7, w[29], 0xabd388f0);
  HAVAL_STEP (HAVAL_FP5_4, s5, s4, s3, s2, s1, s0, s7, s6, w[ 5], 0x6a51a0d2);
  HAVAL_STEP (HAVAL_FP5_4, s4, s3, s2, s1, s0, s7, s6, s5, w[15], 0xd8542f68);
  HAVAL_STEP (HAVAL_FP5_4, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x960fa728);
  HAVAL_STEP (HAVAL_FP5_4, s2, s1, s0, s7, s6, s5, s4, s3, w[10], 0xab5133a3);
  HAVAL_STEP (HAVAL_FP5_4, s1, s0, s7, s6, s5, s4, s3, s2, w[16], 0x6eef0b6c);
  HAVAL_STEP (HAVAL_FP5_4, s0, s7, s6, s5, s4, s3, s2, s1, w[13], 0x137a3be4);

  // pass 5

  HAVAL_STEP (HAVAL_FP5_5, s7, s6, s5, s4, s3, s2, s1, s0, w[27], 0xba3bf050);
  HAVAL_STEP (HAVAL_FP5_5, s6, s5, s4, s3, s2, s1, s0, s7, w[ 3], 0x7efb2a98);
  HAVAL_STEP (HAVAL_FP5_5, s5, s4, s3, s2, s1, s0, s7, s6, w[21], 0xa1f1651d);
  HAVAL_STEP (HAVAL_FP5_5, s4, s3, s2, s1, s0, s7, s6, s5, w[26], 0x39af0176);
  HAVAL_STEP (HAVAL_FP5_5, s3, s2, s1, s0, s7, s6, s5, s4, w[17], 0x66ca593e);
  HAVAL_STEP (HAVAL_FP5_5, s2, s1, s0, s7, s6, s5, s4, s3, w[11], 0x82430e88);
  HAVAL_STEP (HAVAL_FP5_5, s1, s0, s7, s6, s5, s4, s3, s2, w[20], 0x8cee8619);
  HAVAL_STEP (HAVAL_FP5_5, s0, s7, s6, s5, s4, s3, s2, s1, w[29], 0x456f9fb4);
  HAVAL_STEP (HAVAL_FP5_5, s7, s6, s5, s4, s3, s2, s1, s0, w[19], 0x7d84a5c3);
  HAVAL_STEP (HAVAL_FP5_5, s6, s5, s4, s3, s2, s1, s0, s7, w[ 0], 0x3b8b5ebe);
  HAVAL_STEP (HAVAL_FP5_5, s5, s4, s3, s2, s1, s0, s7, s6, w[12], 0xe06f75d8);
  HAVAL_STEP (HAVAL_FP5_5, s4, s3, s2, s1, s0, s7, s6, s5, w[ 7], 0x85c12073);
  HAVAL_STEP (HAVAL_FP5_5, s3, s2, s1, s0, s7, s6, s5, s4, w[13], 0x401a449f);
  HAVAL_STEP (HAVAL_FP5_5, s2, s1, s0, s7, s6, s5, s4, s3, w[ 8], 0x56c16aa6);
  HAVAL_STEP (HAVAL_FP5_5, s1, s0, s7, s6, s5, s4, s3, s2, w[31], 0x4ed3aa62);
  HAVAL_STEP (HAVAL_FP5_5, s0, s7, s6, s5, s4, s3, s2, s1, w[10], 0x363f7706);
  HAVAL_STEP (HAVAL_FP5_5, s7, s6, s5, s4, s3, s2, s1, s0, w[ 5], 0x1bfedf72);
  HAVAL_STEP (HAVAL_FP5_5, s6, s5, s4, s3, s2, s1, s0, s7, w[ 9], 0x429b023d);
  HAVAL_STEP (HAVAL_FP5_5, s5, s4, s3, s2, s1, s0, s7, s6, w[14], 0x37d0d724);
  HAVAL_STEP (HAVAL_FP5_5, s4, s3, s2, s1, s0, s7, s6, s5, w[30], 0xd00a1248);
  HAVAL_STEP (HAVAL_FP5_5, s3, s2, s1, s0, s7, s6, s5, s4, w[18], 0xdb0fead3);
  HAVAL_STEP (HAVAL_FP5_5, s2, s1, s0, s7, s6, s5, s4, s3, w[ 6], 0x49f1c09b);
  HAVAL_STEP (HAVAL_FP5_5, s1, s0, s7, s6, s5, s4, s3, s2, w[28], 0x075372c9);
  HAVAL_STEP (HAVAL_FP5_5, s0, s7, s6, s5, s4, s3, s2, s1, w[24], 0x80991b7b);
  HAVAL_STEP (HAVAL_FP5_5, s7, s6, s5, s4, s3, s2, s1, s0, w[ 2], 0x25d479d8);
  HAVAL_STEP (HAVAL_FP5_5, s6, s5, s4, s3, s2, s1, s0, s7, w[23], 0xf6e8def7);
  HAVAL_STEP (HAVAL_FP5_5, s5, s4, s3, s2, s1, s0, s7, s6, w[16], 0xe3fe501a);
  HAVAL_STEP (HAVAL_FP5_5, s4, s3, s2, s1, s0, s7, s6, s5, w[22], 0xb6794c3b);
  HAVAL_STEP (HAVAL_FP5_5, s3, s2, s1, s0, s7, s6, s5, s4, w[ 4], 0x976ce0bd);
  HAVAL_STEP (HAVAL_FP5_5, s2, s1, s0, s7, s6, s5, s4, s3, w[ 1], 0x04c006ba);
  HAVAL_STEP (HAVAL_FP5_5, s1, s0, s7, s6, s5, s4, s3, s2, w[25], 0xc1a94fb6);
  HAVAL_STEP (HAVAL_FP5_5, s0, s7, s6, s5, s4, s3, s2, s1, w[15], 0x409f60c4);

  h[0] += s0;
  h[1] += s1;
  h[2] += s2;
  h[3] += s3;
  h[4] += s4;
  h[5] += s5;
  h[6] += s6;
  h[7] += s7;
}

DECLSPEC void haval_init (PRIVATE_AS haval_ctx_t *ctx, const int passes, const int olen)
{
  ctx->h[0] = 0x243f6a88;
  ctx->h[1] = 0x85a308d3;
  ctx->h[2] = 0x13198a2e;
  ctx->h[3] = 0x03707344;
  ctx->h[4] = 0xa4093822;
  ctx->h[5] = 0x299f31d0;
  ctx->h[6] = 0x082efa98;
  ctx->h[7] = 0xec4e6c89;

  for (int i = 0; i < 32; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->passes = passes;
  ctx->olen   = olen;
}

DECLSPEC void haval_block (PRIVATE_AS haval_ctx_t *ctx)
{
  if      (ctx->passes == 3) haval_transform3 (ctx->h, ctx->w);
  else if (ctx->passes == 4) haval_transform4 (ctx->h, ctx->w);
  else                       haval_transform5 (ctx->h, ctx->w);

  for (int i = 0; i < 32; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void haval_absorb (PRIVATE_AS haval_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    haval_block (ctx);

    if (n > fit)
    {
      ctx->w[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void haval_update (PRIVATE_AS haval_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    haval_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void haval_absorb_utf16le (PRIVATE_AS haval_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  haval_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) haval_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void haval_update_utf16le (PRIVATE_AS haval_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      haval_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    haval_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void haval_update_global (PRIVATE_AS haval_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    haval_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void haval_update_global_utf16le (PRIVATE_AS haval_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      haval_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    haval_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Fold the 8 state words into olen words, as the reference tailors digests shorter than 256 bits.

#define HAVAL_TAILOR(R,T,ROTL)                                                                                       \
{                                                                                                                    \
  const T s0 = (R)[0];                                                                                               \
  const T s1 = (R)[1];                                                                                               \
  const T s2 = (R)[2];                                                                                               \
  const T s3 = (R)[3];                                                                                               \
  const T s4 = (R)[4];                                                                                               \
  const T s5 = (R)[5];                                                                                               \
  const T s6 = (R)[6];                                                                                               \
  const T s7 = (R)[7];                                                                                               \
                                                                                                                     \
  if (ctx->olen == 4)                                                                                                \
  {                                                                                                                  \
    (R)[0] = s0 + ROTL ((s7 & 0x000000ff) | (s4 & 0x0000ff00) | (s5 & 0x00ff0000) | (s6 & 0xff000000), 24);        \
    (R)[1] = s1 + ROTL ((s6 & 0x000000ff) | (s7 & 0x0000ff00) | (s4 & 0x00ff0000) | (s5 & 0xff000000), 16);        \
    (R)[2] = s2 + ROTL ((s5 & 0x000000ff) | (s6 & 0x0000ff00) | (s7 & 0x00ff0000) | (s4 & 0xff000000),  8);        \
    (R)[3] = s3 +      ((s4 & 0x000000ff) | (s5 & 0x0000ff00) | (s6 & 0x00ff0000) | (s7 & 0xff000000));            \
  }                                                                                                                  \
  else if (ctx->olen == 5)                                                                                           \
  {                                                                                                                  \
    (R)[0] = s0 + ROTL ((s5 & 0x01f80000) | (s6 & 0xfe000000) | (s7 & 0x0000003f), 13);                             \
    (R)[1] = s1 + ROTL ((s5 & 0xfe000000) | (s6 & 0x0000003f) | (s7 & 0x00000fc0),  7);                             \
    (R)[2] = s2 +      ((s5 & 0x0000003f) | (s6 & 0x00000fc0) | (s7 & 0x0007f000));                                 \
    (R)[3] = s3 +     (((s5 & 0x00000fc0) | (s6 & 0x0007f000) | (s7 & 0x01f80000)) >>  6);                           \
    (R)[4] = s4 +     (((s5 & 0x0007f000) | (s6 & 0x01f80000) | (s7 & 0xfe000000)) >> 12);                           \
  }                                                                                                                  \
  else if (ctx->olen == 6)                                                                                           \
  {                                                                                                                  \
    (R)[0] = s0 + ROTL ((s6 & 0xfc000000) | (s7 & 0x0000001f), 6);                                                   \
    (R)[1] = s1 +      ((s6 & 0x0000001f) | (s7 & 0x000003e0));                                                      \
    (R)[2] = s2 +     (((s6 & 0x000003e0) | (s7 & 0x0000fc00)) >>  5);                                               \
    (R)[3] = s3 +     (((s6 & 0x0000fc00) | (s7 & 0x001f0000)) >> 10);                                               \
    (R)[4] = s4 +     (((s6 & 0x001f0000) | (s7 & 0x03e00000)) >> 16);                                               \
    (R)[5] = s5 +     (((s6 & 0x03e00000) | (s7 & 0xfc000000)) >> 21);                                               \
  }                                                                                                                  \
  else if (ctx->olen == 7)                                                                                           \
  {                                                                                                                  \
    (R)[0] = s0 + ((s7 >> 27) & 0x1f);                                                                               \
    (R)[1] = s1 + ((s7 >> 22) & 0x1f);                                                                               \
    (R)[2] = s2 + ((s7 >> 18) & 0x0f);                                                                               \
    (R)[3] = s3 + ((s7 >> 13) & 0x1f);                                                                               \
    (R)[4] = s4 + ((s7 >>  9) & 0x0f);                                                                               \
    (R)[5] = s5 + ((s7 >>  4) & 0x1f);                                                                               \
    (R)[6] = s6 + ((s7 >>  0) & 0x0f);                                                                               \
  }                                                                                                                  \
}

// The final padding consists of the 0x01 byte, zeros up to byte 118, the version and pass count,
// the digest size in bits divided by 4, and the message length in bits. A context with invalid
// UTF-8 input produces a digest with every bit flipped, so that no candidate matches it by chance.

DECLSPEC void haval_final (PRIVATE_AS haval_ctx_t *ctx)
{
  const u32 len = (u32) ctx->len;

  haval_absorb (ctx, 0x01, 1);

  if (ctx->pos > 118) haval_block (ctx);

  ctx->w[29] |= ((u32) (0x01 | (ctx->passes << 3)) << 16) | ((u32) (ctx->olen << 3) << 24);
  ctx->w[30]  = len << 3;
  ctx->w[31]  = len >> 29;

  haval_block (ctx);

  HAVAL_TAILOR (ctx->h, u32, hc_rotl32_S)

  if (ctx->len < 0)
  {
    for (int i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void haval_init_vector (PRIVATE_AS haval_ctx_vector_t *ctx, const int passes, const int olen)
{
  ctx->h[0] = 0x243f6a88;
  ctx->h[1] = 0x85a308d3;
  ctx->h[2] = 0x13198a2e;
  ctx->h[3] = 0x03707344;
  ctx->h[4] = 0xa4093822;
  ctx->h[5] = 0x299f31d0;
  ctx->h[6] = 0x082efa98;
  ctx->h[7] = 0xec4e6c89;

  for (int i = 0; i < 32; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->passes = passes;
  ctx->olen   = olen;
}

DECLSPEC void haval_block_vector (PRIVATE_AS haval_ctx_vector_t *ctx)
{
  if      (ctx->passes == 3) haval_transform3_vector (ctx->h, ctx->w);
  else if (ctx->passes == 4) haval_transform4_vector (ctx->h, ctx->w);
  else                       haval_transform5_vector (ctx->h, ctx->w);

  for (int i = 0; i < 32; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void haval_absorb_vector (PRIVATE_AS haval_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    haval_block_vector (ctx);

    if (n > fit)
    {
      ctx->w[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void haval_update_vector (PRIVATE_AS haval_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    haval_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void haval_update_vector_utf16le (PRIVATE_AS haval_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    haval_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) haval_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void haval_final_vector (PRIVATE_AS haval_ctx_vector_t *ctx)
{
  const u32 len = (u32) ctx->len;

  haval_absorb_vector (ctx, make_u32x (0x01), 1);

  if (ctx->pos > 118) haval_block_vector (ctx);

  ctx->w[29] |= ((u32) (0x01 | (ctx->passes << 3)) << 16) | ((u32) (ctx->olen << 3) << 24);
  ctx->w[30]  = len << 3;
  ctx->w[31]  = len >> 29;

  haval_block_vector (ctx);

  HAVAL_TAILOR (ctx->h, u32x, hc_rotl32)
}
