
/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_ripemd320.h"

// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf needs to be in algorithm native byte order (ripemd320 = LE, sha1 = BE, etc)
// input buf needs to be 64 byte aligned when using ripemd320_update()

DECLSPEC void ripemd320_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest)
{
  u32 a1 = digest[0];
  u32 b1 = digest[1];
  u32 c1 = digest[2];
  u32 d1 = digest[3];
  u32 e1 = digest[4];

  u32 a2 = digest[5];
  u32 b2 = digest[6];
  u32 c2 = digest[7];
  u32 d2 = digest[8];
  u32 e2 = digest[9];

  u32 tmp = 0;

  RIPEMD320_STEP_S (RIPEMD320_F , a1, b1, c1, d1, e1, w0[0], RIPEMD320C00, RIPEMD320S00);
  RIPEMD320_STEP_S (RIPEMD320_F , e1, a1, b1, c1, d1, w0[1], RIPEMD320C00, RIPEMD320S01);
  RIPEMD320_STEP_S (RIPEMD320_F , d1, e1, a1, b1, c1, w0[2], RIPEMD320C00, RIPEMD320S02);
  RIPEMD320_STEP_S (RIPEMD320_F , c1, d1, e1, a1, b1, w0[3], RIPEMD320C00, RIPEMD320S03);
  RIPEMD320_STEP_S (RIPEMD320_F , b1, c1, d1, e1, a1, w1[0], RIPEMD320C00, RIPEMD320S04);
  RIPEMD320_STEP_S (RIPEMD320_F , a1, b1, c1, d1, e1, w1[1], RIPEMD320C00, RIPEMD320S05);
  RIPEMD320_STEP_S (RIPEMD320_F , e1, a1, b1, c1, d1, w1[2], RIPEMD320C00, RIPEMD320S06);
  RIPEMD320_STEP_S (RIPEMD320_F , d1, e1, a1, b1, c1, w1[3], RIPEMD320C00, RIPEMD320S07);
  RIPEMD320_STEP_S (RIPEMD320_F , c1, d1, e1, a1, b1, w2[0], RIPEMD320C00, RIPEMD320S08);
  RIPEMD320_STEP_S (RIPEMD320_F , b1, c1, d1, e1, a1, w2[1], RIPEMD320C00, RIPEMD320S09);
  RIPEMD320_STEP_S (RIPEMD320_F , a1, b1, c1, d1, e1, w2[2], RIPEMD320C00, RIPEMD320S0A);
  RIPEMD320_STEP_S (RIPEMD320_F , e1, a1, b1, c1, d1, w2[3], RIPEMD320C00, RIPEMD320S0B);
  RIPEMD320_STEP_S (RIPEMD320_F , d1, e1, a1, b1, c1, w3[0], RIPEMD320C00, RIPEMD320S0C);
  RIPEMD320_STEP_S (RIPEMD320_F , c1, d1, e1, a1, b1, w3[1], RIPEMD320C00, RIPEMD320S0D);
  RIPEMD320_STEP_S (RIPEMD320_F , b1, c1, d1, e1, a1, w3[2], RIPEMD320C00, RIPEMD320S0E);
  RIPEMD320_STEP_S (RIPEMD320_F , a1, b1, c1, d1, e1, w3[3], RIPEMD320C00, RIPEMD320S0F);

  RIPEMD320_STEP_S (RIPEMD320_J , a2, b2, c2, d2, e2, w1[1], RIPEMD320C50, RIPEMD320S50);
  RIPEMD320_STEP_S (RIPEMD320_J , e2, a2, b2, c2, d2, w3[2], RIPEMD320C50, RIPEMD320S51);
  RIPEMD320_STEP_S (RIPEMD320_J , d2, e2, a2, b2, c2, w1[3], RIPEMD320C50, RIPEMD320S52);
  RIPEMD320_STEP_S (RIPEMD320_J , c2, d2, e2, a2, b2, w0[0], RIPEMD320C50, RIPEMD320S53);
  RIPEMD320_STEP_S (RIPEMD320_J , b2, c2, d2, e2, a2, w2[1], RIPEMD320C50, RIPEMD320S54);
  RIPEMD320_STEP_S (RIPEMD320_J , a2, b2, c2, d2, e2, w0[2], RIPEMD320C50, RIPEMD320S55);
  RIPEMD320_STEP_S (RIPEMD320_J , e2, a2, b2, c2, d2, w2[3], RIPEMD320C50, RIPEMD320S56);
  RIPEMD320_STEP_S (RIPEMD320_J , d2, e2, a2, b2, c2, w1[0], RIPEMD320C50, RIPEMD320S57);
  RIPEMD320_STEP_S (RIPEMD320_J , c2, d2, e2, a2, b2, w3[1], RIPEMD320C50, RIPEMD320S58);
  RIPEMD320_STEP_S (RIPEMD320_J , b2, c2, d2, e2, a2, w1[2], RIPEMD320C50, RIPEMD320S59);
  RIPEMD320_STEP_S (RIPEMD320_J , a2, b2, c2, d2, e2, w3[3], RIPEMD320C50, RIPEMD320S5A);
  RIPEMD320_STEP_S (RIPEMD320_J , e2, a2, b2, c2, d2, w2[0], RIPEMD320C50, RIPEMD320S5B);
  RIPEMD320_STEP_S (RIPEMD320_J , d2, e2, a2, b2, c2, w0[1], RIPEMD320C50, RIPEMD320S5C);
  RIPEMD320_STEP_S (RIPEMD320_J , c2, d2, e2, a2, b2, w2[2], RIPEMD320C50, RIPEMD320S5D);
  RIPEMD320_STEP_S (RIPEMD320_J , b2, c2, d2, e2, a2, w0[3], RIPEMD320C50, RIPEMD320S5E);
  RIPEMD320_STEP_S (RIPEMD320_J , a2, b2, c2, d2, e2, w3[0], RIPEMD320C50, RIPEMD320S5F);

  tmp = a1; a1 = a2; a2 = tmp;

  RIPEMD320_STEP_S (RIPEMD320_Go, e1, a1, b1, c1, d1, w1[3], RIPEMD320C10, RIPEMD320S10);
  RIPEMD320_STEP_S (RIPEMD320_Go, d1, e1, a1, b1, c1, w1[0], RIPEMD320C10, RIPEMD320S11);
  RIPEMD320_STEP_S (RIPEMD320_Go, c1, d1, e1, a1, b1, w3[1], RIPEMD320C10, RIPEMD320S12);
  RIPEMD320_STEP_S (RIPEMD320_Go, b1, c1, d1, e1, a1, w0[1], RIPEMD320C10, RIPEMD320S13);
  RIPEMD320_STEP_S (RIPEMD320_Go, a1, b1, c1, d1, e1, w2[2], RIPEMD320C10, RIPEMD320S14);
  RIPEMD320_STEP_S (RIPEMD320_Go, e1, a1, b1, c1, d1, w1[2], RIPEMD320C10, RIPEMD320S15);
  RIPEMD320_STEP_S (RIPEMD320_Go, d1, e1, a1, b1, c1, w3[3], RIPEMD320C10, RIPEMD320S16);
  RIPEMD320_STEP_S (RIPEMD320_Go, c1, d1, e1, a1, b1, w0[3], RIPEMD320C10, RIPEMD320S17);
  RIPEMD320_STEP_S (RIPEMD320_Go, b1, c1, d1, e1, a1, w3[0], RIPEMD320C10, RIPEMD320S18);
  RIPEMD320_STEP_S (RIPEMD320_Go, a1, b1, c1, d1, e1, w0[0], RIPEMD320C10, RIPEMD320S19);
  RIPEMD320_STEP_S (RIPEMD320_Go, e1, a1, b1, c1, d1, w2[1], RIPEMD320C10, RIPEMD320S1A);
  RIPEMD320_STEP_S (RIPEMD320_Go, d1, e1, a1, b1, c1, w1[1], RIPEMD320C10, RIPEMD320S1B);
  RIPEMD320_STEP_S (RIPEMD320_Go, c1, d1, e1, a1, b1, w0[2], RIPEMD320C10, RIPEMD320S1C);
  RIPEMD320_STEP_S (RIPEMD320_Go, b1, c1, d1, e1, a1, w3[2], RIPEMD320C10, RIPEMD320S1D);
  RIPEMD320_STEP_S (RIPEMD320_Go, a1, b1, c1, d1, e1, w2[3], RIPEMD320C10, RIPEMD320S1E);
  RIPEMD320_STEP_S (RIPEMD320_Go, e1, a1, b1, c1, d1, w2[0], RIPEMD320C10, RIPEMD320S1F);

  RIPEMD320_STEP_S (RIPEMD320_Io, e2, a2, b2, c2, d2, w1[2], RIPEMD320C60, RIPEMD320S60);
  RIPEMD320_STEP_S (RIPEMD320_Io, d2, e2, a2, b2, c2, w2[3], RIPEMD320C60, RIPEMD320S61);
  RIPEMD320_STEP_S (RIPEMD320_Io, c2, d2, e2, a2, b2, w0[3], RIPEMD320C60, RIPEMD320S62);
  RIPEMD320_STEP_S (RIPEMD320_Io, b2, c2, d2, e2, a2, w1[3], RIPEMD320C60, RIPEMD320S63);
  RIPEMD320_STEP_S (RIPEMD320_Io, a2, b2, c2, d2, e2, w0[0], RIPEMD320C60, RIPEMD320S64);
  RIPEMD320_STEP_S (RIPEMD320_Io, e2, a2, b2, c2, d2, w3[1], RIPEMD320C60, RIPEMD320S65);
  RIPEMD320_STEP_S (RIPEMD320_Io, d2, e2, a2, b2, c2, w1[1], RIPEMD320C60, RIPEMD320S66);
  RIPEMD320_STEP_S (RIPEMD320_Io, c2, d2, e2, a2, b2, w2[2], RIPEMD320C60, RIPEMD320S67);
  RIPEMD320_STEP_S (RIPEMD320_Io, b2, c2, d2, e2, a2, w3[2], RIPEMD320C60, RIPEMD320S68);
  RIPEMD320_STEP_S (RIPEMD320_Io, a2, b2, c2, d2, e2, w3[3], RIPEMD320C60, RIPEMD320S69);
  RIPEMD320_STEP_S (RIPEMD320_Io, e2, a2, b2, c2, d2, w2[0], RIPEMD320C60, RIPEMD320S6A);
  RIPEMD320_STEP_S (RIPEMD320_Io, d2, e2, a2, b2, c2, w3[0], RIPEMD320C60, RIPEMD320S6B);
  RIPEMD320_STEP_S (RIPEMD320_Io, c2, d2, e2, a2, b2, w1[0], RIPEMD320C60, RIPEMD320S6C);
  RIPEMD320_STEP_S (RIPEMD320_Io, b2, c2, d2, e2, a2, w2[1], RIPEMD320C60, RIPEMD320S6D);
  RIPEMD320_STEP_S (RIPEMD320_Io, a2, b2, c2, d2, e2, w0[1], RIPEMD320C60, RIPEMD320S6E);
  RIPEMD320_STEP_S (RIPEMD320_Io, e2, a2, b2, c2, d2, w0[2], RIPEMD320C60, RIPEMD320S6F);

  tmp = b1; b1 = b2; b2 = tmp;

  RIPEMD320_STEP_S (RIPEMD320_H , d1, e1, a1, b1, c1, w0[3], RIPEMD320C20, RIPEMD320S20);
  RIPEMD320_STEP_S (RIPEMD320_H , c1, d1, e1, a1, b1, w2[2], RIPEMD320C20, RIPEMD320S21);
  RIPEMD320_STEP_S (RIPEMD320_H , b1, c1, d1, e1, a1, w3[2], RIPEMD320C20, RIPEMD320S22);
  RIPEMD320_STEP_S (RIPEMD320_H , a1, b1, c1, d1, e1, w1[0], RIPEMD320C20, RIPEMD320S23);
  RIPEMD320_STEP_S (RIPEMD320_H , e1, a1, b1, c1, d1, w2[1], RIPEMD320C20, RIPEMD320S24);
  RIPEMD320_STEP_S (RIPEMD320_H , d1, e1, a1, b1, c1, w3[3], RIPEMD320C20, RIPEMD320S25);
  RIPEMD320_STEP_S (RIPEMD320_H , c1, d1, e1, a1, b1, w2[0], RIPEMD320C20, RIPEMD320S26);
  RIPEMD320_STEP_S (RIPEMD320_H , b1, c1, d1, e1, a1, w0[1], RIPEMD320C20, RIPEMD320S27);
  RIPEMD320_STEP_S (RIPEMD320_H , a1, b1, c1, d1, e1, w0[2], RIPEMD320C20, RIPEMD320S28);
  RIPEMD320_STEP_S (RIPEMD320_H , e1, a1, b1, c1, d1, w1[3], RIPEMD320C20, RIPEMD320S29);
  RIPEMD320_STEP_S (RIPEMD320_H , d1, e1, a1, b1, c1, w0[0], RIPEMD320C20, RIPEMD320S2A);
  RIPEMD320_STEP_S (RIPEMD320_H , c1, d1, e1, a1, b1, w1[2], RIPEMD320C20, RIPEMD320S2B);
  RIPEMD320_STEP_S (RIPEMD320_H , b1, c1, d1, e1, a1, w3[1], RIPEMD320C20, RIPEMD320S2C);
  RIPEMD320_STEP_S (RIPEMD320_H , a1, b1, c1, d1, e1, w2[3], RIPEMD320C20, RIPEMD320S2D);
  RIPEMD320_STEP_S (RIPEMD320_H , e1, a1, b1, c1, d1, w1[1], RIPEMD320C20, RIPEMD320S2E);
  RIPEMD320_STEP_S (RIPEMD320_H , d1, e1, a1, b1, c1, w3[0], RIPEMD320C20, RIPEMD320S2F);

  RIPEMD320_STEP_S (RIPEMD320_H , d2, e2, a2, b2, c2, w3[3], RIPEMD320C70, RIPEMD320S70);
  RIPEMD320_STEP_S (RIPEMD320_H , c2, d2, e2, a2, b2, w1[1], RIPEMD320C70, RIPEMD320S71);
  RIPEMD320_STEP_S (RIPEMD320_H , b2, c2, d2, e2, a2, w0[1], RIPEMD320C70, RIPEMD320S72);
  RIPEMD320_STEP_S (RIPEMD320_H , a2, b2, c2, d2, e2, w0[3], RIPEMD320C70, RIPEMD320S73);
  RIPEMD320_STEP_S (RIPEMD320_H , e2, a2, b2, c2, d2, w1[3], RIPEMD320C70, RIPEMD320S74);
  RIPEMD320_STEP_S (RIPEMD320_H , d2, e2, a2, b2, c2, w3[2], RIPEMD320C70, RIPEMD320S75);
  RIPEMD320_STEP_S (RIPEMD320_H , c2, d2, e2, a2, b2, w1[2], RIPEMD320C70, RIPEMD320S76);
  RIPEMD320_STEP_S (RIPEMD320_H , b2, c2, d2, e2, a2, w2[1], RIPEMD320C70, RIPEMD320S77);
  RIPEMD320_STEP_S (RIPEMD320_H , a2, b2, c2, d2, e2, w2[3], RIPEMD320C70, RIPEMD320S78);
  RIPEMD320_STEP_S (RIPEMD320_H , e2, a2, b2, c2, d2, w2[0], RIPEMD320C70, RIPEMD320S79);
  RIPEMD320_STEP_S (RIPEMD320_H , d2, e2, a2, b2, c2, w3[0], RIPEMD320C70, RIPEMD320S7A);
  RIPEMD320_STEP_S (RIPEMD320_H , c2, d2, e2, a2, b2, w0[2], RIPEMD320C70, RIPEMD320S7B);
  RIPEMD320_STEP_S (RIPEMD320_H , b2, c2, d2, e2, a2, w2[2], RIPEMD320C70, RIPEMD320S7C);
  RIPEMD320_STEP_S (RIPEMD320_H , a2, b2, c2, d2, e2, w0[0], RIPEMD320C70, RIPEMD320S7D);
  RIPEMD320_STEP_S (RIPEMD320_H , e2, a2, b2, c2, d2, w1[0], RIPEMD320C70, RIPEMD320S7E);
  RIPEMD320_STEP_S (RIPEMD320_H , d2, e2, a2, b2, c2, w3[1], RIPEMD320C70, RIPEMD320S7F);

  tmp = c1; c1 = c2; c2 = tmp;

  RIPEMD320_STEP_S (RIPEMD320_Io, c1, d1, e1, a1, b1, w0[1], RIPEMD320C30, RIPEMD320S30);
  RIPEMD320_STEP_S (RIPEMD320_Io, b1, c1, d1, e1, a1, w2[1], RIPEMD320C30, RIPEMD320S31);
  RIPEMD320_STEP_S (RIPEMD320_Io, a1, b1, c1, d1, e1, w2[3], RIPEMD320C30, RIPEMD320S32);
  RIPEMD320_STEP_S (RIPEMD320_Io, e1, a1, b1, c1, d1, w2[2], RIPEMD320C30, RIPEMD320S33);
  RIPEMD320_STEP_S (RIPEMD320_Io, d1, e1, a1, b1, c1, w0[0], RIPEMD320C30, RIPEMD320S34);
  RIPEMD320_STEP_S (RIPEMD320_Io, c1, d1, e1, a1, b1, w2[0], RIPEMD320C30, RIPEMD320S35);
  RIPEMD320_STEP_S (RIPEMD320_Io, b1, c1, d1, e1, a1, w3[0], RIPEMD320C30, RIPEMD320S36);
  RIPEMD320_STEP_S (RIPEMD320_Io, a1, b1, c1, d1, e1, w1[0], RIPEMD320C30, RIPEMD320S37);
  RIPEMD320_STEP_S (RIPEMD320_Io, e1, a1, b1, c1, d1, w3[1], RIPEMD320C30, RIPEMD320S38);
  RIPEMD320_STEP_S (RIPEMD320_Io, d1, e1, a1, b1, c1, w0[3], RIPEMD320C30, RIPEMD320S39);
  RIPEMD320_STEP_S (RIPEMD320_Io, c1, d1, e1, a1, b1, w1[3], RIPEMD320C30, RIPEMD320S3A);
  RIPEMD320_STEP_S (RIPEMD320_Io, b1, c1, d1, e1, a1, w3[3], RIPEMD320C30, RIPEMD320S3B);
  RIPEMD320_STEP_S (RIPEMD320_Io, a1, b1, c1, d1, e1, w3[2], RIPEMD320C30, RIPEMD320S3C);
  RIPEMD320_STEP_S (RIPEMD320_Io, e1, a1, b1, c1, d1, w1[1], RIPEMD320C30, RIPEMD320S3D);
  RIPEMD320_STEP_S (RIPEMD320_Io, d1, e1, a1, b1, c1, w1[2], RIPEMD320C30, RIPEMD320S3E);
  RIPEMD320_STEP_S (RIPEMD320_Io, c1, d1, e1, a1, b1, w0[2], RIPEMD320C30, RIPEMD320S3F);

  RIPEMD320_STEP_S (RIPEMD320_Go, c2, d2, e2, a2, b2, w2[0], RIPEMD320C80, RIPEMD320S80);
  RIPEMD320_STEP_S (RIPEMD320_Go, b2, c2, d2, e2, a2, w1[2], RIPEMD320C80, RIPEMD320S81);
  RIPEMD320_STEP_S (RIPEMD320_Go, a2, b2, c2, d2, e2, w1[0], RIPEMD320C80, RIPEMD320S82);
  RIPEMD320_STEP_S (RIPEMD320_Go, e2, a2, b2, c2, d2, w0[1], RIPEMD320C80, RIPEMD320S83);
  RIPEMD320_STEP_S (RIPEMD320_Go, d2, e2, a2, b2, c2, w0[3], RIPEMD320C80, RIPEMD320S84);
  RIPEMD320_STEP_S (RIPEMD320_Go, c2, d2, e2, a2, b2, w2[3], RIPEMD320C80, RIPEMD320S85);
  RIPEMD320_STEP_S (RIPEMD320_Go, b2, c2, d2, e2, a2, w3[3], RIPEMD320C80, RIPEMD320S86);
  RIPEMD320_STEP_S (RIPEMD320_Go, a2, b2, c2, d2, e2, w0[0], RIPEMD320C80, RIPEMD320S87);
  RIPEMD320_STEP_S (RIPEMD320_Go, e2, a2, b2, c2, d2, w1[1], RIPEMD320C80, RIPEMD320S88);
  RIPEMD320_STEP_S (RIPEMD320_Go, d2, e2, a2, b2, c2, w3[0], RIPEMD320C80, RIPEMD320S89);
  RIPEMD320_STEP_S (RIPEMD320_Go, c2, d2, e2, a2, b2, w0[2], RIPEMD320C80, RIPEMD320S8A);
  RIPEMD320_STEP_S (RIPEMD320_Go, b2, c2, d2, e2, a2, w3[1], RIPEMD320C80, RIPEMD320S8B);
  RIPEMD320_STEP_S (RIPEMD320_Go, a2, b2, c2, d2, e2, w2[1], RIPEMD320C80, RIPEMD320S8C);
  RIPEMD320_STEP_S (RIPEMD320_Go, e2, a2, b2, c2, d2, w1[3], RIPEMD320C80, RIPEMD320S8D);
  RIPEMD320_STEP_S (RIPEMD320_Go, d2, e2, a2, b2, c2, w2[2], RIPEMD320C80, RIPEMD320S8E);
  RIPEMD320_STEP_S (RIPEMD320_Go, c2, d2, e2, a2, b2, w3[2], RIPEMD320C80, RIPEMD320S8F);

  tmp = d1; d1 = d2; d2 = tmp;

  RIPEMD320_STEP_S (RIPEMD320_J , b1, c1, d1, e1, a1, w1[0], RIPEMD320C40, RIPEMD320S40);
  RIPEMD320_STEP_S (RIPEMD320_J , a1, b1, c1, d1, e1, w0[0], RIPEMD320C40, RIPEMD320S41);
  RIPEMD320_STEP_S (RIPEMD320_J , e1, a1, b1, c1, d1, w1[1], RIPEMD320C40, RIPEMD320S42);
  RIPEMD320_STEP_S (RIPEMD320_J , d1, e1, a1, b1, c1, w2[1], RIPEMD320C40, RIPEMD320S43);
  RIPEMD320_STEP_S (RIPEMD320_J , c1, d1, e1, a1, b1, w1[3], RIPEMD320C40, RIPEMD320S44);
  RIPEMD320_STEP_S (RIPEMD320_J , b1, c1, d1, e1, a1, w3[0], RIPEMD320C40, RIPEMD320S45);
  RIPEMD320_STEP_S (RIPEMD320_J , a1, b1, c1, d1, e1, w0[2], RIPEMD320C40, RIPEMD320S46);
  RIPEMD320_STEP_S (RIPEMD320_J , e1, a1, b1, c1, d1, w2[2], RIPEMD320C40, RIPEMD320S47);
  RIPEMD320_STEP_S (RIPEMD320_J , d1, e1, a1, b1, c1, w3[2], RIPEMD320C40, RIPEMD320S48);
  RIPEMD320_STEP_S (RIPEMD320_J , c1, d1, e1, a1, b1, w0[1], RIPEMD320C40, RIPEMD320S49);
  RIPEMD320_STEP_S (RIPEMD320_J , b1, c1, d1, e1, a1, w0[3], RIPEMD320C40, RIPEMD320S4A);
  RIPEMD320_STEP_S (RIPEMD320_J , a1, b1, c1, d1, e1, w2[0], RIPEMD320C40, RIPEMD320S4B);
  RIPEMD320_STEP_S (RIPEMD320_J , e1, a1, b1, c1, d1, w2[3], RIPEMD320C40, RIPEMD320S4C);
  RIPEMD320_STEP_S (RIPEMD320_J , d1, e1, a1, b1, c1, w1[2], RIPEMD320C40, RIPEMD320S4D);
  RIPEMD320_STEP_S (RIPEMD320_J , c1, d1, e1, a1, b1, w3[3], RIPEMD320C40, RIPEMD320S4E);
  RIPEMD320_STEP_S (RIPEMD320_J , b1, c1, d1, e1, a1, w3[1], RIPEMD320C40, RIPEMD320S4F);

  RIPEMD320_STEP_S (RIPEMD320_F , b2, c2, d2, e2, a2, w3[0], RIPEMD320C90, RIPEMD320S90);
  RIPEMD320_STEP_S (RIPEMD320_F , a2, b2, c2, d2, e2, w3[3], RIPEMD320C90, RIPEMD320S91);
  RIPEMD320_STEP_S (RIPEMD320_F , e2, a2, b2, c2, d2, w2[2], RIPEMD320C90, RIPEMD320S92);
  RIPEMD320_STEP_S (RIPEMD320_F , d2, e2, a2, b2, c2, w1[0], RIPEMD320C90, RIPEMD320S93);
  RIPEMD320_STEP_S (RIPEMD320_F , c2, d2, e2, a2, b2, w0[1], RIPEMD320C90, RIPEMD320S94);
  RIPEMD320_STEP_S (RIPEMD320_F , b2, c2, d2, e2, a2, w1[1], RIPEMD320C90, RIPEMD320S95);
  RIPEMD320_STEP_S (RIPEMD320_F , a2, b2, c2, d2, e2, w2[0], RIPEMD320C90, RIPEMD320S96);
  RIPEMD320_STEP_S (RIPEMD320_F , e2, a2, b2, c2, d2, w1[3], RIPEMD320C90, RIPEMD320S97);
  RIPEMD320_STEP_S (RIPEMD320_F , d2, e2, a2, b2, c2, w1[2], RIPEMD320C90, RIPEMD320S98);
  RIPEMD320_STEP_S (RIPEMD320_F , c2, d2, e2, a2, b2, w0[2], RIPEMD320C90, RIPEMD320S99);
  RIPEMD320_STEP_S (RIPEMD320_F , b2, c2, d2, e2, a2, w3[1], RIPEMD320C90, RIPEMD320S9A);
  RIPEMD320_STEP_S (RIPEMD320_F , a2, b2, c2, d2, e2, w3[2], RIPEMD320C90, RIPEMD320S9B);
  RIPEMD320_STEP_S (RIPEMD320_F , e2, a2, b2, c2, d2, w0[0], RIPEMD320C90, RIPEMD320S9C);
  RIPEMD320_STEP_S (RIPEMD320_F , d2, e2, a2, b2, c2, w0[3], RIPEMD320C90, RIPEMD320S9D);
  RIPEMD320_STEP_S (RIPEMD320_F , c2, d2, e2, a2, b2, w2[1], RIPEMD320C90, RIPEMD320S9E);
  RIPEMD320_STEP_S (RIPEMD320_F , b2, c2, d2, e2, a2, w2[3], RIPEMD320C90, RIPEMD320S9F);

  tmp = e1; e1 = e2; e2 = tmp;

  const u32 a = digest[0] + a1;
  const u32 b = digest[1] + b1;
  const u32 c = digest[2] + c1;
  const u32 d = digest[3] + d1;
  const u32 e = digest[4] + e1;
  const u32 f = digest[5] + a2;
  const u32 g = digest[6] + b2;
  const u32 h = digest[7] + c2;
  const u32 i = digest[8] + d2;
  const u32 l = digest[9] + e2;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
  digest[5] = f;
  digest[6] = g;
  digest[7] = h;
  digest[8] = i;
  digest[9] = l;
}

DECLSPEC void ripemd320_init (PRIVATE_AS ripemd320_ctx_t *ctx)
{
  ctx->h[0] = RIPEMD320M_A;
  ctx->h[1] = RIPEMD320M_B;
  ctx->h[2] = RIPEMD320M_C;
  ctx->h[3] = RIPEMD320M_D;
  ctx->h[4] = RIPEMD320M_E;
  ctx->h[5] = RIPEMD320M_F;
  ctx->h[6] = RIPEMD320M_G;
  ctx->h[7] = RIPEMD320M_H;
  ctx->h[8] = RIPEMD320M_I;
  ctx->h[9] = RIPEMD320M_L;

  ctx->w0[0] = 0;
  ctx->w0[1] = 0;
  ctx->w0[2] = 0;
  ctx->w0[3] = 0;
  ctx->w1[0] = 0;
  ctx->w1[1] = 0;
  ctx->w1[2] = 0;
  ctx->w1[3] = 0;
  ctx->w2[0] = 0;
  ctx->w2[1] = 0;
  ctx->w2[2] = 0;
  ctx->w2[3] = 0;
  ctx->w3[0] = 0;
  ctx->w3[1] = 0;
  ctx->w3[2] = 0;
  ctx->w3[3] = 0;

  ctx->len = 0;
}

DECLSPEC void ripemd320_update_64 (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len)
{
  if (len == 0) return;

  const int pos = ctx->len & 63;

  ctx->len += len;

  if (pos == 0)
  {
    ctx->w0[0] = w0[0];
    ctx->w0[1] = w0[1];
    ctx->w0[2] = w0[2];
    ctx->w0[3] = w0[3];
    ctx->w1[0] = w1[0];
    ctx->w1[1] = w1[1];
    ctx->w1[2] = w1[2];
    ctx->w1[3] = w1[3];
    ctx->w2[0] = w2[0];
    ctx->w2[1] = w2[1];
    ctx->w2[2] = w2[2];
    ctx->w2[3] = w2[3];
    ctx->w3[0] = w3[0];
    ctx->w3[1] = w3[1];
    ctx->w3[2] = w3[2];
    ctx->w3[3] = w3[3];

    if (len == 64)
    {
      ripemd320_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

      ctx->w0[0] = 0;
      ctx->w0[1] = 0;
      ctx->w0[2] = 0;
      ctx->w0[3] = 0;
      ctx->w1[0] = 0;
      ctx->w1[1] = 0;
      ctx->w1[2] = 0;
      ctx->w1[3] = 0;
      ctx->w2[0] = 0;
      ctx->w2[1] = 0;
      ctx->w2[2] = 0;
      ctx->w2[3] = 0;
      ctx->w3[0] = 0;
      ctx->w3[1] = 0;
      ctx->w3[2] = 0;
      ctx->w3[3] = 0;
    }
  }
  else
  {
    if ((pos + len) < 64)
    {
      switch_buffer_by_offset_le_S (w0, w1, w2, w3, pos);

      ctx->w0[0] |= w0[0];
      ctx->w0[1] |= w0[1];
      ctx->w0[2] |= w0[2];
      ctx->w0[3] |= w0[3];
      ctx->w1[0] |= w1[0];
      ctx->w1[1] |= w1[1];
      ctx->w1[2] |= w1[2];
      ctx->w1[3] |= w1[3];
      ctx->w2[0] |= w2[0];
      ctx->w2[1] |= w2[1];
      ctx->w2[2] |= w2[2];
      ctx->w2[3] |= w2[3];
      ctx->w3[0] |= w3[0];
      ctx->w3[1] |= w3[1];
      ctx->w3[2] |= w3[2];
      ctx->w3[3] |= w3[3];
    }
    else
    {
      u32 c0[4] = { 0 };
      u32 c1[4] = { 0 };
      u32 c2[4] = { 0 };
      u32 c3[4] = { 0 };

      switch_buffer_by_offset_carry_le_S (w0, w1, w2, w3, c0, c1, c2, c3, pos);

      ctx->w0[0] |= w0[0];
      ctx->w0[1] |= w0[1];
      ctx->w0[2] |= w0[2];
      ctx->w0[3] |= w0[3];
      ctx->w1[0] |= w1[0];
      ctx->w1[1] |= w1[1];
      ctx->w1[2] |= w1[2];
      ctx->w1[3] |= w1[3];
      ctx->w2[0] |= w2[0];
      ctx->w2[1] |= w2[1];
      ctx->w2[2] |= w2[2];
      ctx->w2[3] |= w2[3];
      ctx->w3[0] |= w3[0];
      ctx->w3[1] |= w3[1];
      ctx->w3[2] |= w3[2];
      ctx->w3[3] |= w3[3];

      ripemd320_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

      ctx->w0[0] = c0[0];
      ctx->w0[1] = c0[1];
      ctx->w0[2] = c0[2];
      ctx->w0[3] = c0[3];
      ctx->w1[0] = c1[0];
      ctx->w1[1] = c1[1];
      ctx->w1[2] = c1[2];
      ctx->w1[3] = c1[3];
      ctx->w2[0] = c2[0];
      ctx->w2[1] = c2[1];
      ctx->w2[2] = c2[2];
      ctx->w2[3] = c2[3];
      ctx->w3[0] = c3[0];
      ctx->w3[1] = c3[1];
      ctx->w3[2] = c3[2];
      ctx->w3[3] = c3[3];
    }
  }
}

DECLSPEC void ripemd320_update (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    ripemd320_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  ripemd320_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd320_update_swap (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);

    ripemd320_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  ripemd320_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd320_update_utf16le (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      ripemd320_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
    }

    return;
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    ripemd320_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  ripemd320_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd320_update_utf16le_swap (PRIVATE_AS ripemd320_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      enc_buf[ 0] = hc_swap32_S (enc_buf[ 0]);
      enc_buf[ 1] = hc_swap32_S (enc_buf[ 1]);
      enc_buf[ 2] = hc_swap32_S (enc_buf[ 2]);
      enc_buf[ 3] = hc_swap32_S (enc_buf[ 3]);
      enc_buf[ 4] = hc_swap32_S (enc_buf[ 4]);
      enc_buf[ 5] = hc_swap32_S (enc_buf[ 5]);
      enc_buf[ 6] = hc_swap32_S (enc_buf[ 6]);
      enc_buf[ 7] = hc_swap32_S (enc_buf[ 7]);
      enc_buf[ 8] = hc_swap32_S (enc_buf[ 8]);
      enc_buf[ 9] = hc_swap32_S (enc_buf[ 9]);
      enc_buf[10] = hc_swap32_S (enc_buf[10]);
      enc_buf[11] = hc_swap32_S (enc_buf[11]);
      enc_buf[12] = hc_swap32_S (enc_buf[12]);
      enc_buf[13] = hc_swap32_S (enc_buf[13]);
      enc_buf[14] = hc_swap32_S (enc_buf[14]);
      enc_buf[15] = hc_swap32_S (enc_buf[15]);

      ripemd320_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
    }

    return;
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);

    ripemd320_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  ripemd320_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd320_update_global (PRIVATE_AS ripemd320_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    ripemd320_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  ripemd320_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd320_update_global_swap (PRIVATE_AS ripemd320_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);

    ripemd320_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  ripemd320_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd320_update_global_utf16le (PRIVATE_AS ripemd320_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      ripemd320_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
    }

    return;
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    ripemd320_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  ripemd320_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd320_update_global_utf16le_swap (PRIVATE_AS ripemd320_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      enc_buf[ 0] = hc_swap32_S (enc_buf[ 0]);
      enc_buf[ 1] = hc_swap32_S (enc_buf[ 1]);
      enc_buf[ 2] = hc_swap32_S (enc_buf[ 2]);
      enc_buf[ 3] = hc_swap32_S (enc_buf[ 3]);
      enc_buf[ 4] = hc_swap32_S (enc_buf[ 4]);
      enc_buf[ 5] = hc_swap32_S (enc_buf[ 5]);
      enc_buf[ 6] = hc_swap32_S (enc_buf[ 6]);
      enc_buf[ 7] = hc_swap32_S (enc_buf[ 7]);
      enc_buf[ 8] = hc_swap32_S (enc_buf[ 8]);
      enc_buf[ 9] = hc_swap32_S (enc_buf[ 9]);
      enc_buf[10] = hc_swap32_S (enc_buf[10]);
      enc_buf[11] = hc_swap32_S (enc_buf[11]);
      enc_buf[12] = hc_swap32_S (enc_buf[12]);
      enc_buf[13] = hc_swap32_S (enc_buf[13]);
      enc_buf[14] = hc_swap32_S (enc_buf[14]);
      enc_buf[15] = hc_swap32_S (enc_buf[15]);

      ripemd320_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
    }

    return;
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);

    ripemd320_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  ripemd320_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd320_final (PRIVATE_AS ripemd320_ctx_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x80_4x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos);

  if (pos >= 56)
  {
    ripemd320_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
  }

  ctx->w3[2] = ctx->len * 8;
  ctx->w3[3] = 0;

  ripemd320_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

// ripemd320_hmac

DECLSPEC void ripemd320_hmac_init_64 (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3)
{
  u32 a0[4];
  u32 a1[4];
  u32 a2[4];
  u32 a3[4];

  // ipad

  a0[0] = w0[0] ^ 0x36363636;
  a0[1] = w0[1] ^ 0x36363636;
  a0[2] = w0[2] ^ 0x36363636;
  a0[3] = w0[3] ^ 0x36363636;
  a1[0] = w1[0] ^ 0x36363636;
  a1[1] = w1[1] ^ 0x36363636;
  a1[2] = w1[2] ^ 0x36363636;
  a1[3] = w1[3] ^ 0x36363636;
  a2[0] = w2[0] ^ 0x36363636;
  a2[1] = w2[1] ^ 0x36363636;
  a2[2] = w2[2] ^ 0x36363636;
  a2[3] = w2[3] ^ 0x36363636;
  a3[0] = w3[0] ^ 0x36363636;
  a3[1] = w3[1] ^ 0x36363636;
  a3[2] = w3[2] ^ 0x36363636;
  a3[3] = w3[3] ^ 0x36363636;

  ripemd320_init (&ctx->ipad);

  ripemd320_update_64 (&ctx->ipad, a0, a1, a2, a3, 64);

  // opad

  u32 b0[4];
  u32 b1[4];
  u32 b2[4];
  u32 b3[4];

  b0[0] = w0[0] ^ 0x5c5c5c5c;
  b0[1] = w0[1] ^ 0x5c5c5c5c;
  b0[2] = w0[2] ^ 0x5c5c5c5c;
  b0[3] = w0[3] ^ 0x5c5c5c5c;
  b1[0] = w1[0] ^ 0x5c5c5c5c;
  b1[1] = w1[1] ^ 0x5c5c5c5c;
  b1[2] = w1[2] ^ 0x5c5c5c5c;
  b1[3] = w1[3] ^ 0x5c5c5c5c;
  b2[0] = w2[0] ^ 0x5c5c5c5c;
  b2[1] = w2[1] ^ 0x5c5c5c5c;
  b2[2] = w2[2] ^ 0x5c5c5c5c;
  b2[3] = w2[3] ^ 0x5c5c5c5c;
  b3[0] = w3[0] ^ 0x5c5c5c5c;
  b3[1] = w3[1] ^ 0x5c5c5c5c;
  b3[2] = w3[2] ^ 0x5c5c5c5c;
  b3[3] = w3[3] ^ 0x5c5c5c5c;

  ripemd320_init (&ctx->opad);

  ripemd320_update_64 (&ctx->opad, b0, b1, b2, b3, 64);
}

DECLSPEC void ripemd320_hmac_init (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    ripemd320_ctx_t tmp;

    ripemd320_init (&tmp);

    ripemd320_update (&tmp, w, len);

    ripemd320_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = tmp.h[5];
    w1[2] = tmp.h[6];
    w1[3] = tmp.h[7];
    w2[0] = tmp.h[8];
    w2[1] = tmp.h[9];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
  }

  ripemd320_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd320_hmac_init_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    ripemd320_ctx_t tmp;

    ripemd320_init (&tmp);

    ripemd320_update_swap (&tmp, w, len);

    ripemd320_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = tmp.h[5];
    w1[2] = tmp.h[6];
    w1[3] = tmp.h[7];
    w2[0] = tmp.h[8];
    w2[1] = tmp.h[9];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = hc_swap32_S (w[ 0]);
    w0[1] = hc_swap32_S (w[ 1]);
    w0[2] = hc_swap32_S (w[ 2]);
    w0[3] = hc_swap32_S (w[ 3]);
    w1[0] = hc_swap32_S (w[ 4]);
    w1[1] = hc_swap32_S (w[ 5]);
    w1[2] = hc_swap32_S (w[ 6]);
    w1[3] = hc_swap32_S (w[ 7]);
    w2[0] = hc_swap32_S (w[ 8]);
    w2[1] = hc_swap32_S (w[ 9]);
    w2[2] = hc_swap32_S (w[10]);
    w2[3] = hc_swap32_S (w[11]);
    w3[0] = hc_swap32_S (w[12]);
    w3[1] = hc_swap32_S (w[13]);
    w3[2] = hc_swap32_S (w[14]);
    w3[3] = hc_swap32_S (w[15]);
  }

  ripemd320_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd320_hmac_init_global (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    ripemd320_ctx_t tmp;

    ripemd320_init (&tmp);

    ripemd320_update_global (&tmp, w, len);

    ripemd320_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = tmp.h[5];
    w1[2] = tmp.h[6];
    w1[3] = tmp.h[7];
    w2[0] = tmp.h[8];
    w2[1] = tmp.h[9];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
  }

  ripemd320_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd320_hmac_init_global_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    ripemd320_ctx_t tmp;

    ripemd320_init (&tmp);

    ripemd320_update_global_swap (&tmp, w, len);

    ripemd320_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = tmp.h[5];
    w1[2] = tmp.h[6];
    w1[3] = tmp.h[7];
    w2[0] = tmp.h[8];
    w2[1] = tmp.h[9];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = hc_swap32_S (w[ 0]);
    w0[1] = hc_swap32_S (w[ 1]);
    w0[2] = hc_swap32_S (w[ 2]);
    w0[3] = hc_swap32_S (w[ 3]);
    w1[0] = hc_swap32_S (w[ 4]);
    w1[1] = hc_swap32_S (w[ 5]);
    w1[2] = hc_swap32_S (w[ 6]);
    w1[3] = hc_swap32_S (w[ 7]);
    w2[0] = hc_swap32_S (w[ 8]);
    w2[1] = hc_swap32_S (w[ 9]);
    w2[2] = hc_swap32_S (w[10]);
    w2[3] = hc_swap32_S (w[11]);
    w3[0] = hc_swap32_S (w[12]);
    w3[1] = hc_swap32_S (w[13]);
    w3[2] = hc_swap32_S (w[14]);
    w3[3] = hc_swap32_S (w[15]);
  }

  ripemd320_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd320_hmac_update_64 (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len)
{
  ripemd320_update_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void ripemd320_hmac_update (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  ripemd320_update (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_update_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  ripemd320_update_swap (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_update_utf16le (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  ripemd320_update_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_update_utf16le_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  ripemd320_update_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_update_global (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  ripemd320_update_global (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_update_global_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  ripemd320_update_global_swap (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_update_global_utf16le (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  ripemd320_update_global_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_update_global_utf16le_swap (PRIVATE_AS ripemd320_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  ripemd320_update_global_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_final (PRIVATE_AS ripemd320_hmac_ctx_t *ctx)
{
  ripemd320_final (&ctx->ipad);

  ctx->opad.w0[0] = ctx->ipad.h[0];
  ctx->opad.w0[1] = ctx->ipad.h[1];
  ctx->opad.w0[2] = ctx->ipad.h[2];
  ctx->opad.w0[3] = ctx->ipad.h[3];
  ctx->opad.w1[0] = ctx->ipad.h[4];
  ctx->opad.w1[1] = ctx->ipad.h[5];
  ctx->opad.w1[2] = ctx->ipad.h[6];
  ctx->opad.w1[3] = ctx->ipad.h[7];
  ctx->opad.w2[0] = ctx->ipad.h[8];
  ctx->opad.w2[1] = ctx->ipad.h[9];
  ctx->opad.w2[2] = 0;
  ctx->opad.w2[3] = 0;
  ctx->opad.w3[0] = 0;
  ctx->opad.w3[1] = 0;
  ctx->opad.w3[2] = 0;
  ctx->opad.w3[3] = 0;

  ctx->opad.len += 40;

  ripemd320_final (&ctx->opad);
}

// while input buf can be a vector datatype, the length of the different elements can not

DECLSPEC void ripemd320_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u32x *digest)
{
  u32x a1 = digest[0];
  u32x b1 = digest[1];
  u32x c1 = digest[2];
  u32x d1 = digest[3];
  u32x e1 = digest[4];

  u32x a2 = digest[5];
  u32x b2 = digest[6];
  u32x c2 = digest[7];
  u32x d2 = digest[8];
  u32x e2 = digest[9];

  u32x tmp = 0;

  RIPEMD320_STEP (RIPEMD320_F , a1, b1, c1, d1, e1, w0[0], RIPEMD320C00, RIPEMD320S00);
  RIPEMD320_STEP (RIPEMD320_F , e1, a1, b1, c1, d1, w0[1], RIPEMD320C00, RIPEMD320S01);
  RIPEMD320_STEP (RIPEMD320_F , d1, e1, a1, b1, c1, w0[2], RIPEMD320C00, RIPEMD320S02);
  RIPEMD320_STEP (RIPEMD320_F , c1, d1, e1, a1, b1, w0[3], RIPEMD320C00, RIPEMD320S03);
  RIPEMD320_STEP (RIPEMD320_F , b1, c1, d1, e1, a1, w1[0], RIPEMD320C00, RIPEMD320S04);
  RIPEMD320_STEP (RIPEMD320_F , a1, b1, c1, d1, e1, w1[1], RIPEMD320C00, RIPEMD320S05);
  RIPEMD320_STEP (RIPEMD320_F , e1, a1, b1, c1, d1, w1[2], RIPEMD320C00, RIPEMD320S06);
  RIPEMD320_STEP (RIPEMD320_F , d1, e1, a1, b1, c1, w1[3], RIPEMD320C00, RIPEMD320S07);
  RIPEMD320_STEP (RIPEMD320_F , c1, d1, e1, a1, b1, w2[0], RIPEMD320C00, RIPEMD320S08);
  RIPEMD320_STEP (RIPEMD320_F , b1, c1, d1, e1, a1, w2[1], RIPEMD320C00, RIPEMD320S09);
  RIPEMD320_STEP (RIPEMD320_F , a1, b1, c1, d1, e1, w2[2], RIPEMD320C00, RIPEMD320S0A);
  RIPEMD320_STEP (RIPEMD320_F , e1, a1, b1, c1, d1, w2[3], RIPEMD320C00, RIPEMD320S0B);
  RIPEMD320_STEP (RIPEMD320_F , d1, e1, a1, b1, c1, w3[0], RIPEMD320C00, RIPEMD320S0C);
  RIPEMD320_STEP (RIPEMD320_F , c1, d1, e1, a1, b1, w3[1], RIPEMD320C00, RIPEMD320S0D);
  RIPEMD320_STEP (RIPEMD320_F , b1, c1, d1, e1, a1, w3[2], RIPEMD320C00, RIPEMD320S0E);
  RIPEMD320_STEP (RIPEMD320_F , a1, b1, c1, d1, e1, w3[3], RIPEMD320C00, RIPEMD320S0F);

  RIPEMD320_STEP (RIPEMD320_J , a2, b2, c2, d2, e2, w1[1], RIPEMD320C50, RIPEMD320S50);
  RIPEMD320_STEP (RIPEMD320_J , e2, a2, b2, c2, d2, w3[2], RIPEMD320C50, RIPEMD320S51);
  RIPEMD320_STEP (RIPEMD320_J , d2, e2, a2, b2, c2, w1[3], RIPEMD320C50, RIPEMD320S52);
  RIPEMD320_STEP (RIPEMD320_J , c2, d2, e2, a2, b2, w0[0], RIPEMD320C50, RIPEMD320S53);
  RIPEMD320_STEP (RIPEMD320_J , b2, c2, d2, e2, a2, w2[1], RIPEMD320C50, RIPEMD320S54);
  RIPEMD320_STEP (RIPEMD320_J , a2, b2, c2, d2, e2, w0[2], RIPEMD320C50, RIPEMD320S55);
  RIPEMD320_STEP (RIPEMD320_J , e2, a2, b2, c2, d2, w2[3], RIPEMD320C50, RIPEMD320S56);
  RIPEMD320_STEP (RIPEMD320_J , d2, e2, a2, b2, c2, w1[0], RIPEMD320C50, RIPEMD320S57);
  RIPEMD320_STEP (RIPEMD320_J , c2, d2, e2, a2, b2, w3[1], RIPEMD320C50, RIPEMD320S58);
  RIPEMD320_STEP (RIPEMD320_J , b2, c2, d2, e2, a2, w1[2], RIPEMD320C50, RIPEMD320S59);
  RIPEMD320_STEP (RIPEMD320_J , a2, b2, c2, d2, e2, w3[3], RIPEMD320C50, RIPEMD320S5A);
  RIPEMD320_STEP (RIPEMD320_J , e2, a2, b2, c2, d2, w2[0], RIPEMD320C50, RIPEMD320S5B);
  RIPEMD320_STEP (RIPEMD320_J , d2, e2, a2, b2, c2, w0[1], RIPEMD320C50, RIPEMD320S5C);
  RIPEMD320_STEP (RIPEMD320_J , c2, d2, e2, a2, b2, w2[2], RIPEMD320C50, RIPEMD320S5D);
  RIPEMD320_STEP (RIPEMD320_J , b2, c2, d2, e2, a2, w0[3], RIPEMD320C50, RIPEMD320S5E);
  RIPEMD320_STEP (RIPEMD320_J , a2, b2, c2, d2, e2, w3[0], RIPEMD320C50, RIPEMD320S5F);

  tmp = a1; a1 = a2; a2 = tmp;

  RIPEMD320_STEP (RIPEMD320_Go, e1, a1, b1, c1, d1, w1[3], RIPEMD320C10, RIPEMD320S10);
  RIPEMD320_STEP (RIPEMD320_Go, d1, e1, a1, b1, c1, w1[0], RIPEMD320C10, RIPEMD320S11);
  RIPEMD320_STEP (RIPEMD320_Go, c1, d1, e1, a1, b1, w3[1], RIPEMD320C10, RIPEMD320S12);
  RIPEMD320_STEP (RIPEMD320_Go, b1, c1, d1, e1, a1, w0[1], RIPEMD320C10, RIPEMD320S13);
  RIPEMD320_STEP (RIPEMD320_Go, a1, b1, c1, d1, e1, w2[2], RIPEMD320C10, RIPEMD320S14);
  RIPEMD320_STEP (RIPEMD320_Go, e1, a1, b1, c1, d1, w1[2], RIPEMD320C10, RIPEMD320S15);
  RIPEMD320_STEP (RIPEMD320_Go, d1, e1, a1, b1, c1, w3[3], RIPEMD320C10, RIPEMD320S16);
  RIPEMD320_STEP (RIPEMD320_Go, c1, d1, e1, a1, b1, w0[3], RIPEMD320C10, RIPEMD320S17);
  RIPEMD320_STEP (RIPEMD320_Go, b1, c1, d1, e1, a1, w3[0], RIPEMD320C10, RIPEMD320S18);
  RIPEMD320_STEP (RIPEMD320_Go, a1, b1, c1, d1, e1, w0[0], RIPEMD320C10, RIPEMD320S19);
  RIPEMD320_STEP (RIPEMD320_Go, e1, a1, b1, c1, d1, w2[1], RIPEMD320C10, RIPEMD320S1A);
  RIPEMD320_STEP (RIPEMD320_Go, d1, e1, a1, b1, c1, w1[1], RIPEMD320C10, RIPEMD320S1B);
  RIPEMD320_STEP (RIPEMD320_Go, c1, d1, e1, a1, b1, w0[2], RIPEMD320C10, RIPEMD320S1C);
  RIPEMD320_STEP (RIPEMD320_Go, b1, c1, d1, e1, a1, w3[2], RIPEMD320C10, RIPEMD320S1D);
  RIPEMD320_STEP (RIPEMD320_Go, a1, b1, c1, d1, e1, w2[3], RIPEMD320C10, RIPEMD320S1E);
  RIPEMD320_STEP (RIPEMD320_Go, e1, a1, b1, c1, d1, w2[0], RIPEMD320C10, RIPEMD320S1F);

  RIPEMD320_STEP (RIPEMD320_Io, e2, a2, b2, c2, d2, w1[2], RIPEMD320C60, RIPEMD320S60);
  RIPEMD320_STEP (RIPEMD320_Io, d2, e2, a2, b2, c2, w2[3], RIPEMD320C60, RIPEMD320S61);
  RIPEMD320_STEP (RIPEMD320_Io, c2, d2, e2, a2, b2, w0[3], RIPEMD320C60, RIPEMD320S62);
  RIPEMD320_STEP (RIPEMD320_Io, b2, c2, d2, e2, a2, w1[3], RIPEMD320C60, RIPEMD320S63);
  RIPEMD320_STEP (RIPEMD320_Io, a2, b2, c2, d2, e2, w0[0], RIPEMD320C60, RIPEMD320S64);
  RIPEMD320_STEP (RIPEMD320_Io, e2, a2, b2, c2, d2, w3[1], RIPEMD320C60, RIPEMD320S65);
  RIPEMD320_STEP (RIPEMD320_Io, d2, e2, a2, b2, c2, w1[1], RIPEMD320C60, RIPEMD320S66);
  RIPEMD320_STEP (RIPEMD320_Io, c2, d2, e2, a2, b2, w2[2], RIPEMD320C60, RIPEMD320S67);
  RIPEMD320_STEP (RIPEMD320_Io, b2, c2, d2, e2, a2, w3[2], RIPEMD320C60, RIPEMD320S68);
  RIPEMD320_STEP (RIPEMD320_Io, a2, b2, c2, d2, e2, w3[3], RIPEMD320C60, RIPEMD320S69);
  RIPEMD320_STEP (RIPEMD320_Io, e2, a2, b2, c2, d2, w2[0], RIPEMD320C60, RIPEMD320S6A);
  RIPEMD320_STEP (RIPEMD320_Io, d2, e2, a2, b2, c2, w3[0], RIPEMD320C60, RIPEMD320S6B);
  RIPEMD320_STEP (RIPEMD320_Io, c2, d2, e2, a2, b2, w1[0], RIPEMD320C60, RIPEMD320S6C);
  RIPEMD320_STEP (RIPEMD320_Io, b2, c2, d2, e2, a2, w2[1], RIPEMD320C60, RIPEMD320S6D);
  RIPEMD320_STEP (RIPEMD320_Io, a2, b2, c2, d2, e2, w0[1], RIPEMD320C60, RIPEMD320S6E);
  RIPEMD320_STEP (RIPEMD320_Io, e2, a2, b2, c2, d2, w0[2], RIPEMD320C60, RIPEMD320S6F);

  tmp = b1; b1 = b2; b2 = tmp;

  RIPEMD320_STEP (RIPEMD320_H , d1, e1, a1, b1, c1, w0[3], RIPEMD320C20, RIPEMD320S20);
  RIPEMD320_STEP (RIPEMD320_H , c1, d1, e1, a1, b1, w2[2], RIPEMD320C20, RIPEMD320S21);
  RIPEMD320_STEP (RIPEMD320_H , b1, c1, d1, e1, a1, w3[2], RIPEMD320C20, RIPEMD320S22);
  RIPEMD320_STEP (RIPEMD320_H , a1, b1, c1, d1, e1, w1[0], RIPEMD320C20, RIPEMD320S23);
  RIPEMD320_STEP (RIPEMD320_H , e1, a1, b1, c1, d1, w2[1], RIPEMD320C20, RIPEMD320S24);
  RIPEMD320_STEP (RIPEMD320_H , d1, e1, a1, b1, c1, w3[3], RIPEMD320C20, RIPEMD320S25);
  RIPEMD320_STEP (RIPEMD320_H , c1, d1, e1, a1, b1, w2[0], RIPEMD320C20, RIPEMD320S26);
  RIPEMD320_STEP (RIPEMD320_H , b1, c1, d1, e1, a1, w0[1], RIPEMD320C20, RIPEMD320S27);
  RIPEMD320_STEP (RIPEMD320_H , a1, b1, c1, d1, e1, w0[2], RIPEMD320C20, RIPEMD320S28);
  RIPEMD320_STEP (RIPEMD320_H , e1, a1, b1, c1, d1, w1[3], RIPEMD320C20, RIPEMD320S29);
  RIPEMD320_STEP (RIPEMD320_H , d1, e1, a1, b1, c1, w0[0], RIPEMD320C20, RIPEMD320S2A);
  RIPEMD320_STEP (RIPEMD320_H , c1, d1, e1, a1, b1, w1[2], RIPEMD320C20, RIPEMD320S2B);
  RIPEMD320_STEP (RIPEMD320_H , b1, c1, d1, e1, a1, w3[1], RIPEMD320C20, RIPEMD320S2C);
  RIPEMD320_STEP (RIPEMD320_H , a1, b1, c1, d1, e1, w2[3], RIPEMD320C20, RIPEMD320S2D);
  RIPEMD320_STEP (RIPEMD320_H , e1, a1, b1, c1, d1, w1[1], RIPEMD320C20, RIPEMD320S2E);
  RIPEMD320_STEP (RIPEMD320_H , d1, e1, a1, b1, c1, w3[0], RIPEMD320C20, RIPEMD320S2F);

  RIPEMD320_STEP (RIPEMD320_H , d2, e2, a2, b2, c2, w3[3], RIPEMD320C70, RIPEMD320S70);
  RIPEMD320_STEP (RIPEMD320_H , c2, d2, e2, a2, b2, w1[1], RIPEMD320C70, RIPEMD320S71);
  RIPEMD320_STEP (RIPEMD320_H , b2, c2, d2, e2, a2, w0[1], RIPEMD320C70, RIPEMD320S72);
  RIPEMD320_STEP (RIPEMD320_H , a2, b2, c2, d2, e2, w0[3], RIPEMD320C70, RIPEMD320S73);
  RIPEMD320_STEP (RIPEMD320_H , e2, a2, b2, c2, d2, w1[3], RIPEMD320C70, RIPEMD320S74);
  RIPEMD320_STEP (RIPEMD320_H , d2, e2, a2, b2, c2, w3[2], RIPEMD320C70, RIPEMD320S75);
  RIPEMD320_STEP (RIPEMD320_H , c2, d2, e2, a2, b2, w1[2], RIPEMD320C70, RIPEMD320S76);
  RIPEMD320_STEP (RIPEMD320_H , b2, c2, d2, e2, a2, w2[1], RIPEMD320C70, RIPEMD320S77);
  RIPEMD320_STEP (RIPEMD320_H , a2, b2, c2, d2, e2, w2[3], RIPEMD320C70, RIPEMD320S78);
  RIPEMD320_STEP (RIPEMD320_H , e2, a2, b2, c2, d2, w2[0], RIPEMD320C70, RIPEMD320S79);
  RIPEMD320_STEP (RIPEMD320_H , d2, e2, a2, b2, c2, w3[0], RIPEMD320C70, RIPEMD320S7A);
  RIPEMD320_STEP (RIPEMD320_H , c2, d2, e2, a2, b2, w0[2], RIPEMD320C70, RIPEMD320S7B);
  RIPEMD320_STEP (RIPEMD320_H , b2, c2, d2, e2, a2, w2[2], RIPEMD320C70, RIPEMD320S7C);
  RIPEMD320_STEP (RIPEMD320_H , a2, b2, c2, d2, e2, w0[0], RIPEMD320C70, RIPEMD320S7D);
  RIPEMD320_STEP (RIPEMD320_H , e2, a2, b2, c2, d2, w1[0], RIPEMD320C70, RIPEMD320S7E);
  RIPEMD320_STEP (RIPEMD320_H , d2, e2, a2, b2, c2, w3[1], RIPEMD320C70, RIPEMD320S7F);

  tmp = c1; c1 = c2; c2 = tmp;

  RIPEMD320_STEP (RIPEMD320_Io, c1, d1, e1, a1, b1, w0[1], RIPEMD320C30, RIPEMD320S30);
  RIPEMD320_STEP (RIPEMD320_Io, b1, c1, d1, e1, a1, w2[1], RIPEMD320C30, RIPEMD320S31);
  RIPEMD320_STEP (RIPEMD320_Io, a1, b1, c1, d1, e1, w2[3], RIPEMD320C30, RIPEMD320S32);
  RIPEMD320_STEP (RIPEMD320_Io, e1, a1, b1, c1, d1, w2[2], RIPEMD320C30, RIPEMD320S33);
  RIPEMD320_STEP (RIPEMD320_Io, d1, e1, a1, b1, c1, w0[0], RIPEMD320C30, RIPEMD320S34);
  RIPEMD320_STEP (RIPEMD320_Io, c1, d1, e1, a1, b1, w2[0], RIPEMD320C30, RIPEMD320S35);
  RIPEMD320_STEP (RIPEMD320_Io, b1, c1, d1, e1, a1, w3[0], RIPEMD320C30, RIPEMD320S36);
  RIPEMD320_STEP (RIPEMD320_Io, a1, b1, c1, d1, e1, w1[0], RIPEMD320C30, RIPEMD320S37);
  RIPEMD320_STEP (RIPEMD320_Io, e1, a1, b1, c1, d1, w3[1], RIPEMD320C30, RIPEMD320S38);
  RIPEMD320_STEP (RIPEMD320_Io, d1, e1, a1, b1, c1, w0[3], RIPEMD320C30, RIPEMD320S39);
  RIPEMD320_STEP (RIPEMD320_Io, c1, d1, e1, a1, b1, w1[3], RIPEMD320C30, RIPEMD320S3A);
  RIPEMD320_STEP (RIPEMD320_Io, b1, c1, d1, e1, a1, w3[3], RIPEMD320C30, RIPEMD320S3B);
  RIPEMD320_STEP (RIPEMD320_Io, a1, b1, c1, d1, e1, w3[2], RIPEMD320C30, RIPEMD320S3C);
  RIPEMD320_STEP (RIPEMD320_Io, e1, a1, b1, c1, d1, w1[1], RIPEMD320C30, RIPEMD320S3D);
  RIPEMD320_STEP (RIPEMD320_Io, d1, e1, a1, b1, c1, w1[2], RIPEMD320C30, RIPEMD320S3E);
  RIPEMD320_STEP (RIPEMD320_Io, c1, d1, e1, a1, b1, w0[2], RIPEMD320C30, RIPEMD320S3F);

  RIPEMD320_STEP (RIPEMD320_Go, c2, d2, e2, a2, b2, w2[0], RIPEMD320C80, RIPEMD320S80);
  RIPEMD320_STEP (RIPEMD320_Go, b2, c2, d2, e2, a2, w1[2], RIPEMD320C80, RIPEMD320S81);
  RIPEMD320_STEP (RIPEMD320_Go, a2, b2, c2, d2, e2, w1[0], RIPEMD320C80, RIPEMD320S82);
  RIPEMD320_STEP (RIPEMD320_Go, e2, a2, b2, c2, d2, w0[1], RIPEMD320C80, RIPEMD320S83);
  RIPEMD320_STEP (RIPEMD320_Go, d2, e2, a2, b2, c2, w0[3], RIPEMD320C80, RIPEMD320S84);
  RIPEMD320_STEP (RIPEMD320_Go, c2, d2, e2, a2, b2, w2[3], RIPEMD320C80, RIPEMD320S85);
  RIPEMD320_STEP (RIPEMD320_Go, b2, c2, d2, e2, a2, w3[3], RIPEMD320C80, RIPEMD320S86);
  RIPEMD320_STEP (RIPEMD320_Go, a2, b2, c2, d2, e2, w0[0], RIPEMD320C80, RIPEMD320S87);
  RIPEMD320_STEP (RIPEMD320_Go, e2, a2, b2, c2, d2, w1[1], RIPEMD320C80, RIPEMD320S88);
  RIPEMD320_STEP (RIPEMD320_Go, d2, e2, a2, b2, c2, w3[0], RIPEMD320C80, RIPEMD320S89);
  RIPEMD320_STEP (RIPEMD320_Go, c2, d2, e2, a2, b2, w0[2], RIPEMD320C80, RIPEMD320S8A);
  RIPEMD320_STEP (RIPEMD320_Go, b2, c2, d2, e2, a2, w3[1], RIPEMD320C80, RIPEMD320S8B);
  RIPEMD320_STEP (RIPEMD320_Go, a2, b2, c2, d2, e2, w2[1], RIPEMD320C80, RIPEMD320S8C);
  RIPEMD320_STEP (RIPEMD320_Go, e2, a2, b2, c2, d2, w1[3], RIPEMD320C80, RIPEMD320S8D);
  RIPEMD320_STEP (RIPEMD320_Go, d2, e2, a2, b2, c2, w2[2], RIPEMD320C80, RIPEMD320S8E);
  RIPEMD320_STEP (RIPEMD320_Go, c2, d2, e2, a2, b2, w3[2], RIPEMD320C80, RIPEMD320S8F);

  tmp = d1; d1 = d2; d2 = tmp;

  RIPEMD320_STEP (RIPEMD320_J , b1, c1, d1, e1, a1, w1[0], RIPEMD320C40, RIPEMD320S40);
  RIPEMD320_STEP (RIPEMD320_J , a1, b1, c1, d1, e1, w0[0], RIPEMD320C40, RIPEMD320S41);
  RIPEMD320_STEP (RIPEMD320_J , e1, a1, b1, c1, d1, w1[1], RIPEMD320C40, RIPEMD320S42);
  RIPEMD320_STEP (RIPEMD320_J , d1, e1, a1, b1, c1, w2[1], RIPEMD320C40, RIPEMD320S43);
  RIPEMD320_STEP (RIPEMD320_J , c1, d1, e1, a1, b1, w1[3], RIPEMD320C40, RIPEMD320S44);
  RIPEMD320_STEP (RIPEMD320_J , b1, c1, d1, e1, a1, w3[0], RIPEMD320C40, RIPEMD320S45);
  RIPEMD320_STEP (RIPEMD320_J , a1, b1, c1, d1, e1, w0[2], RIPEMD320C40, RIPEMD320S46);
  RIPEMD320_STEP (RIPEMD320_J , e1, a1, b1, c1, d1, w2[2], RIPEMD320C40, RIPEMD320S47);
  RIPEMD320_STEP (RIPEMD320_J , d1, e1, a1, b1, c1, w3[2], RIPEMD320C40, RIPEMD320S48);
  RIPEMD320_STEP (RIPEMD320_J , c1, d1, e1, a1, b1, w0[1], RIPEMD320C40, RIPEMD320S49);
  RIPEMD320_STEP (RIPEMD320_J , b1, c1, d1, e1, a1, w0[3], RIPEMD320C40, RIPEMD320S4A);
  RIPEMD320_STEP (RIPEMD320_J , a1, b1, c1, d1, e1, w2[0], RIPEMD320C40, RIPEMD320S4B);
  RIPEMD320_STEP (RIPEMD320_J , e1, a1, b1, c1, d1, w2[3], RIPEMD320C40, RIPEMD320S4C);
  RIPEMD320_STEP (RIPEMD320_J , d1, e1, a1, b1, c1, w1[2], RIPEMD320C40, RIPEMD320S4D);
  RIPEMD320_STEP (RIPEMD320_J , c1, d1, e1, a1, b1, w3[3], RIPEMD320C40, RIPEMD320S4E);
  RIPEMD320_STEP (RIPEMD320_J , b1, c1, d1, e1, a1, w3[1], RIPEMD320C40, RIPEMD320S4F);

  RIPEMD320_STEP (RIPEMD320_F , b2, c2, d2, e2, a2, w3[0], RIPEMD320C90, RIPEMD320S90);
  RIPEMD320_STEP (RIPEMD320_F , a2, b2, c2, d2, e2, w3[3], RIPEMD320C90, RIPEMD320S91);
  RIPEMD320_STEP (RIPEMD320_F , e2, a2, b2, c2, d2, w2[2], RIPEMD320C90, RIPEMD320S92);
  RIPEMD320_STEP (RIPEMD320_F , d2, e2, a2, b2, c2, w1[0], RIPEMD320C90, RIPEMD320S93);
  RIPEMD320_STEP (RIPEMD320_F , c2, d2, e2, a2, b2, w0[1], RIPEMD320C90, RIPEMD320S94);
  RIPEMD320_STEP (RIPEMD320_F , b2, c2, d2, e2, a2, w1[1], RIPEMD320C90, RIPEMD320S95);
  RIPEMD320_STEP (RIPEMD320_F , a2, b2, c2, d2, e2, w2[0], RIPEMD320C90, RIPEMD320S96);
  RIPEMD320_STEP (RIPEMD320_F , e2, a2, b2, c2, d2, w1[3], RIPEMD320C90, RIPEMD320S97);
  RIPEMD320_STEP (RIPEMD320_F , d2, e2, a2, b2, c2, w1[2], RIPEMD320C90, RIPEMD320S98);
  RIPEMD320_STEP (RIPEMD320_F , c2, d2, e2, a2, b2, w0[2], RIPEMD320C90, RIPEMD320S99);
  RIPEMD320_STEP (RIPEMD320_F , b2, c2, d2, e2, a2, w3[1], RIPEMD320C90, RIPEMD320S9A);
  RIPEMD320_STEP (RIPEMD320_F , a2, b2, c2, d2, e2, w3[2], RIPEMD320C90, RIPEMD320S9B);
  RIPEMD320_STEP (RIPEMD320_F , e2, a2, b2, c2, d2, w0[0], RIPEMD320C90, RIPEMD320S9C);
  RIPEMD320_STEP (RIPEMD320_F , d2, e2, a2, b2, c2, w0[3], RIPEMD320C90, RIPEMD320S9D);
  RIPEMD320_STEP (RIPEMD320_F , c2, d2, e2, a2, b2, w2[1], RIPEMD320C90, RIPEMD320S9E);
  RIPEMD320_STEP (RIPEMD320_F , b2, c2, d2, e2, a2, w2[3], RIPEMD320C90, RIPEMD320S9F);

  tmp = e1; e1 = e2; e2 = tmp;

  const u32x a = digest[0] + a1;
  const u32x b = digest[1] + b1;
  const u32x c = digest[2] + c1;
  const u32x d = digest[3] + d1;
  const u32x e = digest[4] + e1;
  const u32x f = digest[5] + a2;
  const u32x g = digest[6] + b2;
  const u32x h = digest[7] + c2;
  const u32x i = digest[8] + d2;
  const u32x l = digest[9] + e2;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
  digest[5] = f;
  digest[6] = g;
  digest[7] = h;
  digest[8] = i;
  digest[9] = l;
}

DECLSPEC void ripemd320_init_vector (PRIVATE_AS ripemd320_ctx_vector_t *ctx)
{
  ctx->h[0] = RIPEMD320M_A;
  ctx->h[1] = RIPEMD320M_B;
  ctx->h[2] = RIPEMD320M_C;
  ctx->h[3] = RIPEMD320M_D;
  ctx->h[4] = RIPEMD320M_E;
  ctx->h[5] = RIPEMD320M_F;
  ctx->h[6] = RIPEMD320M_G;
  ctx->h[7] = RIPEMD320M_H;
  ctx->h[8] = RIPEMD320M_I;
  ctx->h[9] = RIPEMD320M_L;

  ctx->w0[0] = 0;
  ctx->w0[1] = 0;
  ctx->w0[2] = 0;
  ctx->w0[3] = 0;
  ctx->w1[0] = 0;
  ctx->w1[1] = 0;
  ctx->w1[2] = 0;
  ctx->w1[3] = 0;
  ctx->w2[0] = 0;
  ctx->w2[1] = 0;
  ctx->w2[2] = 0;
  ctx->w2[3] = 0;
  ctx->w3[0] = 0;
  ctx->w3[1] = 0;
  ctx->w3[2] = 0;
  ctx->w3[3] = 0;

  ctx->len = 0;
}

DECLSPEC void ripemd320_init_vector_from_scalar (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS ripemd320_ctx_t *ctx0)
{
  ctx->h[0] = ctx0->h[0];
  ctx->h[1] = ctx0->h[1];
  ctx->h[2] = ctx0->h[2];
  ctx->h[3] = ctx0->h[3];
  ctx->h[4] = ctx0->h[4];
  ctx->h[5] = ctx0->h[5];
  ctx->h[6] = ctx0->h[6];
  ctx->h[7] = ctx0->h[7];
  ctx->h[8] = ctx0->h[8];
  ctx->h[9] = ctx0->h[9];

  ctx->w0[0] = ctx0->w0[0];
  ctx->w0[1] = ctx0->w0[1];
  ctx->w0[2] = ctx0->w0[2];
  ctx->w0[3] = ctx0->w0[3];
  ctx->w1[0] = ctx0->w1[0];
  ctx->w1[1] = ctx0->w1[1];
  ctx->w1[2] = ctx0->w1[2];
  ctx->w1[3] = ctx0->w1[3];
  ctx->w2[0] = ctx0->w2[0];
  ctx->w2[1] = ctx0->w2[1];
  ctx->w2[2] = ctx0->w2[2];
  ctx->w2[3] = ctx0->w2[3];
  ctx->w3[0] = ctx0->w3[0];
  ctx->w3[1] = ctx0->w3[1];
  ctx->w3[2] = ctx0->w3[2];
  ctx->w3[3] = ctx0->w3[3];

  ctx->len = ctx0->len;
}

DECLSPEC void ripemd320_update_vector_64 (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len)
{
  if (len == 0) return;

  const int pos = ctx->len & 63;

  ctx->len += len;

  if (pos == 0)
  {
    ctx->w0[0] = w0[0];
    ctx->w0[1] = w0[1];
    ctx->w0[2] = w0[2];
    ctx->w0[3] = w0[3];
    ctx->w1[0] = w1[0];
    ctx->w1[1] = w1[1];
    ctx->w1[2] = w1[2];
    ctx->w1[3] = w1[3];
    ctx->w2[0] = w2[0];
    ctx->w2[1] = w2[1];
    ctx->w2[2] = w2[2];
    ctx->w2[3] = w2[3];
    ctx->w3[0] = w3[0];
    ctx->w3[1] = w3[1];
    ctx->w3[2] = w3[2];
    ctx->w3[3] = w3[3];

    if (len == 64)
    {
      ripemd320_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

      ctx->w0[0] = 0;
      ctx->w0[1] = 0;
      ctx->w0[2] = 0;
      ctx->w0[3] = 0;
      ctx->w1[0] = 0;
      ctx->w1[1] = 0;
      ctx->w1[2] = 0;
      ctx->w1[3] = 0;
      ctx->w2[0] = 0;
      ctx->w2[1] = 0;
      ctx->w2[2] = 0;
      ctx->w2[3] = 0;
      ctx->w3[0] = 0;
      ctx->w3[1] = 0;
      ctx->w3[2] = 0;
      ctx->w3[3] = 0;
    }
  }
  else
  {
    if ((pos + len) < 64)
    {
      switch_buffer_by_offset_le (w0, w1, w2, w3, pos);

      ctx->w0[0] |= w0[0];
      ctx->w0[1] |= w0[1];
      ctx->w0[2] |= w0[2];
      ctx->w0[3] |= w0[3];
      ctx->w1[0] |= w1[0];
      ctx->w1[1] |= w1[1];
      ctx->w1[2] |= w1[2];
      ctx->w1[3] |= w1[3];
      ctx->w2[0] |= w2[0];
      ctx->w2[1] |= w2[1];
      ctx->w2[2] |= w2[2];
      ctx->w2[3] |= w2[3];
      ctx->w3[0] |= w3[0];
      ctx->w3[1] |= w3[1];
      ctx->w3[2] |= w3[2];
      ctx->w3[3] |= w3[3];
    }
    else
    {
      u32x c0[4] = { 0 };
      u32x c1[4] = { 0 };
      u32x c2[4] = { 0 };
      u32x c3[4] = { 0 };

      switch_buffer_by_offset_carry_le (w0, w1, w2, w3, c0, c1, c2, c3, pos);

      ctx->w0[0] |= w0[0];
      ctx->w0[1] |= w0[1];
      ctx->w0[2] |= w0[2];
      ctx->w0[3] |= w0[3];
      ctx->w1[0] |= w1[0];
      ctx->w1[1] |= w1[1];
      ctx->w1[2] |= w1[2];
      ctx->w1[3] |= w1[3];
      ctx->w2[0] |= w2[0];
      ctx->w2[1] |= w2[1];
      ctx->w2[2] |= w2[2];
      ctx->w2[3] |= w2[3];
      ctx->w3[0] |= w3[0];
      ctx->w3[1] |= w3[1];
      ctx->w3[2] |= w3[2];
      ctx->w3[3] |= w3[3];

      ripemd320_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

      ctx->w0[0] = c0[0];
      ctx->w0[1] = c0[1];
      ctx->w0[2] = c0[2];
      ctx->w0[3] = c0[3];
      ctx->w1[0] = c1[0];
      ctx->w1[1] = c1[1];
      ctx->w1[2] = c1[2];
      ctx->w1[3] = c1[3];
      ctx->w2[0] = c2[0];
      ctx->w2[1] = c2[1];
      ctx->w2[2] = c2[2];
      ctx->w2[3] = c2[3];
      ctx->w3[0] = c3[0];
      ctx->w3[1] = c3[1];
      ctx->w3[2] = c3[2];
      ctx->w3[3] = c3[3];
    }
  }
}

DECLSPEC void ripemd320_update_vector (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    ripemd320_update_vector_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  ripemd320_update_vector_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd320_update_vector_swap (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = hc_swap32 (w3[2]);
    w3[3] = hc_swap32 (w3[3]);

    ripemd320_update_vector_64 (ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  w0[0] = hc_swap32 (w0[0]);
  w0[1] = hc_swap32 (w0[1]);
  w0[2] = hc_swap32 (w0[2]);
  w0[3] = hc_swap32 (w0[3]);
  w1[0] = hc_swap32 (w1[0]);
  w1[1] = hc_swap32 (w1[1]);
  w1[2] = hc_swap32 (w1[2]);
  w1[3] = hc_swap32 (w1[3]);
  w2[0] = hc_swap32 (w2[0]);
  w2[1] = hc_swap32 (w2[1]);
  w2[2] = hc_swap32 (w2[2]);
  w2[3] = hc_swap32 (w2[3]);
  w3[0] = hc_swap32 (w3[0]);
  w3[1] = hc_swap32 (w3[1]);
  w3[2] = hc_swap32 (w3[2]);
  w3[3] = hc_swap32 (w3[3]);

  ripemd320_update_vector_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void ripemd320_update_vector_utf16le (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    ripemd320_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  ripemd320_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd320_update_vector_utf16le_swap (PRIVATE_AS ripemd320_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = hc_swap32 (w3[2]);
    w3[3] = hc_swap32 (w3[3]);

    ripemd320_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  w0[0] = hc_swap32 (w0[0]);
  w0[1] = hc_swap32 (w0[1]);
  w0[2] = hc_swap32 (w0[2]);
  w0[3] = hc_swap32 (w0[3]);
  w1[0] = hc_swap32 (w1[0]);
  w1[1] = hc_swap32 (w1[1]);
  w1[2] = hc_swap32 (w1[2]);
  w1[3] = hc_swap32 (w1[3]);
  w2[0] = hc_swap32 (w2[0]);
  w2[1] = hc_swap32 (w2[1]);
  w2[2] = hc_swap32 (w2[2]);
  w2[3] = hc_swap32 (w2[3]);
  w3[0] = hc_swap32 (w3[0]);
  w3[1] = hc_swap32 (w3[1]);
  w3[2] = hc_swap32 (w3[2]);
  w3[3] = hc_swap32 (w3[3]);

  ripemd320_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void ripemd320_final_vector (PRIVATE_AS ripemd320_ctx_vector_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x80_4x4 (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos);

  if (pos >= 56)
  {
    ripemd320_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
  }

  ctx->w3[2] = ctx->len * 8;
  ctx->w3[3] = 0;

  ripemd320_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

// HMAC + Vector

DECLSPEC void ripemd320_hmac_init_vector_64 (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3)
{
  u32x a0[4];
  u32x a1[4];
  u32x a2[4];
  u32x a3[4];

  // ipad

  a0[0] = w0[0] ^ 0x36363636;
  a0[1] = w0[1] ^ 0x36363636;
  a0[2] = w0[2] ^ 0x36363636;
  a0[3] = w0[3] ^ 0x36363636;
  a1[0] = w1[0] ^ 0x36363636;
  a1[1] = w1[1] ^ 0x36363636;
  a1[2] = w1[2] ^ 0x36363636;
  a1[3] = w1[3] ^ 0x36363636;
  a2[0] = w2[0] ^ 0x36363636;
  a2[1] = w2[1] ^ 0x36363636;
  a2[2] = w2[2] ^ 0x36363636;
  a2[3] = w2[3] ^ 0x36363636;
  a3[0] = w3[0] ^ 0x36363636;
  a3[1] = w3[1] ^ 0x36363636;
  a3[2] = w3[2] ^ 0x36363636;
  a3[3] = w3[3] ^ 0x36363636;

  ripemd320_init_vector (&ctx->ipad);

  ripemd320_update_vector_64 (&ctx->ipad, a0, a1, a2, a3, 64);

  // opad

  u32x b0[4];
  u32x b1[4];
  u32x b2[4];
  u32x b3[4];

  b0[0] = w0[0] ^ 0x5c5c5c5c;
  b0[1] = w0[1] ^ 0x5c5c5c5c;
  b0[2] = w0[2] ^ 0x5c5c5c5c;
  b0[3] = w0[3] ^ 0x5c5c5c5c;
  b1[0] = w1[0] ^ 0x5c5c5c5c;
  b1[1] = w1[1] ^ 0x5c5c5c5c;
  b1[2] = w1[2] ^ 0x5c5c5c5c;
  b1[3] = w1[3] ^ 0x5c5c5c5c;
  b2[0] = w2[0] ^ 0x5c5c5c5c;
  b2[1] = w2[1] ^ 0x5c5c5c5c;
  b2[2] = w2[2] ^ 0x5c5c5c5c;
  b2[3] = w2[3] ^ 0x5c5c5c5c;
  b3[0] = w3[0] ^ 0x5c5c5c5c;
  b3[1] = w3[1] ^ 0x5c5c5c5c;
  b3[2] = w3[2] ^ 0x5c5c5c5c;
  b3[3] = w3[3] ^ 0x5c5c5c5c;

  ripemd320_init_vector (&ctx->opad);

  ripemd320_update_vector_64 (&ctx->opad, b0, b1, b2, b3, 64);
}

DECLSPEC void ripemd320_hmac_init_vector (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  if (len > 64)
  {
    ripemd320_ctx_vector_t tmp;

    ripemd320_init_vector (&tmp);

    ripemd320_update_vector (&tmp, w, len);

    ripemd320_final_vector (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = tmp.h[5];
    w1[2] = tmp.h[6];
    w1[3] = tmp.h[7];
    w2[0] = tmp.h[8];
    w2[1] = tmp.h[9];
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
  }

  ripemd320_hmac_init_vector_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void ripemd320_hmac_update_vector_64 (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len)
{
  ripemd320_update_vector_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void ripemd320_hmac_update_vector (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  ripemd320_update_vector (&ctx->ipad, w, len);
}

DECLSPEC void ripemd320_hmac_final_vector (PRIVATE_AS ripemd320_hmac_ctx_vector_t *ctx)
{
  ripemd320_final_vector (&ctx->ipad);

  ctx->opad.w0[0] = ctx->ipad.h[0];
  ctx->opad.w0[1] = ctx->ipad.h[1];
  ctx->opad.w0[2] = ctx->ipad.h[2];
  ctx->opad.w0[3] = ctx->ipad.h[3];
  ctx->opad.w1[0] = ctx->ipad.h[4];
  ctx->opad.w1[1] = ctx->ipad.h[5];
  ctx->opad.w1[2] = ctx->ipad.h[6];
  ctx->opad.w1[3] = ctx->ipad.h[7];
  ctx->opad.w2[0] = ctx->ipad.h[8];
  ctx->opad.w2[1] = ctx->ipad.h[9];
  ctx->opad.w2[2] = 0;
  ctx->opad.w2[3] = 0;
  ctx->opad.w3[0] = 0;
  ctx->opad.w3[1] = 0;
  ctx->opad.w3[2] = 0;
  ctx->opad.w3[3] = 0;

  ctx->opad.len += 40;

  ripemd320_final_vector (&ctx->opad);
}
