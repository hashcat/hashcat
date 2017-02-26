/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

void ripemd160_transform (const u32x w[16], u32x dgst[5])
{
  u32x a1 = dgst[0];
  u32x b1 = dgst[1];
  u32x c1 = dgst[2];
  u32x d1 = dgst[3];
  u32x e1 = dgst[4];

  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w[ 0], RIPEMD160C00, RIPEMD160S00);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, w[ 1], RIPEMD160C00, RIPEMD160S01);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, w[ 2], RIPEMD160C00, RIPEMD160S02);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, w[ 3], RIPEMD160C00, RIPEMD160S03);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, w[ 4], RIPEMD160C00, RIPEMD160S04);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w[ 5], RIPEMD160C00, RIPEMD160S05);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, w[ 6], RIPEMD160C00, RIPEMD160S06);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, w[ 7], RIPEMD160C00, RIPEMD160S07);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, w[ 8], RIPEMD160C00, RIPEMD160S08);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, w[ 9], RIPEMD160C00, RIPEMD160S09);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w[10], RIPEMD160C00, RIPEMD160S0A);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, w[11], RIPEMD160C00, RIPEMD160S0B);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, w[12], RIPEMD160C00, RIPEMD160S0C);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, w[13], RIPEMD160C00, RIPEMD160S0D);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, w[14], RIPEMD160C00, RIPEMD160S0E);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w[15], RIPEMD160C00, RIPEMD160S0F);

  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w[ 7], RIPEMD160C10, RIPEMD160S10);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, w[ 4], RIPEMD160C10, RIPEMD160S11);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, w[13], RIPEMD160C10, RIPEMD160S12);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, w[ 1], RIPEMD160C10, RIPEMD160S13);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, w[10], RIPEMD160C10, RIPEMD160S14);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w[ 6], RIPEMD160C10, RIPEMD160S15);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, w[15], RIPEMD160C10, RIPEMD160S16);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, w[ 3], RIPEMD160C10, RIPEMD160S17);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, w[12], RIPEMD160C10, RIPEMD160S18);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, w[ 0], RIPEMD160C10, RIPEMD160S19);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w[ 9], RIPEMD160C10, RIPEMD160S1A);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, w[ 5], RIPEMD160C10, RIPEMD160S1B);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, w[ 2], RIPEMD160C10, RIPEMD160S1C);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, w[14], RIPEMD160C10, RIPEMD160S1D);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, w[11], RIPEMD160C10, RIPEMD160S1E);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w[ 8], RIPEMD160C10, RIPEMD160S1F);

  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w[ 3], RIPEMD160C20, RIPEMD160S20);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, w[10], RIPEMD160C20, RIPEMD160S21);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, w[14], RIPEMD160C20, RIPEMD160S22);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, w[ 4], RIPEMD160C20, RIPEMD160S23);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w[ 9], RIPEMD160C20, RIPEMD160S24);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w[15], RIPEMD160C20, RIPEMD160S25);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, w[ 8], RIPEMD160C20, RIPEMD160S26);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, w[ 1], RIPEMD160C20, RIPEMD160S27);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, w[ 2], RIPEMD160C20, RIPEMD160S28);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w[ 7], RIPEMD160C20, RIPEMD160S29);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w[ 0], RIPEMD160C20, RIPEMD160S2A);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, w[ 6], RIPEMD160C20, RIPEMD160S2B);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, w[13], RIPEMD160C20, RIPEMD160S2C);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, w[11], RIPEMD160C20, RIPEMD160S2D);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w[ 5], RIPEMD160C20, RIPEMD160S2E);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w[12], RIPEMD160C20, RIPEMD160S2F);

  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w[ 1], RIPEMD160C30, RIPEMD160S30);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, w[ 9], RIPEMD160C30, RIPEMD160S31);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, w[11], RIPEMD160C30, RIPEMD160S32);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, w[10], RIPEMD160C30, RIPEMD160S33);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w[ 0], RIPEMD160C30, RIPEMD160S34);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w[ 8], RIPEMD160C30, RIPEMD160S35);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, w[12], RIPEMD160C30, RIPEMD160S36);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, w[ 4], RIPEMD160C30, RIPEMD160S37);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, w[13], RIPEMD160C30, RIPEMD160S38);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w[ 3], RIPEMD160C30, RIPEMD160S39);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w[ 7], RIPEMD160C30, RIPEMD160S3A);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, w[15], RIPEMD160C30, RIPEMD160S3B);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, w[14], RIPEMD160C30, RIPEMD160S3C);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, w[ 5], RIPEMD160C30, RIPEMD160S3D);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w[ 6], RIPEMD160C30, RIPEMD160S3E);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w[ 2], RIPEMD160C30, RIPEMD160S3F);

  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w[ 4], RIPEMD160C40, RIPEMD160S40);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w[ 0], RIPEMD160C40, RIPEMD160S41);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, w[ 5], RIPEMD160C40, RIPEMD160S42);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, w[ 9], RIPEMD160C40, RIPEMD160S43);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, w[ 7], RIPEMD160C40, RIPEMD160S44);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w[12], RIPEMD160C40, RIPEMD160S45);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w[ 2], RIPEMD160C40, RIPEMD160S46);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, w[10], RIPEMD160C40, RIPEMD160S47);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, w[14], RIPEMD160C40, RIPEMD160S48);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, w[ 1], RIPEMD160C40, RIPEMD160S49);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w[ 3], RIPEMD160C40, RIPEMD160S4A);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w[ 8], RIPEMD160C40, RIPEMD160S4B);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, w[11], RIPEMD160C40, RIPEMD160S4C);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, w[ 6], RIPEMD160C40, RIPEMD160S4D);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, w[15], RIPEMD160C40, RIPEMD160S4E);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w[13], RIPEMD160C40, RIPEMD160S4F);

  u32x a2 = dgst[0];
  u32x b2 = dgst[1];
  u32x c2 = dgst[2];
  u32x d2 = dgst[3];
  u32x e2 = dgst[4];

  RIPEMD160_STEP_WORKAROUND_BUG (RIPEMD160_J , a2, b2, c2, d2, e2, w[ 5], RIPEMD160C50, RIPEMD160S50);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, w[14], RIPEMD160C50, RIPEMD160S51);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w[ 7], RIPEMD160C50, RIPEMD160S52);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, w[ 0], RIPEMD160C50, RIPEMD160S53);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w[ 9], RIPEMD160C50, RIPEMD160S54);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, w[ 2], RIPEMD160C50, RIPEMD160S55);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, w[11], RIPEMD160C50, RIPEMD160S56);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w[ 4], RIPEMD160C50, RIPEMD160S57);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, w[13], RIPEMD160C50, RIPEMD160S58);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w[ 6], RIPEMD160C50, RIPEMD160S59);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, w[15], RIPEMD160C50, RIPEMD160S5A);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, w[ 8], RIPEMD160C50, RIPEMD160S5B);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w[ 1], RIPEMD160C50, RIPEMD160S5C);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, w[10], RIPEMD160C50, RIPEMD160S5D);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w[ 3], RIPEMD160C50, RIPEMD160S5E);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, w[12], RIPEMD160C50, RIPEMD160S5F);

  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w[ 6], RIPEMD160C60, RIPEMD160S60);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, w[11], RIPEMD160C60, RIPEMD160S61);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, w[ 3], RIPEMD160C60, RIPEMD160S62);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, w[ 7], RIPEMD160C60, RIPEMD160S63);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, w[ 0], RIPEMD160C60, RIPEMD160S64);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w[13], RIPEMD160C60, RIPEMD160S65);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, w[ 5], RIPEMD160C60, RIPEMD160S66);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, w[10], RIPEMD160C60, RIPEMD160S67);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, w[14], RIPEMD160C60, RIPEMD160S68);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, w[15], RIPEMD160C60, RIPEMD160S69);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w[ 8], RIPEMD160C60, RIPEMD160S6A);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, w[12], RIPEMD160C60, RIPEMD160S6B);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, w[ 4], RIPEMD160C60, RIPEMD160S6C);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, w[ 9], RIPEMD160C60, RIPEMD160S6D);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, w[ 1], RIPEMD160C60, RIPEMD160S6E);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w[ 2], RIPEMD160C60, RIPEMD160S6F);

  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, w[15], RIPEMD160C70, RIPEMD160S70);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w[ 5], RIPEMD160C70, RIPEMD160S71);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, w[ 1], RIPEMD160C70, RIPEMD160S72);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, w[ 3], RIPEMD160C70, RIPEMD160S73);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w[ 7], RIPEMD160C70, RIPEMD160S74);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, w[14], RIPEMD160C70, RIPEMD160S75);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w[ 6], RIPEMD160C70, RIPEMD160S76);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, w[ 9], RIPEMD160C70, RIPEMD160S77);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, w[11], RIPEMD160C70, RIPEMD160S78);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w[ 8], RIPEMD160C70, RIPEMD160S79);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, w[12], RIPEMD160C70, RIPEMD160S7A);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w[ 2], RIPEMD160C70, RIPEMD160S7B);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, w[10], RIPEMD160C70, RIPEMD160S7C);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, w[ 0], RIPEMD160C70, RIPEMD160S7D);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w[ 4], RIPEMD160C70, RIPEMD160S7E);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, w[13], RIPEMD160C70, RIPEMD160S7F);

  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w[ 8], RIPEMD160C80, RIPEMD160S80);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, w[ 6], RIPEMD160C80, RIPEMD160S81);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w[ 4], RIPEMD160C80, RIPEMD160S82);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w[ 1], RIPEMD160C80, RIPEMD160S83);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, w[ 3], RIPEMD160C80, RIPEMD160S84);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w[11], RIPEMD160C80, RIPEMD160S85);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, w[15], RIPEMD160C80, RIPEMD160S86);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w[ 0], RIPEMD160C80, RIPEMD160S87);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w[ 5], RIPEMD160C80, RIPEMD160S88);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, w[12], RIPEMD160C80, RIPEMD160S89);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w[ 2], RIPEMD160C80, RIPEMD160S8A);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, w[13], RIPEMD160C80, RIPEMD160S8B);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w[ 9], RIPEMD160C80, RIPEMD160S8C);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w[ 7], RIPEMD160C80, RIPEMD160S8D);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, w[10], RIPEMD160C80, RIPEMD160S8E);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w[14], RIPEMD160C80, RIPEMD160S8F);

  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w[12], RIPEMD160C90, RIPEMD160S90);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, w[15], RIPEMD160C90, RIPEMD160S91);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, w[10], RIPEMD160C90, RIPEMD160S92);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w[ 4], RIPEMD160C90, RIPEMD160S93);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w[ 1], RIPEMD160C90, RIPEMD160S94);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w[ 5], RIPEMD160C90, RIPEMD160S95);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, w[ 8], RIPEMD160C90, RIPEMD160S96);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, w[ 7], RIPEMD160C90, RIPEMD160S97);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w[ 6], RIPEMD160C90, RIPEMD160S98);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w[ 2], RIPEMD160C90, RIPEMD160S99);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w[13], RIPEMD160C90, RIPEMD160S9A);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, w[14], RIPEMD160C90, RIPEMD160S9B);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, w[ 0], RIPEMD160C90, RIPEMD160S9C);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w[ 3], RIPEMD160C90, RIPEMD160S9D);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w[ 9], RIPEMD160C90, RIPEMD160S9E);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w[11], RIPEMD160C90, RIPEMD160S9F);

  const u32x a = dgst[1] + c1 + d2;
  const u32x b = dgst[2] + d1 + e2;
  const u32x c = dgst[3] + e1 + a2;
  const u32x d = dgst[4] + a1 + b2;
  const u32x e = dgst[0] + b1 + c2;

  dgst[0] = a;
  dgst[1] = b;
  dgst[2] = c;
  dgst[3] = d;
  dgst[4] = e;
}

__kernel void m06000_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global netntlm_t *netntlm_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos);

    const u32x pw_len = pw_l_len + pw_r_len;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    /**
     * RipeMD160
     */

    u32x w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = w2[0];
    w[ 9] = w2[1];
    w[10] = w2[2];
    w[11] = w2[3];
    w[12] = w3[0];
    w[13] = w3[1];
    w[14] = pw_len * 8;
    w[15] = 0;

    u32x dgst[5];

    dgst[0] = RIPEMD160M_A;
    dgst[1] = RIPEMD160M_B;
    dgst[2] = RIPEMD160M_C;
    dgst[3] = RIPEMD160M_D;
    dgst[4] = RIPEMD160M_E;

    ripemd160_transform (w, dgst);

    COMPARE_M_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

__kernel void m06000_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m06000_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m06000_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global netntlm_t *netntlm_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos);

    const u32x pw_len = pw_l_len + pw_r_len;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    /**
     * RipeMD160
     */

    u32x w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = w2[0];
    w[ 9] = w2[1];
    w[10] = w2[2];
    w[11] = w2[3];
    w[12] = w3[0];
    w[13] = w3[1];
    w[14] = pw_len * 8;
    w[15] = 0;

    u32x dgst[5];

    dgst[0] = RIPEMD160M_A;
    dgst[1] = RIPEMD160M_B;
    dgst[2] = RIPEMD160M_C;
    dgst[3] = RIPEMD160M_D;
    dgst[4] = RIPEMD160M_E;

    ripemd160_transform (w, dgst);

    COMPARE_S_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

__kernel void m06000_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m06000_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
