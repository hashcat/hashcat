/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define _RIPEMD160_

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"

#include "inc_cipher_aes256.cl"
#include "inc_cipher_twofish256.cl"
#include "inc_cipher_serpent256.cl"

#include "inc_truecrypt_crc32.cl"
#include "inc_truecrypt_xts.cl"

static void ripemd160_transform (const u32 w[16], u32 dgst[5])
{
  u32 a1 = dgst[0];
  u32 b1 = dgst[1];
  u32 c1 = dgst[2];
  u32 d1 = dgst[3];
  u32 e1 = dgst[4];

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

  u32 a2 = dgst[0];
  u32 b2 = dgst[1];
  u32 c2 = dgst[2];
  u32 d2 = dgst[3];
  u32 e2 = dgst[4];

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

  const u32 a = dgst[1] + c1 + d2;
  const u32 b = dgst[2] + d1 + e2;
  const u32 c = dgst[3] + e1 + a2;
  const u32 d = dgst[4] + a1 + b2;
  const u32 e = dgst[0] + b1 + c2;

  dgst[0] = a;
  dgst[1] = b;
  dgst[2] = c;
  dgst[3] = d;
  dgst[4] = e;
}

static void hmac_run2 (const u32 w1[16], const u32 w2[16], const u32 ipad[5], const u32 opad[5], u32 dgst[5])
{
  dgst[0] = ipad[0];
  dgst[1] = ipad[1];
  dgst[2] = ipad[2];
  dgst[3] = ipad[3];
  dgst[4] = ipad[4];

  ripemd160_transform (w1, dgst);
  ripemd160_transform (w2, dgst);

  u32 w[16];

  w[ 0] = dgst[0];
  w[ 1] = dgst[1];
  w[ 2] = dgst[2];
  w[ 3] = dgst[3];
  w[ 4] = dgst[4];
  w[ 5] = 0x80;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = (64 + 20) * 8;
  w[15] = 0;

  dgst[0] = opad[0];
  dgst[1] = opad[1];
  dgst[2] = opad[2];
  dgst[3] = opad[3];
  dgst[4] = opad[4];

  ripemd160_transform (w, dgst);
}

static void hmac_run (u32 w[16], const u32 ipad[5], const u32 opad[5], u32 dgst[5])
{
  dgst[0] = ipad[0];
  dgst[1] = ipad[1];
  dgst[2] = ipad[2];
  dgst[3] = ipad[3];
  dgst[4] = ipad[4];

  ripemd160_transform (w, dgst);

  w[ 0] = dgst[0];
  w[ 1] = dgst[1];
  w[ 2] = dgst[2];
  w[ 3] = dgst[3];
  w[ 4] = dgst[4];
  w[ 5] = 0x80;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = (64 + 20) * 8;
  w[15] = 0;

  dgst[0] = opad[0];
  dgst[1] = opad[1];
  dgst[2] = opad[2];
  dgst[3] = opad[3];
  dgst[4] = opad[4];

  ripemd160_transform (w, dgst);
}

static void hmac_init (u32 w[16], u32 ipad[5], u32 opad[5])
{
  w[ 0] ^= 0x36363636;
  w[ 1] ^= 0x36363636;
  w[ 2] ^= 0x36363636;
  w[ 3] ^= 0x36363636;
  w[ 4] ^= 0x36363636;
  w[ 5] ^= 0x36363636;
  w[ 6] ^= 0x36363636;
  w[ 7] ^= 0x36363636;
  w[ 8] ^= 0x36363636;
  w[ 9] ^= 0x36363636;
  w[10] ^= 0x36363636;
  w[11] ^= 0x36363636;
  w[12] ^= 0x36363636;
  w[13] ^= 0x36363636;
  w[14] ^= 0x36363636;
  w[15] ^= 0x36363636;

  ipad[0] = RIPEMD160M_A;
  ipad[1] = RIPEMD160M_B;
  ipad[2] = RIPEMD160M_C;
  ipad[3] = RIPEMD160M_D;
  ipad[4] = RIPEMD160M_E;

  ripemd160_transform (w, ipad);

  w[ 0] ^= 0x6a6a6a6a;
  w[ 1] ^= 0x6a6a6a6a;
  w[ 2] ^= 0x6a6a6a6a;
  w[ 3] ^= 0x6a6a6a6a;
  w[ 4] ^= 0x6a6a6a6a;
  w[ 5] ^= 0x6a6a6a6a;
  w[ 6] ^= 0x6a6a6a6a;
  w[ 7] ^= 0x6a6a6a6a;
  w[ 8] ^= 0x6a6a6a6a;
  w[ 9] ^= 0x6a6a6a6a;
  w[10] ^= 0x6a6a6a6a;
  w[11] ^= 0x6a6a6a6a;
  w[12] ^= 0x6a6a6a6a;
  w[13] ^= 0x6a6a6a6a;
  w[14] ^= 0x6a6a6a6a;
  w[15] ^= 0x6a6a6a6a;

  opad[0] = RIPEMD160M_A;
  opad[1] = RIPEMD160M_B;
  opad[2] = RIPEMD160M_C;
  opad[3] = RIPEMD160M_D;
  opad[4] = RIPEMD160M_E;

  ripemd160_transform (w, opad);
}

static u32 u8add (const u32 a, const u32 b)
{
  const u32 a1 = (a >>  0) & 0xff;
  const u32 a2 = (a >>  8) & 0xff;
  const u32 a3 = (a >> 16) & 0xff;
  const u32 a4 = (a >> 24) & 0xff;

  const u32 b1 = (b >>  0) & 0xff;
  const u32 b2 = (b >>  8) & 0xff;
  const u32 b3 = (b >> 16) & 0xff;
  const u32 b4 = (b >> 24) & 0xff;

  const u32 r1 = (a1 + b1) & 0xff;
  const u32 r2 = (a2 + b2) & 0xff;
  const u32 r3 = (a3 + b3) & 0xff;
  const u32 r4 = (a4 + b4) & 0xff;

  const u32 r = r1 <<  0
               | r2 <<  8
               | r3 << 16
               | r4 << 24;

  return r;
}

__kernel void m06213_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global tc_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global tc_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  /**
   * keyfile
   */

  w0[0] = u8add (w0[0], esalt_bufs[salt_pos].keyfile_buf[ 0]);
  w0[1] = u8add (w0[1], esalt_bufs[salt_pos].keyfile_buf[ 1]);
  w0[2] = u8add (w0[2], esalt_bufs[salt_pos].keyfile_buf[ 2]);
  w0[3] = u8add (w0[3], esalt_bufs[salt_pos].keyfile_buf[ 3]);
  w1[0] = u8add (w1[0], esalt_bufs[salt_pos].keyfile_buf[ 4]);
  w1[1] = u8add (w1[1], esalt_bufs[salt_pos].keyfile_buf[ 5]);
  w1[2] = u8add (w1[2], esalt_bufs[salt_pos].keyfile_buf[ 6]);
  w1[3] = u8add (w1[3], esalt_bufs[salt_pos].keyfile_buf[ 7]);
  w2[0] = u8add (w2[0], esalt_bufs[salt_pos].keyfile_buf[ 8]);
  w2[1] = u8add (w2[1], esalt_bufs[salt_pos].keyfile_buf[ 9]);
  w2[2] = u8add (w2[2], esalt_bufs[salt_pos].keyfile_buf[10]);
  w2[3] = u8add (w2[3], esalt_bufs[salt_pos].keyfile_buf[11]);
  w3[0] = u8add (w3[0], esalt_bufs[salt_pos].keyfile_buf[12]);
  w3[1] = u8add (w3[1], esalt_bufs[salt_pos].keyfile_buf[13]);
  w3[2] = u8add (w3[2], esalt_bufs[salt_pos].keyfile_buf[14]);
  w3[3] = u8add (w3[3], esalt_bufs[salt_pos].keyfile_buf[15]);

  /**
   * salt
   */

  u32 salt_buf1[16];

  salt_buf1[ 0] = esalt_bufs[salt_pos].salt_buf[ 0];
  salt_buf1[ 1] = esalt_bufs[salt_pos].salt_buf[ 1];
  salt_buf1[ 2] = esalt_bufs[salt_pos].salt_buf[ 2];
  salt_buf1[ 3] = esalt_bufs[salt_pos].salt_buf[ 3];
  salt_buf1[ 4] = esalt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[ 5] = esalt_bufs[salt_pos].salt_buf[ 5];
  salt_buf1[ 6] = esalt_bufs[salt_pos].salt_buf[ 6];
  salt_buf1[ 7] = esalt_bufs[salt_pos].salt_buf[ 7];
  salt_buf1[ 8] = esalt_bufs[salt_pos].salt_buf[ 8];
  salt_buf1[ 9] = esalt_bufs[salt_pos].salt_buf[ 9];
  salt_buf1[10] = esalt_bufs[salt_pos].salt_buf[10];
  salt_buf1[11] = esalt_bufs[salt_pos].salt_buf[11];
  salt_buf1[12] = esalt_bufs[salt_pos].salt_buf[12];
  salt_buf1[13] = esalt_bufs[salt_pos].salt_buf[13];
  salt_buf1[14] = esalt_bufs[salt_pos].salt_buf[14];
  salt_buf1[15] = esalt_bufs[salt_pos].salt_buf[15];

  u32 salt_buf2[16];

  salt_buf2[ 0] = 0;
  salt_buf2[ 1] = 0x80;
  salt_buf2[ 2] = 0;
  salt_buf2[ 3] = 0;
  salt_buf2[ 4] = 0;
  salt_buf2[ 5] = 0;
  salt_buf2[ 6] = 0;
  salt_buf2[ 7] = 0;
  salt_buf2[ 8] = 0;
  salt_buf2[ 9] = 0;
  salt_buf2[10] = 0;
  salt_buf2[11] = 0;
  salt_buf2[12] = 0;
  salt_buf2[13] = 0;
  salt_buf2[14] = (64 + 64 + 4) * 8;
  salt_buf2[15] = 0;

  u32 w[16];

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
  w[14] = w3[2];
  w[15] = w3[3];

  u32 ipad[5];
  u32 opad[5];

  hmac_init (w, ipad, opad);

  tmps[gid].ipad[0] = ipad[0];
  tmps[gid].ipad[1] = ipad[1];
  tmps[gid].ipad[2] = ipad[2];
  tmps[gid].ipad[3] = ipad[3];
  tmps[gid].ipad[4] = ipad[4];

  tmps[gid].opad[0] = opad[0];
  tmps[gid].opad[1] = opad[1];
  tmps[gid].opad[2] = opad[2];
  tmps[gid].opad[3] = opad[3];
  tmps[gid].opad[4] = opad[4];

  for (u32 i = 0, j = 1; i < 48; i += 5, j += 1)
  {
    salt_buf2[0] = swap32 (j);

    u32 dgst[5];

    hmac_run2 (salt_buf1, salt_buf2, ipad, opad, dgst);

    tmps[gid].dgst[i + 0] = dgst[0];
    tmps[gid].dgst[i + 1] = dgst[1];
    tmps[gid].dgst[i + 2] = dgst[2];
    tmps[gid].dgst[i + 3] = dgst[3];
    tmps[gid].dgst[i + 4] = dgst[4];

    tmps[gid].out[i + 0] = dgst[0];
    tmps[gid].out[i + 1] = dgst[1];
    tmps[gid].out[i + 2] = dgst[2];
    tmps[gid].out[i + 3] = dgst[3];
    tmps[gid].out[i + 4] = dgst[4];
  }
}

__kernel void m06213_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global tc_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global tc_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 ipad[5];
  u32 opad[5];

  ipad[0] = tmps[gid].ipad[0];
  ipad[1] = tmps[gid].ipad[1];
  ipad[2] = tmps[gid].ipad[2];
  ipad[3] = tmps[gid].ipad[3];
  ipad[4] = tmps[gid].ipad[4];

  opad[0] = tmps[gid].opad[0];
  opad[1] = tmps[gid].opad[1];
  opad[2] = tmps[gid].opad[2];
  opad[3] = tmps[gid].opad[3];
  opad[4] = tmps[gid].opad[4];

  for (u32 i = 0; i < 48; i += 5)
  {
    u32 dgst[5];
    u32 out[5];

    dgst[0] = tmps[gid].dgst[i + 0];
    dgst[1] = tmps[gid].dgst[i + 1];
    dgst[2] = tmps[gid].dgst[i + 2];
    dgst[3] = tmps[gid].dgst[i + 3];
    dgst[4] = tmps[gid].dgst[i + 4];

    out[0] = tmps[gid].out[i + 0];
    out[1] = tmps[gid].out[i + 1];
    out[2] = tmps[gid].out[i + 2];
    out[3] = tmps[gid].out[i + 3];
    out[4] = tmps[gid].out[i + 4];

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32 w[16];

      w[ 0] = dgst[0];
      w[ 1] = dgst[1];
      w[ 2] = dgst[2];
      w[ 3] = dgst[3];
      w[ 4] = dgst[4];
      w[ 5] = 0x80;
      w[ 6] = 0;
      w[ 7] = 0;
      w[ 8] = 0;
      w[ 9] = 0;
      w[10] = 0;
      w[11] = 0;
      w[12] = 0;
      w[13] = 0;
      w[14] = (64 + 20) * 8;
      w[15] = 0;

      hmac_run (w, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    tmps[gid].dgst[i + 0] = dgst[0];
    tmps[gid].dgst[i + 1] = dgst[1];
    tmps[gid].dgst[i + 2] = dgst[2];
    tmps[gid].dgst[i + 3] = dgst[3];
    tmps[gid].dgst[i + 4] = dgst[4];

    tmps[gid].out[i + 0] = out[0];
    tmps[gid].out[i + 1] = out[1];
    tmps[gid].out[i + 2] = out[2];
    tmps[gid].out[i + 3] = out[3];
    tmps[gid].out[i + 4] = out[4];
  }
}

__kernel void m06213_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global tc_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global tc_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  if (gid >= gid_max) return;

  u32 ukey1[8];

  ukey1[0] = tmps[gid].out[ 0];
  ukey1[1] = tmps[gid].out[ 1];
  ukey1[2] = tmps[gid].out[ 2];
  ukey1[3] = tmps[gid].out[ 3];
  ukey1[4] = tmps[gid].out[ 4];
  ukey1[5] = tmps[gid].out[ 5];
  ukey1[6] = tmps[gid].out[ 6];
  ukey1[7] = tmps[gid].out[ 7];

  u32 ukey2[8];

  ukey2[0] = tmps[gid].out[ 8];
  ukey2[1] = tmps[gid].out[ 9];
  ukey2[2] = tmps[gid].out[10];
  ukey2[3] = tmps[gid].out[11];
  ukey2[4] = tmps[gid].out[12];
  ukey2[5] = tmps[gid].out[13];
  ukey2[6] = tmps[gid].out[14];
  ukey2[7] = tmps[gid].out[15];

  if (verify_header_aes (esalt_bufs, ukey1, ukey2) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, 0, 0, gid, 0);
  }

  if (verify_header_serpent (esalt_bufs, ukey1, ukey2) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, 0, 0, gid, 0);
  }

  if (verify_header_twofish (esalt_bufs, ukey1, ukey2) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, 0, 0, gid, 0);
  }

  u32 ukey3[8];

  ukey3[0] = tmps[gid].out[16];
  ukey3[1] = tmps[gid].out[17];
  ukey3[2] = tmps[gid].out[18];
  ukey3[3] = tmps[gid].out[19];
  ukey3[4] = tmps[gid].out[20];
  ukey3[5] = tmps[gid].out[21];
  ukey3[6] = tmps[gid].out[22];
  ukey3[7] = tmps[gid].out[23];

  #if defined (IS_APPLE) && defined (IS_GPU)
  volatile u32 ukey4[8];
  #else
  u32 ukey4[8];
  #endif

  ukey4[0] = tmps[gid].out[24];
  ukey4[1] = tmps[gid].out[25];
  ukey4[2] = tmps[gid].out[26];
  ukey4[3] = tmps[gid].out[27];
  ukey4[4] = tmps[gid].out[28];
  ukey4[5] = tmps[gid].out[29];
  ukey4[6] = tmps[gid].out[30];
  ukey4[7] = tmps[gid].out[31];

  if (verify_header_aes_twofish (esalt_bufs, ukey1, ukey2, ukey3, ukey4) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, 0, 0, gid, 0);
  }

  if (verify_header_serpent_aes (esalt_bufs, ukey1, ukey2, ukey3, ukey4) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, 0, 0, gid, 0);
  }

  if (verify_header_twofish_serpent (esalt_bufs, ukey1, ukey2, ukey3, ukey4) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, 0, 0, gid, 0);
  }

  #if defined (IS_APPLE) && defined (IS_GPU)
  volatile u32 ukey5[8];
  #else
  u32 ukey5[8];
  #endif

  ukey5[0] = tmps[gid].out[32];
  ukey5[1] = tmps[gid].out[33];
  ukey5[2] = tmps[gid].out[34];
  ukey5[3] = tmps[gid].out[35];
  ukey5[4] = tmps[gid].out[36];
  ukey5[5] = tmps[gid].out[37];
  ukey5[6] = tmps[gid].out[38];
  ukey5[7] = tmps[gid].out[39];

  #if defined (IS_APPLE) && defined (IS_GPU)
  volatile u32 ukey6[8];
  #else
  u32 ukey6[8];
  #endif

  ukey6[0] = tmps[gid].out[40];
  ukey6[1] = tmps[gid].out[41];
  ukey6[2] = tmps[gid].out[42];
  ukey6[3] = tmps[gid].out[43];
  ukey6[4] = tmps[gid].out[44];
  ukey6[5] = tmps[gid].out[45];
  ukey6[6] = tmps[gid].out[46];
  ukey6[7] = tmps[gid].out[47];

  if (verify_header_aes_twofish_serpent (esalt_bufs, ukey1, ukey2, ukey3, ukey4, ukey5, ukey6) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, 0, 0, gid, 0);
  }

  if (verify_header_serpent_twofish_aes (esalt_bufs, ukey1, ukey2, ukey3, ukey4, ukey5, ukey6) == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, 0, 0, gid, 0);
  }
}
