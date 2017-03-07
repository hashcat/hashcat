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

#include "inc_cipher_twofish.cl"

#include "inc_luks_af.cl"
#include "inc_luks_essiv.cl"
#include "inc_luks_xts.cl"

#include "inc_luks_twofish.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define MAX_ENTROPY 7.0

void ripemd160_transform_S (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[5])
{
  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  u32 a1 = digest[0];
  u32 b1 = digest[1];
  u32 c1 = digest[2];
  u32 d1 = digest[3];
  u32 e1 = digest[4];

  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, w0_t, RIPEMD160C00, RIPEMD160S00);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, w1_t, RIPEMD160C00, RIPEMD160S01);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, w2_t, RIPEMD160C00, RIPEMD160S02);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, w3_t, RIPEMD160C00, RIPEMD160S03);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, w4_t, RIPEMD160C00, RIPEMD160S04);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, w5_t, RIPEMD160C00, RIPEMD160S05);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, w6_t, RIPEMD160C00, RIPEMD160S06);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, w7_t, RIPEMD160C00, RIPEMD160S07);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, w8_t, RIPEMD160C00, RIPEMD160S08);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, w9_t, RIPEMD160C00, RIPEMD160S09);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, wa_t, RIPEMD160C00, RIPEMD160S0A);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, wb_t, RIPEMD160C00, RIPEMD160S0B);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, wc_t, RIPEMD160C00, RIPEMD160S0C);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, wd_t, RIPEMD160C00, RIPEMD160S0D);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, we_t, RIPEMD160C00, RIPEMD160S0E);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, wf_t, RIPEMD160C00, RIPEMD160S0F);

  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w7_t, RIPEMD160C10, RIPEMD160S10);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, w4_t, RIPEMD160C10, RIPEMD160S11);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, wd_t, RIPEMD160C10, RIPEMD160S12);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, w1_t, RIPEMD160C10, RIPEMD160S13);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, wa_t, RIPEMD160C10, RIPEMD160S14);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w6_t, RIPEMD160C10, RIPEMD160S15);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, wf_t, RIPEMD160C10, RIPEMD160S16);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, w3_t, RIPEMD160C10, RIPEMD160S17);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, wc_t, RIPEMD160C10, RIPEMD160S18);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, w0_t, RIPEMD160C10, RIPEMD160S19);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w9_t, RIPEMD160C10, RIPEMD160S1A);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, w5_t, RIPEMD160C10, RIPEMD160S1B);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, w2_t, RIPEMD160C10, RIPEMD160S1C);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, we_t, RIPEMD160C10, RIPEMD160S1D);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, wb_t, RIPEMD160C10, RIPEMD160S1E);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w8_t, RIPEMD160C10, RIPEMD160S1F);

  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, w3_t, RIPEMD160C20, RIPEMD160S20);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, wa_t, RIPEMD160C20, RIPEMD160S21);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, we_t, RIPEMD160C20, RIPEMD160S22);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, w4_t, RIPEMD160C20, RIPEMD160S23);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w9_t, RIPEMD160C20, RIPEMD160S24);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, wf_t, RIPEMD160C20, RIPEMD160S25);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, w8_t, RIPEMD160C20, RIPEMD160S26);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, w1_t, RIPEMD160C20, RIPEMD160S27);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, w2_t, RIPEMD160C20, RIPEMD160S28);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w7_t, RIPEMD160C20, RIPEMD160S29);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, w0_t, RIPEMD160C20, RIPEMD160S2A);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, w6_t, RIPEMD160C20, RIPEMD160S2B);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, wd_t, RIPEMD160C20, RIPEMD160S2C);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, wb_t, RIPEMD160C20, RIPEMD160S2D);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w5_t, RIPEMD160C20, RIPEMD160S2E);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, wc_t, RIPEMD160C20, RIPEMD160S2F);

  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w1_t, RIPEMD160C30, RIPEMD160S30);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, w9_t, RIPEMD160C30, RIPEMD160S31);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, wb_t, RIPEMD160C30, RIPEMD160S32);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, wa_t, RIPEMD160C30, RIPEMD160S33);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w0_t, RIPEMD160C30, RIPEMD160S34);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w8_t, RIPEMD160C30, RIPEMD160S35);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, wc_t, RIPEMD160C30, RIPEMD160S36);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, w4_t, RIPEMD160C30, RIPEMD160S37);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, wd_t, RIPEMD160C30, RIPEMD160S38);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w3_t, RIPEMD160C30, RIPEMD160S39);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w7_t, RIPEMD160C30, RIPEMD160S3A);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, wf_t, RIPEMD160C30, RIPEMD160S3B);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, we_t, RIPEMD160C30, RIPEMD160S3C);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, w5_t, RIPEMD160C30, RIPEMD160S3D);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w6_t, RIPEMD160C30, RIPEMD160S3E);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w2_t, RIPEMD160C30, RIPEMD160S3F);

  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, w4_t, RIPEMD160C40, RIPEMD160S40);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w0_t, RIPEMD160C40, RIPEMD160S41);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, w5_t, RIPEMD160C40, RIPEMD160S42);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, w9_t, RIPEMD160C40, RIPEMD160S43);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, w7_t, RIPEMD160C40, RIPEMD160S44);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, wc_t, RIPEMD160C40, RIPEMD160S45);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w2_t, RIPEMD160C40, RIPEMD160S46);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, wa_t, RIPEMD160C40, RIPEMD160S47);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, we_t, RIPEMD160C40, RIPEMD160S48);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, w1_t, RIPEMD160C40, RIPEMD160S49);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, w3_t, RIPEMD160C40, RIPEMD160S4A);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w8_t, RIPEMD160C40, RIPEMD160S4B);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, wb_t, RIPEMD160C40, RIPEMD160S4C);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, w6_t, RIPEMD160C40, RIPEMD160S4D);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, wf_t, RIPEMD160C40, RIPEMD160S4E);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, wd_t, RIPEMD160C40, RIPEMD160S4F);

  u32 a2 = digest[0];
  u32 b2 = digest[1];
  u32 c2 = digest[2];
  u32 d2 = digest[3];
  u32 e2 = digest[4];

  RIPEMD160_STEP_S_WORKAROUND_BUG (RIPEMD160_J , a2, b2, c2, d2, e2, w5_t, RIPEMD160C50, RIPEMD160S50);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, we_t, RIPEMD160C50, RIPEMD160S51);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w7_t, RIPEMD160C50, RIPEMD160S52);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, w0_t, RIPEMD160C50, RIPEMD160S53);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w9_t, RIPEMD160C50, RIPEMD160S54);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, w2_t, RIPEMD160C50, RIPEMD160S55);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, wb_t, RIPEMD160C50, RIPEMD160S56);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w4_t, RIPEMD160C50, RIPEMD160S57);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, wd_t, RIPEMD160C50, RIPEMD160S58);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w6_t, RIPEMD160C50, RIPEMD160S59);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, wf_t, RIPEMD160C50, RIPEMD160S5A);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, w8_t, RIPEMD160C50, RIPEMD160S5B);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w1_t, RIPEMD160C50, RIPEMD160S5C);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, wa_t, RIPEMD160C50, RIPEMD160S5D);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w3_t, RIPEMD160C50, RIPEMD160S5E);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, wc_t, RIPEMD160C50, RIPEMD160S5F);

  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w6_t, RIPEMD160C60, RIPEMD160S60);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, wb_t, RIPEMD160C60, RIPEMD160S61);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, w3_t, RIPEMD160C60, RIPEMD160S62);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, w7_t, RIPEMD160C60, RIPEMD160S63);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, w0_t, RIPEMD160C60, RIPEMD160S64);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, wd_t, RIPEMD160C60, RIPEMD160S65);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, w5_t, RIPEMD160C60, RIPEMD160S66);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, wa_t, RIPEMD160C60, RIPEMD160S67);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, we_t, RIPEMD160C60, RIPEMD160S68);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, wf_t, RIPEMD160C60, RIPEMD160S69);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w8_t, RIPEMD160C60, RIPEMD160S6A);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, wc_t, RIPEMD160C60, RIPEMD160S6B);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, w4_t, RIPEMD160C60, RIPEMD160S6C);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, w9_t, RIPEMD160C60, RIPEMD160S6D);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, w1_t, RIPEMD160C60, RIPEMD160S6E);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w2_t, RIPEMD160C60, RIPEMD160S6F);

  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, wf_t, RIPEMD160C70, RIPEMD160S70);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w5_t, RIPEMD160C70, RIPEMD160S71);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, w1_t, RIPEMD160C70, RIPEMD160S72);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, w3_t, RIPEMD160C70, RIPEMD160S73);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w7_t, RIPEMD160C70, RIPEMD160S74);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, we_t, RIPEMD160C70, RIPEMD160S75);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w6_t, RIPEMD160C70, RIPEMD160S76);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, w9_t, RIPEMD160C70, RIPEMD160S77);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, wb_t, RIPEMD160C70, RIPEMD160S78);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w8_t, RIPEMD160C70, RIPEMD160S79);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, wc_t, RIPEMD160C70, RIPEMD160S7A);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w2_t, RIPEMD160C70, RIPEMD160S7B);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, wa_t, RIPEMD160C70, RIPEMD160S7C);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, w0_t, RIPEMD160C70, RIPEMD160S7D);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w4_t, RIPEMD160C70, RIPEMD160S7E);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, wd_t, RIPEMD160C70, RIPEMD160S7F);

  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, w8_t, RIPEMD160C80, RIPEMD160S80);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, w6_t, RIPEMD160C80, RIPEMD160S81);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w4_t, RIPEMD160C80, RIPEMD160S82);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w1_t, RIPEMD160C80, RIPEMD160S83);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, w3_t, RIPEMD160C80, RIPEMD160S84);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, wb_t, RIPEMD160C80, RIPEMD160S85);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, wf_t, RIPEMD160C80, RIPEMD160S86);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w0_t, RIPEMD160C80, RIPEMD160S87);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w5_t, RIPEMD160C80, RIPEMD160S88);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, wc_t, RIPEMD160C80, RIPEMD160S89);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, w2_t, RIPEMD160C80, RIPEMD160S8A);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, wd_t, RIPEMD160C80, RIPEMD160S8B);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w9_t, RIPEMD160C80, RIPEMD160S8C);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w7_t, RIPEMD160C80, RIPEMD160S8D);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, wa_t, RIPEMD160C80, RIPEMD160S8E);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, we_t, RIPEMD160C80, RIPEMD160S8F);

  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, wc_t, RIPEMD160C90, RIPEMD160S90);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, wf_t, RIPEMD160C90, RIPEMD160S91);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, wa_t, RIPEMD160C90, RIPEMD160S92);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w4_t, RIPEMD160C90, RIPEMD160S93);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w1_t, RIPEMD160C90, RIPEMD160S94);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, w5_t, RIPEMD160C90, RIPEMD160S95);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, w8_t, RIPEMD160C90, RIPEMD160S96);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, w7_t, RIPEMD160C90, RIPEMD160S97);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w6_t, RIPEMD160C90, RIPEMD160S98);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w2_t, RIPEMD160C90, RIPEMD160S99);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, wd_t, RIPEMD160C90, RIPEMD160S9A);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, we_t, RIPEMD160C90, RIPEMD160S9B);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, w0_t, RIPEMD160C90, RIPEMD160S9C);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w3_t, RIPEMD160C90, RIPEMD160S9D);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w9_t, RIPEMD160C90, RIPEMD160S9E);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, wb_t, RIPEMD160C90, RIPEMD160S9F);

  const u32 a = digest[1] + c1 + d2;
  const u32 b = digest[2] + d1 + e2;
  const u32 c = digest[3] + e1 + a2;
  const u32 d = digest[4] + a1 + b2;
  const u32 e = digest[0] + b1 + c2;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
}

void hmac_ripemd160_pad_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[5], u32 opad[5])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = RIPEMD160M_A;
  ipad[1] = RIPEMD160M_B;
  ipad[2] = RIPEMD160M_C;
  ipad[3] = RIPEMD160M_D;
  ipad[4] = RIPEMD160M_E;

  ripemd160_transform_S (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = RIPEMD160M_A;
  opad[1] = RIPEMD160M_B;
  opad[2] = RIPEMD160M_C;
  opad[3] = RIPEMD160M_D;
  opad[4] = RIPEMD160M_E;

  ripemd160_transform_S (w0, w1, w2, w3, opad);
}

void hmac_ripemd160_run_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[5], u32 opad[5], u32 digest[5])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  ripemd160_transform_S (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 20) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  ripemd160_transform_S (w0, w1, w2, w3, digest);
}

void ripemd160_transform_V (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[5])
{
  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = w3[3];

  u32x a1 = digest[0];
  u32x b1 = digest[1];
  u32x c1 = digest[2];
  u32x d1 = digest[3];
  u32x e1 = digest[4];

  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w0_t, RIPEMD160C00, RIPEMD160S00);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, w1_t, RIPEMD160C00, RIPEMD160S01);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, w2_t, RIPEMD160C00, RIPEMD160S02);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, w3_t, RIPEMD160C00, RIPEMD160S03);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, w4_t, RIPEMD160C00, RIPEMD160S04);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, w5_t, RIPEMD160C00, RIPEMD160S05);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, w6_t, RIPEMD160C00, RIPEMD160S06);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, w7_t, RIPEMD160C00, RIPEMD160S07);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, w8_t, RIPEMD160C00, RIPEMD160S08);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, w9_t, RIPEMD160C00, RIPEMD160S09);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, wa_t, RIPEMD160C00, RIPEMD160S0A);
  RIPEMD160_STEP (RIPEMD160_F , e1, a1, b1, c1, d1, wb_t, RIPEMD160C00, RIPEMD160S0B);
  RIPEMD160_STEP (RIPEMD160_F , d1, e1, a1, b1, c1, wc_t, RIPEMD160C00, RIPEMD160S0C);
  RIPEMD160_STEP (RIPEMD160_F , c1, d1, e1, a1, b1, wd_t, RIPEMD160C00, RIPEMD160S0D);
  RIPEMD160_STEP (RIPEMD160_F , b1, c1, d1, e1, a1, we_t, RIPEMD160C00, RIPEMD160S0E);
  RIPEMD160_STEP (RIPEMD160_F , a1, b1, c1, d1, e1, wf_t, RIPEMD160C00, RIPEMD160S0F);

  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w7_t, RIPEMD160C10, RIPEMD160S10);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, w4_t, RIPEMD160C10, RIPEMD160S11);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, wd_t, RIPEMD160C10, RIPEMD160S12);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, w1_t, RIPEMD160C10, RIPEMD160S13);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, wa_t, RIPEMD160C10, RIPEMD160S14);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w6_t, RIPEMD160C10, RIPEMD160S15);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, wf_t, RIPEMD160C10, RIPEMD160S16);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, w3_t, RIPEMD160C10, RIPEMD160S17);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, wc_t, RIPEMD160C10, RIPEMD160S18);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, w0_t, RIPEMD160C10, RIPEMD160S19);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w9_t, RIPEMD160C10, RIPEMD160S1A);
  RIPEMD160_STEP (RIPEMD160_Go, d1, e1, a1, b1, c1, w5_t, RIPEMD160C10, RIPEMD160S1B);
  RIPEMD160_STEP (RIPEMD160_Go, c1, d1, e1, a1, b1, w2_t, RIPEMD160C10, RIPEMD160S1C);
  RIPEMD160_STEP (RIPEMD160_Go, b1, c1, d1, e1, a1, we_t, RIPEMD160C10, RIPEMD160S1D);
  RIPEMD160_STEP (RIPEMD160_Go, a1, b1, c1, d1, e1, wb_t, RIPEMD160C10, RIPEMD160S1E);
  RIPEMD160_STEP (RIPEMD160_Go, e1, a1, b1, c1, d1, w8_t, RIPEMD160C10, RIPEMD160S1F);

  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w3_t, RIPEMD160C20, RIPEMD160S20);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, wa_t, RIPEMD160C20, RIPEMD160S21);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, we_t, RIPEMD160C20, RIPEMD160S22);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, w4_t, RIPEMD160C20, RIPEMD160S23);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w9_t, RIPEMD160C20, RIPEMD160S24);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, wf_t, RIPEMD160C20, RIPEMD160S25);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, w8_t, RIPEMD160C20, RIPEMD160S26);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, w1_t, RIPEMD160C20, RIPEMD160S27);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, w2_t, RIPEMD160C20, RIPEMD160S28);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w7_t, RIPEMD160C20, RIPEMD160S29);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, w0_t, RIPEMD160C20, RIPEMD160S2A);
  RIPEMD160_STEP (RIPEMD160_H , c1, d1, e1, a1, b1, w6_t, RIPEMD160C20, RIPEMD160S2B);
  RIPEMD160_STEP (RIPEMD160_H , b1, c1, d1, e1, a1, wd_t, RIPEMD160C20, RIPEMD160S2C);
  RIPEMD160_STEP (RIPEMD160_H , a1, b1, c1, d1, e1, wb_t, RIPEMD160C20, RIPEMD160S2D);
  RIPEMD160_STEP (RIPEMD160_H , e1, a1, b1, c1, d1, w5_t, RIPEMD160C20, RIPEMD160S2E);
  RIPEMD160_STEP (RIPEMD160_H , d1, e1, a1, b1, c1, wc_t, RIPEMD160C20, RIPEMD160S2F);

  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w1_t, RIPEMD160C30, RIPEMD160S30);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, w9_t, RIPEMD160C30, RIPEMD160S31);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, wb_t, RIPEMD160C30, RIPEMD160S32);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, wa_t, RIPEMD160C30, RIPEMD160S33);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w0_t, RIPEMD160C30, RIPEMD160S34);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w8_t, RIPEMD160C30, RIPEMD160S35);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, wc_t, RIPEMD160C30, RIPEMD160S36);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, w4_t, RIPEMD160C30, RIPEMD160S37);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, wd_t, RIPEMD160C30, RIPEMD160S38);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w3_t, RIPEMD160C30, RIPEMD160S39);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w7_t, RIPEMD160C30, RIPEMD160S3A);
  RIPEMD160_STEP (RIPEMD160_Io, b1, c1, d1, e1, a1, wf_t, RIPEMD160C30, RIPEMD160S3B);
  RIPEMD160_STEP (RIPEMD160_Io, a1, b1, c1, d1, e1, we_t, RIPEMD160C30, RIPEMD160S3C);
  RIPEMD160_STEP (RIPEMD160_Io, e1, a1, b1, c1, d1, w5_t, RIPEMD160C30, RIPEMD160S3D);
  RIPEMD160_STEP (RIPEMD160_Io, d1, e1, a1, b1, c1, w6_t, RIPEMD160C30, RIPEMD160S3E);
  RIPEMD160_STEP (RIPEMD160_Io, c1, d1, e1, a1, b1, w2_t, RIPEMD160C30, RIPEMD160S3F);

  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w4_t, RIPEMD160C40, RIPEMD160S40);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w0_t, RIPEMD160C40, RIPEMD160S41);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, w5_t, RIPEMD160C40, RIPEMD160S42);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, w9_t, RIPEMD160C40, RIPEMD160S43);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, w7_t, RIPEMD160C40, RIPEMD160S44);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, wc_t, RIPEMD160C40, RIPEMD160S45);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w2_t, RIPEMD160C40, RIPEMD160S46);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, wa_t, RIPEMD160C40, RIPEMD160S47);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, we_t, RIPEMD160C40, RIPEMD160S48);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, w1_t, RIPEMD160C40, RIPEMD160S49);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, w3_t, RIPEMD160C40, RIPEMD160S4A);
  RIPEMD160_STEP (RIPEMD160_J , a1, b1, c1, d1, e1, w8_t, RIPEMD160C40, RIPEMD160S4B);
  RIPEMD160_STEP (RIPEMD160_J , e1, a1, b1, c1, d1, wb_t, RIPEMD160C40, RIPEMD160S4C);
  RIPEMD160_STEP (RIPEMD160_J , d1, e1, a1, b1, c1, w6_t, RIPEMD160C40, RIPEMD160S4D);
  RIPEMD160_STEP (RIPEMD160_J , c1, d1, e1, a1, b1, wf_t, RIPEMD160C40, RIPEMD160S4E);
  RIPEMD160_STEP (RIPEMD160_J , b1, c1, d1, e1, a1, wd_t, RIPEMD160C40, RIPEMD160S4F);

  u32x a2 = digest[0];
  u32x b2 = digest[1];
  u32x c2 = digest[2];
  u32x d2 = digest[3];
  u32x e2 = digest[4];

  RIPEMD160_STEP_WORKAROUND_BUG (RIPEMD160_J , a2, b2, c2, d2, e2, w5_t, RIPEMD160C50, RIPEMD160S50);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, we_t, RIPEMD160C50, RIPEMD160S51);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w7_t, RIPEMD160C50, RIPEMD160S52);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, w0_t, RIPEMD160C50, RIPEMD160S53);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w9_t, RIPEMD160C50, RIPEMD160S54);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, w2_t, RIPEMD160C50, RIPEMD160S55);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, wb_t, RIPEMD160C50, RIPEMD160S56);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w4_t, RIPEMD160C50, RIPEMD160S57);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, wd_t, RIPEMD160C50, RIPEMD160S58);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w6_t, RIPEMD160C50, RIPEMD160S59);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, wf_t, RIPEMD160C50, RIPEMD160S5A);
  RIPEMD160_STEP (RIPEMD160_J , e2, a2, b2, c2, d2, w8_t, RIPEMD160C50, RIPEMD160S5B);
  RIPEMD160_STEP (RIPEMD160_J , d2, e2, a2, b2, c2, w1_t, RIPEMD160C50, RIPEMD160S5C);
  RIPEMD160_STEP (RIPEMD160_J , c2, d2, e2, a2, b2, wa_t, RIPEMD160C50, RIPEMD160S5D);
  RIPEMD160_STEP (RIPEMD160_J , b2, c2, d2, e2, a2, w3_t, RIPEMD160C50, RIPEMD160S5E);
  RIPEMD160_STEP (RIPEMD160_J , a2, b2, c2, d2, e2, wc_t, RIPEMD160C50, RIPEMD160S5F);

  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w6_t, RIPEMD160C60, RIPEMD160S60);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, wb_t, RIPEMD160C60, RIPEMD160S61);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, w3_t, RIPEMD160C60, RIPEMD160S62);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, w7_t, RIPEMD160C60, RIPEMD160S63);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, w0_t, RIPEMD160C60, RIPEMD160S64);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, wd_t, RIPEMD160C60, RIPEMD160S65);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, w5_t, RIPEMD160C60, RIPEMD160S66);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, wa_t, RIPEMD160C60, RIPEMD160S67);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, we_t, RIPEMD160C60, RIPEMD160S68);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, wf_t, RIPEMD160C60, RIPEMD160S69);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w8_t, RIPEMD160C60, RIPEMD160S6A);
  RIPEMD160_STEP (RIPEMD160_Io, d2, e2, a2, b2, c2, wc_t, RIPEMD160C60, RIPEMD160S6B);
  RIPEMD160_STEP (RIPEMD160_Io, c2, d2, e2, a2, b2, w4_t, RIPEMD160C60, RIPEMD160S6C);
  RIPEMD160_STEP (RIPEMD160_Io, b2, c2, d2, e2, a2, w9_t, RIPEMD160C60, RIPEMD160S6D);
  RIPEMD160_STEP (RIPEMD160_Io, a2, b2, c2, d2, e2, w1_t, RIPEMD160C60, RIPEMD160S6E);
  RIPEMD160_STEP (RIPEMD160_Io, e2, a2, b2, c2, d2, w2_t, RIPEMD160C60, RIPEMD160S6F);

  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, wf_t, RIPEMD160C70, RIPEMD160S70);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w5_t, RIPEMD160C70, RIPEMD160S71);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, w1_t, RIPEMD160C70, RIPEMD160S72);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, w3_t, RIPEMD160C70, RIPEMD160S73);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w7_t, RIPEMD160C70, RIPEMD160S74);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, we_t, RIPEMD160C70, RIPEMD160S75);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w6_t, RIPEMD160C70, RIPEMD160S76);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, w9_t, RIPEMD160C70, RIPEMD160S77);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, wb_t, RIPEMD160C70, RIPEMD160S78);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w8_t, RIPEMD160C70, RIPEMD160S79);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, wc_t, RIPEMD160C70, RIPEMD160S7A);
  RIPEMD160_STEP (RIPEMD160_H , c2, d2, e2, a2, b2, w2_t, RIPEMD160C70, RIPEMD160S7B);
  RIPEMD160_STEP (RIPEMD160_H , b2, c2, d2, e2, a2, wa_t, RIPEMD160C70, RIPEMD160S7C);
  RIPEMD160_STEP (RIPEMD160_H , a2, b2, c2, d2, e2, w0_t, RIPEMD160C70, RIPEMD160S7D);
  RIPEMD160_STEP (RIPEMD160_H , e2, a2, b2, c2, d2, w4_t, RIPEMD160C70, RIPEMD160S7E);
  RIPEMD160_STEP (RIPEMD160_H , d2, e2, a2, b2, c2, wd_t, RIPEMD160C70, RIPEMD160S7F);

  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w8_t, RIPEMD160C80, RIPEMD160S80);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, w6_t, RIPEMD160C80, RIPEMD160S81);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w4_t, RIPEMD160C80, RIPEMD160S82);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w1_t, RIPEMD160C80, RIPEMD160S83);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, w3_t, RIPEMD160C80, RIPEMD160S84);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, wb_t, RIPEMD160C80, RIPEMD160S85);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, wf_t, RIPEMD160C80, RIPEMD160S86);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w0_t, RIPEMD160C80, RIPEMD160S87);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w5_t, RIPEMD160C80, RIPEMD160S88);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, wc_t, RIPEMD160C80, RIPEMD160S89);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, w2_t, RIPEMD160C80, RIPEMD160S8A);
  RIPEMD160_STEP (RIPEMD160_Go, b2, c2, d2, e2, a2, wd_t, RIPEMD160C80, RIPEMD160S8B);
  RIPEMD160_STEP (RIPEMD160_Go, a2, b2, c2, d2, e2, w9_t, RIPEMD160C80, RIPEMD160S8C);
  RIPEMD160_STEP (RIPEMD160_Go, e2, a2, b2, c2, d2, w7_t, RIPEMD160C80, RIPEMD160S8D);
  RIPEMD160_STEP (RIPEMD160_Go, d2, e2, a2, b2, c2, wa_t, RIPEMD160C80, RIPEMD160S8E);
  RIPEMD160_STEP (RIPEMD160_Go, c2, d2, e2, a2, b2, we_t, RIPEMD160C80, RIPEMD160S8F);

  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, wc_t, RIPEMD160C90, RIPEMD160S90);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, wf_t, RIPEMD160C90, RIPEMD160S91);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, wa_t, RIPEMD160C90, RIPEMD160S92);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w4_t, RIPEMD160C90, RIPEMD160S93);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w1_t, RIPEMD160C90, RIPEMD160S94);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, w5_t, RIPEMD160C90, RIPEMD160S95);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, w8_t, RIPEMD160C90, RIPEMD160S96);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, w7_t, RIPEMD160C90, RIPEMD160S97);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w6_t, RIPEMD160C90, RIPEMD160S98);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w2_t, RIPEMD160C90, RIPEMD160S99);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, wd_t, RIPEMD160C90, RIPEMD160S9A);
  RIPEMD160_STEP (RIPEMD160_F , a2, b2, c2, d2, e2, we_t, RIPEMD160C90, RIPEMD160S9B);
  RIPEMD160_STEP (RIPEMD160_F , e2, a2, b2, c2, d2, w0_t, RIPEMD160C90, RIPEMD160S9C);
  RIPEMD160_STEP (RIPEMD160_F , d2, e2, a2, b2, c2, w3_t, RIPEMD160C90, RIPEMD160S9D);
  RIPEMD160_STEP (RIPEMD160_F , c2, d2, e2, a2, b2, w9_t, RIPEMD160C90, RIPEMD160S9E);
  RIPEMD160_STEP (RIPEMD160_F , b2, c2, d2, e2, a2, wb_t, RIPEMD160C90, RIPEMD160S9F);

  const u32x a = digest[1] + c1 + d2;
  const u32x b = digest[2] + d1 + e2;
  const u32x c = digest[3] + e1 + a2;
  const u32x d = digest[4] + a1 + b2;
  const u32x e = digest[0] + b1 + c2;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
}

void hmac_ripemd160_run_V (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[5], u32x opad[5], u32x digest[5])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  ripemd160_transform_V (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 20) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  ripemd160_transform_V (w0, w1, w2, w3, digest);
}

__kernel void m14643_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global luks_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global luks_t *luks_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
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
   * salt
   */

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 salt_buf0[4];
  u32 salt_buf1[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[7];

  u32 key_size = luks_bufs[digests_offset].key_size;

  /**
   * pads
   */

  u32 ipad[5];
  u32 opad[5];

  hmac_ripemd160_pad_S (w0, w1, w2, w3, ipad, opad);

  tmps[gid].ipad32[0] = ipad[0];
  tmps[gid].ipad32[1] = ipad[1];
  tmps[gid].ipad32[2] = ipad[2];
  tmps[gid].ipad32[3] = ipad[3];
  tmps[gid].ipad32[4] = ipad[4];

  tmps[gid].opad32[0] = opad[0];
  tmps[gid].opad32[1] = opad[1];
  tmps[gid].opad32[2] = opad[2];
  tmps[gid].opad32[3] = opad[3];
  tmps[gid].opad32[4] = opad[4];

  for (u32 i = 0, j = 1; i < ((key_size / 8) / 4); i += 5, j += 1)
  {
    w0[0] = salt_buf0[0];
    w0[1] = salt_buf0[1];
    w0[2] = salt_buf0[2];
    w0[3] = salt_buf0[3];
    w1[0] = salt_buf1[0];
    w1[1] = salt_buf1[1];
    w1[2] = salt_buf1[2];
    w1[3] = salt_buf1[3];
    w2[0] = j << 24;
    w2[1] = 0x80;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = (64 + salt_len + 4) * 8;
    w3[3] = 0;

    u32 dgst[5];

    hmac_ripemd160_run_S (w0, w1, w2, w3, ipad, opad, dgst);

    tmps[gid].dgst32[i + 0] = dgst[0];
    tmps[gid].dgst32[i + 1] = dgst[1];
    tmps[gid].dgst32[i + 2] = dgst[2];
    tmps[gid].dgst32[i + 3] = dgst[3];
    tmps[gid].dgst32[i + 4] = dgst[4];

    tmps[gid].out32[i + 0] = dgst[0];
    tmps[gid].out32[i + 1] = dgst[1];
    tmps[gid].out32[i + 2] = dgst[2];
    tmps[gid].out32[i + 3] = dgst[3];
    tmps[gid].out32[i + 4] = dgst[4];
  }
}

__kernel void m14643_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global luks_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global luks_t *luks_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad32, gid, 0);
  ipad[1] = packv (tmps, ipad32, gid, 1);
  ipad[2] = packv (tmps, ipad32, gid, 2);
  ipad[3] = packv (tmps, ipad32, gid, 3);
  ipad[4] = packv (tmps, ipad32, gid, 4);

  opad[0] = packv (tmps, opad32, gid, 0);
  opad[1] = packv (tmps, opad32, gid, 1);
  opad[2] = packv (tmps, opad32, gid, 2);
  opad[3] = packv (tmps, opad32, gid, 3);
  opad[4] = packv (tmps, opad32, gid, 4);

  u32 key_size = luks_bufs[digests_offset].key_size;

  for (u32 i = 0; i < ((key_size / 8) / 4); i += 5)
  {
    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst32, gid, i + 0);
    dgst[1] = packv (tmps, dgst32, gid, i + 1);
    dgst[2] = packv (tmps, dgst32, gid, i + 2);
    dgst[3] = packv (tmps, dgst32, gid, i + 3);
    dgst[4] = packv (tmps, dgst32, gid, i + 4);

    out[0] = packv (tmps, out32, gid, i + 0);
    out[1] = packv (tmps, out32, gid, i + 1);
    out[2] = packv (tmps, out32, gid, i + 2);
    out[3] = packv (tmps, out32, gid, i + 3);
    out[4] = packv (tmps, out32, gid, i + 4);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = (64 + 20) * 8;
      w3[3] = 0;

      hmac_ripemd160_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    unpackv (tmps, dgst32, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst32, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst32, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst32, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst32, gid, i + 4, dgst[4]);

    unpackv (tmps, out32, gid, i + 0, out[0]);
    unpackv (tmps, out32, gid, i + 1, out[1]);
    unpackv (tmps, out32, gid, i + 2, out[2]);
    unpackv (tmps, out32, gid, i + 3, out[3]);
    unpackv (tmps, out32, gid, i + 4, out[4]);
  }
}

__kernel void m14643_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global luks_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global luks_t *luks_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  // decrypt AF with first pbkdf2 result
  // merge AF to masterkey
  // decrypt first payload sector with masterkey

  u32 pt_buf[128];

  luks_af_ripemd160_then_twofish_decrypt (&luks_bufs[digests_offset], &tmps[gid], pt_buf);

  // check entropy

  const float entropy = get_entropy (pt_buf, 128);

  if (entropy < MAX_ENTROPY)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
  }
}
