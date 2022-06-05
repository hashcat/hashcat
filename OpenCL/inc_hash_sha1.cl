/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha1.h"

// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf needs to be in algorithm native byte order (md5 = LE, sha1 = BE, etc)
// input buf needs to be 64 byte aligned when using sha1_update()

DECLSPEC void sha1_transform (PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3, PRIVATE_AS u32 *digest)
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];

  #ifdef IS_CPU

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

  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w1_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w2_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w3_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w4_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w5_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w6_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w7_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w8_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w9_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, wa_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, wb_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, wc_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, wd_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, we_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, wf_t);
  w0_t = hc_rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w0_t);
  w1_t = hc_rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w1_t);
  w2_t = hc_rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w2_t);
  w3_t = hc_rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = hc_rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w4_t);
  w5_t = hc_rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w5_t);
  w6_t = hc_rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w6_t);
  w7_t = hc_rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w7_t);
  w8_t = hc_rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w8_t);
  w9_t = hc_rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w9_t);
  wa_t = hc_rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wa_t);
  wb_t = hc_rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, wb_t);
  wc_t = hc_rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, wc_t);
  wd_t = hc_rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wd_t);
  we_t = hc_rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, we_t);
  wf_t = hc_rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wf_t);
  w0_t = hc_rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w0_t);
  w1_t = hc_rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w1_t);
  w2_t = hc_rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w2_t);
  w3_t = hc_rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w3_t);
  w4_t = hc_rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w4_t);
  w5_t = hc_rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w5_t);
  w6_t = hc_rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w6_t);
  w7_t = hc_rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = hc_rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w8_t);
  w9_t = hc_rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w9_t);
  wa_t = hc_rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, wa_t);
  wb_t = hc_rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, wb_t);
  wc_t = hc_rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, wc_t);
  wd_t = hc_rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, wd_t);
  we_t = hc_rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, we_t);
  wf_t = hc_rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, wf_t);
  w0_t = hc_rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w0_t);
  w1_t = hc_rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w1_t);
  w2_t = hc_rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w2_t);
  w3_t = hc_rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w3_t);
  w4_t = hc_rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w4_t);
  w5_t = hc_rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w5_t);
  w6_t = hc_rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w6_t);
  w7_t = hc_rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w7_t);
  w8_t = hc_rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w8_t);
  w9_t = hc_rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w9_t);
  wa_t = hc_rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, wa_t);
  wb_t = hc_rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = hc_rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, wc_t);
  wd_t = hc_rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wd_t);
  we_t = hc_rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, we_t);
  wf_t = hc_rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, wf_t);
  w0_t = hc_rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w0_t);
  w1_t = hc_rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w1_t);
  w2_t = hc_rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w2_t);
  w3_t = hc_rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w3_t);
  w4_t = hc_rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w4_t);
  w5_t = hc_rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w5_t);
  w6_t = hc_rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w6_t);
  w7_t = hc_rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w7_t);
  w8_t = hc_rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w8_t);
  w9_t = hc_rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w9_t);
  wa_t = hc_rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wa_t);
  wb_t = hc_rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, wb_t);
  wc_t = hc_rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wc_t);
  wd_t = hc_rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, wd_t);
  we_t = hc_rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, we_t);
  wf_t = hc_rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wf_t);

  #undef K

  #else

  u32 w00_t = w0[0];
  u32 w01_t = w0[1];
  u32 w02_t = w0[2];
  u32 w03_t = w0[3];
  u32 w04_t = w1[0];
  u32 w05_t = w1[1];
  u32 w06_t = w1[2];
  u32 w07_t = w1[3];
  u32 w08_t = w2[0];
  u32 w09_t = w2[1];
  u32 w0a_t = w2[2];
  u32 w0b_t = w2[3];
  u32 w0c_t = w3[0];
  u32 w0d_t = w3[1];
  u32 w0e_t = w3[2];
  u32 w0f_t = w3[3];
  u32 w10_t;
  u32 w11_t;
  u32 w12_t;
  u32 w13_t;
  u32 w14_t;
  u32 w15_t;
  u32 w16_t;
  u32 w17_t;
  u32 w18_t;
  u32 w19_t;
  u32 w1a_t;
  u32 w1b_t;
  u32 w1c_t;
  u32 w1d_t;
  u32 w1e_t;
  u32 w1f_t;
  u32 w20_t;
  u32 w21_t;
  u32 w22_t;
  u32 w23_t;
  u32 w24_t;
  u32 w25_t;
  u32 w26_t;
  u32 w27_t;
  u32 w28_t;
  u32 w29_t;
  u32 w2a_t;
  u32 w2b_t;
  u32 w2c_t;
  u32 w2d_t;
  u32 w2e_t;
  u32 w2f_t;
  u32 w30_t;
  u32 w31_t;
  u32 w32_t;
  u32 w33_t;
  u32 w34_t;
  u32 w35_t;
  u32 w36_t;
  u32 w37_t;
  u32 w38_t;
  u32 w39_t;
  u32 w3a_t;
  u32 w3b_t;
  u32 w3c_t;
  u32 w3d_t;
  u32 w3e_t;
  u32 w3f_t;
  u32 w40_t;
  u32 w41_t;
  u32 w42_t;
  u32 w43_t;
  u32 w44_t;
  u32 w45_t;
  u32 w46_t;
  u32 w47_t;
  u32 w48_t;
  u32 w49_t;
  u32 w4a_t;
  u32 w4b_t;
  u32 w4c_t;
  u32 w4d_t;
  u32 w4e_t;
  u32 w4f_t;

  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w00_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w01_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w02_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w03_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w04_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w05_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w06_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w07_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w08_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w09_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0a_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w0b_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w0c_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w0d_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w0e_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0f_t);
  w10_t = hc_rotl32_S ((w0d_t ^ w08_t ^ w02_t ^ w00_t), 1u); SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w10_t);
  w11_t = hc_rotl32_S ((w0e_t ^ w09_t ^ w03_t ^ w01_t), 1u); SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w11_t);
  w12_t = hc_rotl32_S ((w0f_t ^ w0a_t ^ w04_t ^ w02_t), 1u); SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w12_t);
  w13_t = hc_rotl32_S ((w10_t ^ w0b_t ^ w05_t ^ w03_t), 1u); SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w13_t);

  #undef K
  #define K SHA1C01

  w14_t = hc_rotl32_S ((w11_t ^ w0c_t ^ w06_t ^ w04_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w14_t);
  w15_t = hc_rotl32_S ((w12_t ^ w0d_t ^ w07_t ^ w05_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w15_t);
  w16_t = hc_rotl32_S ((w13_t ^ w0e_t ^ w08_t ^ w06_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w16_t);
  w17_t = hc_rotl32_S ((w14_t ^ w0f_t ^ w09_t ^ w07_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w17_t);
  w18_t = hc_rotl32_S ((w15_t ^ w10_t ^ w0a_t ^ w08_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w18_t);
  w19_t = hc_rotl32_S ((w16_t ^ w11_t ^ w0b_t ^ w09_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w19_t);
  w1a_t = hc_rotl32_S ((w17_t ^ w12_t ^ w0c_t ^ w0a_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w1a_t);
  w1b_t = hc_rotl32_S ((w18_t ^ w13_t ^ w0d_t ^ w0b_t), 1u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w1b_t);
  w1c_t = hc_rotl32_S ((w19_t ^ w14_t ^ w0e_t ^ w0c_t), 1u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w1c_t);
  w1d_t = hc_rotl32_S ((w1a_t ^ w15_t ^ w0f_t ^ w0d_t), 1u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w1d_t);
  w1e_t = hc_rotl32_S ((w1b_t ^ w16_t ^ w10_t ^ w0e_t), 1u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w1e_t);
  w1f_t = hc_rotl32_S ((w1c_t ^ w17_t ^ w11_t ^ w0f_t), 1u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w1f_t);
  w20_t = hc_rotl32_S ((w1a_t ^ w10_t ^ w04_t ^ w00_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w20_t);
  w21_t = hc_rotl32_S ((w1b_t ^ w11_t ^ w05_t ^ w01_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w21_t);
  w22_t = hc_rotl32_S ((w1c_t ^ w12_t ^ w06_t ^ w02_t), 2u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w22_t);
  w23_t = hc_rotl32_S ((w1d_t ^ w13_t ^ w07_t ^ w03_t), 2u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w23_t);
  w24_t = hc_rotl32_S ((w1e_t ^ w14_t ^ w08_t ^ w04_t), 2u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w24_t);
  w25_t = hc_rotl32_S ((w1f_t ^ w15_t ^ w09_t ^ w05_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w25_t);
  w26_t = hc_rotl32_S ((w20_t ^ w16_t ^ w0a_t ^ w06_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w26_t);
  w27_t = hc_rotl32_S ((w21_t ^ w17_t ^ w0b_t ^ w07_t), 2u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w27_t);

  #undef K
  #define K SHA1C02

  w28_t = hc_rotl32_S ((w22_t ^ w18_t ^ w0c_t ^ w08_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w28_t);
  w29_t = hc_rotl32_S ((w23_t ^ w19_t ^ w0d_t ^ w09_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w29_t);
  w2a_t = hc_rotl32_S ((w24_t ^ w1a_t ^ w0e_t ^ w0a_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w2a_t);
  w2b_t = hc_rotl32_S ((w25_t ^ w1b_t ^ w0f_t ^ w0b_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w2b_t);
  w2c_t = hc_rotl32_S ((w26_t ^ w1c_t ^ w10_t ^ w0c_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w2c_t);
  w2d_t = hc_rotl32_S ((w27_t ^ w1d_t ^ w11_t ^ w0d_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w2d_t);
  w2e_t = hc_rotl32_S ((w28_t ^ w1e_t ^ w12_t ^ w0e_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w2e_t);
  w2f_t = hc_rotl32_S ((w29_t ^ w1f_t ^ w13_t ^ w0f_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w2f_t);
  w30_t = hc_rotl32_S ((w2a_t ^ w20_t ^ w14_t ^ w10_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w30_t);
  w31_t = hc_rotl32_S ((w2b_t ^ w21_t ^ w15_t ^ w11_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w31_t);
  w32_t = hc_rotl32_S ((w2c_t ^ w22_t ^ w16_t ^ w12_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w32_t);
  w33_t = hc_rotl32_S ((w2d_t ^ w23_t ^ w17_t ^ w13_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w33_t);
  w34_t = hc_rotl32_S ((w2e_t ^ w24_t ^ w18_t ^ w14_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w34_t);
  w35_t = hc_rotl32_S ((w2f_t ^ w25_t ^ w19_t ^ w15_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w35_t);
  w36_t = hc_rotl32_S ((w30_t ^ w26_t ^ w1a_t ^ w16_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w36_t);
  w37_t = hc_rotl32_S ((w31_t ^ w27_t ^ w1b_t ^ w17_t), 2u); SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w37_t);
  w38_t = hc_rotl32_S ((w32_t ^ w28_t ^ w1c_t ^ w18_t), 2u); SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w38_t);
  w39_t = hc_rotl32_S ((w33_t ^ w29_t ^ w1d_t ^ w19_t), 2u); SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w39_t);
  w3a_t = hc_rotl32_S ((w34_t ^ w2a_t ^ w1e_t ^ w1a_t), 2u); SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w3a_t);
  w3b_t = hc_rotl32_S ((w35_t ^ w2b_t ^ w1f_t ^ w1b_t), 2u); SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w3b_t);

  #undef K
  #define K SHA1C03

  w3c_t = hc_rotl32_S ((w36_t ^ w2c_t ^ w20_t ^ w1c_t), 2u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w3c_t);
  w3d_t = hc_rotl32_S ((w37_t ^ w2d_t ^ w21_t ^ w1d_t), 2u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w3d_t);
  w3e_t = hc_rotl32_S ((w38_t ^ w2e_t ^ w22_t ^ w1e_t), 2u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w3e_t);
  w3f_t = hc_rotl32_S ((w39_t ^ w2f_t ^ w23_t ^ w1f_t), 2u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w3f_t);
  w40_t = hc_rotl32_S ((w34_t ^ w20_t ^ w08_t ^ w00_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w40_t);
  w41_t = hc_rotl32_S ((w35_t ^ w21_t ^ w09_t ^ w01_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w41_t);
  w42_t = hc_rotl32_S ((w36_t ^ w22_t ^ w0a_t ^ w02_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w42_t);
  w43_t = hc_rotl32_S ((w37_t ^ w23_t ^ w0b_t ^ w03_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w43_t);
  w44_t = hc_rotl32_S ((w38_t ^ w24_t ^ w0c_t ^ w04_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w44_t);
  w45_t = hc_rotl32_S ((w39_t ^ w25_t ^ w0d_t ^ w05_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w45_t);
  w46_t = hc_rotl32_S ((w3a_t ^ w26_t ^ w0e_t ^ w06_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w46_t);
  w47_t = hc_rotl32_S ((w3b_t ^ w27_t ^ w0f_t ^ w07_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w47_t);
  w48_t = hc_rotl32_S ((w3c_t ^ w28_t ^ w10_t ^ w08_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w48_t);
  w49_t = hc_rotl32_S ((w3d_t ^ w29_t ^ w11_t ^ w09_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w49_t);
  w4a_t = hc_rotl32_S ((w3e_t ^ w2a_t ^ w12_t ^ w0a_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w4a_t);
  w4b_t = hc_rotl32_S ((w3f_t ^ w2b_t ^ w13_t ^ w0b_t), 4u); SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w4b_t);
  w4c_t = hc_rotl32_S ((w40_t ^ w2c_t ^ w14_t ^ w0c_t), 4u); SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w4c_t);
  w4d_t = hc_rotl32_S ((w41_t ^ w2d_t ^ w15_t ^ w0d_t), 4u); SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w4d_t);
  w4e_t = hc_rotl32_S ((w42_t ^ w2e_t ^ w16_t ^ w0e_t), 4u); SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w4e_t);
  w4f_t = hc_rotl32_S ((w43_t ^ w2f_t ^ w17_t ^ w0f_t), 4u); SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w4f_t);

  #undef K
  #endif

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
}

DECLSPEC void sha1_init (PRIVATE_AS sha1_ctx_t *ctx)
{
  ctx->h[0] = SHA1M_A;
  ctx->h[1] = SHA1M_B;
  ctx->h[2] = SHA1M_C;
  ctx->h[3] = SHA1M_D;
  ctx->h[4] = SHA1M_E;

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

DECLSPEC void sha1_update_64 (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len)
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
      sha1_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

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
      switch_buffer_by_offset_be_S (w0, w1, w2, w3, pos);

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

      switch_buffer_by_offset_carry_be_S (w0, w1, w2, w3, c0, c1, c2, c3, pos);

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

      sha1_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

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

DECLSPEC void sha1_update (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

    sha1_update_64 (ctx, w0, w1, w2, w3, 64);
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

  sha1_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void sha1_update_swap (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

    sha1_update_64 (ctx, w0, w1, w2, w3, 64);
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

  sha1_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void sha1_update_utf16le (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      sha1_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
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

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
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

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_utf16le_swap (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      sha1_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
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

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
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

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_utf16be (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
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

    make_utf16be_S (w1, w2, w3);
    make_utf16be_S (w0, w0, w1);

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16be_S (w1, w2, w3);
  make_utf16be_S (w0, w0, w1);

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_utf16beN (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
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

    make_utf16beN_S (w1, w2, w3);
    make_utf16beN_S (w0, w0, w1);

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16beN_S (w1, w2, w3);
  make_utf16beN_S (w0, w0, w1);

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_utf16be_swap (PRIVATE_AS sha1_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
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

    make_utf16be_S (w1, w2, w3);
    make_utf16be_S (w0, w0, w1);

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

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16be_S (w1, w2, w3);
  make_utf16be_S (w0, w0, w1);

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

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_global (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

    sha1_update_64 (ctx, w0, w1, w2, w3, 64);
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

  sha1_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void sha1_update_global_swap (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

    sha1_update_64 (ctx, w0, w1, w2, w3, 64);
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

  sha1_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void sha1_update_global_utf16le (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      sha1_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
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

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
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

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_global_utf16le_swap (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      sha1_update_64 (ctx, enc_buf + 0, enc_buf + 4, enc_buf + 8, enc_buf + 12, enc_len);
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

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
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

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_global_utf16be (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
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

    make_utf16be_S (w1, w2, w3);
    make_utf16be_S (w0, w0, w1);

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16be_S (w1, w2, w3);
  make_utf16be_S (w0, w0, w1);

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_global_utf16be_swap (PRIVATE_AS sha1_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
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

    make_utf16be_S (w1, w2, w3);
    make_utf16be_S (w0, w0, w1);

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

    sha1_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16be_S (w1, w2, w3);
  make_utf16be_S (w0, w0, w1);

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

  sha1_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_final (PRIVATE_AS sha1_ctx_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x80_4x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

  if (pos >= 56)
  {
    sha1_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

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

  ctx->w3[2] = 0;
  ctx->w3[3] = ctx->len * 8;

  sha1_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

// sha1_hmac

DECLSPEC void sha1_hmac_init_64 (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w0, PRIVATE_AS const u32 *w1, PRIVATE_AS const u32 *w2, PRIVATE_AS const u32 *w3)
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

  sha1_init (&ctx->ipad);

  sha1_update_64 (&ctx->ipad, a0, a1, a2, a3, 64);

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

  sha1_init (&ctx->opad);

  sha1_update_64 (&ctx->opad, b0, b1, b2, b3, 64);
}

DECLSPEC void sha1_hmac_init (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    sha1_ctx_t tmp;

    sha1_init (&tmp);

    sha1_update (&tmp, w, len);

    sha1_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
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

  sha1_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void sha1_hmac_init_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    sha1_ctx_t tmp;

    sha1_init (&tmp);

    sha1_update_swap (&tmp, w, len);

    sha1_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
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

  sha1_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void sha1_hmac_init_global (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    sha1_ctx_t tmp;

    sha1_init (&tmp);

    sha1_update_global (&tmp, w, len);

    sha1_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
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

  sha1_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void sha1_hmac_init_global_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    sha1_ctx_t tmp;

    sha1_init (&tmp);

    sha1_update_global_swap (&tmp, w, len);

    sha1_final (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
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

  sha1_hmac_init_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void sha1_hmac_update_64 (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const int len)
{
  sha1_update_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void sha1_hmac_update (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  sha1_update (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_update_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  sha1_update_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_update_utf16le (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  sha1_update_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_update_utf16le_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  sha1_update_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_update_global (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  sha1_update_global (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_update_global_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  sha1_update_global_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_update_global_utf16le (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  sha1_update_global_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_update_global_utf16le_swap (PRIVATE_AS sha1_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  sha1_update_global_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_final (PRIVATE_AS sha1_hmac_ctx_t *ctx)
{
  sha1_final (&ctx->ipad);

  ctx->opad.w0[0] = ctx->ipad.h[0];
  ctx->opad.w0[1] = ctx->ipad.h[1];
  ctx->opad.w0[2] = ctx->ipad.h[2];
  ctx->opad.w0[3] = ctx->ipad.h[3];
  ctx->opad.w1[0] = ctx->ipad.h[4];
  ctx->opad.w1[1] = 0;
  ctx->opad.w1[2] = 0;
  ctx->opad.w1[3] = 0;
  ctx->opad.w2[0] = 0;
  ctx->opad.w2[1] = 0;
  ctx->opad.w2[2] = 0;
  ctx->opad.w2[3] = 0;
  ctx->opad.w3[0] = 0;
  ctx->opad.w3[1] = 0;
  ctx->opad.w3[2] = 0;
  ctx->opad.w3[3] = 0;

  ctx->opad.len += 20;

  sha1_final (&ctx->opad);
}

// while input buf can be a vector datatype, the length of the different elements can not

DECLSPEC void sha1_transform_vector (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u32x *digest)
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];
  u32x e = digest[4];

  #ifdef IS_CPU


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

  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
  w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
  w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
  w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
  w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
  w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
  w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
  w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
  w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
  w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
  w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
  wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
  wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
  wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
  wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
  we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
  wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

  #undef K

  #else

  u32x w00_t = w0[0];
  u32x w01_t = w0[1];
  u32x w02_t = w0[2];
  u32x w03_t = w0[3];
  u32x w04_t = w1[0];
  u32x w05_t = w1[1];
  u32x w06_t = w1[2];
  u32x w07_t = w1[3];
  u32x w08_t = w2[0];
  u32x w09_t = w2[1];
  u32x w0a_t = w2[2];
  u32x w0b_t = w2[3];
  u32x w0c_t = w3[0];
  u32x w0d_t = w3[1];
  u32x w0e_t = w3[2];
  u32x w0f_t = w3[3];
  u32x w10_t;
  u32x w11_t;
  u32x w12_t;
  u32x w13_t;
  u32x w14_t;
  u32x w15_t;
  u32x w16_t;
  u32x w17_t;
  u32x w18_t;
  u32x w19_t;
  u32x w1a_t;
  u32x w1b_t;
  u32x w1c_t;
  u32x w1d_t;
  u32x w1e_t;
  u32x w1f_t;
  u32x w20_t;
  u32x w21_t;
  u32x w22_t;
  u32x w23_t;
  u32x w24_t;
  u32x w25_t;
  u32x w26_t;
  u32x w27_t;
  u32x w28_t;
  u32x w29_t;
  u32x w2a_t;
  u32x w2b_t;
  u32x w2c_t;
  u32x w2d_t;
  u32x w2e_t;
  u32x w2f_t;
  u32x w30_t;
  u32x w31_t;
  u32x w32_t;
  u32x w33_t;
  u32x w34_t;
  u32x w35_t;
  u32x w36_t;
  u32x w37_t;
  u32x w38_t;
  u32x w39_t;
  u32x w3a_t;
  u32x w3b_t;
  u32x w3c_t;
  u32x w3d_t;
  u32x w3e_t;
  u32x w3f_t;
  u32x w40_t;
  u32x w41_t;
  u32x w42_t;
  u32x w43_t;
  u32x w44_t;
  u32x w45_t;
  u32x w46_t;
  u32x w47_t;
  u32x w48_t;
  u32x w49_t;
  u32x w4a_t;
  u32x w4b_t;
  u32x w4c_t;
  u32x w4d_t;
  u32x w4e_t;
  u32x w4f_t;

  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w00_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w01_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w02_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w03_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w04_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w05_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w06_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w07_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w08_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w09_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0a_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0b_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w0c_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w0d_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w0e_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0f_t);
  w10_t = hc_rotl32 ((w0d_t ^ w08_t ^ w02_t ^ w00_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w10_t);
  w11_t = hc_rotl32 ((w0e_t ^ w09_t ^ w03_t ^ w01_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w11_t);
  w12_t = hc_rotl32 ((w0f_t ^ w0a_t ^ w04_t ^ w02_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w12_t);
  w13_t = hc_rotl32 ((w10_t ^ w0b_t ^ w05_t ^ w03_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w13_t);

  #undef K
  #define K SHA1C01

  w14_t = hc_rotl32 ((w11_t ^ w0c_t ^ w06_t ^ w04_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w14_t);
  w15_t = hc_rotl32 ((w12_t ^ w0d_t ^ w07_t ^ w05_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w15_t);
  w16_t = hc_rotl32 ((w13_t ^ w0e_t ^ w08_t ^ w06_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w16_t);
  w17_t = hc_rotl32 ((w14_t ^ w0f_t ^ w09_t ^ w07_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w17_t);
  w18_t = hc_rotl32 ((w15_t ^ w10_t ^ w0a_t ^ w08_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w18_t);
  w19_t = hc_rotl32 ((w16_t ^ w11_t ^ w0b_t ^ w09_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w19_t);
  w1a_t = hc_rotl32 ((w17_t ^ w12_t ^ w0c_t ^ w0a_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w1a_t);
  w1b_t = hc_rotl32 ((w18_t ^ w13_t ^ w0d_t ^ w0b_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w1b_t);
  w1c_t = hc_rotl32 ((w19_t ^ w14_t ^ w0e_t ^ w0c_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1c_t);
  w1d_t = hc_rotl32 ((w1a_t ^ w15_t ^ w0f_t ^ w0d_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w1d_t);
  w1e_t = hc_rotl32 ((w1b_t ^ w16_t ^ w10_t ^ w0e_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1e_t);
  w1f_t = hc_rotl32 ((w1c_t ^ w17_t ^ w11_t ^ w0f_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w1f_t);
  w20_t = hc_rotl32 ((w1a_t ^ w10_t ^ w04_t ^ w00_t), 2u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w20_t);
  w21_t = hc_rotl32 ((w1b_t ^ w11_t ^ w05_t ^ w01_t), 2u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w21_t);
  w22_t = hc_rotl32 ((w1c_t ^ w12_t ^ w06_t ^ w02_t), 2u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w22_t);
  w23_t = hc_rotl32 ((w1d_t ^ w13_t ^ w07_t ^ w03_t), 2u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w23_t);
  w24_t = hc_rotl32 ((w1e_t ^ w14_t ^ w08_t ^ w04_t), 2u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w24_t);
  w25_t = hc_rotl32 ((w1f_t ^ w15_t ^ w09_t ^ w05_t), 2u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w25_t);
  w26_t = hc_rotl32 ((w20_t ^ w16_t ^ w0a_t ^ w06_t), 2u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w26_t);
  w27_t = hc_rotl32 ((w21_t ^ w17_t ^ w0b_t ^ w07_t), 2u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w27_t);

  #undef K
  #define K SHA1C02

  w28_t = hc_rotl32 ((w22_t ^ w18_t ^ w0c_t ^ w08_t), 2u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w28_t);
  w29_t = hc_rotl32 ((w23_t ^ w19_t ^ w0d_t ^ w09_t), 2u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w29_t);
  w2a_t = hc_rotl32 ((w24_t ^ w1a_t ^ w0e_t ^ w0a_t), 2u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w2a_t);
  w2b_t = hc_rotl32 ((w25_t ^ w1b_t ^ w0f_t ^ w0b_t), 2u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w2b_t);
  w2c_t = hc_rotl32 ((w26_t ^ w1c_t ^ w10_t ^ w0c_t), 2u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w2c_t);
  w2d_t = hc_rotl32 ((w27_t ^ w1d_t ^ w11_t ^ w0d_t), 2u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2d_t);
  w2e_t = hc_rotl32 ((w28_t ^ w1e_t ^ w12_t ^ w0e_t), 2u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w2e_t);
  w2f_t = hc_rotl32 ((w29_t ^ w1f_t ^ w13_t ^ w0f_t), 2u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w2f_t);
  w30_t = hc_rotl32 ((w2a_t ^ w20_t ^ w14_t ^ w10_t), 2u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w30_t);
  w31_t = hc_rotl32 ((w2b_t ^ w21_t ^ w15_t ^ w11_t), 2u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w31_t);
  w32_t = hc_rotl32 ((w2c_t ^ w22_t ^ w16_t ^ w12_t), 2u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w32_t);
  w33_t = hc_rotl32 ((w2d_t ^ w23_t ^ w17_t ^ w13_t), 2u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w33_t);
  w34_t = hc_rotl32 ((w2e_t ^ w24_t ^ w18_t ^ w14_t), 2u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w34_t);
  w35_t = hc_rotl32 ((w2f_t ^ w25_t ^ w19_t ^ w15_t), 2u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w35_t);
  w36_t = hc_rotl32 ((w30_t ^ w26_t ^ w1a_t ^ w16_t), 2u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w36_t);
  w37_t = hc_rotl32 ((w31_t ^ w27_t ^ w1b_t ^ w17_t), 2u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w37_t);
  w38_t = hc_rotl32 ((w32_t ^ w28_t ^ w1c_t ^ w18_t), 2u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w38_t);
  w39_t = hc_rotl32 ((w33_t ^ w29_t ^ w1d_t ^ w19_t), 2u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w39_t);
  w3a_t = hc_rotl32 ((w34_t ^ w2a_t ^ w1e_t ^ w1a_t), 2u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w3a_t);
  w3b_t = hc_rotl32 ((w35_t ^ w2b_t ^ w1f_t ^ w1b_t), 2u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w3b_t);

  #undef K
  #define K SHA1C03

  w3c_t = hc_rotl32 ((w36_t ^ w2c_t ^ w20_t ^ w1c_t), 2u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3c_t);
  w3d_t = hc_rotl32 ((w37_t ^ w2d_t ^ w21_t ^ w1d_t), 2u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w3d_t);
  w3e_t = hc_rotl32 ((w38_t ^ w2e_t ^ w22_t ^ w1e_t), 2u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3e_t);
  w3f_t = hc_rotl32 ((w39_t ^ w2f_t ^ w23_t ^ w1f_t), 2u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w3f_t);
  w40_t = hc_rotl32 ((w34_t ^ w20_t ^ w08_t ^ w00_t), 4u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w40_t);
  w41_t = hc_rotl32 ((w35_t ^ w21_t ^ w09_t ^ w01_t), 4u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w41_t);
  w42_t = hc_rotl32 ((w36_t ^ w22_t ^ w0a_t ^ w02_t), 4u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w42_t);
  w43_t = hc_rotl32 ((w37_t ^ w23_t ^ w0b_t ^ w03_t), 4u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w43_t);
  w44_t = hc_rotl32 ((w38_t ^ w24_t ^ w0c_t ^ w04_t), 4u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w44_t);
  w45_t = hc_rotl32 ((w39_t ^ w25_t ^ w0d_t ^ w05_t), 4u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w45_t);
  w46_t = hc_rotl32 ((w3a_t ^ w26_t ^ w0e_t ^ w06_t), 4u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w46_t);
  w47_t = hc_rotl32 ((w3b_t ^ w27_t ^ w0f_t ^ w07_t), 4u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w47_t);
  w48_t = hc_rotl32 ((w3c_t ^ w28_t ^ w10_t ^ w08_t), 4u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w48_t);
  w49_t = hc_rotl32 ((w3d_t ^ w29_t ^ w11_t ^ w09_t), 4u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w49_t);
  w4a_t = hc_rotl32 ((w3e_t ^ w2a_t ^ w12_t ^ w0a_t), 4u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w4a_t);
  w4b_t = hc_rotl32 ((w3f_t ^ w2b_t ^ w13_t ^ w0b_t), 4u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4b_t);
  w4c_t = hc_rotl32 ((w40_t ^ w2c_t ^ w14_t ^ w0c_t), 4u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4c_t);
  w4d_t = hc_rotl32 ((w41_t ^ w2d_t ^ w15_t ^ w0d_t), 4u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w4d_t);
  w4e_t = hc_rotl32 ((w42_t ^ w2e_t ^ w16_t ^ w0e_t), 4u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4e_t);
  w4f_t = hc_rotl32 ((w43_t ^ w2f_t ^ w17_t ^ w0f_t), 4u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w4f_t);

  #undef K

  #endif

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
}

DECLSPEC void sha1_init_vector (PRIVATE_AS sha1_ctx_vector_t *ctx)
{
  ctx->h[0] = SHA1M_A;
  ctx->h[1] = SHA1M_B;
  ctx->h[2] = SHA1M_C;
  ctx->h[3] = SHA1M_D;
  ctx->h[4] = SHA1M_E;

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

DECLSPEC void sha1_init_vector_from_scalar (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS sha1_ctx_t *ctx0)
{
  ctx->h[0] = ctx0->h[0];
  ctx->h[1] = ctx0->h[1];
  ctx->h[2] = ctx0->h[2];
  ctx->h[3] = ctx0->h[3];
  ctx->h[4] = ctx0->h[4];

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

DECLSPEC void sha1_update_vector_64 (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len)
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
      sha1_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

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
      switch_buffer_by_offset_be (w0, w1, w2, w3, pos);

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

      switch_buffer_by_offset_carry_be (w0, w1, w2, w3, c0, c1, c2, c3, pos);

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

      sha1_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

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

DECLSPEC void sha1_update_vector (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
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

    sha1_update_vector_64 (ctx, w0, w1, w2, w3, 64);
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

  sha1_update_vector_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void sha1_update_vector_swap (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
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

    sha1_update_vector_64 (ctx, w0, w1, w2, w3, 64);
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

  sha1_update_vector_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void sha1_update_vector_utf16le (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
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

    sha1_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
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

  sha1_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_vector_utf16le_swap (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
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

    sha1_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
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

  sha1_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_vector_utf16leN (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
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

    make_utf16leN (w1, w2, w3);
    make_utf16leN (w0, w0, w1);

    sha1_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16leN (w1, w2, w3);
  make_utf16leN (w0, w0, w1);

  sha1_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_update_vector_utf16beN (PRIVATE_AS sha1_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
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

    make_utf16beN (w1, w2, w3);
    make_utf16beN (w0, w0, w1);

    sha1_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16beN (w1, w2, w3);
  make_utf16beN (w0, w0, w1);

  sha1_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void sha1_final_vector (PRIVATE_AS sha1_ctx_vector_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x80_4x4 (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

  if (pos >= 56)
  {
    sha1_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);

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

  ctx->w3[2] = 0;
  ctx->w3[3] = ctx->len * 8;

  sha1_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h);
}

// HMAC + Vector

DECLSPEC void sha1_hmac_init_vector_64 (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3)
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

  sha1_init_vector (&ctx->ipad);

  sha1_update_vector_64 (&ctx->ipad, a0, a1, a2, a3, 64);

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

  sha1_init_vector (&ctx->opad);

  sha1_update_vector_64 (&ctx->opad, b0, b1, b2, b3, 64);
}

DECLSPEC void sha1_hmac_init_vector (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  if (len > 64)
  {
    sha1_ctx_vector_t tmp;

    sha1_init_vector (&tmp);

    sha1_update_vector (&tmp, w, len);

    sha1_final_vector (&tmp);

    w0[0] = tmp.h[0];
    w0[1] = tmp.h[1];
    w0[2] = tmp.h[2];
    w0[3] = tmp.h[3];
    w1[0] = tmp.h[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
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

  sha1_hmac_init_vector_64 (ctx, w0, w1, w2, w3);
}

DECLSPEC void sha1_hmac_update_vector_64 (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx, PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, const int len)
{
  sha1_update_vector_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void sha1_hmac_update_vector (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  sha1_update_vector (&ctx->ipad, w, len);
}

DECLSPEC void sha1_hmac_final_vector (PRIVATE_AS sha1_hmac_ctx_vector_t *ctx)
{
  sha1_final_vector (&ctx->ipad);

  ctx->opad.w0[0] = ctx->ipad.h[0];
  ctx->opad.w0[1] = ctx->ipad.h[1];
  ctx->opad.w0[2] = ctx->ipad.h[2];
  ctx->opad.w0[3] = ctx->ipad.h[3];
  ctx->opad.w1[0] = ctx->ipad.h[4];
  ctx->opad.w1[1] = 0;
  ctx->opad.w1[2] = 0;
  ctx->opad.w1[3] = 0;
  ctx->opad.w2[0] = 0;
  ctx->opad.w2[1] = 0;
  ctx->opad.w2[2] = 0;
  ctx->opad.w2[3] = 0;
  ctx->opad.w3[0] = 0;
  ctx->opad.w3[1] = 0;
  ctx->opad.w3[2] = 0;
  ctx->opad.w3[3] = 0;

  ctx->opad.len += 20;

  sha1_final_vector (&ctx->opad);
}
