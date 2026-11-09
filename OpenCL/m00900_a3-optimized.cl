/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

// whether the run kernel's windows reach step 21: three fixed bytes of w0 give 11 bits there, two
// bytes give three, and a window under 10 bits stops no wavefront

#define RUN_DEEP 1

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

#define MD4_STEP_REV(f,a,b,c,d,x,t,s)   \
{                                       \
  a  = hc_rotr32_S (a, s);              \
  a -= f (b, c, d);                     \
  a -= x;                               \
  a -= t;                               \
}

#define MD4_STEP_REV1(f,a,b,c,d,x,t,s)  \
{                                       \
  a  = hc_rotr32_S (a, s);              \
  a -= x;                               \
  a -= t;                               \
}

// The windows of the round 2 state a run of right words requires, from the low bits those words
// share. md4_run_windows_S () leaves them as whole words, so the two compared before a rotate are
// rotated back into the sum they are compared against.

#define RUN_WINDOWS(lo)                                                       \
{                                                                             \
  u32 win[5];                                                                 \
                                                                              \
  md4_run_windows_S ((lo), a_rev, b_rev, c_rev, d_rev, sav_c, sav_d, w, win); \
                                                                              \
  chk21 = hc_rotr32_S (win[0] & win21, 3);                                    \
  chk22 = win[1] & win21;                                                     \
  chk23 = win[2] & win21;                                                     \
  chk24 = win[3] & win21;                                                     \
  chk25 = hc_rotr32_S (win[4] & win25, 3);                                    \
}

DECLSPEC void m00900m (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * base
   */

  const u32 F_w0c00 =     0 + MD4C00;
  const u32 F_w1c00 = w[ 1] + MD4C00;
  const u32 F_w2c00 = w[ 2] + MD4C00;
  const u32 F_w3c00 = w[ 3] + MD4C00;
  const u32 F_w4c00 = w[ 4] + MD4C00;
  const u32 F_w5c00 = w[ 5] + MD4C00;
  const u32 F_w6c00 = w[ 6] + MD4C00;
  const u32 F_w7c00 = w[ 7] + MD4C00;
  const u32 F_w8c00 = w[ 8] + MD4C00;
  const u32 F_w9c00 = w[ 9] + MD4C00;
  const u32 F_wac00 = w[10] + MD4C00;
  const u32 F_wbc00 = w[11] + MD4C00;
  const u32 F_wcc00 = w[12] + MD4C00;
  const u32 F_wdc00 = w[13] + MD4C00;
  const u32 F_wec00 = w[14] + MD4C00;
  const u32 F_wfc00 = w[15] + MD4C00;

  const u32 G_w0c01 =     0 + MD4C01;
  const u32 G_w4c01 = w[ 4] + MD4C01;
  const u32 G_w8c01 = w[ 8] + MD4C01;
  const u32 G_wcc01 = w[12] + MD4C01;
  const u32 G_w1c01 = w[ 1] + MD4C01;
  const u32 G_w5c01 = w[ 5] + MD4C01;
  const u32 G_w9c01 = w[ 9] + MD4C01;
  const u32 G_wdc01 = w[13] + MD4C01;
  const u32 G_w2c01 = w[ 2] + MD4C01;
  const u32 G_w6c01 = w[ 6] + MD4C01;
  const u32 G_wac01 = w[10] + MD4C01;
  const u32 G_wec01 = w[14] + MD4C01;
  const u32 G_w3c01 = w[ 3] + MD4C01;
  const u32 G_w7c01 = w[ 7] + MD4C01;
  const u32 G_wbc01 = w[11] + MD4C01;
  const u32 G_wfc01 = w[15] + MD4C01;

  const u32 H_w0c02 =     0 + MD4C02;
  const u32 H_w8c02 = w[ 8] + MD4C02;
  const u32 H_w4c02 = w[ 4] + MD4C02;
  const u32 H_wcc02 = w[12] + MD4C02;
  const u32 H_w2c02 = w[ 2] + MD4C02;
  const u32 H_wac02 = w[10] + MD4C02;
  const u32 H_w6c02 = w[ 6] + MD4C02;
  const u32 H_wec02 = w[14] + MD4C02;
  const u32 H_w1c02 = w[ 1] + MD4C02;
  const u32 H_w9c02 = w[ 9] + MD4C02;
  const u32 H_w5c02 = w[ 5] + MD4C02;
  const u32 H_wdc02 = w[13] + MD4C02;
  const u32 H_w3c02 = w[ 3] + MD4C02;
  const u32 H_wbc02 = w[11] + MD4C02;
  const u32 H_w7c02 = w[ 7] + MD4C02;
  const u32 H_wfc02 = w[15] + MD4C02;

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0, F_w0c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w1c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_w2c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_w3c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_w4c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w5c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_w6c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_w7c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_w8c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w9c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_wac00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_wbc00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_wcc00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_wdc00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_wec00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_wfc00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0, G_w0c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w4c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_w8c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wcc01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,     G_w1c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w5c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_w9c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wdc01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,     G_w2c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w6c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_wac01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wec01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,     G_w3c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w7c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_wbc01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wfc01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0, H_w0c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_w8c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w4c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wcc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w2c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_wac02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w6c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wec02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w1c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_w9c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w5c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wdc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w3c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_wbc02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w7c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wfc02, MD4S23);

    COMPARE_M_SIMD (a, d, c, b);
  }
}

DECLSPEC void m00900s (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * base
   */

  const u32 F_w0c00 =     0 + MD4C00;
  const u32 F_w1c00 = w[ 1] + MD4C00;
  const u32 F_w2c00 = w[ 2] + MD4C00;
  const u32 F_w3c00 = w[ 3] + MD4C00;
  const u32 F_w4c00 = w[ 4] + MD4C00;
  const u32 F_w5c00 = w[ 5] + MD4C00;
  const u32 F_w6c00 = w[ 6] + MD4C00;
  const u32 F_w7c00 = w[ 7] + MD4C00;
  const u32 F_w8c00 = w[ 8] + MD4C00;
  const u32 F_w9c00 = w[ 9] + MD4C00;
  const u32 F_wac00 = w[10] + MD4C00;
  const u32 F_wbc00 = w[11] + MD4C00;
  const u32 F_wcc00 = w[12] + MD4C00;
  const u32 F_wdc00 = w[13] + MD4C00;
  const u32 F_wec00 = w[14] + MD4C00;
  const u32 F_wfc00 = w[15] + MD4C00;

  const u32 G_w0c01 =     0 + MD4C01;
  const u32 G_w4c01 = w[ 4] + MD4C01;
  const u32 G_w8c01 = w[ 8] + MD4C01;
  const u32 G_wcc01 = w[12] + MD4C01;
  const u32 G_w1c01 = w[ 1] + MD4C01;
  const u32 G_w5c01 = w[ 5] + MD4C01;
  const u32 G_w9c01 = w[ 9] + MD4C01;
  const u32 G_wdc01 = w[13] + MD4C01;
  const u32 G_w2c01 = w[ 2] + MD4C01;
  const u32 G_w6c01 = w[ 6] + MD4C01;
  const u32 G_wac01 = w[10] + MD4C01;
  const u32 G_wec01 = w[14] + MD4C01;
  const u32 G_w3c01 = w[ 3] + MD4C01;
  const u32 G_w7c01 = w[ 7] + MD4C01;
  const u32 G_wbc01 = w[11] + MD4C01;
  const u32 G_wfc01 = w[15] + MD4C01;

  const u32 H_w0c02 =     0 + MD4C02;
  const u32 H_w8c02 = w[ 8] + MD4C02;
  const u32 H_w4c02 = w[ 4] + MD4C02;
  const u32 H_wcc02 = w[12] + MD4C02;
  const u32 H_w2c02 = w[ 2] + MD4C02;
  const u32 H_wac02 = w[10] + MD4C02;
  const u32 H_w6c02 = w[ 6] + MD4C02;
  const u32 H_wec02 = w[14] + MD4C02;
  const u32 H_w1c02 = w[ 1] + MD4C02;
  const u32 H_w9c02 = w[ 9] + MD4C02;
  const u32 H_w5c02 = w[ 5] + MD4C02;
  const u32 H_wdc02 = w[13] + MD4C02;
  const u32 H_w3c02 = w[ 3] + MD4C02;
  const u32 H_wbc02 = w[11] + MD4C02;
  const u32 H_w7c02 = w[ 7] + MD4C02;
  const u32 H_wfc02 = w[15] + MD4C02;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * reverse
   */

  u32 a_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0];
  u32 b_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1];
  u32 c_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2];
  u32 d_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3];

  MD4_STEP_REV (MD4_H_S, b_rev, c_rev, d_rev, a_rev, w[15], MD4C02, MD4S23);
  MD4_STEP_REV (MD4_H_S, c_rev, d_rev, a_rev, b_rev, w[ 7], MD4C02, MD4S22);
  MD4_STEP_REV (MD4_H_S, d_rev, a_rev, b_rev, c_rev, w[11], MD4C02, MD4S21);
  MD4_STEP_REV (MD4_H_S, a_rev, b_rev, c_rev, d_rev, w[ 3], MD4C02, MD4S20);
  MD4_STEP_REV (MD4_H_S, b_rev, c_rev, d_rev, a_rev, w[13], MD4C02, MD4S23);
  MD4_STEP_REV (MD4_H_S, c_rev, d_rev, a_rev, b_rev, w[ 5], MD4C02, MD4S22);
  MD4_STEP_REV (MD4_H_S, d_rev, a_rev, b_rev, c_rev, w[ 9], MD4C02, MD4S21);
  MD4_STEP_REV (MD4_H_S, a_rev, b_rev, c_rev, d_rev, w[ 1], MD4C02, MD4S20);
  MD4_STEP_REV (MD4_H_S, b_rev, c_rev, d_rev, a_rev, w[14], MD4C02, MD4S23);
  MD4_STEP_REV (MD4_H_S, c_rev, d_rev, a_rev, b_rev, w[ 6], MD4C02, MD4S22);
  MD4_STEP_REV (MD4_H_S, d_rev, a_rev, b_rev, c_rev, w[10], MD4C02, MD4S21);
  MD4_STEP_REV (MD4_H_S, a_rev, b_rev, c_rev, d_rev, w[ 2], MD4C02, MD4S20);
  MD4_STEP_REV (MD4_H_S, b_rev, c_rev, d_rev, a_rev, w[12], MD4C02, MD4S23);
  MD4_STEP_REV (MD4_H_S, c_rev, d_rev, a_rev, b_rev, w[ 4], MD4C02, MD4S22);
  MD4_STEP_REV (MD4_H_S, d_rev, a_rev, b_rev, c_rev, w[ 8], MD4C02, MD4S21);
  MD4_STEP_REV (MD4_H_S, a_rev, b_rev, c_rev, d_rev,     0, MD4C02, MD4S20);

  const u32 sav_c = c_rev;
  const u32 sav_d = d_rev;

  MD4_STEP_REV1(MD4_G_S, b_rev, c_rev, d_rev, a_rev, w[15], MD4C01, MD4S13);
  MD4_STEP_REV1(MD4_G_S, c_rev, d_rev, a_rev, b_rev, w[11], MD4C01, MD4S12);

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x pre_a = a_rev;
    u32x pre_b = b_rev;
    u32x pre_c = c_rev;

    pre_a = pre_a - w0;
    pre_b = pre_b - MD4_G (sav_c, sav_d, pre_a);
    pre_c = pre_c - MD4_G (sav_d, pre_a, pre_b);

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0, F_w0c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w1c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_w2c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_w3c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_w4c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w5c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_w6c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_w7c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_w8c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w9c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_wac00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_wbc00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_wcc00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_wdc00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_wec00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_wfc00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0, G_w0c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w4c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_w8c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wcc01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,     G_w1c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w5c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_w9c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wdc01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,     G_w2c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w6c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_wac01, MD4S12); if (MATCHES_NONE_VV (c, pre_c)) continue;
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wec01, MD4S13); if (MATCHES_NONE_VV (b, pre_b)) continue;
    MD4_STEP0(MD4_Go, a, b, c, d,     G_w3c01, MD4S10); if (MATCHES_NONE_VV (a, pre_a)) continue;
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w7c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_wbc01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wfc01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0, H_w0c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_w8c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w4c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wcc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w2c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_wac02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w6c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wec02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w1c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_w9c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w5c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wdc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w3c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_wbc02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w7c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wfc02, MD4S23);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

// The run kernels below reject on the low bits of the required round 2 state while the right side
// of the mask holds the low bytes of w0 fixed over a run of words, which is where r_markov puts
// them. The backend launches them in place of the single-hash kernels above for a mask that gives
// such runs and hands over where the launch's words sit in their run. The single-hash kernels
// above are unchanged.

DECLSPEC void m00900r (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * base
   */

  const u32 F_w0c00 =     0 + MD4C00;
  const u32 F_w1c00 = w[ 1] + MD4C00;
  const u32 F_w2c00 = w[ 2] + MD4C00;
  const u32 F_w3c00 = w[ 3] + MD4C00;
  const u32 F_w4c00 = w[ 4] + MD4C00;
  const u32 F_w5c00 = w[ 5] + MD4C00;
  const u32 F_w6c00 = w[ 6] + MD4C00;
  const u32 F_w7c00 = w[ 7] + MD4C00;
  const u32 F_w8c00 = w[ 8] + MD4C00;
  const u32 F_w9c00 = w[ 9] + MD4C00;
  const u32 F_wac00 = w[10] + MD4C00;
  const u32 F_wbc00 = w[11] + MD4C00;
  const u32 F_wcc00 = w[12] + MD4C00;
  const u32 F_wdc00 = w[13] + MD4C00;
  const u32 F_wec00 = w[14] + MD4C00;
  const u32 F_wfc00 = w[15] + MD4C00;

  const u32 G_w0c01 =     0 + MD4C01;
  const u32 G_w4c01 = w[ 4] + MD4C01;
  const u32 G_w8c01 = w[ 8] + MD4C01;
  const u32 G_wcc01 = w[12] + MD4C01;
  const u32 G_w1c01 = w[ 1] + MD4C01;
  const u32 G_w5c01 = w[ 5] + MD4C01;
  const u32 G_w9c01 = w[ 9] + MD4C01;
  const u32 G_wdc01 = w[13] + MD4C01;
  const u32 G_w2c01 = w[ 2] + MD4C01;
  const u32 G_w6c01 = w[ 6] + MD4C01;
  const u32 G_wac01 = w[10] + MD4C01;
  const u32 G_wec01 = w[14] + MD4C01;
  const u32 G_w3c01 = w[ 3] + MD4C01;
  const u32 G_w7c01 = w[ 7] + MD4C01;
  const u32 G_wbc01 = w[11] + MD4C01;
  const u32 G_wfc01 = w[15] + MD4C01;

  const u32 H_w0c02 =     0 + MD4C02;
  const u32 H_w8c02 = w[ 8] + MD4C02;
  const u32 H_w4c02 = w[ 4] + MD4C02;
  const u32 H_wcc02 = w[12] + MD4C02;
  const u32 H_w2c02 = w[ 2] + MD4C02;
  const u32 H_wac02 = w[10] + MD4C02;
  const u32 H_w6c02 = w[ 6] + MD4C02;
  const u32 H_wec02 = w[14] + MD4C02;
  const u32 H_w1c02 = w[ 1] + MD4C02;
  const u32 H_w9c02 = w[ 9] + MD4C02;
  const u32 H_w5c02 = w[ 5] + MD4C02;
  const u32 H_wdc02 = w[13] + MD4C02;
  const u32 H_w3c02 = w[ 3] + MD4C02;
  const u32 H_wbc02 = w[11] + MD4C02;
  const u32 H_w7c02 = w[ 7] + MD4C02;
  const u32 H_wfc02 = w[15] + MD4C02;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * reverse
   */

  u32 a_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0];
  u32 b_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1];
  u32 c_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2];
  u32 d_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3];

  MD4_STEP_REV (MD4_H_S, b_rev, c_rev, d_rev, a_rev, w[15], MD4C02, MD4S23);
  MD4_STEP_REV (MD4_H_S, c_rev, d_rev, a_rev, b_rev, w[ 7], MD4C02, MD4S22);
  MD4_STEP_REV (MD4_H_S, d_rev, a_rev, b_rev, c_rev, w[11], MD4C02, MD4S21);
  MD4_STEP_REV (MD4_H_S, a_rev, b_rev, c_rev, d_rev, w[ 3], MD4C02, MD4S20);
  MD4_STEP_REV (MD4_H_S, b_rev, c_rev, d_rev, a_rev, w[13], MD4C02, MD4S23);
  MD4_STEP_REV (MD4_H_S, c_rev, d_rev, a_rev, b_rev, w[ 5], MD4C02, MD4S22);
  MD4_STEP_REV (MD4_H_S, d_rev, a_rev, b_rev, c_rev, w[ 9], MD4C02, MD4S21);
  MD4_STEP_REV (MD4_H_S, a_rev, b_rev, c_rev, d_rev, w[ 1], MD4C02, MD4S20);
  MD4_STEP_REV (MD4_H_S, b_rev, c_rev, d_rev, a_rev, w[14], MD4C02, MD4S23);
  MD4_STEP_REV (MD4_H_S, c_rev, d_rev, a_rev, b_rev, w[ 6], MD4C02, MD4S22);
  MD4_STEP_REV (MD4_H_S, d_rev, a_rev, b_rev, c_rev, w[10], MD4C02, MD4S21);
  MD4_STEP_REV (MD4_H_S, a_rev, b_rev, c_rev, d_rev, w[ 2], MD4C02, MD4S20);
  MD4_STEP_REV (MD4_H_S, b_rev, c_rev, d_rev, a_rev, w[12], MD4C02, MD4S23);
  MD4_STEP_REV (MD4_H_S, c_rev, d_rev, a_rev, b_rev, w[ 4], MD4C02, MD4S22);
  MD4_STEP_REV (MD4_H_S, d_rev, a_rev, b_rev, c_rev, w[ 8], MD4C02, MD4S21);
  MD4_STEP_REV (MD4_H_S, a_rev, b_rev, c_rev, d_rev,     0, MD4C02, MD4S20);

  // The state entering step 33 is (a_rev - w0, b_rev, c_rev, d_rev): one subtraction and three
  // constants. Reversed further, the low bits of every required word stay exact for as long as
  // the low bits of w0 are fixed, because borrows only travel upward, G is bitwise and round 2
  // rotates by at most 13.

  const u32 sav_c = c_rev;
  const u32 sav_d = d_rev;

  MD4_STEP_REV1(MD4_G_S, b_rev, c_rev, d_rev, a_rev, w[15], MD4C01, MD4S13);
  MD4_STEP_REV1(MD4_G_S, c_rev, d_rev, a_rev, b_rev, w[11], MD4C01, MD4S12);
  MD4_STEP_REV1(MD4_G_S, d_rev, a_rev, b_rev, c_rev, w[ 7], MD4C01, MD4S11);

  /**
   * loop
   */

  // run_len right words share the low run_mask bits of w0, and run_pos is where the first word of
  // this launch sits in its run. The windows of the state a run requires are computed once per run
  // and held in scalars, and a vector holding the end of one run and the start of the next checks
  // its first lanes against the previous run's windows as well. The first window is compared before
  // the rotate of its step, so only the lanes that pass pay for the rotate. The host launches this
  // kernel only with all four bytes of w0 on the right side, so w0 is the right word alone.

  const u32 run_len  = kernel_param->run_len;
  const u32 run_mask = kernel_param->run_mask;

  // the windows are three bits narrower than the fixed bits at step 25 and 13 bits narrower below

  const u32 win25 = run_mask >> 3;
  const u32 win21 = run_mask >> 13;

  // the same windows as they sit in the sum before the rotate of their step

  const u32 win25t = hc_rotr32_S (win25, 3);
  const u32 win21t = hc_rotr32_S (win21, 3);

  u32 chk21 = 0;
  u32 chk22 = 0;
  u32 chk23 = 0;
  u32 chk24 = 0;
  u32 chk25 = 0;

  u32 old21 = 0;
  u32 old25 = 0;

  u32 phase = kernel_param->run_pos;

  // a launch that opens inside a run takes that run's windows from its first word

  if (phase > 0)
  {
    RUN_WINDOWS (VECTOR_ELEMENT (words_buf_r[0], 0) & run_mask);
  }

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0 = words_buf_r[il_pos / VECT_SIZE];

    if (phase == 0)
    {
      RUN_WINDOWS (VECTOR_ELEMENT (w0, 0) & run_mask);
    }

    // lanes at the front of the vector that still belong to the previous run. A vector of one
    // lane never straddles, so at that width the run bookkeeping is a counter and nothing else.

    #if VECT_SIZE == 1

    const u32 before = 0;

    phase++;

    if (phase == run_len) phase = 0;

    #else

    u32 before = 0;

    if ((phase + VECT_SIZE) > run_len)
    {
      before = run_len - phase;

      old21 = chk21;
      old25 = chk25;

      RUN_WINDOWS (VECTOR_ELEMENT (w0, before) & run_mask);

      phase = (phase + VECT_SIZE) - run_len;
    }
    else
    {
      phase += VECT_SIZE;

      if (phase == run_len) phase = 0;
    }

    #endif

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0, F_w0c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w1c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_w2c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_w3c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_w4c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w5c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_w6c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_w7c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_w8c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_w9c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_wac00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_wbc00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,     F_wcc00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,     F_wdc00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,     F_wec00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,     F_wfc00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0, G_w0c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w4c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_w8c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wcc01, MD4S13);

    #if RUN_DEEP == 1

    // step 21, compared before its rotate

    a = hc_add3 (a, G_w1c01, MD4_Go (b, c, d));

    if ((MATCHES_NONE_VS (a & make_u32x (win21t), chk21)) && ((before == 0) || (MATCHES_NONE_VS (a & make_u32x (win21t), old21)))) continue;

    a = hc_rotl32 (a, MD4S10);

    MD4_STEP0(MD4_Go, d, a, b, c,     G_w5c01, MD4S11); if ((before == 0) && (MATCHES_NONE_VS (d & make_u32x (win21), chk22))) continue;
    MD4_STEP0(MD4_Go, c, d, a, b,     G_w9c01, MD4S12); if ((before == 0) && (MATCHES_NONE_VS (c & make_u32x (win21), chk23))) continue;
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wdc01, MD4S13); if ((before == 0) && (MATCHES_NONE_VS (b & make_u32x (win21), chk24))) continue;

    #else

    MD4_STEP0(MD4_Go, a, b, c, d,     G_w1c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w5c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_w9c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wdc01, MD4S13);

    #endif

    // step 25, compared before its rotate

    a = hc_add3 (a, G_w2c01, MD4_Go (b, c, d));

    if ((MATCHES_NONE_VS (a & make_u32x (win25t), chk25)) && ((before == 0) || (MATCHES_NONE_VS (a & make_u32x (win25t), old25)))) continue;

    a = hc_rotl32 (a, MD4S10);

    // the full backward values, for the few vectors that get here

    u32x pre_a = a_rev;
    u32x pre_b = b_rev;
    u32x pre_c = c_rev;
    u32x pre_d = d_rev;

    pre_a = pre_a - w0;
    pre_b = pre_b - MD4_G (sav_c, sav_d, pre_a);
    pre_c = pre_c - MD4_G (sav_d, pre_a, pre_b);
    pre_d = pre_d - MD4_G (pre_a, pre_b, pre_c);

    MD4_STEP0(MD4_Go, d, a, b, c,     G_w6c01, MD4S11); if (MATCHES_NONE_VV (d, pre_d)) continue;
    MD4_STEP0(MD4_Go, c, d, a, b,     G_wac01, MD4S12); if (MATCHES_NONE_VV (c, pre_c)) continue;
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wec01, MD4S13); if (MATCHES_NONE_VV (b, pre_b)) continue;
    MD4_STEP0(MD4_Go, a, b, c, d,     G_w3c01, MD4S10); if (MATCHES_NONE_VV (a, pre_a)) continue;
    MD4_STEP0(MD4_Go, d, a, b, c,     G_w7c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,     G_wbc01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,     G_wfc01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0, H_w0c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_w8c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w4c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wcc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w2c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_wac02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w6c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wec02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w1c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_w9c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w5c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wdc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,     H_w3c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,     H_wbc02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,     H_w7c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,     H_wfc02, MD4S23);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

KERNEL_FQ KERNEL_FA void m00900_m04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m00900_m08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m00900_m16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m00900_s04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m00900_s08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m00900_s16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m00900_r04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900r (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m00900_r08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = pws[gid].i[14];
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900r (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m00900_r16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00900r (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
