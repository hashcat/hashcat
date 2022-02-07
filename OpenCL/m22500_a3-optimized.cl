/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

DECLSPEC int is_valid_bitcoinj_8 (const u8 v)
{
  // .abcdefghijklmnopqrstuvwxyz

  if (v > (u8) 'z') return 0;
  if (v < (u8) '.') return 0;

  if ((v > (u8) '.') && (v < (u8) 'a')) return 0;

  return 1;
}

DECLSPEC void m22500 (SHM_TYPE u32a *s_te0, SHM_TYPE u32a *s_te1, SHM_TYPE u32a *s_te2, SHM_TYPE u32a *s_te3, SHM_TYPE u32a *s_te4, SHM_TYPE u32a *s_td0, SHM_TYPE u32a *s_td1, SHM_TYPE u32a *s_td2, SHM_TYPE u32a *s_td3, SHM_TYPE u32a *s_td4, PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf0[2] = 0x80;
  salt_buf0[3] = 0;

  u32 salt_buf1[4] = { 0 };
  u32 salt_buf2[4] = { 0 };
  u32 salt_buf3[4] = { 0 };

  const u32 pw_salt_len = pw_len + 8;

  switch_buffer_by_offset_le_S (salt_buf0, salt_buf1, salt_buf2, salt_buf3, pw_len);

  w[ 0] |= salt_buf0[0];
  w[ 1] |= salt_buf0[1];
  w[ 2] |= salt_buf0[2];
  w[ 3] |= salt_buf0[3];
  w[ 4] |= salt_buf1[0];
  w[ 5] |= salt_buf1[1];
  w[ 6] |= salt_buf1[2];
  w[ 7] |= salt_buf1[3];
  w[ 8] |= salt_buf2[0];
  w[ 9] |= salt_buf2[1];
  w[10] |= salt_buf2[2];
  w[11] |= salt_buf2[3];
  w[12] |= salt_buf3[0];
  w[13] |= salt_buf3[1];
  w[14]  = pw_salt_len * 8;
  w[15]  = 0;

  u32 data[8];

  data[0] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  data[1] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  data[2] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  data[3] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  data[4] = salt_bufs[SALT_POS_HOST].salt_buf[6];
  data[5] = salt_bufs[SALT_POS_HOST].salt_buf[7];
  data[6] = salt_bufs[SALT_POS_HOST].salt_buf[8];
  data[7] = salt_bufs[SALT_POS_HOST].salt_buf[9];

  /**
   * base
   */

  const u32 F_w0c00 =    0u + MD5C00;
  const u32 F_w1c01 = w[ 1] + MD5C01;
  const u32 F_w2c02 = w[ 2] + MD5C02;
  const u32 F_w3c03 = w[ 3] + MD5C03;
  const u32 F_w4c04 = w[ 4] + MD5C04;
  const u32 F_w5c05 = w[ 5] + MD5C05;
  const u32 F_w6c06 = w[ 6] + MD5C06;
  const u32 F_w7c07 = w[ 7] + MD5C07;
  const u32 F_w8c08 = w[ 8] + MD5C08;
  const u32 F_w9c09 = w[ 9] + MD5C09;
  const u32 F_wac0a = w[10] + MD5C0a;
  const u32 F_wbc0b = w[11] + MD5C0b;
  const u32 F_wcc0c = w[12] + MD5C0c;
  const u32 F_wdc0d = w[13] + MD5C0d;
  const u32 F_wec0e = w[14] + MD5C0e;
  const u32 F_wfc0f = w[15] + MD5C0f;

  const u32 G_w1c10 = w[ 1] + MD5C10;
  const u32 G_w6c11 = w[ 6] + MD5C11;
  const u32 G_wbc12 = w[11] + MD5C12;
  const u32 G_w0c13 =    0u + MD5C13;
  const u32 G_w5c14 = w[ 5] + MD5C14;
  const u32 G_wac15 = w[10] + MD5C15;
  const u32 G_wfc16 = w[15] + MD5C16;
  const u32 G_w4c17 = w[ 4] + MD5C17;
  const u32 G_w9c18 = w[ 9] + MD5C18;
  const u32 G_wec19 = w[14] + MD5C19;
  const u32 G_w3c1a = w[ 3] + MD5C1a;
  const u32 G_w8c1b = w[ 8] + MD5C1b;
  const u32 G_wdc1c = w[13] + MD5C1c;
  const u32 G_w2c1d = w[ 2] + MD5C1d;
  const u32 G_w7c1e = w[ 7] + MD5C1e;
  const u32 G_wcc1f = w[12] + MD5C1f;

  const u32 H_w5c20 = w[ 5] + MD5C20;
  const u32 H_w8c21 = w[ 8] + MD5C21;
  const u32 H_wbc22 = w[11] + MD5C22;
  const u32 H_wec23 = w[14] + MD5C23;
  const u32 H_w1c24 = w[ 1] + MD5C24;
  const u32 H_w4c25 = w[ 4] + MD5C25;
  const u32 H_w7c26 = w[ 7] + MD5C26;
  const u32 H_wac27 = w[10] + MD5C27;
  const u32 H_wdc28 = w[13] + MD5C28;
  const u32 H_w0c29 =    0u + MD5C29;
  const u32 H_w3c2a = w[ 3] + MD5C2a;
  const u32 H_w6c2b = w[ 6] + MD5C2b;
  const u32 H_w9c2c = w[ 9] + MD5C2c;
  const u32 H_wcc2d = w[12] + MD5C2d;
  const u32 H_wfc2e = w[15] + MD5C2e;
  const u32 H_w2c2f = w[ 2] + MD5C2f;

  const u32 I_w0c30 =    0u + MD5C30;
  const u32 I_w7c31 = w[ 7] + MD5C31;
  const u32 I_wec32 = w[14] + MD5C32;
  const u32 I_w5c33 = w[ 5] + MD5C33;
  const u32 I_wcc34 = w[12] + MD5C34;
  const u32 I_w3c35 = w[ 3] + MD5C35;
  const u32 I_wac36 = w[10] + MD5C36;
  const u32 I_w1c37 = w[ 1] + MD5C37;
  const u32 I_w8c38 = w[ 8] + MD5C38;
  const u32 I_wfc39 = w[15] + MD5C39;
  const u32 I_w6c3a = w[ 6] + MD5C3a;
  const u32 I_wdc3b = w[13] + MD5C3b;
  const u32 I_w4c3c = w[ 4] + MD5C3c;
  const u32 I_wbc3d = w[11] + MD5C3d;
  const u32 I_w2c3e = w[ 2] + MD5C3e;
  const u32 I_w9c3f = w[ 9] + MD5C3f;

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    /**
     * key1 = md5 ($pass . $salt):
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0, F_w0c00, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,     F_w1c01, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,     F_w2c02, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,     F_w3c03, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,     F_w4c04, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,     F_w5c05, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,     F_w6c06, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,     F_w7c07, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,     F_w8c08, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,     F_w9c09, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,     F_wac0a, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,     F_wbc0b, MD5S03);
    MD5_STEP0(MD5_Fo, a, b, c, d,     F_wcc0c, MD5S00);
    MD5_STEP0(MD5_Fo, d, a, b, c,     F_wdc0d, MD5S01);
    MD5_STEP0(MD5_Fo, c, d, a, b,     F_wec0e, MD5S02);
    MD5_STEP0(MD5_Fo, b, c, d, a,     F_wfc0f, MD5S03);

    MD5_STEP0(MD5_Go, a, b, c, d,     G_w1c10, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,     G_w6c11, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,     G_wbc12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0, G_w0c13, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,     G_w5c14, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,     G_wac15, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,     G_wfc16, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,     G_w4c17, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,     G_w9c18, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,     G_wec19, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,     G_w3c1a, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,     G_w8c1b, MD5S13);
    MD5_STEP0(MD5_Go, a, b, c, d,     G_wdc1c, MD5S10);
    MD5_STEP0(MD5_Go, d, a, b, c,     G_w2c1d, MD5S11);
    MD5_STEP0(MD5_Go, c, d, a, b,     G_w7c1e, MD5S12);
    MD5_STEP0(MD5_Go, b, c, d, a,     G_wcc1f, MD5S13);

    u32x t;

    MD5_STEP0(MD5_H1, a, b, c, d,     H_w5c20, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,     H_w8c21, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,     H_wbc22, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,     H_wec23, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,     H_w1c24, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,     H_w4c25, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,     H_w7c26, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,     H_wac27, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,     H_wdc28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0, H_w0c29, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,     H_w3c2a, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,     H_w6c2b, MD5S23);
    MD5_STEP0(MD5_H1, a, b, c, d,     H_w9c2c, MD5S20);
    MD5_STEP0(MD5_H2, d, a, b, c,     H_wcc2d, MD5S21);
    MD5_STEP0(MD5_H1, c, d, a, b,     H_wfc2e, MD5S22);
    MD5_STEP0(MD5_H2, b, c, d, a,     H_w2c2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0, I_w0c30, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,     I_w7c31, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,     I_wec32, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,     I_w5c33, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,     I_wcc34, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,     I_w3c35, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,     I_wac36, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,     I_w1c37, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,     I_w8c38, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,     I_wfc39, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,     I_w6c3a, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,     I_wdc3b, MD5S33);
    MD5_STEP0(MD5_I , a, b, c, d,     I_w4c3c, MD5S30);
    MD5_STEP0(MD5_I , d, a, b, c,     I_wbc3d, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,     I_w2c3e, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,     I_w9c3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    u32 ukey[8];

    ukey[0] = a;
    ukey[1] = b;
    ukey[2] = c;
    ukey[3] = d;

    /**
     * key2 = md5 ($key1 . $pass . $salt):
     */

    const u32x dgst_pw_salt_len = 16 + pw_salt_len;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = a;
    w0_t[1] = b;
    w0_t[2] = c;
    w0_t[3] = d;

    w1_t[0] = w0;
    w1_t[1] = w[1];
    w1_t[2] = w[2];
    w1_t[3] = w[3];

    w2_t[0] = w[4];
    w2_t[1] = w[5];
    w2_t[2] = w[6];
    w2_t[3] = w[7];

    w3_t[0] = w[8];
    w3_t[1] = w[9];
    w3_t[2] = dgst_pw_salt_len * 8;
    w3_t[3] = 0;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    ukey[4] = a;
    ukey[5] = b;
    ukey[6] = c;
    ukey[7] = d;

    /**
     * iv = md5 ($key2 . $pass . $salt):
     */

    w0_t[0] = a;
    w0_t[1] = b;
    w0_t[2] = c;
    w0_t[3] = d;

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H1, a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    u32 iv[4];

    iv[0] = a;
    iv[1] = b;
    iv[2] = c;
    iv[3] = d;

    /**
     * AES-256-CBC:
     */

    #define KEYLEN 60

    u32 ks[KEYLEN];

    aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 encrypted[4];

    encrypted[0] = data[0];
    encrypted[1] = data[1];
    encrypted[2] = data[2];
    encrypted[3] = data[3];

    u32 out[4];

    aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];

    // first char of decrypted wallet data must be K, L, Q, 5, # or \n

    const u32 first_byte = out[0] & 0xff;

    if ((first_byte != 0x4b) && // K
        (first_byte != 0x4c) && // L
        (first_byte != 0x51) && // Q
        (first_byte != 0x35) && // 5
        (first_byte != 0x23) && // #
        (first_byte != 0x0a))   // \n
    {
      continue;
    }

    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    if ((first_byte == 0x4b) || // K => MultiBit Classic Wallet
        (first_byte == 0x4c) || // L
        (first_byte == 0x51) || // Q
        (first_byte == 0x35))   // 5
    {
      // base58 check:

      if (is_valid_base58_32 (out[0]) == 0) continue;
      if (is_valid_base58_32 (out[1]) == 0) continue;
      if (is_valid_base58_32 (out[2]) == 0) continue;
      if (is_valid_base58_32 (out[3]) == 0) continue;

      iv[0] = encrypted[0];
      iv[1] = encrypted[1];
      iv[2] = encrypted[2];
      iv[3] = encrypted[3];

      encrypted[0] = data[4];
      encrypted[1] = data[5];
      encrypted[2] = data[6];
      encrypted[3] = data[7];

      aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      if (is_valid_base58_32 (out[0]) == 0) continue;
      if (is_valid_base58_32 (out[1]) == 0) continue;
      if (is_valid_base58_32 (out[2]) == 0) continue;
      if (is_valid_base58_32 (out[3]) == 0) continue;
    }
    else if (first_byte == 0x0a) // \n => bitcoinj
    {
      if ((out[0] & 0x0000ff00)  > 0x00007f00) continue; // second_byte

      // check for "org." substring:

      if ((out[0] & 0xffff0000) != 0x726f0000) continue; // "ro" (byte swapped)
      if ((out[1] & 0x0000ffff) != 0x00002e67) continue; // ".g"

      if (is_valid_bitcoinj_8 (out[1] >> 16) == 0) continue; // byte  6 (counting from 0)
      if (is_valid_bitcoinj_8 (out[1] >> 24) == 0) continue; // byte  7

      if (is_valid_bitcoinj_8 (out[2] >>  0) == 0) continue; // byte  8
      if (is_valid_bitcoinj_8 (out[2] >>  8) == 0) continue; // byte  9
      if (is_valid_bitcoinj_8 (out[2] >> 16) == 0) continue; // byte 10
      if (is_valid_bitcoinj_8 (out[2] >> 24) == 0) continue; // byte 11

      if (is_valid_bitcoinj_8 (out[3] >>  0) == 0) continue; // byte 12
      if (is_valid_bitcoinj_8 (out[3] >>  8) == 0) continue; // byte 13
    }
    else // if (first_byte == 0x23) // # => KnCGroup Bitcoin Wallet
    {
      // Full string would be:
      // "# KEEP YOUR PRIVATE KEYS SAFE! Anyone who can read this can spend your Bitcoins."

      // check for "# KEEP YOUR PRIV" substring:

      if (out[0] != 0x454b2023) continue; // "EK #" (byte swapped)
      if (out[1] != 0x59205045) continue; // "Y PE"
      if (out[2] != 0x2052554f) continue; // " RUO"
      if (out[3] != 0x56495250) continue; // "VIRP"

      iv[0] = encrypted[0];
      iv[1] = encrypted[1];
      iv[2] = encrypted[2];
      iv[3] = encrypted[3];

      encrypted[0] = data[4];
      encrypted[1] = data[5];
      encrypted[2] = data[6];
      encrypted[3] = data[7];

      aes256_decrypt (ks, encrypted, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      out[0] ^= iv[0];
      out[1] ^= iv[1];
      out[2] ^= iv[2];
      out[3] ^= iv[3];

      // check for "ATE KEYS SAFE! A" substring:

      if (out[0] != 0x20455441) continue; // " ETA" (byte swapped)
      if (out[1] != 0x5359454b) continue; // "SYEK"
      if (out[2] != 0x46415320) continue; // "FAS "
      if (out[3] != 0x41202145) continue; // "A !E"
    }

    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
    }
  }
}

KERNEL_FQ void m22500_m04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m22500 (s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m22500_m08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m22500 (s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m22500_m16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m22500 (s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m22500_s04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m22500 (s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m22500_s08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m22500 (s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m22500_s16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m22500 (s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
