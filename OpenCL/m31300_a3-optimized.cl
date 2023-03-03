/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

DECLSPEC void m31300m (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
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
   * salt
   */

  const u32 salt_len = 48;

  u32 salt_buf[12];

  salt_buf[ 0] = salt_bufs[SALT_POS_HOST].salt_buf[ 0];
  salt_buf[ 1] = salt_bufs[SALT_POS_HOST].salt_buf[ 1];
  salt_buf[ 2] = salt_bufs[SALT_POS_HOST].salt_buf[ 2];
  salt_buf[ 3] = salt_bufs[SALT_POS_HOST].salt_buf[ 3];
  salt_buf[ 4] = salt_bufs[SALT_POS_HOST].salt_buf[ 4];
  salt_buf[ 5] = salt_bufs[SALT_POS_HOST].salt_buf[ 5];
  salt_buf[ 6] = salt_bufs[SALT_POS_HOST].salt_buf[ 6];
  salt_buf[ 7] = salt_bufs[SALT_POS_HOST].salt_buf[ 7];
  salt_buf[ 8] = salt_bufs[SALT_POS_HOST].salt_buf[ 8];
  salt_buf[ 9] = salt_bufs[SALT_POS_HOST].salt_buf[ 9];
  salt_buf[10] = salt_bufs[SALT_POS_HOST].salt_buf[10];
  salt_buf[11] = salt_bufs[SALT_POS_HOST].salt_buf[11];

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0lr = w0l | w0r;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0lr, F_w0c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,       F_w1c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,       F_w2c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,       F_w3c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,       F_w4c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,       F_w5c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,       F_w6c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,       F_w7c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,       F_w8c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,       F_w9c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,       F_wac00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,       F_wbc00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,       F_wcc00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,       F_wdc00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,       F_wec00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,       F_wfc00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0lr, G_w0c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,       G_w4c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,       G_w8c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,       G_wcc01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,       G_w1c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,       G_w5c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,       G_w9c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,       G_wdc01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,       G_w2c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,       G_w6c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,       G_wac01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,       G_wec01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,       G_w3c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,       G_w7c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,       G_wbc01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,       G_wfc01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0lr, H_w0c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,       H_w8c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,       H_w4c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,       H_wcc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,       H_w2c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,       H_wac02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,       H_w6c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,       H_wec02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,       H_w1c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,       H_w9c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,       H_w5c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,       H_wdc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,       H_w3c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,       H_wbc02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,       H_w7c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,       H_wfc02, MD4S23);

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = a + MD4M_A;
    w0[1] = b + MD4M_B;
    w0[2] = c + MD4M_C;
    w0[3] = d + MD4M_D;
    w1[0] = salt_buf[ 0];
    w1[1] = salt_buf[ 1];
    w1[2] = salt_buf[ 2];
    w1[3] = salt_buf[ 3];
    w2[0] = salt_buf[ 4];
    w2[1] = salt_buf[ 5];
    w2[2] = salt_buf[ 6];
    w2[3] = salt_buf[ 7];
    w3[0] = salt_buf[ 8];
    w3[1] = salt_buf[ 9];
    w3[2] = salt_buf[10];
    w3[3] = salt_buf[11];

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    a = a + MD5M_A;
    b = b + MD5M_B;
    c = c + MD5M_C;
    d = d + MD5M_D;

    const u32x a1 = a;
    const u32x b1 = b;
    const u32x c1 = c;
    const u32x d1 = d;

    w0[0] = 0x80;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 64 * 8;
    w3[3] = 0;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    //u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    a = a + a1;
    b = b + b1;
    c = c + c1;
    d = d + d1;

    COMPARE_M_SIMD (a, d, c, b);
  }
}

DECLSPEC void m31300s (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
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
   * salt
   */

  const u32 salt_len = 48;

  u32 salt_buf[12];

  salt_buf[ 0] = salt_bufs[SALT_POS_HOST].salt_buf[ 0];
  salt_buf[ 1] = salt_bufs[SALT_POS_HOST].salt_buf[ 1];
  salt_buf[ 2] = salt_bufs[SALT_POS_HOST].salt_buf[ 2];
  salt_buf[ 3] = salt_bufs[SALT_POS_HOST].salt_buf[ 3];
  salt_buf[ 4] = salt_bufs[SALT_POS_HOST].salt_buf[ 4];
  salt_buf[ 5] = salt_bufs[SALT_POS_HOST].salt_buf[ 5];
  salt_buf[ 6] = salt_bufs[SALT_POS_HOST].salt_buf[ 6];
  salt_buf[ 7] = salt_bufs[SALT_POS_HOST].salt_buf[ 7];
  salt_buf[ 8] = salt_bufs[SALT_POS_HOST].salt_buf[ 8];
  salt_buf[ 9] = salt_bufs[SALT_POS_HOST].salt_buf[ 9];
  salt_buf[10] = salt_bufs[SALT_POS_HOST].salt_buf[10];
  salt_buf[11] = salt_bufs[SALT_POS_HOST].salt_buf[11];

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0lr = w0l | w0r;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0lr, F_w0c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,       F_w1c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,       F_w2c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,       F_w3c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,       F_w4c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,       F_w5c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,       F_w6c00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,       F_w7c00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,       F_w8c00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,       F_w9c00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,       F_wac00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,       F_wbc00, MD4S03);
    MD4_STEP0(MD4_Fo, a, b, c, d,       F_wcc00, MD4S00);
    MD4_STEP0(MD4_Fo, d, a, b, c,       F_wdc00, MD4S01);
    MD4_STEP0(MD4_Fo, c, d, a, b,       F_wec00, MD4S02);
    MD4_STEP0(MD4_Fo, b, c, d, a,       F_wfc00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0lr, G_w0c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,       G_w4c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,       G_w8c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,       G_wcc01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,       G_w1c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,       G_w5c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,       G_w9c01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,       G_wdc01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,       G_w2c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,       G_w6c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,       G_wac01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,       G_wec01, MD4S13);
    MD4_STEP0(MD4_Go, a, b, c, d,       G_w3c01, MD4S10);
    MD4_STEP0(MD4_Go, d, a, b, c,       G_w7c01, MD4S11);
    MD4_STEP0(MD4_Go, c, d, a, b,       G_wbc01, MD4S12);
    MD4_STEP0(MD4_Go, b, c, d, a,       G_wfc01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0lr, H_w0c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,       H_w8c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,       H_w4c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,       H_wcc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,       H_w2c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,       H_wac02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,       H_w6c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,       H_wec02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,       H_w1c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,       H_w9c02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,       H_w5c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,       H_wdc02, MD4S23);
    MD4_STEP0(MD4_H , a, b, c, d,       H_w3c02, MD4S20);
    MD4_STEP0(MD4_H , d, a, b, c,       H_wbc02, MD4S21);
    MD4_STEP0(MD4_H , c, d, a, b,       H_w7c02, MD4S22);
    MD4_STEP0(MD4_H , b, c, d, a,       H_wfc02, MD4S23);

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = a + MD4M_A;
    w0[1] = b + MD4M_B;
    w0[2] = c + MD4M_C;
    w0[3] = d + MD4M_D;
    w1[0] = salt_buf[ 0];
    w1[1] = salt_buf[ 1];
    w1[2] = salt_buf[ 2];
    w1[3] = salt_buf[ 3];
    w2[0] = salt_buf[ 4];
    w2[1] = salt_buf[ 5];
    w2[2] = salt_buf[ 6];
    w2[3] = salt_buf[ 7];
    w3[0] = salt_buf[ 8];
    w3[1] = salt_buf[ 9];
    w3[2] = salt_buf[10];
    w3[3] = salt_buf[11];

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    a = a + MD5M_A;
    b = b + MD5M_B;
    c = c + MD5M_C;
    d = d + MD5M_D;

    const u32x a1 = a;
    const u32x b1 = b;
    const u32x c1 = c;
    const u32x d1 = d;

    w0[0] = 0x80;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 64 * 8;
    w3[3] = 0;

    MD5_STEP (MD5_Fo, a, b, c, d, w0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3[0], MD5C1f, MD5S13);

    //u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, w1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, w2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, w3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, w3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, w0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2[1], MD5C3f, MD5S33);

    a = a + a1;
    b = b + b1;
    c = c + c1;
    d = d + d1;

    COMPARE_S_SIMD (a, d, c, b);
  }
}

KERNEL_FQ void m31300_m04 (KERN_ATTR_VECTOR ())
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

  m31300m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31300_m08 (KERN_ATTR_VECTOR ())
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

  m31300m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31300_m16 (KERN_ATTR_VECTOR ())
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

  m31300m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31300_s04 (KERN_ATTR_VECTOR ())
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

  m31300s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31300_s08 (KERN_ATTR_VECTOR ())
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

  m31300s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31300_s16 (KERN_ATTR_VECTOR ())
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

  m31300s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
