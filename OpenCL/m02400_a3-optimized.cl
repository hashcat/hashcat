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

DECLSPEC void m02400m (u32 *w, const u32 pw_len, KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * algorithm specific
   */

  if (pw_len <= 16)
  {
    w[ 4] = 0x80;
    w[ 5] = 0;
    w[ 6] = 0;
    w[ 7] = 0;
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 16 * 8;
    w[15] = 0;
  }
  else if (pw_len <= 32)
  {
    w[ 8] = 0x80;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 32 * 8;
    w[15] = 0;
  }
  else if (pw_len <= 48)
  {
    w[12] = 0x80;
    w[13] = 0;
    w[14] = 48 * 8;
    w[15] = 0;
  }

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

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

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

    a &= 0x00ffffff;
    d &= 0x00ffffff;
    c &= 0x00ffffff;
    b &= 0x00ffffff;

    COMPARE_M_SIMD (a, d, c, b);
  }
}

DECLSPEC void m02400s (u32 *w, const u32 pw_len, KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * algorithm specific
   */

  if (pw_len <= 16)
  {
    w[ 4] = 0x80;
    w[ 5] = 0;
    w[ 6] = 0;
    w[ 7] = 0;
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 16 * 8;
    w[15] = 0;
  }
  else if (pw_len <= 32)
  {
    w[ 8] = 0x80;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 32 * 8;
    w[15] = 0;
  }
  else if (pw_len <= 48)
  {
    w[12] = 0x80;
    w[13] = 0;
    w[14] = 48 * 8;
    w[15] = 0;
  }

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

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

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

    if (MATCHES_NONE_VS ((a & 0x00ffffff), search[0])) continue;

    MD5_STEP0(MD5_I , d, a, b, c,     I_wbc3d, MD5S31);
    MD5_STEP0(MD5_I , c, d, a, b,     I_w2c3e, MD5S32);
    MD5_STEP0(MD5_I , b, c, d, a,     I_w9c3f, MD5S33);

    a &= 0x00ffffff;
    d &= 0x00ffffff;
    c &= 0x00ffffff;
    b &= 0x00ffffff;

    COMPARE_S_SIMD (a, d, c, b);
  }
}

__kernel void m02400_m04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m02400m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m02400_m08 (KERN_ATTR_VECTOR ())
{
}

__kernel void m02400_m16 (KERN_ATTR_VECTOR ())
{
}

__kernel void m02400_s04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m02400s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m02400_s08 (KERN_ATTR_VECTOR ())
{
}

__kernel void m02400_s16 (KERN_ATTR_VECTOR ())
{
}
