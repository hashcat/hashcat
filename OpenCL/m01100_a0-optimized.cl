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
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

KERNEL_FQ KERNEL_FA void m01100_m04 (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  LOCAL_VK salt_t s_salt_buf[1];

  if (lid == 0)
  {
    s_salt_buf[0] = salt_bufs[SALT_POS_HOST];

    s_salt_buf[0].salt_buf[10] = (16 + s_salt_buf[0].salt_len) * 8;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  #define salt_buf00 s_salt_buf[0].salt_buf[ 0]
  #define salt_buf01 s_salt_buf[0].salt_buf[ 1]
  #define salt_buf02 s_salt_buf[0].salt_buf[ 2]
  #define salt_buf03 s_salt_buf[0].salt_buf[ 3]
  #define salt_buf04 s_salt_buf[0].salt_buf[ 4]
  #define salt_buf05 s_salt_buf[0].salt_buf[ 5]
  #define salt_buf06 s_salt_buf[0].salt_buf[ 6]
  #define salt_buf07 s_salt_buf[0].salt_buf[ 7]
  #define salt_buf08 s_salt_buf[0].salt_buf[ 8]
  #define salt_buf09 s_salt_buf[0].salt_buf[ 9]
  #define salt_buf10 s_salt_buf[0].salt_buf[10]

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w3[2] = out_len * 2 * 8;
    w3[3] = 0;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

    a += make_u32x (MD4M_A);
    b += make_u32x (MD4M_B);
    c += make_u32x (MD4M_C);
    d += make_u32x (MD4M_D);

    w0[0] = a;
    w0[1] = b;
    w0[2] = c;
    w0[3] = d;
    w1[0] = salt_buf00;
    w1[1] = salt_buf01;
    w1[2] = salt_buf02;
    w1[3] = salt_buf03;
    w2[0] = salt_buf04;
    w2[1] = salt_buf05;
    w2[2] = salt_buf06;
    w2[3] = salt_buf07;
    w3[0] = salt_buf08;
    w3[1] = salt_buf09;
    w3[2] = salt_buf10;
    w3[3] = 0;

    a = MD4M_A;
    b = MD4M_B;
    c = MD4M_C;
    d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

    COMPARE_M_SIMD (a, d, c, b);
  }
}

KERNEL_FQ KERNEL_FA void m01100_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m01100_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m01100_s04 (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  LOCAL_VK salt_t s_salt_buf[1];

  if (lid == 0)
  {
    s_salt_buf[0] = salt_bufs[SALT_POS_HOST];

    s_salt_buf[0].salt_buf[10] = (16 + s_salt_buf[0].salt_len) * 8;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  #define salt_buf00 s_salt_buf[0].salt_buf[ 0]
  #define salt_buf01 s_salt_buf[0].salt_buf[ 1]
  #define salt_buf02 s_salt_buf[0].salt_buf[ 2]
  #define salt_buf03 s_salt_buf[0].salt_buf[ 3]
  #define salt_buf04 s_salt_buf[0].salt_buf[ 4]
  #define salt_buf05 s_salt_buf[0].salt_buf[ 5]
  #define salt_buf06 s_salt_buf[0].salt_buf[ 6]
  #define salt_buf07 s_salt_buf[0].salt_buf[ 7]
  #define salt_buf08 s_salt_buf[0].salt_buf[ 8]
  #define salt_buf09 s_salt_buf[0].salt_buf[ 9]
  #define salt_buf10 s_salt_buf[0].salt_buf[10]

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
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w3[2] = out_len * 2 * 8;
    w3[3] = 0;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

    a += make_u32x (MD4M_A);
    b += make_u32x (MD4M_B);
    c += make_u32x (MD4M_C);
    d += make_u32x (MD4M_D);

    w0[0] = a;
    w0[1] = b;
    w0[2] = c;
    w0[3] = d;
    w1[0] = salt_buf00;
    w1[1] = salt_buf01;
    w1[2] = salt_buf02;
    w1[3] = salt_buf03;
    w2[0] = salt_buf04;
    w2[1] = salt_buf05;
    w2[2] = salt_buf06;
    w2[3] = salt_buf07;
    w3[0] = salt_buf08;
    w3[1] = salt_buf09;
    w3[2] = salt_buf10;
    w3[3] = 0;

    a = MD4M_A;
    b = MD4M_B;
    c = MD4M_C;
    d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);

    if (MATCHES_NONE_VS (a, search[0])) continue;

    MD4_STEP (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

    COMPARE_S_SIMD (a, d, c, b);
  }
}

KERNEL_FQ KERNEL_FA void m01100_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m01100_s16 (KERN_ATTR_RULES ())
{
}
