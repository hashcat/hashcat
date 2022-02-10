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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

DECLSPEC void m24900m (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * loop
   */

  const u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x t0[4];
    u32x t1[4];
    u32x t2[4];
    u32x t3[4];

    t0[0] = w0lr;
    t0[1] = w0[1];
    t0[2] = w0[2];
    t0[3] = w0[3];
    t1[0] = w1[0];
    t1[1] = w1[1];
    t1[2] = w1[2];
    t1[3] = w1[3];
    t2[0] = w2[0];
    t2[1] = w2[1];
    t2[2] = w2[2];
    t2[3] = w2[3];
    t3[0] = w3[0];
    t3[1] = w3[1];
    t3[2] = pw_len * 8;
    t3[3] = 0;

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, t0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, t0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t3[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, t1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, t0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t2[1], MD5C3f, MD5S33);

    a += make_u32x (MD5M_A);
    b += make_u32x (MD5M_B);
    c += make_u32x (MD5M_C);
    d += make_u32x (MD5M_D);

    const u32x a0 = (((a >>  0) & 0xff) + ((a >>  8) & 0xff)) % 62;
    const u32x a1 = (((a >> 16) & 0xff) + ((a >> 24) & 0xff)) % 62;
    const u32x b0 = (((b >>  0) & 0xff) + ((b >>  8) & 0xff)) % 62;
    const u32x b1 = (((b >> 16) & 0xff) + ((b >> 24) & 0xff)) % 62;
    const u32x c0 = (((c >>  0) & 0xff) + ((c >>  8) & 0xff)) % 62;
    const u32x c1 = (((c >> 16) & 0xff) + ((c >> 24) & 0xff)) % 62;
    const u32x d0 = (((d >>  0) & 0xff) + ((d >>  8) & 0xff)) % 62;
    const u32x d1 = (((d >> 16) & 0xff) + ((d >> 24) & 0xff)) % 62;

    const u32x ax = (a0 <<  0) | (a1 <<  8);
    const u32x bx = (b0 <<  0) | (b1 <<  8);
    const u32x cx = (c0 <<  0) | (c1 <<  8);
    const u32x dx = (d0 <<  0) | (d1 <<  8);

    COMPARE_M_SIMD (ax, bx, cx, dx);
  }
}

DECLSPEC void m24900s (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3],
  };

  /**
   * loop
   */

  const u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x t0[4];
    u32x t1[4];
    u32x t2[4];
    u32x t3[4];

    t0[0] = w0lr;
    t0[1] = w0[1];
    t0[2] = w0[2];
    t0[3] = w0[3];
    t1[0] = w1[0];
    t1[1] = w1[1];
    t1[2] = w1[2];
    t1[3] = w1[3];
    t2[0] = w2[0];
    t2[1] = w2[1];
    t2[2] = w2[2];
    t2[3] = w2[3];
    t3[0] = w3[0];
    t3[1] = w3[1];
    t3[2] = pw_len * 8;
    t3[3] = 0;

    /**
     * md5
     */

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, t0[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t0[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t0[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t0[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t1[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t1[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t1[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t1[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t2[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t2[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t2[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t2[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, t3[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, t3[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, t3[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, t3[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, t0[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t1[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t2[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t0[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t1[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t2[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t3[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t1[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t2[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t3[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t0[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t2[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, t3[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, t0[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, t1[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, t3[0], MD5C1f, MD5S13);

    u32x t;

    MD5_STEP (MD5_H1, a, b, c, d, t1[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t2[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t2[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t3[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t0[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t1[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t1[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t2[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t3[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t0[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t0[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t1[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H1, a, b, c, d, t2[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H2, d, a, b, c, t3[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H1, c, d, a, b, t3[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H2, b, c, d, a, t0[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, t0[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t1[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t3[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t1[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t3[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t0[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t2[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t0[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t2[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t3[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t1[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t3[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, t1[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, t2[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, t0[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, t2[1], MD5C3f, MD5S33);

    a += make_u32x (MD5M_A);
    b += make_u32x (MD5M_B);
    c += make_u32x (MD5M_C);
    d += make_u32x (MD5M_D);

    const u32x a0 = (((a >>  0) & 0xff) + ((a >>  8) & 0xff)) % 62;
    const u32x a1 = (((a >> 16) & 0xff) + ((a >> 24) & 0xff)) % 62;
    const u32x b0 = (((b >>  0) & 0xff) + ((b >>  8) & 0xff)) % 62;
    const u32x b1 = (((b >> 16) & 0xff) + ((b >> 24) & 0xff)) % 62;
    const u32x c0 = (((c >>  0) & 0xff) + ((c >>  8) & 0xff)) % 62;
    const u32x c1 = (((c >> 16) & 0xff) + ((c >> 24) & 0xff)) % 62;
    const u32x d0 = (((d >>  0) & 0xff) + ((d >>  8) & 0xff)) % 62;
    const u32x d1 = (((d >> 16) & 0xff) + ((d >> 24) & 0xff)) % 62;

    const u32x ax = (a0 <<  0) | (a1 <<  8);
    const u32x bx = (b0 <<  0) | (b1 <<  8);
    const u32x cx = (c0 <<  0) | (c1 <<  8);
    const u32x dx = (d0 <<  0) | (d1 <<  8);

    COMPARE_S_SIMD (ax, bx, cx, dx);
  }
}

KERNEL_FQ void m24900_m04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m24900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m24900_m08 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m24900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m24900_m16 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m24900m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m24900_s04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m24900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m24900_s08 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m24900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m24900_s16 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m24900s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
