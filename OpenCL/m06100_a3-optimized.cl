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
#include M2S(INCLUDE_PATH/inc_hash_whirlpool.cl)
#endif

DECLSPEC void whirlpool_transform_transport_vector (PRIVATE_AS const u32x *w, PRIVATE_AS u32x *digest, SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7)
{
  whirlpool_transform_vector (w + 0, w + 4, w + 8, w + 12, digest, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

DECLSPEC void m06100m (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7)
{
  /**
   * modifiers are taken from args
   */

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w[16];

    w[ 0] = w0lr;
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = pw_len * 8;

    /**
     * Whirlool
     */

    u32x dgst[16];

    dgst[ 0] = 0;
    dgst[ 1] = 0;
    dgst[ 2] = 0;
    dgst[ 3] = 0;
    dgst[ 4] = 0;
    dgst[ 5] = 0;
    dgst[ 6] = 0;
    dgst[ 7] = 0;
    dgst[ 8] = 0;
    dgst[ 9] = 0;
    dgst[10] = 0;
    dgst[11] = 0;
    dgst[12] = 0;
    dgst[13] = 0;
    dgst[14] = 0;
    dgst[15] = 0;

    whirlpool_transform_transport_vector (w, dgst, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

    COMPARE_M_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

DECLSPEC void m06100s (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC (), SHM_TYPE u64 *s_MT0, SHM_TYPE u64 *s_MT1, SHM_TYPE u64 *s_MT2, SHM_TYPE u64 *s_MT3, SHM_TYPE u64 *s_MT4, SHM_TYPE u64 *s_MT5, SHM_TYPE u64 *s_MT6, SHM_TYPE u64 *s_MT7)
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
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    u32x w[16];

    w[ 0] = w0lr;
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = 0;
    w[ 9] = 0;
    w[10] = 0;
    w[11] = 0;
    w[12] = 0;
    w[13] = 0;
    w[14] = 0;
    w[15] = pw_len * 8;

    /**
     * Whirlool
     */

    u32x dgst[16];

    dgst[ 0] = 0;
    dgst[ 1] = 0;
    dgst[ 2] = 0;
    dgst[ 3] = 0;
    dgst[ 4] = 0;
    dgst[ 5] = 0;
    dgst[ 6] = 0;
    dgst[ 7] = 0;
    dgst[ 8] = 0;
    dgst[ 9] = 0;
    dgst[10] = 0;
    dgst[11] = 0;
    dgst[12] = 0;
    dgst[13] = 0;
    dgst[14] = 0;
    dgst[15] = 0;

    whirlpool_transform_transport_vector (w, dgst, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);

    COMPARE_S_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

KERNEL_FQ void m06100_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT0[256];
  LOCAL_VK u64 s_MT1[256];
  LOCAL_VK u64 s_MT2[256];
  LOCAL_VK u64 s_MT3[256];
  LOCAL_VK u64 s_MT4[256];
  LOCAL_VK u64 s_MT5[256];
  LOCAL_VK u64 s_MT6[256];
  LOCAL_VK u64 s_MT7[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
    s_MT1[i] = MT1[i];
    s_MT2[i] = MT2[i];
    s_MT3[i] = MT3[i];
    s_MT4[i] = MT4[i];
    s_MT5[i] = MT5[i];
    s_MT6[i] = MT6[i];
    s_MT7[i] = MT7[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m06100m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

KERNEL_FQ void m06100_m08 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT0[256];
  LOCAL_VK u64 s_MT1[256];
  LOCAL_VK u64 s_MT2[256];
  LOCAL_VK u64 s_MT3[256];
  LOCAL_VK u64 s_MT4[256];
  LOCAL_VK u64 s_MT5[256];
  LOCAL_VK u64 s_MT6[256];
  LOCAL_VK u64 s_MT7[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
    s_MT1[i] = MT1[i];
    s_MT2[i] = MT2[i];
    s_MT3[i] = MT3[i];
    s_MT4[i] = MT4[i];
    s_MT5[i] = MT5[i];
    s_MT6[i] = MT6[i];
    s_MT7[i] = MT7[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m06100m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

KERNEL_FQ void m06100_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m06100_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT0[256];
  LOCAL_VK u64 s_MT1[256];
  LOCAL_VK u64 s_MT2[256];
  LOCAL_VK u64 s_MT3[256];
  LOCAL_VK u64 s_MT4[256];
  LOCAL_VK u64 s_MT5[256];
  LOCAL_VK u64 s_MT6[256];
  LOCAL_VK u64 s_MT7[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
    s_MT1[i] = MT1[i];
    s_MT2[i] = MT2[i];
    s_MT3[i] = MT3[i];
    s_MT4[i] = MT4[i];
    s_MT5[i] = MT5[i];
    s_MT6[i] = MT6[i];
    s_MT7[i] = MT7[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m06100s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

KERNEL_FQ void m06100_s08 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT0[256];
  LOCAL_VK u64 s_MT1[256];
  LOCAL_VK u64 s_MT2[256];
  LOCAL_VK u64 s_MT3[256];
  LOCAL_VK u64 s_MT4[256];
  LOCAL_VK u64 s_MT5[256];
  LOCAL_VK u64 s_MT6[256];
  LOCAL_VK u64 s_MT7[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT0[i] = MT0[i];
    s_MT1[i] = MT1[i];
    s_MT2[i] = MT2[i];
    s_MT3[i] = MT3[i];
    s_MT4[i] = MT4[i];
    s_MT5[i] = MT5[i];
    s_MT6[i] = MT6[i];
    s_MT7[i] = MT7[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_MT0 = MT0;
  CONSTANT_AS u64a *s_MT1 = MT1;
  CONSTANT_AS u64a *s_MT2 = MT2;
  CONSTANT_AS u64a *s_MT3 = MT3;
  CONSTANT_AS u64a *s_MT4 = MT4;
  CONSTANT_AS u64a *s_MT5 = MT5;
  CONSTANT_AS u64a *s_MT6 = MT6;
  CONSTANT_AS u64a *s_MT7 = MT7;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

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

  m06100s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz, s_MT0, s_MT1, s_MT2, s_MT3, s_MT4, s_MT5, s_MT6, s_MT7);
}

KERNEL_FQ void m06100_s16 (KERN_ATTR_BASIC ())
{
}
