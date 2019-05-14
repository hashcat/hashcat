/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_whirlpool.cl"
#endif

DECLSPEC void whirlpool_transform_transport_vector (const u32x *w, u32x *digest, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  whirlpool_transform_vector (w + 0, w + 4, w + 8, w + 12, digest, s_Ch, s_Cl);
}

KERNEL_FQ void m06100_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_Ch[8][256];
  LOCAL_VK u32 s_Cl[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_Ch[0][i] = Ch[0][i];
    s_Ch[1][i] = Ch[1][i];
    s_Ch[2][i] = Ch[2][i];
    s_Ch[3][i] = Ch[3][i];
    s_Ch[4][i] = Ch[4][i];
    s_Ch[5][i] = Ch[5][i];
    s_Ch[6][i] = Ch[6][i];
    s_Ch[7][i] = Ch[7][i];

    s_Cl[0][i] = Cl[0][i];
    s_Cl[1][i] = Cl[1][i];
    s_Cl[2][i] = Cl[2][i];
    s_Cl[3][i] = Cl[3][i];
    s_Cl[4][i] = Cl[4][i];
    s_Cl[5][i] = Cl[5][i];
    s_Cl[6][i] = Cl[6][i];
    s_Cl[7][i] = Cl[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_Ch)[256] = Ch;
  CONSTANT_AS u32a (*s_Cl)[256] = Cl;

  #endif

  if (gid >= gid_max) return;

  /**
   * base
   */

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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    u32x w[16];

    w[ 0] = hc_swap32 (w0[0]);
    w[ 1] = hc_swap32 (w0[1]);
    w[ 2] = hc_swap32 (w0[2]);
    w[ 3] = hc_swap32 (w0[3]);
    w[ 4] = hc_swap32 (w1[0]);
    w[ 5] = hc_swap32 (w1[1]);
    w[ 6] = hc_swap32 (w1[2]);
    w[ 7] = hc_swap32 (w1[3]);
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

    whirlpool_transform_transport_vector (w, dgst, s_Ch, s_Cl);

    COMPARE_M_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

KERNEL_FQ void m06100_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m06100_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m06100_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_Ch[8][256];
  LOCAL_VK u32 s_Cl[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_Ch[0][i] = Ch[0][i];
    s_Ch[1][i] = Ch[1][i];
    s_Ch[2][i] = Ch[2][i];
    s_Ch[3][i] = Ch[3][i];
    s_Ch[4][i] = Ch[4][i];
    s_Ch[5][i] = Ch[5][i];
    s_Ch[6][i] = Ch[6][i];
    s_Ch[7][i] = Ch[7][i];

    s_Cl[0][i] = Cl[0][i];
    s_Cl[1][i] = Cl[1][i];
    s_Cl[2][i] = Cl[2][i];
    s_Cl[3][i] = Cl[3][i];
    s_Cl[4][i] = Cl[4][i];
    s_Cl[5][i] = Cl[5][i];
    s_Cl[6][i] = Cl[6][i];
    s_Cl[7][i] = Cl[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_Ch)[256] = Ch;
  CONSTANT_AS u32a (*s_Cl)[256] = Cl;

  #endif

  if (gid >= gid_max) return;

  /**
   * base
   */

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

  const u32 pw_l_len = pws[gid].pw_len & 63;

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

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    u32x w[16];

    w[ 0] = hc_swap32 (w0[0]);
    w[ 1] = hc_swap32 (w0[1]);
    w[ 2] = hc_swap32 (w0[2]);
    w[ 3] = hc_swap32 (w0[3]);
    w[ 4] = hc_swap32 (w1[0]);
    w[ 5] = hc_swap32 (w1[1]);
    w[ 6] = hc_swap32 (w1[2]);
    w[ 7] = hc_swap32 (w1[3]);
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

    whirlpool_transform_transport_vector (w, dgst, s_Ch, s_Cl);

    COMPARE_S_SIMD (dgst[0], dgst[1], dgst[2], dgst[3]);
  }
}

KERNEL_FQ void m06100_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m06100_s16 (KERN_ATTR_BASIC ())
{
}
