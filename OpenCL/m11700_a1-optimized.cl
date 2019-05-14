/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_streebog256.cl"
#endif

#define INITVAL 0x0101010101010101

DECLSPEC void streebog_g (u64x *h, const u64x *m, LOCAL_AS u64 (*s_sbob_sl64)[256])
{
  u64x k[8];
  u64x s[8];
  u64x t[8];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    t[i] = h[i];
  }

  for (int i = 0; i < 8; i++)
  {
    k[i] = SBOG_LPSti64;
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    s[i] = m[i];
  }

  for (int r = 0; r < 12; r++)
  {
    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      t[i] = s[i] ^ k[i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      s[i] = SBOG_LPSti64;
    }

    for (int i = 0; i < 8; i++)
    {
      t[i] = k[i] ^ sbob256_rc64[r][i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      k[i] = SBOG_LPSti64;
    }
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    h[i] ^= s[i] ^ k[i] ^ m[i];
  }
}

KERNEL_FQ void m11700_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

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

    /**
     * GOST
     */

    u32x w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = w2[0];
    w[ 9] = w2[1];
    w[10] = w2[2];
    w[11] = w2[3];
    w[12] = w3[0];
    w[13] = w3[1];
    w[14] = w3[2];
    w[15] = w3[3];

    /**
     * reverse message block
     */

    u64x m[8];

    m[0] = hl32_to_64 (w[15], w[14]);
    m[1] = hl32_to_64 (w[13], w[12]);
    m[2] = hl32_to_64 (w[11], w[10]);
    m[3] = hl32_to_64 (w[ 9], w[ 8]);
    m[4] = hl32_to_64 (w[ 7], w[ 6]);
    m[5] = hl32_to_64 (w[ 5], w[ 4]);
    m[6] = hl32_to_64 (w[ 3], w[ 2]);
    m[7] = hl32_to_64 (w[ 1], w[ 0]);

    m[0] = hc_swap64 (m[0]);
    m[1] = hc_swap64 (m[1]);
    m[2] = hc_swap64 (m[2]);
    m[3] = hc_swap64 (m[3]);
    m[4] = hc_swap64 (m[4]);
    m[5] = hc_swap64 (m[5]);
    m[6] = hc_swap64 (m[6]);
    m[7] = hc_swap64 (m[7]);

    // state buffer (hash)

    u64x h[8];

    h[0] = INITVAL;
    h[1] = INITVAL;
    h[2] = INITVAL;
    h[3] = INITVAL;
    h[4] = INITVAL;
    h[5] = INITVAL;
    h[6] = INITVAL;
    h[7] = INITVAL;

    streebog_g (h, m, s_sbob_sl64);

    u64x z[8];

    z[0] = 0;
    z[1] = 0;
    z[2] = 0;
    z[3] = 0;
    z[4] = 0;
    z[5] = 0;
    z[6] = 0;
    z[7] = hc_swap64 ((u64) (pw_len * 8));

    streebog_g (h, z, s_sbob_sl64);
    streebog_g (h, m, s_sbob_sl64);

    const u32x r0 = l32_from_64 (h[0]);
    const u32x r1 = h32_from_64 (h[0]);
    const u32x r2 = l32_from_64 (h[1]);
    const u32x r3 = h32_from_64 (h[1]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m11700_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m11700_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m11700_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

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

    /**
     * GOST
     */

    u32x w[16];

    w[ 0] = w0[0];
    w[ 1] = w0[1];
    w[ 2] = w0[2];
    w[ 3] = w0[3];
    w[ 4] = w1[0];
    w[ 5] = w1[1];
    w[ 6] = w1[2];
    w[ 7] = w1[3];
    w[ 8] = w2[0];
    w[ 9] = w2[1];
    w[10] = w2[2];
    w[11] = w2[3];
    w[12] = w3[0];
    w[13] = w3[1];
    w[14] = w3[2];
    w[15] = w3[3];

    /**
     * reverse message block
     */

    u64x m[8];

    m[0] = hl32_to_64 (w[15], w[14]);
    m[1] = hl32_to_64 (w[13], w[12]);
    m[2] = hl32_to_64 (w[11], w[10]);
    m[3] = hl32_to_64 (w[ 9], w[ 8]);
    m[4] = hl32_to_64 (w[ 7], w[ 6]);
    m[5] = hl32_to_64 (w[ 5], w[ 4]);
    m[6] = hl32_to_64 (w[ 3], w[ 2]);
    m[7] = hl32_to_64 (w[ 1], w[ 0]);

    m[0] = hc_swap64 (m[0]);
    m[1] = hc_swap64 (m[1]);
    m[2] = hc_swap64 (m[2]);
    m[3] = hc_swap64 (m[3]);
    m[4] = hc_swap64 (m[4]);
    m[5] = hc_swap64 (m[5]);
    m[6] = hc_swap64 (m[6]);
    m[7] = hc_swap64 (m[7]);

    // state buffer (hash)

    u64x h[8];

    h[0] = INITVAL;
    h[1] = INITVAL;
    h[2] = INITVAL;
    h[3] = INITVAL;
    h[4] = INITVAL;
    h[5] = INITVAL;
    h[6] = INITVAL;
    h[7] = INITVAL;

    streebog_g (h, m, s_sbob_sl64);

    u64x z[8];

    z[0] = 0;
    z[1] = 0;
    z[2] = 0;
    z[3] = 0;
    z[4] = 0;
    z[5] = 0;
    z[6] = 0;
    z[7] = hc_swap64 ((u64) (pw_len * 8));

    streebog_g (h, z, s_sbob_sl64);
    streebog_g (h, m, s_sbob_sl64);

    const u32x r0 = l32_from_64 (h[0]);
    const u32x r1 = h32_from_64 (h[0]);
    const u32x r2 = l32_from_64 (h[1]);
    const u32x r3 = h32_from_64 (h[1]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m11700_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m11700_s16 (KERN_ATTR_BASIC ())
{
}
