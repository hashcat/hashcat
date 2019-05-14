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

  for (int i = 0; i < 8; i++)
  {
    t[i] = h[i];
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    k[i] = SBOG_LPSti64;
  }

  for (int i = 0; i < 8; i++)
  {
    s[i] = m[i];
  }

  for (int r = 0; r < 12; r++)
  {
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

  for (int i = 0; i < 8; i++)
  {
    h[i] ^= s[i] ^ k[i] ^ m[i];
  }
}

DECLSPEC void m11700m (LOCAL_AS u64 (*s_sbob_sl64)[256], u32 *w, const u32 pw_len, KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * GOST
     */

    u64x m[8];

    m[0] = hl32_to_64 (w[15], w[14]);
    m[1] = hl32_to_64 (w[13], w[12]);
    m[2] = hl32_to_64 (w[11], w[10]);
    m[3] = hl32_to_64 (w[ 9], w[ 8]);
    m[4] = hl32_to_64 (w[ 7], w[ 6]);
    m[5] = hl32_to_64 (w[ 5], w[ 4]);
    m[6] = hl32_to_64 (w[ 3], w[ 2]);
    m[7] = hl32_to_64 (w[ 1], w0lr );

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

DECLSPEC void m11700s (LOCAL_AS u64 (*s_sbob_sl64)[256], u32 *w, const u32 pw_len, KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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
    const u32x w0r = ix_create_bft (bfs_buf, il_pos);

    const u32x w0lr = w0l | w0r;

    /**
     * GOST
     */

    u64x m[8];

    m[0] = hl32_to_64 (w[15], w[14]);
    m[1] = hl32_to_64 (w[13], w[12]);
    m[2] = hl32_to_64 (w[11], w[10]);
    m[3] = hl32_to_64 (w[ 9], w[ 8]);
    m[4] = hl32_to_64 (w[ 7], w[ 6]);
    m[5] = hl32_to_64 (w[ 5], w[ 4]);
    m[6] = hl32_to_64 (w[ 3], w[ 2]);
    m[7] = hl32_to_64 (w[ 1], w0lr );

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

  m11700m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m11700_m08 (KERN_ATTR_BASIC ())
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
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11700m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m11700_m16 (KERN_ATTR_BASIC ())
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

  m11700m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
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

  m11700s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m11700_s08 (KERN_ATTR_BASIC ())
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
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11700s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m11700_s16 (KERN_ATTR_BASIC ())
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

  m11700s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}
