/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_streebog512.cl)
#endif

#define INITVAL 0

DECLSPEC void streebog_g (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, SBOG_LOCAL_TYPE u64 (*s_sbob_sl64)[256])
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
      t[i] = k[i] ^ sbob512_rc64[r][i];
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

CONSTANT_VK u64a STREEBOG_RK[13][8] =
{
  { 0x74a5d4ce2efc83b3UL, 0x74a5d4ce2efc83b3UL, 0x74a5d4ce2efc83b3UL, 0x74a5d4ce2efc83b3UL, 0x74a5d4ce2efc83b3UL, 0x74a5d4ce2efc83b3UL, 0x74a5d4ce2efc83b3UL, 0x74a5d4ce2efc83b3UL },
  { 0x8fd72f640708b0d0UL, 0x0de874c7ebc3f213UL, 0xe92eef3ad202e9e0UL, 0xc1e9da0708013da7UL, 0x9727dab2f014be88UL, 0x103051a02bcd6935UL, 0x33ec7e1dbd28f736UL, 0x1ecf460cf78ad1f4UL },
  { 0x0b2d9f89c775449dUL, 0x6b6eefc6dab7e8b0UL, 0xf1a0d31667f6ec44UL, 0x2a71132d5e108166UL, 0x0e9357c2ec87931aUL, 0xc99f5c1b4a01612dUL, 0x7e60b16e637d4ee2UL, 0xa9fcb827f9ba6d81UL },
  { 0x231feca5ab3d285cUL, 0x70c6e1483c838c3bUL, 0x9c21c3c40ce4e2daUL, 0x2fa796bd5688e573UL, 0x04c0e3ff55809fdfUL, 0x5ff978bfb8e3cdc8UL, 0xc54a19d6a3d07033UL, 0x0fca83fdde872478UL },
  { 0xbdf9312726339f10UL, 0x51a5ba1793bc9c56UL, 0xc4428da14f96d2d4UL, 0xec925222374eab1fUL, 0x79477893747dd92fUL, 0xc495e19a46886304UL, 0x9c23f893ba7cfa36UL, 0x0c47268881fc5febUL },
  { 0xcf117966029b2cb3UL, 0x07179abe77088a8fUL, 0x671ef4cc2650e257UL, 0x7474b8b170dab5c6UL, 0x4224febecf35113eUL, 0x993d156c675c5537UL, 0x2dee3a5782c39b45UL, 0xe7c586f2990dd385UL },
  { 0x8608fd95b1c1138aUL, 0x8bb0847d9e9849acUL, 0x5e76623f4f0eb0c7UL, 0x34c2bdbafc5060ceUL, 0xe9e814475907826cUL, 0x22c9ed94d6aac7c9UL, 0xe6b75e28171eb0d6UL, 0xf1329e5534e60215UL },
  { 0x86bb4814b1c3ce52UL, 0xe8f226c9fbddd017UL, 0xceded67991cb3087UL, 0x76c33e32fdbfaca5UL, 0xdbb13be1a9f7474cUL, 0x3d0273470342c356UL, 0x8e7246c51cf07f61UL, 0xac8c125ddef8df71UL },
  { 0x6d73e747795b8cf3UL, 0x4e4aa65ea0072050UL, 0xa14a1582cb43c2b9UL, 0x748ef2b7bb63b938UL, 0x126789534410d7d4UL, 0xd4d48ff40301d791UL, 0xc67dfbe315c41fc0UL, 0x35e7a1a1af88601cUL },
  { 0x9bd33ea0fab34007UL, 0xf51b7cdbe3d67d25UL, 0xd3abda0ce4186e6bUL, 0x8e61ddadcbce1706UL, 0x58994565b41be6a5UL, 0x7a87abc1240cd31dUL, 0xfafe6c28487968d0UL, 0x15b368609ff9eea7UL },
  { 0xae33263ccf115818UL, 0x93b2dbe9cadfcfc8UL, 0x0a91952bf91b0147UL, 0x458e67ca5f1ed73aUL, 0x94c2e5f288f074e3UL, 0x377895e85c69e996UL, 0xf11a4456aab37b10UL, 0x163131934816821aUL },
  { 0xd07e4a2366bf469dUL, 0x5ef1a3d220213b6cUL, 0x3c5bb78971d8ed0fUL, 0x0de05e6b9006f2d2UL, 0xc58cfb00b8eaa1c9UL, 0xefcdb54d1f250b76UL, 0xfd135634fa527042UL, 0x4cee791290516407UL },
  { 0xd800b9264010790fUL, 0x974c4823e2b668d7UL, 0xa605a4b385c5e361UL, 0x3f6c92da5a56d8d2UL, 0x82b9d67c12ef8277UL, 0x0ab6b4582561bf90UL, 0x46954fd98fc2cba3UL, 0x70be45cb21b6760dUL },
};

DECLSPEC void streebog_g_first (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, SBOG_LOCAL_TYPE u64 (*s_sbob_sl64)[256])
{
  u64x s[8];
  u64x t[8];

  for (int i = 0; i < 8; i++)
  {
    s[i] = m[i];
  }

  for (int r = 0; r < 12; r++)
  {
    for (int i = 0; i < 8; i++)
    {
      t[i] = s[i] ^ STREEBOG_RK[r][i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      s[i] = SBOG_LPSti64;
    }
  }

  for (int i = 0; i < 8; i++)
  {
    h[i] ^= s[i] ^ STREEBOG_RK[12][i] ^ m[i];
  }
}

DECLSPEC void m11800m (SBOG_LOCAL_TYPE u64 (*s_sbob_sl64)[256], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
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

    streebog_g_first (h, m, s_sbob_sl64);

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

DECLSPEC void m11800s (SBOG_LOCAL_TYPE u64 (*s_sbob_sl64)[256], PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
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

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
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

    streebog_g_first (h, m, s_sbob_sl64);

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

KERNEL_FQ KERNEL_FA void m11800_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef SBOG_CONSTANT_TABLES

  CONSTANT_AS u64 (*s_sbob_sl64)[256] = sbob512_sl64;

  #else

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

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
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11800m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11800_m08 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef SBOG_CONSTANT_TABLES

  CONSTANT_AS u64 (*s_sbob_sl64)[256] = sbob512_sl64;

  #else

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

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
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11800m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11800_m16 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef SBOG_CONSTANT_TABLES

  CONSTANT_AS u64 (*s_sbob_sl64)[256] = sbob512_sl64;

  #else

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

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

  m11800m (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11800_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef SBOG_CONSTANT_TABLES

  CONSTANT_AS u64 (*s_sbob_sl64)[256] = sbob512_sl64;

  #else

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

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
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11800s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11800_s08 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef SBOG_CONSTANT_TABLES

  CONSTANT_AS u64 (*s_sbob_sl64)[256] = sbob512_sl64;

  #else

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

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
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m11800s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m11800_s16 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef SBOG_CONSTANT_TABLES

  CONSTANT_AS u64 (*s_sbob_sl64)[256] = sbob512_sl64;

  #else

  LOCAL_VK u64 s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

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

  m11800s (s_sbob_sl64, w, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
