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
#include M2S(INCLUDE_PATH/inc_hash_md6.cl)
#endif

DECLSPEC void m34600m (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
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

    /**
     * md6-256
     */

    u64x A[128] = { 0 }; // 128-word circular buffer (MD6 reads only last 89 words)
    u64x N[33]   = { 0 };
    u64x B[8]    = { 0 };

    B[0] = hl32_to_64 (w0[1], w0lr);
    B[1] = hl32_to_64 (w0[3], w0[2]);
    B[2] = hl32_to_64 (w1[1], w1[0]);
    B[3] = hl32_to_64 (w1[3], w1[2]);
    B[4] = hl32_to_64 (w2[1], w2[0]);
    B[5] = hl32_to_64 (w2[3], w2[2]);
    B[6] = hl32_to_64 (w3[1], w3[0]);
    B[7] = hl32_to_64 (w3[3], w3[2]);

    B[0] = hc_swap64 (B[0]);
    B[1] = hc_swap64 (B[1]);
    B[2] = hc_swap64 (B[2]);
    B[3] = hc_swap64 (B[3]);
    B[4] = hc_swap64 (B[4]);
    B[5] = hc_swap64 (B[5]);
    B[6] = hc_swap64 (B[6]);
    B[7] = hc_swap64 (B[7]);

    const u64x _pw_len = hl32_to_64 (0, pw_len);
    u64x databitlen = (u64x) (_pw_len * 8);
    u64x p = (u64x) (md6_b * md6_w - databitlen);
    u64x V = (MD6_Vs | (p << 20) | MD6_Ve); // only p change, so we can use precomputed values

    N[ 0] = MD6_Q[ 0];
    N[ 1] = MD6_Q[ 1];
    N[ 2] = MD6_Q[ 2];
    N[ 3] = MD6_Q[ 3];
    N[ 4] = MD6_Q[ 4];
    N[ 5] = MD6_Q[ 5];
    N[ 6] = MD6_Q[ 6];
    N[ 7] = MD6_Q[ 7];
    N[ 8] = MD6_Q[ 8];
    N[ 9] = MD6_Q[ 9];
    N[10] = MD6_Q[10];
    N[11] = MD6_Q[11];
    N[12] = MD6_Q[12];
    N[13] = MD6_Q[13];
    N[14] = MD6_Q[14];
    N[15] = 0;
    N[16] = 0;
    N[17] = 0;
    N[18] = 0;
    N[19] = 0;
    N[20] = 0;
    N[21] = 0;
    N[22] = 0;
    N[23] = MD6_256_DEFAULT_NODEID;
    N[24] = V;
    N[25] = B[0];
    N[26] = B[1];
    N[27] = B[2];
    N[28] = B[3];
    N[29] = B[4];
    N[30] = B[5];
    N[31] = B[6];
    N[32] = B[7];

    u64x x;

    u64x S = MD6_S0;

    u32 i = 0;
    u32 j = 0;

    u32 rXc = MD6_256_ROUNDS * md6_c;

    for (j = 0; j < 33; j++) A[j] = N[j];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (j = 0, i = md6_n; j < rXc; j += md6_c)
    {
      /*
      ** Unroll loop c=16 times. (One "round" of computation.)
      ** Shift amounts are embedded in macros RLnn.
      */

      RL00
      RL01
      RL02
      RL03
      RL04
      RL05
      RL06
      RL07
      RL08
      RL09
      RL10
      RL11
      RL12
      RL13
      RL14
      RL15

      /* Advance round constant S to the next round constant. */

      S = (S << 1) ^ (S >> (md6_w - 1)) ^ (S & MD6_Smask);

      i += 16;
    }

    u32 off = (MD6_256_ROUNDS - 1) * md6_c + md6_n;

    const u32x r0 = l32_from_64 (A[(off+15) & 127]);
    const u32x r1 = h32_from_64 (A[(off+15) & 127]);
    const u32x r2 = l32_from_64 (A[(off+14) & 127]);
    const u32x r3 = h32_from_64 (A[(off+14) & 127]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

DECLSPEC void m34600s (PRIVATE_AS u32 *w0, PRIVATE_AS u32 *w1, PRIVATE_AS u32 *w2, PRIVATE_AS u32 *w3, const u32 pw_len, KERN_ATTR_FUNC_BASIC ())
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

    /**
     * md6-256
     */

    u64x A[128] = { 0 }; // 128-word circular buffer (MD6 reads only last 89 words)
    u64x N[33]   = { 0 };
    u64x B[8]    = { 0 };

    B[0] = hl32_to_64 (w0[1], w0lr);
    B[1] = hl32_to_64 (w0[3], w0[2]);
    B[2] = hl32_to_64 (w1[1], w1[0]);
    B[3] = hl32_to_64 (w1[3], w1[2]);
    B[4] = hl32_to_64 (w2[1], w2[0]);
    B[5] = hl32_to_64 (w2[3], w2[2]);
    B[6] = hl32_to_64 (w3[1], w3[0]);
    B[7] = hl32_to_64 (w3[3], w3[2]);

    B[0] = hc_swap64 (B[0]);
    B[1] = hc_swap64 (B[1]);
    B[2] = hc_swap64 (B[2]);
    B[3] = hc_swap64 (B[3]);
    B[4] = hc_swap64 (B[4]);
    B[5] = hc_swap64 (B[5]);
    B[6] = hc_swap64 (B[6]);
    B[7] = hc_swap64 (B[7]);

    const u64x _pw_len = hl32_to_64 (0, pw_len);
    u64x databitlen = (u64x) (_pw_len * 8);
    u64x p = (u64x) (md6_b * md6_w - databitlen);
    u64x V = (MD6_Vs | (p << 20) | MD6_Ve); // only p change, so we can use precomputed values

    N[ 0] = MD6_Q[ 0];
    N[ 1] = MD6_Q[ 1];
    N[ 2] = MD6_Q[ 2];
    N[ 3] = MD6_Q[ 3];
    N[ 4] = MD6_Q[ 4];
    N[ 5] = MD6_Q[ 5];
    N[ 6] = MD6_Q[ 6];
    N[ 7] = MD6_Q[ 7];
    N[ 8] = MD6_Q[ 8];
    N[ 9] = MD6_Q[ 9];
    N[10] = MD6_Q[10];
    N[11] = MD6_Q[11];
    N[12] = MD6_Q[12];
    N[13] = MD6_Q[13];
    N[14] = MD6_Q[14];
    N[15] = 0;
    N[16] = 0;
    N[17] = 0;
    N[18] = 0;
    N[19] = 0;
    N[20] = 0;
    N[21] = 0;
    N[22] = 0;
    N[23] = MD6_256_DEFAULT_NODEID;
    N[24] = V;
    N[25] = B[0];
    N[26] = B[1];
    N[27] = B[2];
    N[28] = B[3];
    N[29] = B[4];
    N[30] = B[5];
    N[31] = B[6];
    N[32] = B[7];

    u64x x;

    u64x S = MD6_S0;

    u32 i = 0;
    u32 j = 0;

    u32 rXc = MD6_256_ROUNDS * md6_c;

    for (j = 0; j < 33; j++) A[j] = N[j];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (j = 0, i = md6_n; j < rXc; j += md6_c)
    {
      /*
      ** Unroll loop c=16 times. (One "round" of computation.)
      ** Shift amounts are embedded in macros RLnn.
      */

      RL00
      RL01
      RL02
      RL03
      RL04
      RL05
      RL06
      RL07
      RL08
      RL09
      RL10
      RL11
      RL12
      RL13
      RL14
      RL15

      /* Advance round constant S to the next round constant. */

      S = (S << 1) ^ (S >> (md6_w - 1)) ^ (S & MD6_Smask);

      i += 16;
    }

    u32 off = (MD6_256_ROUNDS - 1) * md6_c + md6_n;

    const u32x r0 = l32_from_64 (A[(off+15) & 127]);
    const u32x r1 = h32_from_64 (A[(off+15) & 127]);
    const u32x r2 = l32_from_64 (A[(off+14) & 127]);
    const u32x r3 = h32_from_64 (A[(off+14) & 127]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m34600_m04 (KERN_ATTR_BASIC ())
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

  m34600m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m34600_m08 (KERN_ATTR_BASIC ())
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

  m34600m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m34600_m16 (KERN_ATTR_BASIC ())
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

  m34600m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m34600_s04 (KERN_ATTR_BASIC ())
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

  m34600s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m34600_s08 (KERN_ATTR_BASIC ())
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

  m34600s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m34600_s16 (KERN_ATTR_BASIC ())
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

  m34600s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
