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
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md6.cl)
#endif

KERNEL_FQ KERNEL_FA void m34600_m04 (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len_tmp = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);
    const u64x out_len = hl32_to_64 (0, out_len_tmp);

    /**
     * md6-256
     */

    u64x A[128] = { 0 }; // 128-word circular buffer (MD6 reads only last 89 words)
    u64x N[29]   = { 0 };
    u64x B[4]    = { 0 };

    B[0] = hl32_to_64 (w0[1], w0[0]);
    B[1] = hl32_to_64 (w0[3], w0[2]);
    B[2] = hl32_to_64 (w1[1], w1[0]);
    B[3] = hl32_to_64 (w1[3], w1[2]);

    B[0] = hc_swap64 (B[0]);
    B[1] = hc_swap64 (B[1]);
    B[2] = hc_swap64 (B[2]);
    B[3] = hc_swap64 (B[3]);

    u64x databitlen = (u64x) (out_len * 8);
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

    u64x x;

    u64x S = MD6_S0;

    u32 i = 0;
    u32 j = 0;

    u32 rXc = MD6_256_ROUNDS * md6_c;

    for (j = 0; j < 29; j++) A[j] = N[j];

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

KERNEL_FQ KERNEL_FA void m34600_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m34600_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m34600_s04 (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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

    const u32x out_len_tmp = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);
    const u64x out_len = hl32_to_64 (0, out_len_tmp);

    /**
     * md6-256
     */

    u64x A[128] = { 0 }; // 128-word circular buffer (MD6 reads only last 89 words)
    u64x N[29]   = { 0 };
    u64x B[4]    = { 0 };

    B[0] = hl32_to_64 (w0[1], w0[0]);
    B[1] = hl32_to_64 (w0[3], w0[2]);
    B[2] = hl32_to_64 (w1[1], w1[0]);
    B[3] = hl32_to_64 (w1[3], w1[2]);

    B[0] = hc_swap64 (B[0]);
    B[1] = hc_swap64 (B[1]);
    B[2] = hc_swap64 (B[2]);
    B[3] = hc_swap64 (B[3]);

    u64x databitlen = (u64x) (out_len * 8);
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

    u64x x;

    u64x S = MD6_S0;

    u32 i = 0;
    u32 j = 0;

    u32 rXc = MD6_256_ROUNDS * md6_c;

    for (j = 0; j < 29; j++) A[j] = N[j];

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

KERNEL_FQ KERNEL_FA void m34600_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ KERNEL_FA void m34600_s16 (KERN_ATTR_RULES ())
{
}
