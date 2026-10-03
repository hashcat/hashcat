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

KERNEL_FQ KERNEL_FA void m34600_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = COMBS_PW_R_LEN (il_pos) & 63;

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

    #if ATTACK_MODE == 12
    if (COMBS_IS_MIDDLE)
    {
      // -a 12 assembles five pieces in these two register sets: mask, base word, mask, second word,
      // mask. wordl is the accumulator and wordr carries one piece at a time. The piece behind the
      // last word is left in wordr, because the OR below already folds wordr in.
      //
      // Only the second word changes length from one amplifier item to the next. Every other offset
      // is a property of the mask, so those shifts are by a scalar and cost what the shift by
      // pw_l_len costs today.

      if (COMBS_PRE_LEN > 0)
      {
        switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, COMBS_PRE_LEN);

        combs_piece8_VV (combs_buf, il_pos, COMBS_PIECE_PRE, wordr0, wordr1, wordr2, wordr3);

        combs_fold_VV (wordl0, wordl1, wordl2, wordl3, wordr0, wordr1, wordr2, wordr3);
      }

      u32x comb_off = COMBS_PRE_LEN + pw_l_len;

      if (COMBS_MID_LEN > 0)
      {
        combs_piece8_VV (combs_buf, il_pos, COMBS_PIECE_MID, wordr0, wordr1, wordr2, wordr3);

        switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, comb_off);

        combs_fold_VV (wordl0, wordl1, wordl2, wordl3, wordr0, wordr1, wordr2, wordr3);

        comb_off += COMBS_MID_LEN;
      }

      if (COMBS_HAS_Q > 0)
      {
        combs_piece8_VV (combs_buf, il_pos, COMBS_PIECE_WORD, wordr0, wordr1, wordr2, wordr3);

        switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, comb_off);

        combs_fold_VV (wordl0, wordl1, wordl2, wordl3, wordr0, wordr1, wordr2, wordr3);

        comb_off += pwlenx_create_combp (combs_buf, il_pos, COMBS_PIECE_WORD);
      }

      combs_piece8_VV (combs_buf, il_pos, COMBS_PIECE_POST, wordr0, wordr1, wordr2, wordr3);

      if (COMBS_POST_LEN > 0) switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, comb_off);
    }
    else
    #endif
    {
      wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
      wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
      wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
      wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
      wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
      wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
      wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
      wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

      if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
      {
        switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
      }
      else
      {
        switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
      }
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
     * md6-256
     */

    u64x A[2048] = { 0 }; // min 1753 for MD6-256
    u64x N[33]   = { 0 };
    u64x B[8]    = { 0 };

    B[0] = hl32_to_64 (w0[1], w0[0]);
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

    u64x _pw_len = hl32_to_64 (0, pw_len);
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

    const u32x r0 = l32_from_64 (A[off+15]);
    const u32x r1 = h32_from_64 (A[off+15]);
    const u32x r2 = l32_from_64 (A[off+14]);
    const u32x r3 = h32_from_64 (A[off+14]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}


KERNEL_FQ KERNEL_FA void m34600_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m34600_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m34600_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

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

  const u32 pw_l_len = pws[gid].pw_len & 63;

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
    const u32x pw_r_len = COMBS_PW_R_LEN (il_pos) & 63;

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

    #if ATTACK_MODE == 12
    if (COMBS_IS_MIDDLE)
    {
      // -a 12 assembles five pieces in these two register sets: mask, base word, mask, second word,
      // mask. wordl is the accumulator and wordr carries one piece at a time. The piece behind the
      // last word is left in wordr, because the OR below already folds wordr in.
      //
      // Only the second word changes length from one amplifier item to the next. Every other offset
      // is a property of the mask, so those shifts are by a scalar and cost what the shift by
      // pw_l_len costs today.

      if (COMBS_PRE_LEN > 0)
      {
        switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, COMBS_PRE_LEN);

        combs_piece8_VV (combs_buf, il_pos, COMBS_PIECE_PRE, wordr0, wordr1, wordr2, wordr3);

        combs_fold_VV (wordl0, wordl1, wordl2, wordl3, wordr0, wordr1, wordr2, wordr3);
      }

      u32x comb_off = COMBS_PRE_LEN + pw_l_len;

      if (COMBS_MID_LEN > 0)
      {
        combs_piece8_VV (combs_buf, il_pos, COMBS_PIECE_MID, wordr0, wordr1, wordr2, wordr3);

        switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, comb_off);

        combs_fold_VV (wordl0, wordl1, wordl2, wordl3, wordr0, wordr1, wordr2, wordr3);

        comb_off += COMBS_MID_LEN;
      }

      if (COMBS_HAS_Q > 0)
      {
        combs_piece8_VV (combs_buf, il_pos, COMBS_PIECE_WORD, wordr0, wordr1, wordr2, wordr3);

        switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, comb_off);

        combs_fold_VV (wordl0, wordl1, wordl2, wordl3, wordr0, wordr1, wordr2, wordr3);

        comb_off += pwlenx_create_combp (combs_buf, il_pos, COMBS_PIECE_WORD);
      }

      combs_piece8_VV (combs_buf, il_pos, COMBS_PIECE_POST, wordr0, wordr1, wordr2, wordr3);

      if (COMBS_POST_LEN > 0) switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, comb_off);
    }
    else
    #endif
    {
      wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
      wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
      wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
      wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
      wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
      wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
      wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
      wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

      if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
      {
        switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
      }
      else
      {
        switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
      }
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
     * md6-256
     */

    u64x A[2048] = { 0 }; // min 1753 for MD6-256
    u64x N[33]   = { 0 };
    u64x B[8]    = { 0 };

    B[0] = hl32_to_64 (w0[1], w0[0]);
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

    u64x _pw_len = hl32_to_64 (0, pw_len);
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

    const u32x r0 = l32_from_64 (A[off+15]);
    const u32x r1 = h32_from_64 (A[off+15]);
    const u32x r2 = l32_from_64 (A[off+14]);
    const u32x r3 = h32_from_64 (A[off+14]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m34600_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m34600_s16 (KERN_ATTR_BASIC ())
{
}
