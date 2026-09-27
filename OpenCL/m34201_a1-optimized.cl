/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

DECLSPEC u64 MurmurHash64A (PRIVATE_AS const u32 *data, const u32 len)
{
  #define M 0xc6a4a7935bd1e995
  #define R 47

  // Initialize hash
  u64 hash = len * M;

  // Twice the number of u64 blocks
  const u32 num_u32_blocks = (len / 8) * 2;

  // Loop over one u64 at a time
  u32 i = 0;
  while (i < num_u32_blocks)
  {
    // Reconstruct u64 from two u32s
    u64 k = hl32_to_64 (data[i + 1], data[i]);

    k *= M;
    k ^= k >> R;
    k *= M;

    hash ^= k;
    hash *= M;

    i += 2;
  }

  // Up to 7 overflow bytes
  const u32 overflow = len & 7;

  if (overflow > 4)
  {
    hash ^= hl32_to_64 (data[i + 1], data[i]);
    hash *= M;
  }
  else if (overflow > 0)
  {
    hash ^= hl32_to_64 (0, data[i]);
    hash *= M;
  }

  hash ^= hash >> R;
  hash *= M;
  hash ^= hash >> R;

  #undef M
  #undef R

  return hash;
}

KERNEL_FQ KERNEL_FA void m34201_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

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

  const u32 pw_l_len = pws[gid].pw_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 pw_r_len = COMBS_PW_R_LEN (il_pos);

    const u32 pw_len = pw_l_len + pw_r_len;

    /**
     * concat password candidate
     */

    u32 wordl0[4] = { 0 };
    u32 wordl1[4] = { 0 };
    u32 wordl2[4] = { 0 };
    u32 wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32 wordr0[4] = { 0 };
    u32 wordr1[4] = { 0 };
    u32 wordr2[4] = { 0 };
    u32 wordr3[4] = { 0 };

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

      u32 comb_off = COMBS_PRE_LEN + pw_l_len;

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

    u32 w[16];

    w[ 0] = wordl0[0] | wordr0[0];
    w[ 1] = wordl0[1] | wordr0[1];
    w[ 2] = wordl0[2] | wordr0[2];
    w[ 3] = wordl0[3] | wordr0[3];
    w[ 4] = wordl1[0] | wordr1[0];
    w[ 5] = wordl1[1] | wordr1[1];
    w[ 6] = wordl1[2] | wordr1[2];
    w[ 7] = wordl1[3] | wordr1[3];
    w[ 8] = wordl2[0] | wordr2[0];
    w[ 9] = wordl2[1] | wordr2[1];
    w[10] = wordl2[2] | wordr2[2];
    w[11] = wordl2[3] | wordr2[3];
    w[12] = wordl3[0] | wordr3[0];
    w[13] = wordl3[1] | wordr3[1];
    w[14] = wordl3[2] | wordr3[2];
    w[15] = wordl3[3] | wordr3[3];

    u64x hash = MurmurHash64A (w, pw_len);

    const u32x r0 = l32_from_64 (hash);
    const u32x r1 = h32_from_64 (hash);
    const u32x z = 0;

    COMPARE_M_SIMD (r0, r1, z, z);
  }
}

KERNEL_FQ KERNEL_FA void m34201_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m34201_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m34201_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

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

  const u32 pw_l_len = pws[gid].pw_len;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 pw_r_len = COMBS_PW_R_LEN (il_pos);

    const u32 pw_len = pw_l_len + pw_r_len;

    /**
     * concat password candidate
     */

    u32 wordl0[4] = { 0 };
    u32 wordl1[4] = { 0 };
    u32 wordl2[4] = { 0 };
    u32 wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32 wordr0[4] = { 0 };
    u32 wordr1[4] = { 0 };
    u32 wordr2[4] = { 0 };
    u32 wordr3[4] = { 0 };

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

      u32 comb_off = COMBS_PRE_LEN + pw_l_len;

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

    u32 w[16];

    w[ 0] = wordl0[0] | wordr0[0];
    w[ 1] = wordl0[1] | wordr0[1];
    w[ 2] = wordl0[2] | wordr0[2];
    w[ 3] = wordl0[3] | wordr0[3];
    w[ 4] = wordl1[0] | wordr1[0];
    w[ 5] = wordl1[1] | wordr1[1];
    w[ 6] = wordl1[2] | wordr1[2];
    w[ 7] = wordl1[3] | wordr1[3];
    w[ 8] = wordl2[0] | wordr2[0];
    w[ 9] = wordl2[1] | wordr2[1];
    w[10] = wordl2[2] | wordr2[2];
    w[11] = wordl2[3] | wordr2[3];
    w[12] = wordl3[0] | wordr3[0];
    w[13] = wordl3[1] | wordr3[1];
    w[14] = wordl3[2] | wordr3[2];
    w[15] = wordl3[3] | wordr3[3];

    u64 hash = MurmurHash64A (w, pw_len);

    const u32 r0 = l32_from_64 (hash);
    const u32 r1 = h32_from_64 (hash);
    const u32 z = 0;

    COMPARE_S_SIMD (r0, r1, z, z);
  }
}

KERNEL_FQ KERNEL_FA void m34201_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m34201_s16 (KERN_ATTR_BASIC ())
{
}
