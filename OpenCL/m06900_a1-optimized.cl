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
#include M2S(INCLUDE_PATH/inc_hash_gost94.cl)
#endif

KERNEL_FQ KERNEL_FA void m06900_m04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

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

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    /**
     * GOST
     */

    u32x data[8];

    data[0] = w0[0];
    data[1] = w0[1];
    data[2] = w0[2];
    data[3] = w0[3];
    data[4] = w1[0];
    data[5] = w1[1];
    data[6] = w1[2];
    data[7] = w1[3];

    u32x state[16];

    state[ 0] = 0;
    state[ 1] = 0;
    state[ 2] = 0;
    state[ 3] = 0;
    state[ 4] = 0;
    state[ 5] = 0;
    state[ 6] = 0;
    state[ 7] = 0;
    state[ 8] = data[0];
    state[ 9] = data[1];
    state[10] = data[2];
    state[11] = data[3];
    state[12] = data[4];
    state[13] = data[5];
    state[14] = data[6];
    state[15] = data[7];

    u32x state_m[8];
    u32x data_m[8];

    /* gost1 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    u32x tmp[8];

    //if (pw_len > 0) // not really SIMD compatible
    {
      PASS0 (state, tmp, state_m, data_m, s_tables);
      PASS2 (state, tmp, state_m, data_m, s_tables);
      PASS4 (state, tmp, state_m, data_m, s_tables);
      PASS6 (state, tmp, state_m, data_m, s_tables);

      SHIFT12 (state_m, data, tmp);
      SHIFT16 (state, data_m, state_m);
      SHIFT61 (state, data_m);
    }

    data[0] = pw_len * 8;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;

    /* gost2 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* gost3 */

    data[0] = state[ 8];
    data[1] = state[ 9];
    data[2] = state[10];
    data[3] = state[11];
    data[4] = state[12];
    data[5] = state[13];
    data[6] = state[14];
    data[7] = state[15];

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* store */

    COMPARE_M_SIMD (state[0], state[1], state[2], state[3]);
  }
}

KERNEL_FQ KERNEL_FA void m06900_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m06900_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m06900_s04 (KERN_ATTR_BASIC ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox
   */

  LOCAL_VK u32 s_tables[4][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_tables[0][i] = c_tables[0][i];
    s_tables[1][i] = c_tables[1][i];
    s_tables[2][i] = c_tables[2][i];
    s_tables[3][i] = c_tables[3][i];
  }

  SYNC_THREADS ();

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

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    /**
     * GOST
     */

    u32x data[8];

    data[0] = w0[0];
    data[1] = w0[1];
    data[2] = w0[2];
    data[3] = w0[3];
    data[4] = w1[0];
    data[5] = w1[1];
    data[6] = w1[2];
    data[7] = w1[3];

    u32x state[16];

    state[ 0] = 0;
    state[ 1] = 0;
    state[ 2] = 0;
    state[ 3] = 0;
    state[ 4] = 0;
    state[ 5] = 0;
    state[ 6] = 0;
    state[ 7] = 0;
    state[ 8] = data[0];
    state[ 9] = data[1];
    state[10] = data[2];
    state[11] = data[3];
    state[12] = data[4];
    state[13] = data[5];
    state[14] = data[6];
    state[15] = data[7];

    u32x state_m[8];
    u32x data_m[8];

    /* gost1 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    u32x tmp[8];

    //if (pw_len > 0) // not really SIMD compatible
    {
      PASS0 (state, tmp, state_m, data_m, s_tables);
      PASS2 (state, tmp, state_m, data_m, s_tables);
      PASS4 (state, tmp, state_m, data_m, s_tables);
      PASS6 (state, tmp, state_m, data_m, s_tables);

      SHIFT12 (state_m, data, tmp);
      SHIFT16 (state, data_m, state_m);
      SHIFT61 (state, data_m);
    }

    data[0] = pw_len * 8;
    data[1] = 0;
    data[2] = 0;
    data[3] = 0;
    data[4] = 0;
    data[5] = 0;
    data[6] = 0;
    data[7] = 0;

    /* gost2 */

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* gost3 */

    data[0] = state[ 8];
    data[1] = state[ 9];
    data[2] = state[10];
    data[3] = state[11];
    data[4] = state[12];
    data[5] = state[13];
    data[6] = state[14];
    data[7] = state[15];

    state_m[0] = state[0];
    state_m[1] = state[1];
    state_m[2] = state[2];
    state_m[3] = state[3];
    state_m[4] = state[4];
    state_m[5] = state[5];
    state_m[6] = state[6];
    state_m[7] = state[7];

    data_m[0] = data[0];
    data_m[1] = data[1];
    data_m[2] = data[2];
    data_m[3] = data[3];
    data_m[4] = data[4];
    data_m[5] = data[5];
    data_m[6] = data[6];
    data_m[7] = data[7];

    PASS0 (state, tmp, state_m, data_m, s_tables);
    PASS2 (state, tmp, state_m, data_m, s_tables);
    PASS4 (state, tmp, state_m, data_m, s_tables);
    PASS6 (state, tmp, state_m, data_m, s_tables);

    SHIFT12 (state_m, data, tmp);
    SHIFT16 (state, data_m, state_m);
    SHIFT61 (state, data_m);

    /* store */

    COMPARE_S_SIMD (state[0], state[1], state[2], state[3]);
  }
}

KERNEL_FQ KERNEL_FA void m06900_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m06900_s16 (KERN_ATTR_BASIC ())
{
}
