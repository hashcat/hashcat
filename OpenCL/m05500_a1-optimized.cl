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
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

typedef struct netntlm
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

DECLSPEC void transform_netntlmv1_key (const u32x w0, const u32x w1, PRIVATE_AS u32x *out)
{
  u32x t[8];

  t[0] = (w0 >>  0) & 0xff;
  t[1] = (w0 >>  8) & 0xff;
  t[2] = (w0 >> 16) & 0xff;
  t[3] = (w0 >> 24) & 0xff;
  t[4] = (w1 >>  0) & 0xff;
  t[5] = (w1 >>  8) & 0xff;
  t[6] = (w1 >> 16) & 0xff;
  t[7] = (w1 >> 24) & 0xff;

  u32x k[8];

  k[0] =               (t[0] >> 0);
  k[1] = (t[0] << 7) | (t[1] >> 1);
  k[2] = (t[1] << 6) | (t[2] >> 2);
  k[3] = (t[2] << 5) | (t[3] >> 3);
  k[4] = (t[3] << 4) | (t[4] >> 4);
  k[5] = (t[4] << 3) | (t[5] >> 5);
  k[6] = (t[5] << 2) | (t[6] >> 6);
  k[7] = (t[6] << 1);

  out[0] = ((k[0] & 0xff) <<  0)
         | ((k[1] & 0xff) <<  8)
         | ((k[2] & 0xff) << 16)
         | ((k[3] & 0xff) << 24);

  out[1] = ((k[4] & 0xff) <<  0)
         | ((k[5] & 0xff) <<  8)
         | ((k[6] & 0xff) << 16)
         | ((k[7] & 0xff) << 24);
}

KERNEL_FQ KERNEL_FA void m05500_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

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
   * salt
   */

  const u32 s0 = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 s1 = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u32 s2 = salt_bufs[SALT_POS_HOST].salt_buf[2];

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

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_utf16le (w0, w0_t, w1_t);
    make_utf16le (w1, w2_t, w3_t);

    w3_t[2] = pw_len * 8 * 2;
    w3_t[3] = 0;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3_t[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0_t[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0_t[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[3], MD4C02, MD4S21);

    if (MATCHES_NONE_VS (((d + make_u32x (MD4M_D)) >> 16), s2)) continue;

    MD4_STEP (MD4_H , c, d, a, b, w1_t[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[3], MD4C02, MD4S23);

    a += make_u32x (MD4M_A);
    b += make_u32x (MD4M_B);
    c += make_u32x (MD4M_C);
    d += make_u32x (MD4M_D);

    /**
     * DES1
     */

    u32x key[2];

    transform_netntlmv1_key (a, b, key);

    u32x Kc[16];
    u32x Kd[16];

    _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

    u32x data[2];

    data[0] = s0;
    data[1] = s1;

    u32x iv1[2];

    _des_crypt_encrypt_lm_vect (iv1, data, Kc, Kd, s_SPtrans);

    /**
     * DES2
     */

    transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

    _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

    u32x iv2[2];

    _des_crypt_encrypt_lm_vect (iv2, data, Kc, Kd, s_SPtrans);

    /**
     * compare
     */

    COMPARE_M_SIMD (iv1[0], iv1[1], iv2[0], iv2[1]);
  }
}

KERNEL_FQ KERNEL_FA void m05500_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m05500_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m05500_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * sbox, kbox
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

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
   * salt
   */

  const u32 s0 = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 s1 = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u32 s2 = salt_bufs[SALT_POS_HOST].salt_buf[2];

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

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_utf16le (w0, w0_t, w1_t);
    make_utf16le (w1, w2_t, w3_t);

    w3_t[2] = pw_len * 8 * 2;
    w3_t[3] = 0;

    u32x a = MD4M_A;
    u32x b = MD4M_B;
    u32x c = MD4M_C;
    u32x d = MD4M_D;

    MD4_STEP (MD4_Fo, a, b, c, d, w0_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w0_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w0_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w0_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w1_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w1_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w1_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w1_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w2_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w2_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w2_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w2_t[3], MD4C00, MD4S03);
    MD4_STEP (MD4_Fo, a, b, c, d, w3_t[0], MD4C00, MD4S00);
    MD4_STEP (MD4_Fo, d, a, b, c, w3_t[1], MD4C00, MD4S01);
    MD4_STEP (MD4_Fo, c, d, a, b, w3_t[2], MD4C00, MD4S02);
    MD4_STEP (MD4_Fo, b, c, d, a, w3_t[3], MD4C00, MD4S03);

    MD4_STEP (MD4_Go, a, b, c, d, w0_t[0], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[0], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[0], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[0], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[1], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[1], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[1], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[1], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[2], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[2], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[2], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[2], MD4C01, MD4S13);
    MD4_STEP (MD4_Go, a, b, c, d, w0_t[3], MD4C01, MD4S10);
    MD4_STEP (MD4_Go, d, a, b, c, w1_t[3], MD4C01, MD4S11);
    MD4_STEP (MD4_Go, c, d, a, b, w2_t[3], MD4C01, MD4S12);
    MD4_STEP (MD4_Go, b, c, d, a, w3_t[3], MD4C01, MD4S13);

    MD4_STEP (MD4_H , a, b, c, d, w0_t[0], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[0], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[0], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[0], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[2], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[2], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[2], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[2], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[1], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[1], MD4C02, MD4S21);
    MD4_STEP (MD4_H , c, d, a, b, w1_t[1], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[1], MD4C02, MD4S23);
    MD4_STEP (MD4_H , a, b, c, d, w0_t[3], MD4C02, MD4S20);
    MD4_STEP (MD4_H , d, a, b, c, w2_t[3], MD4C02, MD4S21);

    if (MATCHES_NONE_VS (((d + make_u32x (MD4M_D)) >> 16), s2)) continue;

    MD4_STEP (MD4_H , c, d, a, b, w1_t[3], MD4C02, MD4S22);
    MD4_STEP (MD4_H , b, c, d, a, w3_t[3], MD4C02, MD4S23);

    a += make_u32x (MD4M_A);
    b += make_u32x (MD4M_B);
    c += make_u32x (MD4M_C);
    d += make_u32x (MD4M_D);

    /**
     * DES1
     */

    u32x key[2];

    transform_netntlmv1_key (a, b, key);

    u32x Kc[16];
    u32x Kd[16];

    _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

    u32x data[2];

    data[0] = s0;
    data[1] = s1;

    u32x iv1[2];

    _des_crypt_encrypt_lm_vect (iv1, data, Kc, Kd, s_SPtrans);

    /**
     * DES2
     */

    /*
    transform_netntlmv1_key (((b >> 24) | (c << 8)), ((c >> 24) | (d << 8)), key);

    _des_crypt_keysetup_lm_vect (key[0], key[1], Kc, Kd, s_skb);

    u32x iv2[2];

    _des_crypt_encrypt_lm_vect (iv2, data, Kc, Kd, s_SPtrans);
    */

    u32x iv2[2];

    iv2[0] = search[2];
    iv2[1] = search[3];

    /**
     * compare
     */

    COMPARE_S_SIMD (iv1[0], iv1[1], iv2[0], iv2[1]);
  }
}

KERNEL_FQ KERNEL_FA void m05500_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ KERNEL_FA void m05500_s16 (KERN_ATTR_BASIC ())
{
}
