/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 * This algorithm for password-storage for the Radmin 3 software was analyzed and made public by synacktiv: 
 * https://www.synacktiv.com/publications/cracking-radmin-server-3-passwords.html
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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_bignum_operations.cl)
#include M2S(INCLUDE_PATH/inc_radmin3_constants.h)
#endif

typedef struct radmin3
{
  u32 user[64];
  u32 user_len;

  u32 pre[PRECOMP_DATALEN]; // 38400 for PRECOMP_BITS = 4

} radmin3_t;


KERNEL_FQ void m29200_m04 (KERN_ATTR_RULES_ESALT (radmin3_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);


  /**
   * cache constant values to shared memory
   */

  LOCAL_VK u32 m[64];
  LOCAL_VK u32 r[64];
  LOCAL_VK u32 fact[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    m[i]    = RADMIN3_M[i];
    r[i]    = RADMIN3_R[i];
    fact[i] = RADMIN3_FACT[i];
  }

  SYNC_THREADS ();

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
   * salt
   */

  u32 salt1_buf0[4];
  u32 salt1_buf1[4];
  u32 salt1_buf2[4];
  u32 salt1_buf3[4];

  salt1_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt1_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt1_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt1_buf0[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  salt1_buf1[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  salt1_buf1[1] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  salt1_buf1[2] = salt_bufs[SALT_POS_HOST].salt_buf[6];
  salt1_buf1[3] = salt_bufs[SALT_POS_HOST].salt_buf[7];
  salt1_buf2[0] = 0;
  salt1_buf2[1] = 0;
  salt1_buf2[2] = 0;
  salt1_buf2[3] = 0;
  salt1_buf3[0] = 0;
  salt1_buf3[1] = 0;
  salt1_buf3[2] = 0;
  salt1_buf3[3] = 0;

  u32 salt2_buf0[4];
  u32 salt2_buf1[4];
  u32 salt2_buf2[4];
  u32 salt2_buf3[4];

  salt2_buf0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 0]);
  salt2_buf0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 1]);
  salt2_buf0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 2]);
  salt2_buf0[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 3]);
  salt2_buf1[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 4]);
  salt2_buf1[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 5]);
  salt2_buf1[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 6]);
  salt2_buf1[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 7]);
  salt2_buf2[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 8]);
  salt2_buf2[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 9]);
  salt2_buf2[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[10]);
  salt2_buf2[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[11]);
  salt2_buf3[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[12]);
  salt2_buf3[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[13]);
  salt2_buf3[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[14]);
  salt2_buf3[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[15]);

  const u32 salt2_len = esalt_bufs[DIGESTS_OFFSET_HOST].user_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
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

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
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

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    const u32x pw_len2 = pw_len * 2;

    /**
     * prepend salt
     */

    const u32x pw_salt_len = pw_len2 + salt2_len;

    switch_buffer_by_offset_le (w0, w1, w2, w3, salt2_len);

    w0[0] |= salt2_buf0[0];
    w0[1] |= salt2_buf0[1];
    w0[2] |= salt2_buf0[2];
    w0[3] |= salt2_buf0[3];
    w1[0] |= salt2_buf1[0];
    w1[1] |= salt2_buf1[1];
    w1[2] |= salt2_buf1[2];
    w1[3] |= salt2_buf1[3];
    w2[0] |= salt2_buf2[0];
    w2[1] |= salt2_buf2[1];
    w2[2] |= salt2_buf2[2];
    w2[3] |= salt2_buf2[3];
    w3[0] |= salt2_buf3[0];
    w3[1] |= salt2_buf3[1];
    w3[2] |= salt2_buf3[2];
    w3[3] |= salt2_buf3[3];

    append_0x80_4x4_VV (w0, w1, w2, w3, pw_salt_len);

    /**
     * sha1
     */

    u32x w0_t = hc_swap32 (w0[0]);
    u32x w1_t = hc_swap32 (w0[1]);
    u32x w2_t = hc_swap32 (w0[2]);
    u32x w3_t = hc_swap32 (w0[3]);
    u32x w4_t = hc_swap32 (w1[0]);
    u32x w5_t = hc_swap32 (w1[1]);
    u32x w6_t = hc_swap32 (w1[2]);
    u32x w7_t = hc_swap32 (w1[3]);
    u32x w8_t = hc_swap32 (w2[0]);
    u32x w9_t = hc_swap32 (w2[1]);
    u32x wa_t = hc_swap32 (w2[2]);
    u32x wb_t = hc_swap32 (w2[3]);
    u32x wc_t = hc_swap32 (w3[0]);
    u32x wd_t = hc_swap32 (w3[1]);
    u32x we_t = 0;
    u32x wf_t = pw_salt_len * 8;

    u32x a = SHA1M_A;
    u32x b = SHA1M_B;
    u32x c = SHA1M_C;
    u32x d = SHA1M_D;
    u32x e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

    #undef K
    #define K SHA1C01

    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

    #undef K
    #define K SHA1C02

    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

    #undef K
    #define K SHA1C03

    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

    a += make_u32x (SHA1M_A);
    b += make_u32x (SHA1M_B);
    c += make_u32x (SHA1M_C);
    d += make_u32x (SHA1M_D);
    e += make_u32x (SHA1M_E);

    w0_t = salt1_buf0[0];
    w1_t = salt1_buf0[1];
    w2_t = salt1_buf0[2];
    w3_t = salt1_buf0[3];
    w4_t = salt1_buf1[0];
    w5_t = salt1_buf1[1];
    w6_t = salt1_buf1[2];
    w7_t = salt1_buf1[3];
    w8_t = a;
    w9_t = b;
    wa_t = c;
    wb_t = d;
    wc_t = e;
    wd_t = 0x80000000;
    we_t = 0;
    wf_t = (32 + 20) * 8;

    a = SHA1M_A;
    b = SHA1M_B;
    c = SHA1M_C;
    d = SHA1M_D;
    e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

    #undef K
    #define K SHA1C01

    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

    #undef K
    #define K SHA1C02

    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

    #undef K
    #define K SHA1C03

    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

        a += make_u32x (SHA1M_A);
    b += make_u32x (SHA1M_B);
    c += make_u32x (SHA1M_C);
    d += make_u32x (SHA1M_D);
    e += make_u32x (SHA1M_E);

    u32 exponent[5] = { 0 };

    exponent[0] = e;
    exponent[1] = d;
    exponent[2] = c;
    exponent[3] = b;
    exponent[4] = a;

    u32 r_t[64] =
    {
      r[ 0], r[ 1], r[ 2], r[ 3], r[ 4], r[ 5], r[ 6], r[ 7],
      r[ 8], r[ 9], r[10], r[11], r[12], r[13], r[14], r[15],
      r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23],
      r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31],
      r[32], r[33], r[34], r[35], r[36], r[37], r[38], r[39],
      r[40], r[41], r[42], r[43], r[44], r[45], r[46], r[47],
      r[48], r[49], r[50], r[51], r[52], r[53], r[54], r[55],
      r[56], r[57], r[58], r[59], r[60], r[61], r[62], r[63],
    };

    for (u32 i = 0, j = 0; i < PRECOMP_SLOTS; i += 1, j += PRECOMP_ENTRIES - 1)
    {
      const u32 div   = (PRECOMP_BITS * i) / 32; // for 4 bits: (i / 8)
      const u32 shift = (PRECOMP_BITS * i) % 32; // for 4 bits: (i % 8) * 4

      // const
      u32 cur_sel = (exponent[div] >> shift) & PRECOMP_MASK; // 0x0f == 0b1111 (4 bits)

      // working with non-divisible u32 (see PRECOMP_BITS):

      if (32 - shift < PRECOMP_BITS)
      {
        cur_sel |= (exponent[div + 1] << (32 - shift)) & PRECOMP_MASK;
      }

      if (cur_sel == 0) continue;

      const u32 pre_idx = (j + cur_sel - 1) * PRECOMP_ENTRYLEN; // x * 64 is same as x << 6

      // u32 p[64]; for (u32 i = 0; i < 64; i++) p[i] = esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + i];

      const u32 p[64] =
      {
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  0],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  1],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  2],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  3],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  4],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  5],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  6],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  7],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  8],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  9],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 10],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 11],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 12],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 13],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 14],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 15],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 16],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 17],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 18],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 19],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 20],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 21],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 22],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 23],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 24],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 25],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 26],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 27],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 28],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 29],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 30],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 31],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 32],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 33],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 34],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 35],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 36],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 37],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 38],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 39],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 40],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 41],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 42],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 43],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 44],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 45],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 46],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 47],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 48],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 49],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 50],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 51],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 52],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 53],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 54],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 55],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 56],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 57],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 58],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 59],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 60],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 61],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 62],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 63],
      };

      mul_mod (r_t, p, m, fact); // r = (r * pre[n]) % m
    }

    const u32 r0 = r_t[0];
    const u32 r1 = r_t[1];
    const u32 r2 = r_t[2];
    const u32 r3 = r_t[3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m29200_m08 (KERN_ATTR_RULES_ESALT (radmin3_t))
{
}

KERNEL_FQ void m29200_m16 (KERN_ATTR_RULES_ESALT (radmin3_t))
{
}

KERNEL_FQ void m29200_s04 (KERN_ATTR_RULES_ESALT (radmin3_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);


  /**
   * cache constant values to shared memory
   */

  LOCAL_VK u32 m[64];
  LOCAL_VK u32 r[64];
  LOCAL_VK u32 fact[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    m[i]    = RADMIN3_M[i];
    r[i]    = RADMIN3_R[i];
    fact[i] = RADMIN3_FACT[i];
  }
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
   * base
   */

  SYNC_THREADS ();

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
   * salt
   */

  u32 salt1_buf0[4];
  u32 salt1_buf1[4];
  u32 salt1_buf2[4];
  u32 salt1_buf3[4];

  salt1_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt1_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt1_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt1_buf0[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  salt1_buf1[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  salt1_buf1[1] = salt_bufs[SALT_POS_HOST].salt_buf[5];
  salt1_buf1[2] = salt_bufs[SALT_POS_HOST].salt_buf[6];
  salt1_buf1[3] = salt_bufs[SALT_POS_HOST].salt_buf[7];
  salt1_buf2[0] = 0;
  salt1_buf2[1] = 0;
  salt1_buf2[2] = 0;
  salt1_buf2[3] = 0;
  salt1_buf3[0] = 0;
  salt1_buf3[1] = 0;
  salt1_buf3[2] = 0;
  salt1_buf3[3] = 0;

  u32 salt2_buf0[4];
  u32 salt2_buf1[4];
  u32 salt2_buf2[4];
  u32 salt2_buf3[4];

  salt2_buf0[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 0]);
  salt2_buf0[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 1]);
  salt2_buf0[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 2]);
  salt2_buf0[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 3]);
  salt2_buf1[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 4]);
  salt2_buf1[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 5]);
  salt2_buf1[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 6]);
  salt2_buf1[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 7]);
  salt2_buf2[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 8]);
  salt2_buf2[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[ 9]);
  salt2_buf2[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[10]);
  salt2_buf2[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[11]);
  salt2_buf3[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[12]);
  salt2_buf3[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[13]);
  salt2_buf3[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[14]);
  salt2_buf3[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].user[15]);
  
  const u32 salt2_len = esalt_bufs[DIGESTS_OFFSET_HOST].user_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
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

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
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

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    const u32x pw_len2 = pw_len * 2;

    /**
     * prepend salt
     */

    const u32x pw_salt_len = pw_len2 + salt2_len;

    switch_buffer_by_offset_le (w0, w1, w2, w3, salt2_len);

    w0[0] |= salt2_buf0[0];
    w0[1] |= salt2_buf0[1];
    w0[2] |= salt2_buf0[2];
    w0[3] |= salt2_buf0[3];
    w1[0] |= salt2_buf1[0];
    w1[1] |= salt2_buf1[1];
    w1[2] |= salt2_buf1[2];
    w1[3] |= salt2_buf1[3];
    w2[0] |= salt2_buf2[0];
    w2[1] |= salt2_buf2[1];
    w2[2] |= salt2_buf2[2];
    w2[3] |= salt2_buf2[3];
    w3[0] |= salt2_buf3[0];
    w3[1] |= salt2_buf3[1];
    w3[2] |= salt2_buf3[2];
    w3[3] |= salt2_buf3[3];

    append_0x80_4x4_VV (w0, w1, w2, w3, pw_salt_len);

    /**
     * sha1
     */

    u32x w0_t = hc_swap32 (w0[0]);
    u32x w1_t = hc_swap32 (w0[1]);
    u32x w2_t = hc_swap32 (w0[2]);
    u32x w3_t = hc_swap32 (w0[3]);
    u32x w4_t = hc_swap32 (w1[0]);
    u32x w5_t = hc_swap32 (w1[1]);
    u32x w6_t = hc_swap32 (w1[2]);
    u32x w7_t = hc_swap32 (w1[3]);
    u32x w8_t = hc_swap32 (w2[0]);
    u32x w9_t = hc_swap32 (w2[1]);
    u32x wa_t = hc_swap32 (w2[2]);
    u32x wb_t = hc_swap32 (w2[3]);
    u32x wc_t = hc_swap32 (w3[0]);
    u32x wd_t = hc_swap32 (w3[1]);
    u32x we_t = 0;
    u32x wf_t = pw_salt_len * 8;

    u32x a = SHA1M_A;
    u32x b = SHA1M_B;
    u32x c = SHA1M_C;
    u32x d = SHA1M_D;
    u32x e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

    #undef K
    #define K SHA1C01

    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

    #undef K
    #define K SHA1C02

    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

    #undef K
    #define K SHA1C03

    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

    a += make_u32x (SHA1M_A);
    b += make_u32x (SHA1M_B);
    c += make_u32x (SHA1M_C);
    d += make_u32x (SHA1M_D);
    e += make_u32x (SHA1M_E);

    w0_t = salt1_buf0[0];
    w1_t = salt1_buf0[1];
    w2_t = salt1_buf0[2];
    w3_t = salt1_buf0[3];
    w4_t = salt1_buf1[0];
    w5_t = salt1_buf1[1];
    w6_t = salt1_buf1[2];
    w7_t = salt1_buf1[3];
    w8_t = a;
    w9_t = b;
    wa_t = c;
    wb_t = d;
    wc_t = e;
    wd_t = 0x80000000;
    we_t = 0;
    wf_t = (32 + 20) * 8;

    a = SHA1M_A;
    b = SHA1M_B;
    c = SHA1M_C;
    d = SHA1M_D;
    e = SHA1M_E;

    #undef K
    #define K SHA1C00

    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
    SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
    SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
    SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
    SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
    SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

    #undef K
    #define K SHA1C01

    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

    #undef K
    #define K SHA1C02

    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

    #undef K
    #define K SHA1C03

    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
    w0_t = hc_rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
    w1_t = hc_rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
    w2_t = hc_rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
    w3_t = hc_rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
    w4_t = hc_rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
    w5_t = hc_rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
    w6_t = hc_rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
    w7_t = hc_rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
    w8_t = hc_rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
    w9_t = hc_rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
    wa_t = hc_rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
    wb_t = hc_rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
    wc_t = hc_rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
    wd_t = hc_rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
    we_t = hc_rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
    wf_t = hc_rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

        a += make_u32x (SHA1M_A);
    b += make_u32x (SHA1M_B);
    c += make_u32x (SHA1M_C);
    d += make_u32x (SHA1M_D);
    e += make_u32x (SHA1M_E);

    u32 exponent[5] = { 0 };

    exponent[0] = e;
    exponent[1] = d;
    exponent[2] = c;
    exponent[3] = b;
    exponent[4] = a;

    u32 r_t[64] =
    {
      r[ 0], r[ 1], r[ 2], r[ 3], r[ 4], r[ 5], r[ 6], r[ 7],
      r[ 8], r[ 9], r[10], r[11], r[12], r[13], r[14], r[15],
      r[16], r[17], r[18], r[19], r[20], r[21], r[22], r[23],
      r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31],
      r[32], r[33], r[34], r[35], r[36], r[37], r[38], r[39],
      r[40], r[41], r[42], r[43], r[44], r[45], r[46], r[47],
      r[48], r[49], r[50], r[51], r[52], r[53], r[54], r[55],
      r[56], r[57], r[58], r[59], r[60], r[61], r[62], r[63],
    };

    for (u32 i = 0, j = 0; i < PRECOMP_SLOTS; i += 1, j += PRECOMP_ENTRIES - 1)
    {
      const u32 div   = (PRECOMP_BITS * i) / 32; // for 4 bits: (i / 8)
      const u32 shift = (PRECOMP_BITS * i) % 32; // for 4 bits: (i % 8) * 4

      // const
      u32 cur_sel = (exponent[div] >> shift) & PRECOMP_MASK; // 0x0f == 0b1111 (4 bits)

      // working with non-divisible u32 (see PRECOMP_BITS):

      if (32 - shift < PRECOMP_BITS)
      {
        cur_sel |= (exponent[div + 1] << (32 - shift)) & PRECOMP_MASK;
      }

      if (cur_sel == 0) continue;

      const u32 pre_idx = (j + cur_sel - 1) * PRECOMP_ENTRYLEN; // x * 64 is same as x << 6

      // u32 p[64]; for (u32 i = 0; i < 64; i++) p[i] = esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + i];

      const u32 p[64] =
      {
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  0],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  1],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  2],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  3],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  4],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  5],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  6],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  7],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  8],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx +  9],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 10],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 11],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 12],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 13],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 14],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 15],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 16],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 17],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 18],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 19],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 20],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 21],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 22],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 23],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 24],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 25],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 26],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 27],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 28],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 29],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 30],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 31],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 32],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 33],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 34],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 35],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 36],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 37],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 38],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 39],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 40],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 41],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 42],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 43],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 44],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 45],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 46],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 47],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 48],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 49],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 50],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 51],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 52],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 53],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 54],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 55],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 56],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 57],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 58],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 59],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 60],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 61],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 62],
        esalt_bufs[DIGESTS_OFFSET_HOST].pre[pre_idx + 63],
      };

      mul_mod (r_t, p, m, fact); // r = (r * pre[n]) % m
    }

    const u32 r0 = r_t[0];
    const u32 r1 = r_t[1];
    const u32 r2 = r_t[2];
    const u32 r3 = r_t[3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m29200_s08 (KERN_ATTR_RULES_ESALT (radmin3_t))
{
}

KERNEL_FQ void m29200_s16 (KERN_ATTR_RULES_ESALT (radmin3_t))
{
}
