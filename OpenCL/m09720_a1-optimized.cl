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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

typedef struct oldoffice01
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[4];
  u32 rc4key[2];

} oldoffice01_t;

DECLSPEC void gen336 (PRIVATE_AS u32x *digest_pre, PRIVATE_AS u32 *salt_buf, PRIVATE_AS u32x *digest)
{
  u32x digest_t0[2];
  u32x digest_t1[2];
  u32x digest_t2[2];
  u32x digest_t3[2];

  digest_t0[0] = digest_pre[0];
  digest_t0[1] = digest_pre[1] & 0xff;

  digest_t1[0] =                       digest_pre[0] <<  8;
  digest_t1[1] = digest_pre[0] >> 24 | digest_pre[1] <<  8;

  digest_t2[0] =                       digest_pre[0] << 16;
  digest_t2[1] = digest_pre[0] >> 16 | digest_pre[1] << 16;

  digest_t3[0] =                       digest_pre[0] << 24;
  digest_t3[1] = digest_pre[0] >>  8 | digest_pre[1] << 24;

  u32x salt_buf_t0[4];
  u32x salt_buf_t1[5];
  u32x salt_buf_t2[5];
  u32x salt_buf_t3[5];

  salt_buf_t0[0] = salt_buf[0];
  salt_buf_t0[1] = salt_buf[1];
  salt_buf_t0[2] = salt_buf[2];
  salt_buf_t0[3] = salt_buf[3];

  salt_buf_t1[0] =                     salt_buf[0] <<  8;
  salt_buf_t1[1] = salt_buf[0] >> 24 | salt_buf[1] <<  8;
  salt_buf_t1[2] = salt_buf[1] >> 24 | salt_buf[2] <<  8;
  salt_buf_t1[3] = salt_buf[2] >> 24 | salt_buf[3] <<  8;
  salt_buf_t1[4] = salt_buf[3] >> 24;

  salt_buf_t2[0] =                     salt_buf[0] << 16;
  salt_buf_t2[1] = salt_buf[0] >> 16 | salt_buf[1] << 16;
  salt_buf_t2[2] = salt_buf[1] >> 16 | salt_buf[2] << 16;
  salt_buf_t2[3] = salt_buf[2] >> 16 | salt_buf[3] << 16;
  salt_buf_t2[4] = salt_buf[3] >> 16;

  salt_buf_t3[0] =                     salt_buf[0] << 24;
  salt_buf_t3[1] = salt_buf[0] >>  8 | salt_buf[1] << 24;
  salt_buf_t3[2] = salt_buf[1] >>  8 | salt_buf[2] << 24;
  salt_buf_t3[3] = salt_buf[2] >>  8 | salt_buf[3] << 24;
  salt_buf_t3[4] = salt_buf[3] >>  8;

  u32x w0_t[4];
  u32x w1_t[4];
  u32x w2_t[4];
  u32x w3_t[4];

  // generate the 16 * 21 buffer

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..5
  w0_t[0]  = digest_t0[0];
  w0_t[1]  = digest_t0[1];

  // 5..21
  w0_t[1] |= salt_buf_t1[0];
  w0_t[2]  = salt_buf_t1[1];
  w0_t[3]  = salt_buf_t1[2];
  w1_t[0]  = salt_buf_t1[3];
  w1_t[1]  = salt_buf_t1[4];

  // 21..26
  w1_t[1] |= digest_t1[0];
  w1_t[2]  = digest_t1[1];

  // 26..42
  w1_t[2] |= salt_buf_t2[0];
  w1_t[3]  = salt_buf_t2[1];
  w2_t[0]  = salt_buf_t2[2];
  w2_t[1]  = salt_buf_t2[3];
  w2_t[2]  = salt_buf_t2[4];

  // 42..47
  w2_t[2] |= digest_t2[0];
  w2_t[3]  = digest_t2[1];

  // 47..63
  w2_t[3] |= salt_buf_t3[0];
  w3_t[0]  = salt_buf_t3[1];
  w3_t[1]  = salt_buf_t3[2];
  w3_t[2]  = salt_buf_t3[3];
  w3_t[3]  = salt_buf_t3[4];

  // 63..

  w3_t[3] |= digest_t3[0];

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..4
  w0_t[0]  = digest_t3[1];

  // 4..20
  w0_t[1]  = salt_buf_t0[0];
  w0_t[2]  = salt_buf_t0[1];
  w0_t[3]  = salt_buf_t0[2];
  w1_t[0]  = salt_buf_t0[3];

  // 20..25
  w1_t[1]  = digest_t0[0];
  w1_t[2]  = digest_t0[1];

  // 25..41
  w1_t[2] |= salt_buf_t1[0];
  w1_t[3]  = salt_buf_t1[1];
  w2_t[0]  = salt_buf_t1[2];
  w2_t[1]  = salt_buf_t1[3];
  w2_t[2]  = salt_buf_t1[4];

  // 41..46
  w2_t[2] |= digest_t1[0];
  w2_t[3]  = digest_t1[1];

  // 46..62
  w2_t[3] |= salt_buf_t2[0];
  w3_t[0]  = salt_buf_t2[1];
  w3_t[1]  = salt_buf_t2[2];
  w3_t[2]  = salt_buf_t2[3];
  w3_t[3]  = salt_buf_t2[4];

  // 62..
  w3_t[3] |= digest_t2[0];

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..3
  w0_t[0]  = digest_t2[1];

  // 3..19
  w0_t[0] |= salt_buf_t3[0];
  w0_t[1]  = salt_buf_t3[1];
  w0_t[2]  = salt_buf_t3[2];
  w0_t[3]  = salt_buf_t3[3];
  w1_t[0]  = salt_buf_t3[4];

  // 19..24
  w1_t[0] |= digest_t3[0];
  w1_t[1]  = digest_t3[1];

  // 24..40
  w1_t[2]  = salt_buf_t0[0];
  w1_t[3]  = salt_buf_t0[1];
  w2_t[0]  = salt_buf_t0[2];
  w2_t[1]  = salt_buf_t0[3];

  // 40..45
  w2_t[2]  = digest_t0[0];
  w2_t[3]  = digest_t0[1];

  // 45..61
  w2_t[3] |= salt_buf_t1[0];
  w3_t[0]  = salt_buf_t1[1];
  w3_t[1]  = salt_buf_t1[2];
  w3_t[2]  = salt_buf_t1[3];
  w3_t[3]  = salt_buf_t1[4];

  // 61..
  w3_t[3] |= digest_t1[0];

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..2
  w0_t[0]  = digest_t1[1];

  // 2..18
  w0_t[0] |= salt_buf_t2[0];
  w0_t[1]  = salt_buf_t2[1];
  w0_t[2]  = salt_buf_t2[2];
  w0_t[3]  = salt_buf_t2[3];
  w1_t[0]  = salt_buf_t2[4];

  // 18..23
  w1_t[0] |= digest_t2[0];
  w1_t[1]  = digest_t2[1];

  // 23..39
  w1_t[1] |= salt_buf_t3[0];
  w1_t[2]  = salt_buf_t3[1];
  w1_t[3]  = salt_buf_t3[2];
  w2_t[0]  = salt_buf_t3[3];
  w2_t[1]  = salt_buf_t3[4];

  // 39..44
  w2_t[1] |= digest_t3[0];
  w2_t[2]  = digest_t3[1];

  // 44..60
  w2_t[3]  = salt_buf_t0[0];
  w3_t[0]  = salt_buf_t0[1];
  w3_t[1]  = salt_buf_t0[2];
  w3_t[2]  = salt_buf_t0[3];

  // 60..
  w3_t[3]  = digest_t0[0];

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..1
  w0_t[0]  = digest_t0[1];

  // 1..17
  w0_t[0] |= salt_buf_t1[0];
  w0_t[1]  = salt_buf_t1[1];
  w0_t[2]  = salt_buf_t1[2];
  w0_t[3]  = salt_buf_t1[3];
  w1_t[0]  = salt_buf_t1[4];

  // 17..22
  w1_t[0] |= digest_t1[0];
  w1_t[1]  = digest_t1[1];

  // 22..38
  w1_t[1] |= salt_buf_t2[0];
  w1_t[2]  = salt_buf_t2[1];
  w1_t[3]  = salt_buf_t2[2];
  w2_t[0]  = salt_buf_t2[3];
  w2_t[1]  = salt_buf_t2[4];

  // 38..43
  w2_t[1] |= digest_t2[0];
  w2_t[2]  = digest_t2[1];

  // 43..59
  w2_t[2] |= salt_buf_t3[0];
  w2_t[3]  = salt_buf_t3[1];
  w3_t[0]  = salt_buf_t3[2];
  w3_t[1]  = salt_buf_t3[3];
  w3_t[2]  = salt_buf_t3[4];

  // 59..
  w3_t[2] |= digest_t3[0];
  w3_t[3]  = digest_t3[1];

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0]  = salt_buf_t0[0];
  w0_t[1]  = salt_buf_t0[1];
  w0_t[2]  = salt_buf_t0[2];
  w0_t[3]  = salt_buf_t0[3];
  w1_t[0]  = 0x80;
  w1_t[1]  = 0;
  w1_t[2]  = 0;
  w1_t[3]  = 0;
  w2_t[0]  = 0;
  w2_t[1]  = 0;
  w2_t[2]  = 0;
  w2_t[3]  = 0;
  w3_t[0]  = 0;
  w3_t[1]  = 0;
  w3_t[2]  = 21 * 16 * 8;
  w3_t[3]  = 0;

  md5_transform_vector (w0_t, w1_t, w2_t, w3_t, digest);
}

KERNEL_FQ void m09720_m04 (KERN_ATTR_ESALT (oldoffice01_t))
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
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

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

    /**
     * md5
     */

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w3[2] = pw_len * 8 * 2;
    w3[3] = 0;

    u32x digest_pre[4];

    digest_pre[0] = MD5M_A;
    digest_pre[1] = MD5M_B;
    digest_pre[2] = MD5M_C;
    digest_pre[3] = MD5M_D;

    md5_transform_vector (w0, w1, w2, w3, digest_pre);

    digest_pre[0] &= 0xffffffff;
    digest_pre[1] &= 0x000000ff;
    digest_pre[2] &= 0x00000000;
    digest_pre[3] &= 0x00000000;

    u32x digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    gen336 (digest_pre, salt_buf, digest);

    u32x a = digest[0];
    u32x b = digest[1] & 0xff;
    u32x c = 0;
    u32x d = 0;

    COMPARE_M_SIMD (a, b, c, d);
  }
}

KERNEL_FQ void m09720_m08 (KERN_ATTR_ESALT (oldoffice01_t))
{
}

KERNEL_FQ void m09720_m16 (KERN_ATTR_ESALT (oldoffice01_t))
{
}

KERNEL_FQ void m09720_s04 (KERN_ATTR_ESALT (oldoffice01_t))
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
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  salt_buf[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  salt_buf[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  salt_buf[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

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

    /**
     * md5
     */

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w3[2] = pw_len * 8 * 2;
    w3[3] = 0;

    u32x digest_pre[4];

    digest_pre[0] = MD5M_A;
    digest_pre[1] = MD5M_B;
    digest_pre[2] = MD5M_C;
    digest_pre[3] = MD5M_D;

    md5_transform_vector (w0, w1, w2, w3, digest_pre);

    digest_pre[0] &= 0xffffffff;
    digest_pre[1] &= 0x000000ff;
    digest_pre[2] &= 0x00000000;
    digest_pre[3] &= 0x00000000;

    u32x digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    gen336 (digest_pre, salt_buf, digest);

    u32x a = digest[0];
    u32x b = digest[1] & 0xff;
    u32x c = 0;
    u32x d = 0;

    COMPARE_S_SIMD (a, b, c, d);
  }
}

KERNEL_FQ void m09720_s08 (KERN_ATTR_ESALT (oldoffice01_t))
{
}

KERNEL_FQ void m09720_s16 (KERN_ATTR_ESALT (oldoffice01_t))
{
}
