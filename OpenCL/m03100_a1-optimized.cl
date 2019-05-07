/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_cipher_des.cl"
#endif

KERNEL_FQ void m03100_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * des shared
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

  if (gid >= gid_max) return;

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

  u32 salt_buf0[4];
  u32 salt_buf1[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[7];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    const u32x salt_word_len = (salt_len + pw_len) * 2;

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

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
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

    /**
     * prepend salt
     */

    switch_buffer_by_offset_le (w0, w1, w2, w3, salt_len);

    u32x dst[16];

    dst[ 0] = w0[0] | salt_buf0[0];
    dst[ 1] = w0[1] | salt_buf0[1];
    dst[ 2] = w0[2] | salt_buf0[2];
    dst[ 3] = w0[3] | salt_buf0[3];
    dst[ 4] = w1[0] | salt_buf1[0];
    dst[ 5] = w1[1] | salt_buf1[1];
    dst[ 6] = w1[2] | salt_buf1[2];
    dst[ 7] = w1[3] | salt_buf1[3];
    dst[ 8] = w2[0];
    dst[ 9] = w2[1];
    dst[10] = w2[2];
    dst[11] = w2[3];
    dst[12] = w3[0];
    dst[13] = w3[1];
    dst[14] = w3[2];
    dst[15] = w3[3];

    /**
     * precompute key1 since key is static: 0x0123456789abcdef
     * plus LEFT_ROTATE by 2
     */

    u32x Kc[16];

    Kc[ 0] = 0x64649040;
    Kc[ 1] = 0x14909858;
    Kc[ 2] = 0xc4b44888;
    Kc[ 3] = 0x9094e438;
    Kc[ 4] = 0xd8a004f0;
    Kc[ 5] = 0xa8f02810;
    Kc[ 6] = 0xc84048d8;
    Kc[ 7] = 0x68d804a8;
    Kc[ 8] = 0x0490e40c;
    Kc[ 9] = 0xac183024;
    Kc[10] = 0x24c07c10;
    Kc[11] = 0x8c88c038;
    Kc[12] = 0xc048c824;
    Kc[13] = 0x4c0470a8;
    Kc[14] = 0x584020b4;
    Kc[15] = 0x00742c4c;

    u32x Kd[16];

    Kd[ 0] = 0xa42ce40c;
    Kd[ 1] = 0x64689858;
    Kd[ 2] = 0x484050b8;
    Kd[ 3] = 0xe8184814;
    Kd[ 4] = 0x405cc070;
    Kd[ 5] = 0xa010784c;
    Kd[ 6] = 0x6074a800;
    Kd[ 7] = 0x80701c1c;
    Kd[ 8] = 0x9cd49430;
    Kd[ 9] = 0x4c8ce078;
    Kd[10] = 0x5c18c088;
    Kd[11] = 0x28a8a4c8;
    Kd[12] = 0x3c180838;
    Kd[13] = 0xb0b86c20;
    Kd[14] = 0xac84a094;
    Kd[15] = 0x4ce0c0c4;

    /**
     * key1 (generate key)
     */

    u32x iv[2];

    iv[0] = 0;
    iv[1] = 0;

    for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
    {
      u32x data[2];

      data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
      data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

      data[0] ^= iv[0];
      data[1] ^= iv[1];

      _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
    }

    /**
     * key2 (generate hash)
     */

    _des_crypt_keysetup (iv[0], iv[1], Kc, Kd, s_skb);

    iv[0] = 0;
    iv[1] = 0;

    for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
    {
      u32x data[2];

      data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
      data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

      data[0] ^= iv[0];
      data[1] ^= iv[1];

      _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
    }

    /**
     * cmp
     */

    u32x z = 0;

    COMPARE_M_SIMD (iv[0], iv[1], z, z);
  }
}

KERNEL_FQ void m03100_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m03100_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m03100_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * des shared
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

  if (gid >= gid_max) return;

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

  u32 salt_buf0[4];
  u32 salt_buf1[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[7];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    const u32x salt_word_len = (salt_len + pw_len) * 2;

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

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
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

    /**
     * prepend salt
     */

    switch_buffer_by_offset_le (w0, w1, w2, w3, salt_len);

    u32x dst[16];

    dst[ 0] = w0[0] | salt_buf0[0];
    dst[ 1] = w0[1] | salt_buf0[1];
    dst[ 2] = w0[2] | salt_buf0[2];
    dst[ 3] = w0[3] | salt_buf0[3];
    dst[ 4] = w1[0] | salt_buf1[0];
    dst[ 5] = w1[1] | salt_buf1[1];
    dst[ 6] = w1[2] | salt_buf1[2];
    dst[ 7] = w1[3] | salt_buf1[3];
    dst[ 8] = w2[0];
    dst[ 9] = w2[1];
    dst[10] = w2[2];
    dst[11] = w2[3];
    dst[12] = w3[0];
    dst[13] = w3[1];
    dst[14] = w3[2];
    dst[15] = w3[3];

    /**
     * precompute key1 since key is static: 0x0123456789abcdef
     * plus LEFT_ROTATE by 2
     */

    u32x Kc[16];

    Kc[ 0] = 0x64649040;
    Kc[ 1] = 0x14909858;
    Kc[ 2] = 0xc4b44888;
    Kc[ 3] = 0x9094e438;
    Kc[ 4] = 0xd8a004f0;
    Kc[ 5] = 0xa8f02810;
    Kc[ 6] = 0xc84048d8;
    Kc[ 7] = 0x68d804a8;
    Kc[ 8] = 0x0490e40c;
    Kc[ 9] = 0xac183024;
    Kc[10] = 0x24c07c10;
    Kc[11] = 0x8c88c038;
    Kc[12] = 0xc048c824;
    Kc[13] = 0x4c0470a8;
    Kc[14] = 0x584020b4;
    Kc[15] = 0x00742c4c;

    u32x Kd[16];

    Kd[ 0] = 0xa42ce40c;
    Kd[ 1] = 0x64689858;
    Kd[ 2] = 0x484050b8;
    Kd[ 3] = 0xe8184814;
    Kd[ 4] = 0x405cc070;
    Kd[ 5] = 0xa010784c;
    Kd[ 6] = 0x6074a800;
    Kd[ 7] = 0x80701c1c;
    Kd[ 8] = 0x9cd49430;
    Kd[ 9] = 0x4c8ce078;
    Kd[10] = 0x5c18c088;
    Kd[11] = 0x28a8a4c8;
    Kd[12] = 0x3c180838;
    Kd[13] = 0xb0b86c20;
    Kd[14] = 0xac84a094;
    Kd[15] = 0x4ce0c0c4;

    /**
     * key1 (generate key)
     */

    u32x iv[2];

    iv[0] = 0;
    iv[1] = 0;

    for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
    {
      u32x data[2];

      data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
      data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

      data[0] ^= iv[0];
      data[1] ^= iv[1];

      _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
    }

    /**
     * key2 (generate hash)
     */

    _des_crypt_keysetup (iv[0], iv[1], Kc, Kd, s_skb);

    iv[0] = 0;
    iv[1] = 0;

    for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
    {
      u32x data[2];

      data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
      data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

      data[0] ^= iv[0];
      data[1] ^= iv[1];

      _des_crypt_encrypt (iv, data, Kc, Kd, s_SPtrans);
    }

    /**
     * cmp
     */

    u32x z = 0;

    COMPARE_S_SIMD (iv[0], iv[1], z, z);
  }
}

KERNEL_FQ void m03100_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m03100_s16 (KERN_ATTR_BASIC ())
{
}
