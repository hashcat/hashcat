/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_cipher_des.cl"
#endif

DECLSPEC void m03100m (SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64], u32 *w, const u32 pw_len, KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  const u32 salt_word_len = (salt_len + pw_len) * 2;

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0lr = w0l | w0r;

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = w0lr;
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];

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

      _des_crypt_encrypt_vect (iv, data, Kc, Kd, s_SPtrans);
    }

    /**
     * key2 (generate hash)
     */

    _des_crypt_keysetup_vect (iv[0], iv[1], Kc, Kd, s_skb);

    iv[0] = 0;
    iv[1] = 0;

    for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
    {
      u32x data[2];

      data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
      data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

      data[0] ^= iv[0];
      data[1] ^= iv[1];

      _des_crypt_encrypt_vect (iv, data, Kc, Kd, s_SPtrans);
    }

    /**
     * cmp
     */

    u32x z = 0;

    COMPARE_M_SIMD (iv[0], iv[1], z, z);
  }
}

DECLSPEC void m03100s (SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64], u32 *w, const u32 pw_len, KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  const u32 salt_word_len = (salt_len + pw_len) * 2;

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

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0lr = w0l | w0r;

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = w0lr;
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];

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

      _des_crypt_encrypt_vect (iv, data, Kc, Kd, s_SPtrans);
    }

    /**
     * key2 (generate hash)
     */

    _des_crypt_keysetup_vect (iv[0], iv[1], Kc, Kd, s_skb);

    iv[0] = 0;
    iv[1] = 0;

    for (u32 j = 0, k = 0; j < salt_word_len; j += 8, k++)
    {
      u32x data[2];

      data[0] = ((dst[k] << 16) & 0xff000000) | ((dst[k] << 8) & 0x0000ff00);
      data[1] = ((dst[k] >>  0) & 0xff000000) | ((dst[k] >> 8) & 0x0000ff00);

      data[0] ^= iv[0];
      data[1] ^= iv[1];

      _des_crypt_encrypt_vect (iv, data, Kc, Kd, s_SPtrans);
    }

    /**
     * cmp
     */

    u32x z = 0;

    COMPARE_S_SIMD (iv[0], iv[1], z, z);
  }
}

KERNEL_FQ void m03100_m04 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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
   * main
   */

  m03100m (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m03100_m08 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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
   * main
   */

  m03100m (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m03100_m16 (KERN_ATTR_VECTOR ())
{
}

KERNEL_FQ void m03100_s04 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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
   * main
   */

  m03100s (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m03100_s08 (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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
   * main
   */

  m03100s (s_SPtrans, s_skb, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

KERNEL_FQ void m03100_s16 (KERN_ATTR_VECTOR ())
{
}
