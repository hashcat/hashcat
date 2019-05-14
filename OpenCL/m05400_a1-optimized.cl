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
#include "inc_hash_sha1.cl"
#endif

typedef struct ikepsk
{
  u32 nr_buf[16];
  u32 nr_len;

  u32 msg_buf[128];
  u32 msg_len[6];

} ikepsk_t;

DECLSPEC void hmac_sha1_pad (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad)
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA1M_A;
  ipad[1] = SHA1M_B;
  ipad[2] = SHA1M_C;
  ipad[3] = SHA1M_D;
  ipad[4] = SHA1M_E;

  sha1_transform_vector (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA1M_A;
  opad[1] = SHA1M_B;
  opad[2] = SHA1M_C;
  opad[3] = SHA1M_D;
  opad[4] = SHA1M_E;

  sha1_transform_vector (w0, w1, w2, w3, opad);
}

DECLSPEC void hmac_sha1_run (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m05400_m04 (KERN_ATTR_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  LOCAL_VK u32 s_nr_buf[16];

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = hc_swap32_S (esalt_bufs[digests_offset].nr_buf[i]);
  }

  LOCAL_VK u32 s_msg_buf[128];

  for (u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = hc_swap32_S (esalt_bufs[digests_offset].msg_buf[i]);
  }

  SYNC_THREADS ();

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

  const u32 nr_len  = esalt_bufs[digests_offset].nr_len;
  const u32 msg_len = esalt_bufs[digests_offset].msg_len[5];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
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
     * pads
     */

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = hc_swap32 (w3[2]);
    w3[3] = hc_swap32 (w3[3]);

    u32x ipad[5];
    u32x opad[5];

    hmac_sha1_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = s_nr_buf[ 0];
    w0[1] = s_nr_buf[ 1];
    w0[2] = s_nr_buf[ 2];
    w0[3] = s_nr_buf[ 3];
    w1[0] = s_nr_buf[ 4];
    w1[1] = s_nr_buf[ 5];
    w1[2] = s_nr_buf[ 6];
    w1[3] = s_nr_buf[ 7];
    w2[0] = s_nr_buf[ 8];
    w2[1] = s_nr_buf[ 9];
    w2[2] = s_nr_buf[10];
    w2[3] = s_nr_buf[11];
    w3[0] = s_nr_buf[12];
    w3[1] = s_nr_buf[13];
    w3[2] = 0;
    w3[3] = (64 + nr_len) * 8;

    u32x digest[5];

    hmac_sha1_run (w0, w1, w2, w3, ipad, opad, digest);

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha1_pad (w0, w1, w2, w3, ipad, opad);

    int left;
    int off;

    for (left = msg_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0[0] = s_msg_buf[off +  0];
      w0[1] = s_msg_buf[off +  1];
      w0[2] = s_msg_buf[off +  2];
      w0[3] = s_msg_buf[off +  3];
      w1[0] = s_msg_buf[off +  4];
      w1[1] = s_msg_buf[off +  5];
      w1[2] = s_msg_buf[off +  6];
      w1[3] = s_msg_buf[off +  7];
      w2[0] = s_msg_buf[off +  8];
      w2[1] = s_msg_buf[off +  9];
      w2[2] = s_msg_buf[off + 10];
      w2[3] = s_msg_buf[off + 11];
      w3[0] = s_msg_buf[off + 12];
      w3[1] = s_msg_buf[off + 13];
      w3[2] = s_msg_buf[off + 14];
      w3[3] = s_msg_buf[off + 15];

      sha1_transform_vector (w0, w1, w2, w3, ipad);
    }

    w0[0] = s_msg_buf[off +  0];
    w0[1] = s_msg_buf[off +  1];
    w0[2] = s_msg_buf[off +  2];
    w0[3] = s_msg_buf[off +  3];
    w1[0] = s_msg_buf[off +  4];
    w1[1] = s_msg_buf[off +  5];
    w1[2] = s_msg_buf[off +  6];
    w1[3] = s_msg_buf[off +  7];
    w2[0] = s_msg_buf[off +  8];
    w2[1] = s_msg_buf[off +  9];
    w2[2] = s_msg_buf[off + 10];
    w2[3] = s_msg_buf[off + 11];
    w3[0] = s_msg_buf[off + 12];
    w3[1] = s_msg_buf[off + 13];
    w3[2] = 0;
    w3[3] = (64 + msg_len) * 8;

    hmac_sha1_run (w0, w1, w2, w3, ipad, opad, digest);

    COMPARE_M_SIMD (digest[3], digest[4], digest[2], digest[1]);
  }
}

KERNEL_FQ void m05400_m08 (KERN_ATTR_ESALT (ikepsk_t))
{
}

KERNEL_FQ void m05400_m16 (KERN_ATTR_ESALT (ikepsk_t))
{
}

KERNEL_FQ void m05400_s04 (KERN_ATTR_ESALT (ikepsk_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * s_msg
   */

  LOCAL_VK u32 s_nr_buf[16];

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_nr_buf[i] = hc_swap32_S (esalt_bufs[digests_offset].nr_buf[i]);
  }

  LOCAL_VK u32 s_msg_buf[128];

  for (u32 i = lid; i < 128; i += lsz)
  {
    s_msg_buf[i] = hc_swap32_S (esalt_bufs[digests_offset].msg_buf[i]);
  }

  SYNC_THREADS ();

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

  const u32 nr_len  = esalt_bufs[digests_offset].nr_len;
  const u32 msg_len = esalt_bufs[digests_offset].msg_len[5];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
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
     * pads
     */

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = hc_swap32 (w3[2]);
    w3[3] = hc_swap32 (w3[3]);

    u32x ipad[5];
    u32x opad[5];

    hmac_sha1_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = s_nr_buf[ 0];
    w0[1] = s_nr_buf[ 1];
    w0[2] = s_nr_buf[ 2];
    w0[3] = s_nr_buf[ 3];
    w1[0] = s_nr_buf[ 4];
    w1[1] = s_nr_buf[ 5];
    w1[2] = s_nr_buf[ 6];
    w1[3] = s_nr_buf[ 7];
    w2[0] = s_nr_buf[ 8];
    w2[1] = s_nr_buf[ 9];
    w2[2] = s_nr_buf[10];
    w2[3] = s_nr_buf[11];
    w3[0] = s_nr_buf[12];
    w3[1] = s_nr_buf[13];
    w3[2] = 0;
    w3[3] = (64 + nr_len) * 8;

    u32x digest[5];

    hmac_sha1_run (w0, w1, w2, w3, ipad, opad, digest);

    w0[0] = digest[0];
    w0[1] = digest[1];
    w0[2] = digest[2];
    w0[3] = digest[3];
    w1[0] = digest[4];
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    hmac_sha1_pad (w0, w1, w2, w3, ipad, opad);

    int left;
    int off;

    for (left = msg_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0[0] = s_msg_buf[off +  0];
      w0[1] = s_msg_buf[off +  1];
      w0[2] = s_msg_buf[off +  2];
      w0[3] = s_msg_buf[off +  3];
      w1[0] = s_msg_buf[off +  4];
      w1[1] = s_msg_buf[off +  5];
      w1[2] = s_msg_buf[off +  6];
      w1[3] = s_msg_buf[off +  7];
      w2[0] = s_msg_buf[off +  8];
      w2[1] = s_msg_buf[off +  9];
      w2[2] = s_msg_buf[off + 10];
      w2[3] = s_msg_buf[off + 11];
      w3[0] = s_msg_buf[off + 12];
      w3[1] = s_msg_buf[off + 13];
      w3[2] = s_msg_buf[off + 14];
      w3[3] = s_msg_buf[off + 15];

      sha1_transform_vector (w0, w1, w2, w3, ipad);
    }

    w0[0] = s_msg_buf[off +  0];
    w0[1] = s_msg_buf[off +  1];
    w0[2] = s_msg_buf[off +  2];
    w0[3] = s_msg_buf[off +  3];
    w1[0] = s_msg_buf[off +  4];
    w1[1] = s_msg_buf[off +  5];
    w1[2] = s_msg_buf[off +  6];
    w1[3] = s_msg_buf[off +  7];
    w2[0] = s_msg_buf[off +  8];
    w2[1] = s_msg_buf[off +  9];
    w2[2] = s_msg_buf[off + 10];
    w2[3] = s_msg_buf[off + 11];
    w3[0] = s_msg_buf[off + 12];
    w3[1] = s_msg_buf[off + 13];
    w3[2] = 0;
    w3[3] = (64 + msg_len) * 8;

    hmac_sha1_run (w0, w1, w2, w3, ipad, opad, digest);

    COMPARE_S_SIMD (digest[3], digest[4], digest[2], digest[1]);
  }
}

KERNEL_FQ void m05400_s08 (KERN_ATTR_ESALT (ikepsk_t))
{
}

KERNEL_FQ void m05400_s16 (KERN_ATTR_ESALT (ikepsk_t))
{
}
