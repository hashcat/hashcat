/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"

DECLSPEC void sha512_transform_transport_vector (const u64x *w0, const u64x *w1, const u64x *w2, const u64x *w3, u64x *digest)
{
  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];
  u32x t4[4];
  u32x t5[4];
  u32x t6[4];
  u32x t7[4];

  t0[0] = h32_from_64 (w0[0]);
  t0[1] = l32_from_64 (w0[0]);
  t0[2] = h32_from_64 (w0[1]);
  t0[3] = l32_from_64 (w0[1]);
  t1[0] = h32_from_64 (w0[2]);
  t1[1] = l32_from_64 (w0[2]);
  t1[2] = h32_from_64 (w0[3]);
  t1[3] = l32_from_64 (w0[3]);
  t2[0] = h32_from_64 (w1[0]);
  t2[1] = l32_from_64 (w1[0]);
  t2[2] = h32_from_64 (w1[1]);
  t2[3] = l32_from_64 (w1[1]);
  t3[0] = h32_from_64 (w1[2]);
  t3[1] = l32_from_64 (w1[2]);
  t3[2] = h32_from_64 (w1[3]);
  t3[3] = l32_from_64 (w1[3]);
  t4[0] = h32_from_64 (w2[0]);
  t4[1] = l32_from_64 (w2[0]);
  t4[2] = h32_from_64 (w2[1]);
  t4[3] = l32_from_64 (w2[1]);
  t5[0] = h32_from_64 (w2[2]);
  t5[1] = l32_from_64 (w2[2]);
  t5[2] = h32_from_64 (w2[3]);
  t5[3] = l32_from_64 (w2[3]);
  t6[0] = h32_from_64 (w3[0]);
  t6[1] = l32_from_64 (w3[0]);
  t6[2] = h32_from_64 (w3[1]);
  t6[3] = l32_from_64 (w3[1]);
  t7[0] = h32_from_64 (w3[2]);
  t7[1] = l32_from_64 (w3[2]);
  t7[2] = h32_from_64 (w3[3]);
  t7[3] = l32_from_64 (w3[3]);

  sha512_transform_vector (t0, t1, t2, t3, t4, t5, t6, t7, digest);
}

DECLSPEC void hmac_sha512_pad (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u64x *ipad, u64x *opad)
{
  u64x w0_t[4];
  u64x w1_t[4];
  u64x w2_t[4];
  u64x w3_t[4];

  w0_t[0] = hl32_to_64 (w0[0], w0[1]) ^ (u64x) 0x3636363636363636;
  w0_t[1] = hl32_to_64 (w0[2], w0[3]) ^ (u64x) 0x3636363636363636;
  w0_t[2] = hl32_to_64 (w1[0], w1[1]) ^ (u64x) 0x3636363636363636;
  w0_t[3] = hl32_to_64 (w1[2], w1[3]) ^ (u64x) 0x3636363636363636;
  w1_t[0] = hl32_to_64 (w2[0], w2[1]) ^ (u64x) 0x3636363636363636;
  w1_t[1] = hl32_to_64 (w2[2], w2[3]) ^ (u64x) 0x3636363636363636;
  w1_t[2] = hl32_to_64 (w3[0], w3[1]) ^ (u64x) 0x3636363636363636;
  w1_t[3] = hl32_to_64 (w3[2], w3[3]) ^ (u64x) 0x3636363636363636;
  w2_t[0] =                             (u64x) 0x3636363636363636;
  w2_t[1] =                             (u64x) 0x3636363636363636;
  w2_t[2] =                             (u64x) 0x3636363636363636;
  w2_t[3] =                             (u64x) 0x3636363636363636;
  w3_t[0] =                             (u64x) 0x3636363636363636;
  w3_t[1] =                             (u64x) 0x3636363636363636;
  w3_t[2] =                             (u64x) 0x3636363636363636;
  w3_t[3] =                             (u64x) 0x3636363636363636;

  ipad[0] = SHA512M_A;
  ipad[1] = SHA512M_B;
  ipad[2] = SHA512M_C;
  ipad[3] = SHA512M_D;
  ipad[4] = SHA512M_E;
  ipad[5] = SHA512M_F;
  ipad[6] = SHA512M_G;
  ipad[7] = SHA512M_H;

  sha512_transform_transport_vector (w0_t, w1_t, w2_t, w3_t, ipad);

  w0_t[0] = hl32_to_64 (w0[0], w0[1]) ^ (u64x) 0x5c5c5c5c5c5c5c5c;
  w0_t[1] = hl32_to_64 (w0[2], w0[3]) ^ (u64x) 0x5c5c5c5c5c5c5c5c;
  w0_t[2] = hl32_to_64 (w1[0], w1[1]) ^ (u64x) 0x5c5c5c5c5c5c5c5c;
  w0_t[3] = hl32_to_64 (w1[2], w1[3]) ^ (u64x) 0x5c5c5c5c5c5c5c5c;
  w1_t[0] = hl32_to_64 (w2[0], w2[1]) ^ (u64x) 0x5c5c5c5c5c5c5c5c;
  w1_t[1] = hl32_to_64 (w2[2], w2[3]) ^ (u64x) 0x5c5c5c5c5c5c5c5c;
  w1_t[2] = hl32_to_64 (w3[0], w3[1]) ^ (u64x) 0x5c5c5c5c5c5c5c5c;
  w1_t[3] = hl32_to_64 (w3[2], w3[3]) ^ (u64x) 0x5c5c5c5c5c5c5c5c;
  w2_t[0] =                             (u64x) 0x5c5c5c5c5c5c5c5c;
  w2_t[1] =                             (u64x) 0x5c5c5c5c5c5c5c5c;
  w2_t[2] =                             (u64x) 0x5c5c5c5c5c5c5c5c;
  w2_t[3] =                             (u64x) 0x5c5c5c5c5c5c5c5c;
  w3_t[0] =                             (u64x) 0x5c5c5c5c5c5c5c5c;
  w3_t[1] =                             (u64x) 0x5c5c5c5c5c5c5c5c;
  w3_t[2] =                             (u64x) 0x5c5c5c5c5c5c5c5c;
  w3_t[3] =                             (u64x) 0x5c5c5c5c5c5c5c5c;

  opad[0] = SHA512M_A;
  opad[1] = SHA512M_B;
  opad[2] = SHA512M_C;
  opad[3] = SHA512M_D;
  opad[4] = SHA512M_E;
  opad[5] = SHA512M_F;
  opad[6] = SHA512M_G;
  opad[7] = SHA512M_H;

  sha512_transform_transport_vector (w0_t, w1_t, w2_t, w3_t, opad);
}

DECLSPEC void hmac_sha512_run (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u64x *ipad, u64x *opad, u64x *digest)
{
  u64x w0_t[4];
  u64x w1_t[4];
  u64x w2_t[4];
  u64x w3_t[4];

  w0_t[0] = hl32_to_64 (w0[0], w0[1]);
  w0_t[1] = hl32_to_64 (w0[2], w0[3]);
  w0_t[2] = hl32_to_64 (w1[0], w1[1]);
  w0_t[3] = hl32_to_64 (w1[2], w1[3]);
  w1_t[0] = hl32_to_64 (w2[0], w2[1]);
  w1_t[1] = hl32_to_64 (w2[2], w2[3]);
  w1_t[2] = hl32_to_64 (w3[0], w3[1]);
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = hl32_to_64 (w3[2], w3[3]);

  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_transport_vector (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = digest[0];
  w0_t[1] = digest[1];
  w0_t[2] = digest[2];
  w0_t[3] = digest[3];
  w1_t[0] = digest[4];
  w1_t[1] = digest[5];
  w1_t[2] = digest[6];
  w1_t[3] = digest[7];
  w2_t[0] = 0x8000000000000000;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_transport_vector (w0_t, w1_t, w2_t, w3_t, digest);
}

__kernel void m01750_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = swap32_S (salt_bufs[salt_pos].salt_buf[ 0]);
  salt_buf0[1] = swap32_S (salt_bufs[salt_pos].salt_buf[ 1]);
  salt_buf0[2] = swap32_S (salt_bufs[salt_pos].salt_buf[ 2]);
  salt_buf0[3] = swap32_S (salt_bufs[salt_pos].salt_buf[ 3]);
  salt_buf1[0] = swap32_S (salt_bufs[salt_pos].salt_buf[ 4]);
  salt_buf1[1] = swap32_S (salt_bufs[salt_pos].salt_buf[ 5]);
  salt_buf1[2] = swap32_S (salt_bufs[salt_pos].salt_buf[ 6]);
  salt_buf1[3] = swap32_S (salt_bufs[salt_pos].salt_buf[ 7]);
  salt_buf2[0] = swap32_S (salt_bufs[salt_pos].salt_buf[ 8]);
  salt_buf2[1] = swap32_S (salt_bufs[salt_pos].salt_buf[ 9]);
  salt_buf2[2] = swap32_S (salt_bufs[salt_pos].salt_buf[10]);
  salt_buf2[3] = swap32_S (salt_bufs[salt_pos].salt_buf[11]);
  salt_buf3[0] = swap32_S (salt_bufs[salt_pos].salt_buf[12]);
  salt_buf3[1] = swap32_S (salt_bufs[salt_pos].salt_buf[13]);
  salt_buf3[2] = swap32_S (salt_bufs[salt_pos].salt_buf[14]);
  salt_buf3[3] = swap32_S (salt_bufs[salt_pos].salt_buf[15]);

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

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

    w0[0] = swap32 (w0[0]);
    w0[1] = swap32 (w0[1]);
    w0[2] = swap32 (w0[2]);
    w0[3] = swap32 (w0[3]);
    w1[0] = swap32 (w1[0]);
    w1[1] = swap32 (w1[1]);
    w1[2] = swap32 (w1[2]);
    w1[3] = swap32 (w1[3]);
    w2[0] = swap32 (w2[0]);
    w2[1] = swap32 (w2[1]);
    w2[2] = swap32 (w2[2]);
    w2[3] = swap32 (w2[3]);
    w3[0] = swap32 (w3[0]);
    w3[1] = swap32 (w3[1]);
    w3[2] = swap32 (w3[2]);
    w3[3] = swap32 (w3[3]);

    /**
     * pads
     */

    u64x ipad[8];
    u64x opad[8];

    hmac_sha512_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = salt_buf0[0];
    w0[1] = salt_buf0[1];
    w0[2] = salt_buf0[2];
    w0[3] = salt_buf0[3];
    w1[0] = salt_buf1[0];
    w1[1] = salt_buf1[1];
    w1[2] = salt_buf1[2];
    w1[3] = salt_buf1[3];
    w2[0] = salt_buf2[0];
    w2[1] = salt_buf2[1];
    w2[2] = salt_buf2[2];
    w2[3] = salt_buf2[3];
    w3[0] = salt_buf3[0];
    w3[1] = salt_buf3[1];
    w3[2] = 0;
    w3[3] = (128 + salt_len) * 8;

    u64x digest[8];

    hmac_sha512_run (w0, w1, w2, w3, ipad, opad, digest);

    const u32x r0 = l32_from_64 (digest[7]);
    const u32x r1 = h32_from_64 (digest[7]);
    const u32x r2 = l32_from_64 (digest[3]);
    const u32x r3 = h32_from_64 (digest[3]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

__kernel void m01750_m08 (KERN_ATTR_BASIC ())
{
}

__kernel void m01750_m16 (KERN_ATTR_BASIC ())
{
}

__kernel void m01750_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = swap32_S (salt_bufs[salt_pos].salt_buf[ 0]);
  salt_buf0[1] = swap32_S (salt_bufs[salt_pos].salt_buf[ 1]);
  salt_buf0[2] = swap32_S (salt_bufs[salt_pos].salt_buf[ 2]);
  salt_buf0[3] = swap32_S (salt_bufs[salt_pos].salt_buf[ 3]);
  salt_buf1[0] = swap32_S (salt_bufs[salt_pos].salt_buf[ 4]);
  salt_buf1[1] = swap32_S (salt_bufs[salt_pos].salt_buf[ 5]);
  salt_buf1[2] = swap32_S (salt_bufs[salt_pos].salt_buf[ 6]);
  salt_buf1[3] = swap32_S (salt_bufs[salt_pos].salt_buf[ 7]);
  salt_buf2[0] = swap32_S (salt_bufs[salt_pos].salt_buf[ 8]);
  salt_buf2[1] = swap32_S (salt_bufs[salt_pos].salt_buf[ 9]);
  salt_buf2[2] = swap32_S (salt_bufs[salt_pos].salt_buf[10]);
  salt_buf2[3] = swap32_S (salt_bufs[salt_pos].salt_buf[11]);
  salt_buf3[0] = swap32_S (salt_bufs[salt_pos].salt_buf[12]);
  salt_buf3[1] = swap32_S (salt_bufs[salt_pos].salt_buf[13]);
  salt_buf3[2] = swap32_S (salt_bufs[salt_pos].salt_buf[14]);
  salt_buf3[3] = swap32_S (salt_bufs[salt_pos].salt_buf[15]);

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

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

    w0[0] = swap32 (w0[0]);
    w0[1] = swap32 (w0[1]);
    w0[2] = swap32 (w0[2]);
    w0[3] = swap32 (w0[3]);
    w1[0] = swap32 (w1[0]);
    w1[1] = swap32 (w1[1]);
    w1[2] = swap32 (w1[2]);
    w1[3] = swap32 (w1[3]);
    w2[0] = swap32 (w2[0]);
    w2[1] = swap32 (w2[1]);
    w2[2] = swap32 (w2[2]);
    w2[3] = swap32 (w2[3]);
    w3[0] = swap32 (w3[0]);
    w3[1] = swap32 (w3[1]);
    w3[2] = swap32 (w3[2]);
    w3[3] = swap32 (w3[3]);

    /**
     * pads
     */

    u64x ipad[8];
    u64x opad[8];

    hmac_sha512_pad (w0, w1, w2, w3, ipad, opad);

    w0[0] = salt_buf0[0];
    w0[1] = salt_buf0[1];
    w0[2] = salt_buf0[2];
    w0[3] = salt_buf0[3];
    w1[0] = salt_buf1[0];
    w1[1] = salt_buf1[1];
    w1[2] = salt_buf1[2];
    w1[3] = salt_buf1[3];
    w2[0] = salt_buf2[0];
    w2[1] = salt_buf2[1];
    w2[2] = salt_buf2[2];
    w2[3] = salt_buf2[3];
    w3[0] = salt_buf3[0];
    w3[1] = salt_buf3[1];
    w3[2] = 0;
    w3[3] = (128 + salt_len) * 8;

    u64x digest[8];

    hmac_sha512_run (w0, w1, w2, w3, ipad, opad, digest);

    const u32x r0 = l32_from_64 (digest[7]);
    const u32x r1 = h32_from_64 (digest[7]);
    const u32x r2 = l32_from_64 (digest[3]);
    const u32x r3 = h32_from_64 (digest[3]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

__kernel void m01750_s08 (KERN_ATTR_BASIC ())
{
}

__kernel void m01750_s16 (KERN_ATTR_BASIC ())
{
}
