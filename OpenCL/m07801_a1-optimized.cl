/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible data-dependant code
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"
#endif

CONSTANT_VK u32a theMagicArray[64] =
{
  0x91ac5114, 0x9f675443, 0x24e73be0, 0x28747bc2, 0x863313eb, 0x5a4fcb5c, 0x080a7337, 0x0e5d1c2f,
  0x338fe6e5, 0xf89baedd, 0x16f24b8d, 0x2ce1d4dc, 0xb0cbdf9d, 0xd4706d17, 0xf94d423f, 0x9b1b1194,
  0x9f5bc19b, 0x06059d03, 0x9d5e138a, 0x1e9a6ae8, 0xd97c1417, 0x58c72af6, 0xa199630a, 0xd7fd70c3,
  0xf65e7413, 0x03c90b04, 0x2698f726, 0x8a929325, 0xb0a20d23, 0xed63796d, 0x1332fa3c, 0x35029aa3,
  0xb3dd8e0a, 0x24bf51c3, 0x7ccd559f, 0x37af944c, 0x29085282, 0xb23b4e37, 0x9f170791, 0x113bfdcd,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
  0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

DECLSPEC u32 GETSHIFTEDINT_CONST (CONSTANT_AS u32a *a, const int n)
{
  const int d = n / 4;
  const int m = n & 3;

  u64 tmp = hl32_to_64_S (a[d + 0], a[d + 1]);

  tmp <<= m * 8;

  return h32_from_64_S (tmp);
}

DECLSPEC void SETSHIFTEDINT (u32 *a, const int n, const u32 v)
{
  const int d = n / 4;
  const int m = n & 3;

  u64 tmp = hl32_to_64_S (v, 0);

  tmp >>= m * 8;

  a[d + 0] |= h32_from_64_S (tmp);
  a[d + 1]  = l32_from_64_S (tmp);
}

KERNEL_FQ void m07801_m04 (KERN_ATTR_BASIC ())
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

  u32 salt_buf[8];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf[4] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf[5] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf[6] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf[7] = salt_bufs[salt_pos].salt_buf[7];

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

    /**
     * SAP
     */

    u32 s0[4];
    u32 s1[4];
    u32 s2[4];
    u32 s3[4];

    s0[0] = salt_buf[0];
    s0[1] = salt_buf[1];
    s0[2] = salt_buf[2];
    s0[3] = salt_buf[3];
    s1[0] = salt_buf[4];
    s1[1] = salt_buf[5];
    s1[2] = salt_buf[6];
    s1[3] = salt_buf[7];
    s2[0] = 0;
    s2[1] = 0;
    s2[2] = 0;
    s2[3] = 0;
    s3[0] = 0;
    s3[1] = 0;
    s3[2] = 0;
    s3[3] = 0;

    switch_buffer_by_offset_le_VV (s0, s1, s2, s3, pw_len);

    const u32x pw_salt_len = pw_len + salt_len;

    /**
     * sha1
     */

    u32 final[32];

    final[ 0] = hc_swap32_S (w0[0] | s0[0]);
    final[ 1] = hc_swap32_S (w0[1] | s0[1]);
    final[ 2] = hc_swap32_S (w0[2] | s0[2]);
    final[ 3] = hc_swap32_S (w0[3] | s0[3]);
    final[ 4] = hc_swap32_S (w1[0] | s1[0]);
    final[ 5] = hc_swap32_S (w1[1] | s1[1]);
    final[ 6] = hc_swap32_S (w1[2] | s1[2]);
    final[ 7] = hc_swap32_S (w1[3] | s1[3]);
    final[ 8] = hc_swap32_S (w2[0] | s2[0]);
    final[ 9] = hc_swap32_S (w2[1] | s2[1]);
    final[10] = hc_swap32_S (w2[2] | s2[2]);
    final[11] = hc_swap32_S (w2[3] | s2[3]);
    final[12] = hc_swap32_S (w3[0] | s3[0]);
    final[13] = hc_swap32_S (w3[1] | s3[1]);
    final[14] = 0;
    final[15] = pw_salt_len * 8;
    final[16] = 0;
    final[17] = 0;
    final[18] = 0;
    final[19] = 0;
    final[20] = 0;
    final[21] = 0;
    final[22] = 0;
    final[23] = 0;
    final[24] = 0;
    final[25] = 0;
    final[26] = 0;
    final[27] = 0;
    final[28] = 0;
    final[29] = 0;
    final[30] = 0;
    final[31] = 0;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (&final[0], &final[4], &final[8], &final[12], digest);

    // prepare magic array range

    u32 lengthMagicArray = 0x20;
    u32 offsetMagicArray = 0;

    lengthMagicArray += ((digest[0] >> 24) & 0xff) % 6;
    lengthMagicArray += ((digest[0] >> 16) & 0xff) % 6;
    lengthMagicArray += ((digest[0] >>  8) & 0xff) % 6;
    lengthMagicArray += ((digest[0] >>  0) & 0xff) % 6;
    lengthMagicArray += ((digest[1] >> 24) & 0xff) % 6;
    lengthMagicArray += ((digest[1] >> 16) & 0xff) % 6;
    lengthMagicArray += ((digest[1] >>  8) & 0xff) % 6;
    lengthMagicArray += ((digest[1] >>  0) & 0xff) % 6;
    lengthMagicArray += ((digest[2] >> 24) & 0xff) % 6;
    lengthMagicArray += ((digest[2] >> 16) & 0xff) % 6;
    offsetMagicArray += ((digest[2] >>  8) & 0xff) % 8;
    offsetMagicArray += ((digest[2] >>  0) & 0xff) % 8;
    offsetMagicArray += ((digest[3] >> 24) & 0xff) % 8;
    offsetMagicArray += ((digest[3] >> 16) & 0xff) % 8;
    offsetMagicArray += ((digest[3] >>  8) & 0xff) % 8;
    offsetMagicArray += ((digest[3] >>  0) & 0xff) % 8;
    offsetMagicArray += ((digest[4] >> 24) & 0xff) % 8;
    offsetMagicArray += ((digest[4] >> 16) & 0xff) % 8;
    offsetMagicArray += ((digest[4] >>  8) & 0xff) % 8;
    offsetMagicArray += ((digest[4] >>  0) & 0xff) % 8;

    // final

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    final[ 0] = hc_swap32_S (w0[0]);
    final[ 1] = hc_swap32_S (w0[1]);
    final[ 2] = hc_swap32_S (w0[2]);
    final[ 3] = hc_swap32_S (w0[3]);
    final[ 4] = hc_swap32_S (w1[0]);
    final[ 5] = hc_swap32_S (w1[1]);
    final[ 6] = hc_swap32_S (w1[2]);
    final[ 7] = hc_swap32_S (w1[3]);
    final[ 8] = hc_swap32_S (w2[0]);
    final[ 9] = hc_swap32_S (w2[1]);
    final[10] = hc_swap32_S (w2[2]);
    final[11] = hc_swap32_S (w2[3]);
    final[12] = hc_swap32_S (w3[0]);
    final[13] = hc_swap32_S (w3[1]);
    final[14] = 0;
    final[15] = 0;

    u32 final_len = pw_len;

    u32 i;

    // append MagicArray

    for (i = 0; i < lengthMagicArray - 4; i += 4)
    {
      const u32 tmp = GETSHIFTEDINT_CONST (theMagicArray, offsetMagicArray + i);

      SETSHIFTEDINT (final, final_len + i, tmp);
    }

    const u32 mask = 0xffffffff << (((4 - (lengthMagicArray - i)) & 3) * 8);

    const u32 tmp = GETSHIFTEDINT_CONST (theMagicArray, offsetMagicArray + i) & mask;

    SETSHIFTEDINT (final, final_len + i, tmp);

    final_len += lengthMagicArray;

    // append Salt

    for (i = 0; i < salt_len + 1; i += 4) // +1 for the 0x80
    {
      const u32 tmp = hc_swap32_S (salt_buf[i / 4]); // attention, int[] not char[]

      SETSHIFTEDINT (final, final_len + i, tmp);
    }

    final_len += salt_len;

    // calculate

    int left;
    int off;

    for (left = final_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      sha1_transform (&final[off + 0], &final[off + 4], &final[off + 8], &final[off + 12], digest);
    }

    final[off + 15] = final_len * 8;

    sha1_transform (&final[off + 0], &final[off + 4], &final[off + 8], &final[off + 12], digest);

    COMPARE_M_SIMD (0, 0, digest[2] & 0xffff0000, digest[1]);
  }
}

KERNEL_FQ void m07801_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m07801_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m07801_s04 (KERN_ATTR_BASIC ())
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

  u32 salt_buf[8];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];
  salt_buf[4] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf[5] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf[6] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf[7] = salt_bufs[salt_pos].salt_buf[7];

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

    /**
     * SAP
     */

    u32 s0[4];
    u32 s1[4];
    u32 s2[4];
    u32 s3[4];

    s0[0] = salt_buf[0];
    s0[1] = salt_buf[1];
    s0[2] = salt_buf[2];
    s0[3] = salt_buf[3];
    s1[0] = salt_buf[4];
    s1[1] = salt_buf[5];
    s1[2] = salt_buf[6];
    s1[3] = salt_buf[7];
    s2[0] = 0;
    s2[1] = 0;
    s2[2] = 0;
    s2[3] = 0;
    s3[0] = 0;
    s3[1] = 0;
    s3[2] = 0;
    s3[3] = 0;

    switch_buffer_by_offset_le_VV (s0, s1, s2, s3, pw_len);

    const u32x pw_salt_len = pw_len + salt_len;

    /**
     * sha1
     */

    u32 final[32];

    final[ 0] = hc_swap32_S (w0[0] | s0[0]);
    final[ 1] = hc_swap32_S (w0[1] | s0[1]);
    final[ 2] = hc_swap32_S (w0[2] | s0[2]);
    final[ 3] = hc_swap32_S (w0[3] | s0[3]);
    final[ 4] = hc_swap32_S (w1[0] | s1[0]);
    final[ 5] = hc_swap32_S (w1[1] | s1[1]);
    final[ 6] = hc_swap32_S (w1[2] | s1[2]);
    final[ 7] = hc_swap32_S (w1[3] | s1[3]);
    final[ 8] = hc_swap32_S (w2[0] | s2[0]);
    final[ 9] = hc_swap32_S (w2[1] | s2[1]);
    final[10] = hc_swap32_S (w2[2] | s2[2]);
    final[11] = hc_swap32_S (w2[3] | s2[3]);
    final[12] = hc_swap32_S (w3[0] | s3[0]);
    final[13] = hc_swap32_S (w3[1] | s3[1]);
    final[14] = 0;
    final[15] = pw_salt_len * 8;
    final[16] = 0;
    final[17] = 0;
    final[18] = 0;
    final[19] = 0;
    final[20] = 0;
    final[21] = 0;
    final[22] = 0;
    final[23] = 0;
    final[24] = 0;
    final[25] = 0;
    final[26] = 0;
    final[27] = 0;
    final[28] = 0;
    final[29] = 0;
    final[30] = 0;
    final[31] = 0;

    u32 digest[5];

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    sha1_transform (&final[0], &final[4], &final[8], &final[12], digest);

    // prepare magic array range

    u32 lengthMagicArray = 0x20;
    u32 offsetMagicArray = 0;

    lengthMagicArray += ((digest[0] >> 24) & 0xff) % 6;
    lengthMagicArray += ((digest[0] >> 16) & 0xff) % 6;
    lengthMagicArray += ((digest[0] >>  8) & 0xff) % 6;
    lengthMagicArray += ((digest[0] >>  0) & 0xff) % 6;
    lengthMagicArray += ((digest[1] >> 24) & 0xff) % 6;
    lengthMagicArray += ((digest[1] >> 16) & 0xff) % 6;
    lengthMagicArray += ((digest[1] >>  8) & 0xff) % 6;
    lengthMagicArray += ((digest[1] >>  0) & 0xff) % 6;
    lengthMagicArray += ((digest[2] >> 24) & 0xff) % 6;
    lengthMagicArray += ((digest[2] >> 16) & 0xff) % 6;
    offsetMagicArray += ((digest[2] >>  8) & 0xff) % 8;
    offsetMagicArray += ((digest[2] >>  0) & 0xff) % 8;
    offsetMagicArray += ((digest[3] >> 24) & 0xff) % 8;
    offsetMagicArray += ((digest[3] >> 16) & 0xff) % 8;
    offsetMagicArray += ((digest[3] >>  8) & 0xff) % 8;
    offsetMagicArray += ((digest[3] >>  0) & 0xff) % 8;
    offsetMagicArray += ((digest[4] >> 24) & 0xff) % 8;
    offsetMagicArray += ((digest[4] >> 16) & 0xff) % 8;
    offsetMagicArray += ((digest[4] >>  8) & 0xff) % 8;
    offsetMagicArray += ((digest[4] >>  0) & 0xff) % 8;

    // final

    digest[0] = SHA1M_A;
    digest[1] = SHA1M_B;
    digest[2] = SHA1M_C;
    digest[3] = SHA1M_D;
    digest[4] = SHA1M_E;

    final[ 0] = hc_swap32_S (w0[0]);
    final[ 1] = hc_swap32_S (w0[1]);
    final[ 2] = hc_swap32_S (w0[2]);
    final[ 3] = hc_swap32_S (w0[3]);
    final[ 4] = hc_swap32_S (w1[0]);
    final[ 5] = hc_swap32_S (w1[1]);
    final[ 6] = hc_swap32_S (w1[2]);
    final[ 7] = hc_swap32_S (w1[3]);
    final[ 8] = hc_swap32_S (w2[0]);
    final[ 9] = hc_swap32_S (w2[1]);
    final[10] = hc_swap32_S (w2[2]);
    final[11] = hc_swap32_S (w2[3]);
    final[12] = hc_swap32_S (w3[0]);
    final[13] = hc_swap32_S (w3[1]);
    final[14] = 0;
    final[15] = 0;

    u32 final_len = pw_len;

    u32 i;

    // append MagicArray

    for (i = 0; i < lengthMagicArray - 4; i += 4)
    {
      const u32 tmp = GETSHIFTEDINT_CONST (theMagicArray, offsetMagicArray + i);

      SETSHIFTEDINT (final, final_len + i, tmp);
    }

    const u32 mask = 0xffffffff << (((4 - (lengthMagicArray - i)) & 3) * 8);

    const u32 tmp = GETSHIFTEDINT_CONST (theMagicArray, offsetMagicArray + i) & mask;

    SETSHIFTEDINT (final, final_len + i, tmp);

    final_len += lengthMagicArray;

    // append Salt

    for (i = 0; i < salt_len + 1; i += 4) // +1 for the 0x80
    {
      const u32 tmp = hc_swap32_S (salt_buf[i / 4]); // attention, int[] not char[]

      SETSHIFTEDINT (final, final_len + i, tmp);
    }

    final_len += salt_len;

    // calculate

    int left;
    int off;

    for (left = final_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      sha1_transform (&final[off + 0], &final[off + 4], &final[off + 8], &final[off + 12], digest);
    }

    final[off + 15] = final_len * 8;

    sha1_transform (&final[off + 0], &final[off + 4], &final[off + 8], &final[off + 12], digest);

    COMPARE_S_SIMD (0, 0, digest[2] & 0xffff0000, digest[1]);
  }
}

KERNEL_FQ void m07801_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m07801_s16 (KERN_ATTR_BASIC ())
{
}
