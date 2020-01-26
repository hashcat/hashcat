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
#include "inc_hash_blake2.cl"
#endif

KERNEL_FQ void m00600_mxx (KERN_ATTR_ESALT (blake2_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

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

  u64 tmp_h[8];
  u64 tmp_t[2];
  u64 tmp_f[2];

  tmp_h[0] = esalt_bufs[digests_offset].h[0];
  tmp_h[1] = esalt_bufs[digests_offset].h[1];
  tmp_h[2] = esalt_bufs[digests_offset].h[2];
  tmp_h[3] = esalt_bufs[digests_offset].h[3];
  tmp_h[4] = esalt_bufs[digests_offset].h[4];
  tmp_h[5] = esalt_bufs[digests_offset].h[5];
  tmp_h[6] = esalt_bufs[digests_offset].h[6];
  tmp_h[7] = esalt_bufs[digests_offset].h[7];

  tmp_t[0] = esalt_bufs[digests_offset].t[0];
  tmp_t[1] = esalt_bufs[digests_offset].t[1];
  tmp_f[0] = esalt_bufs[digests_offset].f[0];
  tmp_f[1] = esalt_bufs[digests_offset].f[1];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x out_len = pw_l_len + pw_r_len;

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

    u64x digest[8];
    u64x m[16];
    u64x v[16];

    u64x h[8];
    u64x t[2];
    u64x f[2];

    h[0] = tmp_h[0];
    h[1] = tmp_h[1];
    h[2] = tmp_h[2];
    h[3] = tmp_h[3];
    h[4] = tmp_h[4];
    h[5] = tmp_h[5];
    h[6] = tmp_h[6];
    h[7] = tmp_h[7];

    t[0] = tmp_t[0];
    t[1] = tmp_t[1];
    f[0] = tmp_f[0];
    f[1] = tmp_f[1];

    blake2b_transform(h, t, f, m, v, w0, w1, w2, w3, out_len, BLAKE2B_FINAL);

    digest[0] = h[0];
    digest[1] = h[1];
    digest[2] = h[2];
    digest[3] = h[3];
    digest[4] = h[4];
    digest[5] = h[5];
    digest[6] = h[6];
    digest[7] = h[7];

    const u32x r0 = h32_from_64(digest[0]);
    const u32x r1 = l32_from_64(digest[0]);
    const u32x r2 = h32_from_64(digest[1]);
    const u32x r3 = l32_from_64(digest[1]);

    COMPARE_M_SIMD(r0, r1, r2, r3);
  }
}

KERNEL_FQ void m00600_sxx (KERN_ATTR_ESALT (blake2_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

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

  u64 tmp_h[8];
  u64 tmp_t[2];
  u64 tmp_f[2];

  tmp_h[0] = esalt_bufs[digests_offset].h[0];
  tmp_h[1] = esalt_bufs[digests_offset].h[1];
  tmp_h[2] = esalt_bufs[digests_offset].h[2];
  tmp_h[3] = esalt_bufs[digests_offset].h[3];
  tmp_h[4] = esalt_bufs[digests_offset].h[4];
  tmp_h[5] = esalt_bufs[digests_offset].h[5];
  tmp_h[6] = esalt_bufs[digests_offset].h[6];
  tmp_h[7] = esalt_bufs[digests_offset].h[7];

  tmp_t[0] = esalt_bufs[digests_offset].t[0];
  tmp_t[1] = esalt_bufs[digests_offset].t[1];
  tmp_f[0] = esalt_bufs[digests_offset].f[0];
  tmp_f[1] = esalt_bufs[digests_offset].f[1];

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

    const u32x out_len = pw_l_len + pw_r_len;

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

    u64x digest[8];
    u64x m[16];
    u64x v[16];

    u64x h[8];
    u64x t[2];
    u64x f[2];

    h[0] = tmp_h[0];
    h[1] = tmp_h[1];
    h[2] = tmp_h[2];
    h[3] = tmp_h[3];
    h[4] = tmp_h[4];
    h[5] = tmp_h[5];
    h[6] = tmp_h[6];
    h[7] = tmp_h[7];

    t[0] = tmp_t[0];
    t[1] = tmp_t[1];
    f[0] = tmp_f[0];
    f[1] = tmp_f[1];

    blake2b_transform(h, t, f, m, v, w0, w1, w2, w3, out_len, BLAKE2B_FINAL);

    digest[0] = h[0];
    digest[1] = h[1];
    digest[2] = h[2];
    digest[3] = h[3];
    digest[4] = h[4];
    digest[5] = h[5];
    digest[6] = h[6];
    digest[7] = h[7];

    const u32x r0 = h32_from_64(digest[0]);
    const u32x r1 = l32_from_64(digest[0]);
    const u32x r2 = h32_from_64(digest[1]);
    const u32x r3 = l32_from_64(digest[1]);

    COMPARE_S_SIMD(r0, r1, r2, r3);
  }
}

