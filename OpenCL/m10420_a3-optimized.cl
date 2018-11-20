/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"

__constant u32a padding[8] =
{
  0x5e4ebf28,
  0x418a754e,
  0x564e0064,
  0x0801faff,
  0xb6002e2e,
  0x803e68d0,
  0xfea90c2f,
  0x7a695364
};

DECLSPEC void m10420m (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (pdf_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[digests_offset].o_buf[0];
  o_buf[1] = esalt_bufs[digests_offset].o_buf[1];
  o_buf[2] = esalt_bufs[digests_offset].o_buf[2];
  o_buf[3] = esalt_bufs[digests_offset].o_buf[3];
  o_buf[4] = esalt_bufs[digests_offset].o_buf[4];
  o_buf[5] = esalt_bufs[digests_offset].o_buf[5];
  o_buf[6] = esalt_bufs[digests_offset].o_buf[6];
  o_buf[7] = esalt_bufs[digests_offset].o_buf[7];

  u32 P = esalt_bufs[digests_offset].P;

  u32 id_buf[4];

  id_buf[0] = esalt_bufs[digests_offset].id_buf[0];
  id_buf[1] = esalt_bufs[digests_offset].id_buf[1];
  id_buf[2] = esalt_bufs[digests_offset].id_buf[2];
  id_buf[3] = esalt_bufs[digests_offset].id_buf[3];

  u32 p0[4];
  u32 p1[4];
  u32 p2[4];
  u32 p3[4];

  p0[0] = padding[0];
  p0[1] = padding[1];
  p0[2] = padding[2];
  p0[3] = padding[3];
  p1[0] = padding[4];
  p1[1] = padding[5];
  p1[2] = padding[6];
  p1[3] = padding[7];
  p2[0] = 0;
  p2[1] = 0;
  p2[2] = 0;
  p2[3] = 0;
  p3[0] = 0;
  p3[1] = 0;
  p3[2] = 0;
  p3[3] = 0;

  switch_buffer_by_offset_le_S (p0, p1, p2, p3, pw_len);

  w0[0] |= p0[0];
  w0[1] |= p0[1];
  w0[2] |= p0[2];
  w0[3] |= p0[3];
  w1[0] |= p1[0];
  w1[1] |= p1[1];
  w1[2] |= p1[2];
  w1[3] |= p1[3];
  w2[0] |= p2[0];
  w2[1] |= p2[1];
  w2[2] |= p2[2];
  w2[3] |= p2[3];
  w3[0] |= p3[0];
  w3[1] |= p3[1];
  w3[2] |= p3[2];
  w3[3] |= p3[3];

  /**
   * loop
   */

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 w0r = (u32) bfs_buf[il_pos + 0].i;

    w0[0] = w0l | w0r;

    /**
     * pdf
     */

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    // add password
    // truncate at 32 is wanted, not a bug!
    // add o_buf

    w0_t[0] = w0[0];
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = o_buf[0];
    w2_t[1] = o_buf[1];
    w2_t[2] = o_buf[2];
    w2_t[3] = o_buf[3];
    w3_t[0] = o_buf[4];
    w3_t[1] = o_buf[5];
    w3_t[2] = o_buf[6];
    w3_t[3] = o_buf[7];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = P;
    w0_t[1] = id_buf[0];
    w0_t[2] = id_buf[1];
    w0_t[3] = id_buf[2];
    w1_t[0] = id_buf[3];
    w1_t[1] = 0x80;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 84 * 8;
    w3_t[3] = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    u32 a = digest[0];
    u32 b = digest[1] & 0xff;
    u32 c = 0;
    u32 d = 0;

    COMPARE_M_SIMD (a, b, c, d);
  }
}

DECLSPEC void m10420s (u32 *w0, u32 *w1, u32 *w2, u32 *w3, const u32 pw_len, KERN_ATTR_ESALT (pdf_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * U_buf
   */

  u32 o_buf[8];

  o_buf[0] = esalt_bufs[digests_offset].o_buf[0];
  o_buf[1] = esalt_bufs[digests_offset].o_buf[1];
  o_buf[2] = esalt_bufs[digests_offset].o_buf[2];
  o_buf[3] = esalt_bufs[digests_offset].o_buf[3];
  o_buf[4] = esalt_bufs[digests_offset].o_buf[4];
  o_buf[5] = esalt_bufs[digests_offset].o_buf[5];
  o_buf[6] = esalt_bufs[digests_offset].o_buf[6];
  o_buf[7] = esalt_bufs[digests_offset].o_buf[7];

  u32 P = esalt_bufs[digests_offset].P;

  u32 id_buf[4];

  id_buf[0] = esalt_bufs[digests_offset].id_buf[0];
  id_buf[1] = esalt_bufs[digests_offset].id_buf[1];
  id_buf[2] = esalt_bufs[digests_offset].id_buf[2];
  id_buf[3] = esalt_bufs[digests_offset].id_buf[3];

  u32 p0[4];
  u32 p1[4];
  u32 p2[4];
  u32 p3[4];

  p0[0] = padding[0];
  p0[1] = padding[1];
  p0[2] = padding[2];
  p0[3] = padding[3];
  p1[0] = padding[4];
  p1[1] = padding[5];
  p1[2] = padding[6];
  p1[3] = padding[7];
  p2[0] = 0;
  p2[1] = 0;
  p2[2] = 0;
  p2[3] = 0;
  p3[0] = 0;
  p3[1] = 0;
  p3[2] = 0;
  p3[3] = 0;

  switch_buffer_by_offset_le_S (p0, p1, p2, p3, pw_len);

  w0[0] |= p0[0];
  w0[1] |= p0[1];
  w0[2] |= p0[2];
  w0[3] |= p0[3];
  w1[0] |= p1[0];
  w1[1] |= p1[1];
  w1[2] |= p1[2];
  w1[3] |= p1[3];
  w2[0] |= p2[0];
  w2[1] |= p2[1];
  w2[2] |= p2[2];
  w2[3] |= p2[3];
  w3[0] |= p3[0];
  w3[1] |= p3[1];
  w3[2] |= p3[2];
  w3[3] |= p3[3];

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

  u32 w0l = w0[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 w0r = (u32) bfs_buf[il_pos].i;

    w0[0] = w0l | w0r;

    /**
     * pdf
     */

    u32 w0_t[4];
    u32 w1_t[4];
    u32 w2_t[4];
    u32 w3_t[4];

    // add password
    // truncate at 32 is wanted, not a bug!
    // add o_buf

    w0_t[0] = w0[0];
    w0_t[1] = w0[1];
    w0_t[2] = w0[2];
    w0_t[3] = w0[3];
    w1_t[0] = w1[0];
    w1_t[1] = w1[1];
    w1_t[2] = w1[2];
    w1_t[3] = w1[3];
    w2_t[0] = o_buf[0];
    w2_t[1] = o_buf[1];
    w2_t[2] = o_buf[2];
    w2_t[3] = o_buf[3];
    w3_t[0] = o_buf[4];
    w3_t[1] = o_buf[5];
    w3_t[2] = o_buf[6];
    w3_t[3] = o_buf[7];

    u32 digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = P;
    w0_t[1] = id_buf[0];
    w0_t[2] = id_buf[1];
    w0_t[3] = id_buf[2];
    w1_t[0] = id_buf[3];
    w1_t[1] = 0x80;
    w1_t[2] = 0;
    w1_t[3] = 0;
    w2_t[0] = 0;
    w2_t[1] = 0;
    w2_t[2] = 0;
    w2_t[3] = 0;
    w3_t[0] = 0;
    w3_t[1] = 0;
    w3_t[2] = 84 * 8;
    w3_t[3] = 0;

    md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

    u32 a = digest[0];
    u32 b = digest[1] & 0xff;
    u32 c = 0;
    u32 d = 0;

    COMPARE_S_SIMD (a, b, c, d);
  }
}

__kernel void m10420_m04 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m10420m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m10420_m08 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m10420m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m10420_m16 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m10420m (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m10420_s04 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m10420s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m10420_s08 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;

  u32 w3[4];

  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m10420s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m10420_s16 (KERN_ATTR_ESALT (pdf_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = 0;
  w3[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m10420s (w0, w1, w2, w3, pw_len, pws, rules_buf, combs_buf, bfs_buf, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}
