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
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_md5.cl"

__kernel void m16100_mxx (__global pw_t *pws, __constant const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const tacacs_plus_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
}

__kernel void m16100_sxx (__global pw_t *pws, __constant const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const tacacs_plus_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  u32 es0[4];
  u32 es1[4];
  u32 es2[4];
  u32 es3[4];

  es0[ 0] = esalt_bufs[digests_offset].session_buf[0];
  es0[ 1] = 0;
  es0[ 2] = 0;
  es0[ 3] = 0;
  es1[ 0] = 0;
  es1[ 1] = 0;
  es1[ 2] = 0;
  es1[ 3] = 0;
  es2[ 0] = 0;
  es2[ 1] = 0;
  es2[ 2] = 0;
  es2[ 3] = 0;
  es3[ 0] = 0;
  es3[ 1] = 0;
  es3[ 2] = 0;
  es3[ 3] = 0;

  md5_update_64 (&ctx0, es0, es1, es2, es3, 4);

  es0[ 0] = esalt_bufs[digests_offset].sequence_buf[0];
  es0[ 1] = 0;
  es0[ 2] = 0;
  es0[ 3] = 0;
  es1[ 0] = 0;
  es1[ 1] = 0;
  es1[ 2] = 0;
  es1[ 3] = 0;
  es2[ 0] = 0;
  es2[ 1] = 0;
  es2[ 2] = 0;
  es2[ 3] = 0;
  es3[ 0] = 0;
  es3[ 1] = 0;
  es3[ 2] = 0;
  es3[ 3] = 0;

  u32 ct_buf[2];

  ct_buf[0] = esalt_bufs[digests_offset].ct_data_buf[0];
  ct_buf[1] = esalt_bufs[digests_offset].ct_data_buf[1];

  u32 cl_len = esalt_bufs[digests_offset].ct_data_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md5_ctx_t ctx = ctx0;

    md5_update (&ctx, tmp.i, tmp.pw_len);

    md5_update_64 (&ctx, es0, es1, es2, es3, 2);

    md5_final (&ctx);

    u32 test[2];

    test[0] = ctx.h[0] ^ ct_buf[0];
    test[1] = ctx.h[1] ^ ct_buf[1];

    const u32 status    = ((test[0] >>  0) & 0xff);
    const u32 flags     = ((test[0] >>  8) & 0xff);
    const u32 msg_len   = ((test[0] >> 16) & 0xff) << 8
                        | ((test[0] >> 24) & 0xff) << 0;
    const u32 data_len  = ((test[1] >>  0) & 0xff) << 8
                        | ((test[1] >>  8) & 0xff) << 0;

    if (((status >= 0x01 && status <= 0x07) || status == 0x21)
     &&  (flags  == 0x01 || flags  == 0x00)
     &&  (6 + msg_len + data_len == cl_len))
    {
      if (atomic_inc (&hashes_shown[digests_offset]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
      }
    }
  }
}
