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
#include "inc_hash_sha384.cl"

__kernel void m10800_mxx (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  const u32 pw_lenv = ceil ((float) pw_len / 4);

  u32 w[64] = { 0 };

  for (int idx = 0; idx < pw_lenv; idx++)
  {
    w[idx] = swap32_S (pws[gid].i[idx]);

    barrier (CLK_GLOBAL_MEM_FENCE);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    // todo: add rules engine

    sha384_ctx_t ctx;

    sha384_init (&ctx);

    sha384_update (&ctx, w, pw_len);

    sha384_final (&ctx);

    const u32x r0 = l32_from_64 (ctx.h[3]);
    const u32x r1 = h32_from_64 (ctx.h[3]);
    const u32x r2 = l32_from_64 (ctx.h[2]);
    const u32x r3 = h32_from_64 (ctx.h[2]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m10800_sxx (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

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
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  const u32 pw_lenv = ceil ((float) pw_len / 4);

  u32 w[64] = { 0 };

  for (int idx = 0; idx < pw_lenv; idx++)
  {
    w[idx] = swap32_S (pws[gid].i[idx]);

    barrier (CLK_GLOBAL_MEM_FENCE);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    // todo: add rules engine

    sha384_ctx_t ctx;

    sha384_init (&ctx);

    sha384_update (&ctx, w, pw_len);

    sha384_final (&ctx);

    const u32x r0 = l32_from_64 (ctx.h[3]);
    const u32x r1 = h32_from_64 (ctx.h[3]);
    const u32x r2 = l32_from_64 (ctx.h[2]);
    const u32x r3 = h32_from_64 (ctx.h[2]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
