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
#include "inc_scalar.cl"
#include "inc_hash_md5.cl"

__kernel void m04800_mxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[salt_pos].salt_len - 1;

  u32 s[16] = { 0 };

  s[0] = salt_bufs[salt_pos].salt_buf[0];
  s[1] = salt_bufs[salt_pos].salt_buf[1];
  s[2] = salt_bufs[salt_pos].salt_buf[2];
  s[3] = salt_bufs[salt_pos].salt_buf[3];

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  ctx0.w0[0] = salt_bufs[salt_pos].salt_buf[4];

  ctx0.len = 1;

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len & 255);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len & 255);

    md5_update (&ctx, s, salt_len);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m04800_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

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

  const u32 salt_len = salt_bufs[salt_pos].salt_len - 1;

  u32 s[16] = { 0 };

  s[0] = salt_bufs[salt_pos].salt_buf[0];
  s[1] = salt_bufs[salt_pos].salt_buf[1];
  s[2] = salt_bufs[salt_pos].salt_buf[2];
  s[3] = salt_bufs[salt_pos].salt_buf[3];

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  ctx0.w0[0] = salt_bufs[salt_pos].salt_buf[4];

  ctx0.len = 1;

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len & 255);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len & 255);

    md5_update (&ctx, s, salt_len);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
