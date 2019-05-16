/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_md5.cl"
#endif

KERNEL_FQ void m05100_mxx (KERN_ATTR_BASIC ())
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

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    u32 z = 0;

    COMPARE_M_SCALAR (r0, r1, z, z);
    COMPARE_M_SCALAR (r1, r2, z, z);
    COMPARE_M_SCALAR (r2, r3, z, z);
  }
}

KERNEL_FQ void m05100_sxx (KERN_ATTR_BASIC ())
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
    0,
    0
  };

  /**
   * base
   */

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    u32 z = 0;

    COMPARE_S_SCALAR (r0, r1, z, z);
    COMPARE_S_SCALAR (r1, r2, z, z);
    COMPARE_S_SCALAR (r2, r3, z, z);
  }
}
