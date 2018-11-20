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
#include "inc_hash_sha256.cl"

__kernel void m13800_mxx (KERN_ATTR_ESALT (win8phone_t))
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

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_utf16le_swap (&ctx0, pws[gid].i, pws[gid].pw_len & 255);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha256_ctx_t ctx = ctx0;

    sha256_update_global_utf16le_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len & 255);

    sha256_update_global (&ctx, esalt_bufs[digests_offset].salt_buf, 128);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m13800_sxx (KERN_ATTR_ESALT (win8phone_t))
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

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_utf16le_swap (&ctx0, pws[gid].i, pws[gid].pw_len & 255);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha256_ctx_t ctx = ctx0;

    sha256_update_global_utf16le_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len & 255);

    sha256_update_global (&ctx, esalt_bufs[digests_offset].salt_buf, 128);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
