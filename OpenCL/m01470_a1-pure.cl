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
#include "inc_hash_sha256.cl"
#endif

KERNEL_FQ void m01470_mxx (KERN_ATTR_BASIC ())
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

  sha256_ctx_t ctx1;

  sha256_init (&ctx1);

  sha256_update_global_swap (&ctx1, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha256_ctx_t ctx0 = ctx1;

    sha256_update_global_swap (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha256_final (&ctx0);

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    u32 _w0[4];
    _w0[0] = ctx0.h[0]; _w0[1] = ctx0.h[1]; _w0[2] = ctx0.h[2]; _w0[3] = ctx0.h[3];
    u32 _w1[4];
    _w1[0] = ctx0.h[4]; _w1[1] = ctx0.h[5]; _w1[2] = ctx0.h[6]; _w1[3] = ctx0.h[7];
    u32 _w2[4] = { 0, 0, 0, 0 };
    u32 _w3[4] = { 0, 0, 0, 0 };

    sha256_update_64 (&ctx, _w0, _w1, _w2, _w3, 32);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m01470_sxx (KERN_ATTR_BASIC ())
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

  sha256_ctx_t ctx1;

  sha256_init (&ctx1);

  sha256_update_global_swap (&ctx1, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha256_ctx_t ctx0 = ctx1;

    sha256_update_global_swap (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha256_final (&ctx0);

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    u32 _w0[4];
    _w0[0] = ctx0.h[0]; _w0[1] = ctx0.h[1]; _w0[2] = ctx0.h[2]; _w0[3] = ctx0.h[3];
    u32 _w1[4];
    _w1[0] = ctx0.h[4]; _w1[1] = ctx0.h[5]; _w1[2] = ctx0.h[6]; _w1[3] = ctx0.h[7];
    u32 _w2[4] = { 0, 0, 0, 0 };
    u32 _w3[4] = { 0, 0, 0, 0 };

    sha256_update_64 (&ctx, _w0, _w1, _w2, _w3, 32);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
