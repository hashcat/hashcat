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
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha1.cl"
#endif

KERNEL_FQ void m07000_mxx (KERN_ATTR_RULES ())
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

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_ctx_t ctx = ctx0;

    sha1_update_swap (&ctx, tmp.i, tmp.pw_len);

    /**
     * pepper
     */

    u32 p0[4];
    u32 p1[4];
    u32 p2[4];
    u32 p3[4];

    p0[0] = hc_swap32_S (FORTIGATE_A);
    p0[1] = hc_swap32_S (FORTIGATE_B);
    p0[2] = hc_swap32_S (FORTIGATE_C);
    p0[3] = hc_swap32_S (FORTIGATE_D);
    p1[0] = hc_swap32_S (FORTIGATE_E);
    p1[1] = hc_swap32_S (FORTIGATE_F);
    p1[2] = 0;
    p1[3] = 0;
    p2[0] = 0;
    p2[1] = 0;
    p2[2] = 0;
    p2[3] = 0;
    p3[0] = 0;
    p3[1] = 0;
    p3[2] = 0;
    p3[3] = 0;

    sha1_update_64 (&ctx, p0, p1, p2, p3, 24);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m07000_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_ctx_t ctx = ctx0;

    sha1_update_swap (&ctx, tmp.i, tmp.pw_len);

    /**
     * pepper
     */

    u32 p0[4];
    u32 p1[4];
    u32 p2[4];
    u32 p3[4];

    p0[0] = hc_swap32_S (FORTIGATE_A);
    p0[1] = hc_swap32_S (FORTIGATE_B);
    p0[2] = hc_swap32_S (FORTIGATE_C);
    p0[3] = hc_swap32_S (FORTIGATE_D);
    p1[0] = hc_swap32_S (FORTIGATE_E);
    p1[1] = hc_swap32_S (FORTIGATE_F);
    p1[2] = 0;
    p1[3] = 0;
    p2[0] = 0;
    p2[1] = 0;
    p2[2] = 0;
    p2[3] = 0;
    p3[0] = 0;
    p3[1] = 0;
    p3[2] = 0;
    p3[3] = 0;

    sha1_update_64 (&ctx, p0, p1, p2, p3, 24);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
