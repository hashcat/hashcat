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
#include "inc_hash_sha512.cl"
#endif

KERNEL_FQ void m21000_mxx (KERN_ATTR_RULES ())
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

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha512_ctx_t ctx0;

    sha512_init (&ctx0);

    sha512_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha512_final (&ctx0);

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    u32 final[32] = { 0 };

    final[ 0] = h32_from_64_S (ctx0.h[0]);
    final[ 1] = l32_from_64_S (ctx0.h[0]);
    final[ 2] = h32_from_64_S (ctx0.h[1]);
    final[ 3] = l32_from_64_S (ctx0.h[1]);
    final[ 4] = h32_from_64_S (ctx0.h[2]);
    final[ 5] = l32_from_64_S (ctx0.h[2]);
    final[ 6] = h32_from_64_S (ctx0.h[3]);
    final[ 7] = l32_from_64_S (ctx0.h[3]);
    final[ 8] = h32_from_64_S (ctx0.h[4]);
    final[ 9] = l32_from_64_S (ctx0.h[4]);
    final[10] = h32_from_64_S (ctx0.h[5]);
    final[11] = l32_from_64_S (ctx0.h[5]);
    final[12] = h32_from_64_S (ctx0.h[6]);
    final[13] = l32_from_64_S (ctx0.h[6]);
    final[14] = h32_from_64_S (ctx0.h[7]);
    final[15] = l32_from_64_S (ctx0.h[7]);

    sha512_update (&ctx, final, 64);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m21000_sxx (KERN_ATTR_RULES ())
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

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha512_ctx_t ctx0;

    sha512_init (&ctx0);

    sha512_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha512_final (&ctx0);

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    u32 final[32] = { 0 };

    final[ 0] = h32_from_64_S (ctx0.h[0]);
    final[ 1] = l32_from_64_S (ctx0.h[0]);
    final[ 2] = h32_from_64_S (ctx0.h[1]);
    final[ 3] = l32_from_64_S (ctx0.h[1]);
    final[ 4] = h32_from_64_S (ctx0.h[2]);
    final[ 5] = l32_from_64_S (ctx0.h[2]);
    final[ 6] = h32_from_64_S (ctx0.h[3]);
    final[ 7] = l32_from_64_S (ctx0.h[3]);
    final[ 8] = h32_from_64_S (ctx0.h[4]);
    final[ 9] = l32_from_64_S (ctx0.h[4]);
    final[10] = h32_from_64_S (ctx0.h[5]);
    final[11] = l32_from_64_S (ctx0.h[5]);
    final[12] = h32_from_64_S (ctx0.h[6]);
    final[13] = l32_from_64_S (ctx0.h[6]);
    final[14] = h32_from_64_S (ctx0.h[7]);
    final[15] = l32_from_64_S (ctx0.h[7]);

    sha512_update (&ctx, final, 64);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
