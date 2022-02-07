/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

KERNEL_FQ void m21000_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  sha512_ctx_t ctx00;

  sha512_init (&ctx00);

  sha512_update_global_swap (&ctx00, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha512_ctx_t ctx0 = ctx00;

    sha512_update_global_swap (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

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

KERNEL_FQ void m21000_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  sha512_ctx_t ctx00;

  sha512_init (&ctx00);

  sha512_update_global_swap (&ctx00, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha512_ctx_t ctx0 = ctx00;

    sha512_update_global_swap (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

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
