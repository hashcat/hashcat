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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#endif

KERNEL_FQ void m00620_mxx (KERN_ATTR_RULES ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  blake2b_ctx_t ctx0;

  blake2b_init (&ctx0);

  blake2b_update_global (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    blake2b_ctx_t ctx = ctx0;

    blake2b_update (&ctx, tmp.i, tmp.pw_len);
    blake2b_final  (&ctx);

    const u32 r0 = h32_from_64_S (ctx.h[0]);
    const u32 r1 = l32_from_64_S (ctx.h[0]);
    const u32 r2 = h32_from_64_S (ctx.h[1]);
    const u32 r3 = l32_from_64_S (ctx.h[1]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m00620_sxx (KERN_ATTR_RULES ())
{
  /**
   * base
   */

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

  COPY_PW (pws[gid]);

  blake2b_ctx_t ctx0;

  blake2b_init (&ctx0);

  blake2b_update_global (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    blake2b_ctx_t ctx = ctx0;

    blake2b_update (&ctx, tmp.i, tmp.pw_len);
    blake2b_final  (&ctx);

    const u32 r0 = h32_from_64_S (ctx.h[0]);
    const u32 r1 = l32_from_64_S (ctx.h[0]);
    const u32 r2 = h32_from_64_S (ctx.h[1]);
    const u32 r3 = l32_from_64_S (ctx.h[1]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
