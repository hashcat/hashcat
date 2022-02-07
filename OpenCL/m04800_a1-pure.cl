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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

KERNEL_FQ void m04800_mxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len - 1;

  u32 s[16] = { 0 };

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  s[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  s[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  ctx0.w0[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];

  ctx0.len = 1;

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, s, salt_len);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m04800_sxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len - 1;

  u32 s[16] = { 0 };

  s[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  s[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];
  s[2] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  s[3] = salt_bufs[SALT_POS_HOST].salt_buf[3];

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  ctx0.w0[0] = salt_bufs[SALT_POS_HOST].salt_buf[4];

  ctx0.len = 1;

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_update (&ctx, s, salt_len);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
