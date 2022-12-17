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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

KERNEL_FQ void m30700_mxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  ctx0.h[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  ctx0.h[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];
  ctx0.h[2] = salt_bufs[SALT_POS_HOST].salt_buf_pc[2];
  ctx0.h[3] = salt_bufs[SALT_POS_HOST].salt_buf_pc[3];
  ctx0.h[4] = salt_bufs[SALT_POS_HOST].salt_buf_pc[4];
  ctx0.h[5] = salt_bufs[SALT_POS_HOST].salt_buf_pc[5];
  ctx0.h[6] = salt_bufs[SALT_POS_HOST].salt_buf_pc[6];
  ctx0.h[7] = salt_bufs[SALT_POS_HOST].salt_buf_pc[7];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx = ctx0;

    sha256_update_swap (&ctx, tmp.i, tmp.pw_len);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m30700_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  ctx0.h[0] = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  ctx0.h[1] = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];
  ctx0.h[2] = salt_bufs[SALT_POS_HOST].salt_buf_pc[2];
  ctx0.h[3] = salt_bufs[SALT_POS_HOST].salt_buf_pc[3];
  ctx0.h[4] = salt_bufs[SALT_POS_HOST].salt_buf_pc[4];
  ctx0.h[5] = salt_bufs[SALT_POS_HOST].salt_buf_pc[5];
  ctx0.h[6] = salt_bufs[SALT_POS_HOST].salt_buf_pc[6];
  ctx0.h[7] = salt_bufs[SALT_POS_HOST].salt_buf_pc[7];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx = ctx0;

    sha256_update_swap (&ctx, tmp.i, tmp.pw_len);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
