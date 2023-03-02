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
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

KERNEL_FQ void m31300_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * salt
   */

  const u32 salt_len = 48;

  u32 salt_buf[12];

  salt_buf[ 0] = salt_bufs[SALT_POS_HOST].salt_buf[ 0];
  salt_buf[ 1] = salt_bufs[SALT_POS_HOST].salt_buf[ 1];
  salt_buf[ 2] = salt_bufs[SALT_POS_HOST].salt_buf[ 2];
  salt_buf[ 3] = salt_bufs[SALT_POS_HOST].salt_buf[ 3];
  salt_buf[ 4] = salt_bufs[SALT_POS_HOST].salt_buf[ 4];
  salt_buf[ 5] = salt_bufs[SALT_POS_HOST].salt_buf[ 5];
  salt_buf[ 6] = salt_bufs[SALT_POS_HOST].salt_buf[ 6];
  salt_buf[ 7] = salt_bufs[SALT_POS_HOST].salt_buf[ 7];
  salt_buf[ 8] = salt_bufs[SALT_POS_HOST].salt_buf[ 8];
  salt_buf[ 9] = salt_bufs[SALT_POS_HOST].salt_buf[ 9];
  salt_buf[10] = salt_bufs[SALT_POS_HOST].salt_buf[10];
  salt_buf[11] = salt_bufs[SALT_POS_HOST].salt_buf[11];

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md4_ctx_t ctx0;

    md4_init (&ctx0);

    md4_update_utf16le (&ctx0, tmp.i, tmp.pw_len);

    md4_final (&ctx0);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx0.h[0];
    w0[1] = ctx0.h[1];
    w0[2] = ctx0.h[2];
    w0[3] = ctx0.h[3];
    w1[0] = salt_buf[ 0];
    w1[1] = salt_buf[ 1];
    w1[2] = salt_buf[ 2];
    w1[3] = salt_buf[ 3];
    w2[0] = salt_buf[ 4];
    w2[1] = salt_buf[ 5];
    w2[2] = salt_buf[ 6];
    w2[3] = salt_buf[ 7];
    w3[0] = salt_buf[ 8];
    w3[1] = salt_buf[ 9];
    w3[2] = salt_buf[10];
    w3[3] = salt_buf[11];

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_transform (w0, w1, w2, w3, ctx.h);

    ctx.len = 64;

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m31300_sxx (KERN_ATTR_RULES ())
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
   * salt
   */

  const u32 salt_len = 48;

  u32 salt_buf[12];

  salt_buf[ 0] = salt_bufs[SALT_POS_HOST].salt_buf[ 0];
  salt_buf[ 1] = salt_bufs[SALT_POS_HOST].salt_buf[ 1];
  salt_buf[ 2] = salt_bufs[SALT_POS_HOST].salt_buf[ 2];
  salt_buf[ 3] = salt_bufs[SALT_POS_HOST].salt_buf[ 3];
  salt_buf[ 4] = salt_bufs[SALT_POS_HOST].salt_buf[ 4];
  salt_buf[ 5] = salt_bufs[SALT_POS_HOST].salt_buf[ 5];
  salt_buf[ 6] = salt_bufs[SALT_POS_HOST].salt_buf[ 6];
  salt_buf[ 7] = salt_bufs[SALT_POS_HOST].salt_buf[ 7];
  salt_buf[ 8] = salt_bufs[SALT_POS_HOST].salt_buf[ 8];
  salt_buf[ 9] = salt_bufs[SALT_POS_HOST].salt_buf[ 9];
  salt_buf[10] = salt_bufs[SALT_POS_HOST].salt_buf[10];
  salt_buf[11] = salt_bufs[SALT_POS_HOST].salt_buf[11];

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md4_ctx_t ctx0;

    md4_init (&ctx0);

    md4_update_utf16le (&ctx0, tmp.i, tmp.pw_len);

    md4_final (&ctx0);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx0.h[0];
    w0[1] = ctx0.h[1];
    w0[2] = ctx0.h[2];
    w0[3] = ctx0.h[3];
    w1[0] = salt_buf[ 0];
    w1[1] = salt_buf[ 1];
    w1[2] = salt_buf[ 2];
    w1[3] = salt_buf[ 3];
    w2[0] = salt_buf[ 4];
    w2[1] = salt_buf[ 5];
    w2[2] = salt_buf[ 6];
    w2[3] = salt_buf[ 7];
    w3[0] = salt_buf[ 8];
    w3[1] = salt_buf[ 9];
    w3[2] = salt_buf[10];
    w3[3] = salt_buf[11];

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_transform (w0, w1, w2, w3, ctx.h);

    ctx.len = 64;

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
