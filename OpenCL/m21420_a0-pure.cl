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
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

KERNEL_FQ KERNEL_FA void m21420_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  COPY_PW (pws[gid]);

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx0;

    sha256_init (&ctx0);

    sha256_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha256_final (&ctx0);

    const u32 a = ctx0.h[0];
    const u32 b = ctx0.h[1];
    const u32 c = ctx0.h[2];
    const u32 d = ctx0.h[3];
    const u32 e = ctx0.h[4];
    const u32 f = ctx0.h[5];
    const u32 g = ctx0.h[6];
    const u32 h = ctx0.h[7];

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    sha256_update (&ctx, s, salt_len);

    w0[0] = a;
    w0[1] = b;
    w0[2] = c;
    w0[3] = d;
    w1[0] = e;
    w1[1] = f;
    w1[2] = g;
    w1[3] = h;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_update_64 (&ctx, w0, w1, w2, w3, 32);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m21420_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  COPY_PW (pws[gid]);

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx0;

    sha256_init (&ctx0);

    sha256_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha256_final (&ctx0);

    const u32 a = ctx0.h[0];
    const u32 b = ctx0.h[1];
    const u32 c = ctx0.h[2];
    const u32 d = ctx0.h[3];
    const u32 e = ctx0.h[4];
    const u32 f = ctx0.h[5];
    const u32 g = ctx0.h[6];
    const u32 h = ctx0.h[7];

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    sha256_update (&ctx, s, salt_len);

    w0[0] = a;
    w0[1] = b;
    w0[2] = c;
    w0[3] = d;
    w1[0] = e;
    w1[1] = f;
    w1[2] = g;
    w1[3] = h;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_update_64 (&ctx, w0, w1, w2, w3, 32);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
