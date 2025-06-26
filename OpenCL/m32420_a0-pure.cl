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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

KERNEL_FQ KERNEL_FA void m32420_mxx (KERN_ATTR_RULES ())
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
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  COPY_PW (pws[gid]);

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
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

    sha512_ctx_t ctx0;

    sha512_init (&ctx0);

    sha512_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha512_final (&ctx0);

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    w0[0] = h32_from_64_S (ctx0.h[0]);
    w0[1] = l32_from_64_S (ctx0.h[0]);
    w0[2] = h32_from_64_S (ctx0.h[1]);
    w0[3] = l32_from_64_S (ctx0.h[1]);
    w1[0] = h32_from_64_S (ctx0.h[2]);
    w1[1] = l32_from_64_S (ctx0.h[2]);
    w1[2] = h32_from_64_S (ctx0.h[3]);
    w1[3] = l32_from_64_S (ctx0.h[3]);
    w2[0] = h32_from_64_S (ctx0.h[4]);
    w2[1] = l32_from_64_S (ctx0.h[4]);
    w2[2] = h32_from_64_S (ctx0.h[5]);
    w2[3] = l32_from_64_S (ctx0.h[5]);
    w3[0] = h32_from_64_S (ctx0.h[6]);
    w3[1] = l32_from_64_S (ctx0.h[6]);
    w3[2] = h32_from_64_S (ctx0.h[7]);
    w3[3] = l32_from_64_S (ctx0.h[7]);
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;

    sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64);

    sha512_update (&ctx, s, salt_len);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m32420_sxx (KERN_ATTR_RULES ())
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
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  COPY_PW (pws[gid]);

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
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

    sha512_ctx_t ctx0;

    sha512_init (&ctx0);

    sha512_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha512_final (&ctx0);

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    w0[0] = h32_from_64_S (ctx0.h[0]);
    w0[1] = l32_from_64_S (ctx0.h[0]);
    w0[2] = h32_from_64_S (ctx0.h[1]);
    w0[3] = l32_from_64_S (ctx0.h[1]);
    w1[0] = h32_from_64_S (ctx0.h[2]);
    w1[1] = l32_from_64_S (ctx0.h[2]);
    w1[2] = h32_from_64_S (ctx0.h[3]);
    w1[3] = l32_from_64_S (ctx0.h[3]);
    w2[0] = h32_from_64_S (ctx0.h[4]);
    w2[1] = l32_from_64_S (ctx0.h[4]);
    w2[2] = h32_from_64_S (ctx0.h[5]);
    w2[3] = l32_from_64_S (ctx0.h[5]);
    w3[0] = h32_from_64_S (ctx0.h[6]);
    w3[1] = l32_from_64_S (ctx0.h[6]);
    w3[2] = h32_from_64_S (ctx0.h[7]);
    w3[3] = l32_from_64_S (ctx0.h[7]);
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;

    sha512_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64);

    sha512_update (&ctx, s, salt_len);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
