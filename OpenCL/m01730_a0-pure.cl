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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

KERNEL_FQ KERNEL_FA void m01730_mxx (KERN_ATTR_RULES ())
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

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    sha512_update_utf16le_swap (&ctx, tmp.i, tmp.pw_len);

    sha512_update (&ctx, s, salt_len);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m01730_sxx (KERN_ATTR_RULES ())
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

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    sha512_update_utf16le_swap (&ctx, tmp.i, tmp.pw_len);

    sha512_update (&ctx, s, salt_len);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
