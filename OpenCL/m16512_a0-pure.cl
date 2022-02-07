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
#include M2S(INCLUDE_PATH/inc_hash_sha384.cl)
#endif

typedef struct jwt
{
  u32 salt_buf[1024];
  u32 salt_len;

  u32 signature_len;

} jwt_t;

KERNEL_FQ void m16512_mxx (KERN_ATTR_RULES_ESALT (jwt_t))
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

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha384_hmac_ctx_t ctx;

    sha384_hmac_init_swap (&ctx, tmp.i, tmp.pw_len);

    sha384_hmac_update_global_swap (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

    sha384_hmac_final (&ctx);

    const u32x r0 = l32_from_64 (ctx.opad.h[0]);
    const u32x r1 = h32_from_64 (ctx.opad.h[0]);
    const u32x r2 = l32_from_64 (ctx.opad.h[1]);
    const u32x r3 = h32_from_64 (ctx.opad.h[1]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m16512_sxx (KERN_ATTR_RULES_ESALT (jwt_t))
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

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha384_hmac_ctx_t ctx;

    sha384_hmac_init_swap (&ctx, tmp.i, tmp.pw_len);

    sha384_hmac_update_global_swap (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

    sha384_hmac_final (&ctx);

    const u32x r0 = l32_from_64 (ctx.opad.h[0]);
    const u32x r1 = h32_from_64 (ctx.opad.h[0]);
    const u32x r2 = l32_from_64 (ctx.opad.h[1]);
    const u32x r3 = h32_from_64 (ctx.opad.h[1]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
