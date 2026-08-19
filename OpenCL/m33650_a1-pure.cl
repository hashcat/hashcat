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
#include M2S(INCLUDE_PATH/inc_hash_ripemd320.cl)
#endif

KERNEL_FQ KERNEL_FA void m33650_mxx (KERN_ATTR_BASIC ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 c[64];

    // -a 12 puts the base word inside the amplifier instead of beside it, so the candidate is five
    // pieces: mask, base word, mask, second word, mask. The assembler takes all five in order and
    // does the plain two piece case the other attack modes need as well.

    const u32 c_len = combs_assemble_1x64_le_S (combs_buf, il_pos, COMBS_MODE, w, pw_len, c);

    ripemd320_hmac_ctx_t ctx;

    ripemd320_hmac_init (&ctx, c, c_len);

    ripemd320_hmac_update (&ctx, s, salt_len);

    ripemd320_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m33650_sxx (KERN_ATTR_BASIC ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32 c[64];

    // -a 12 puts the base word inside the amplifier instead of beside it, so the candidate is five
    // pieces: mask, base word, mask, second word, mask. The assembler takes all five in order and
    // does the plain two piece case the other attack modes need as well.

    const u32 c_len = combs_assemble_1x64_le_S (combs_buf, il_pos, COMBS_MODE, w, pw_len, c);

    ripemd320_hmac_ctx_t ctx;

    ripemd320_hmac_init (&ctx, c, c_len);

    ripemd320_hmac_update (&ctx, s, salt_len);

    ripemd320_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
