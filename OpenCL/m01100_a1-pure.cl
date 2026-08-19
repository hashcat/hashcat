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
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#endif

KERNEL_FQ KERNEL_FA void m01100_mxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  md4_ctx_t ctx0_pre = ctx0;

  md4_update_global_utf16le (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md4_ctx_t ctx1 = ctx0;

    // -a 12 puts the base word inside the amplifier instead of beside it, so a candidate is five
    // pieces: mask, base word, mask, second word, mask. Any of them may be empty, and the two in the
    // middle are empty unless the mask carries a ?q.
    //
    // Every thread reads the same il_pos, so the branches below are uniform across the warp and the
    // attack modes that do not take them pay nothing but the compare.

    if (COMBS_IS_MIDDLE)
    {
      if (COMBS_PRE (il_pos).pw_len > 0)
      {
        ctx1 = ctx0_pre;

        md4_update_global_utf16le (&ctx1, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        md4_update_global_utf16le (&ctx1, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) md4_update_global_utf16le (&ctx1, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) md4_update_global_utf16le (&ctx1, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    md4_update_global_utf16le (&ctx1, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    md4_final (&ctx1);

    md4_ctx_t ctx;

    md4_init (&ctx);

    ctx.w0[0] = ctx1.h[0];
    ctx.w0[1] = ctx1.h[1];
    ctx.w0[2] = ctx1.h[2];
    ctx.w0[3] = ctx1.h[3];

    ctx.len = 16;

    md4_update_utf16le (&ctx, s, salt_len);

    md4_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m01100_sxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[SALT_POS_HOST].salt_buf[idx];
  }

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  md4_ctx_t ctx0_pre = ctx0;

  md4_update_global_utf16le (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md4_ctx_t ctx1 = ctx0;

    // -a 12 puts the base word inside the amplifier instead of beside it, so a candidate is five
    // pieces: mask, base word, mask, second word, mask. Any of them may be empty, and the two in the
    // middle are empty unless the mask carries a ?q.
    //
    // Every thread reads the same il_pos, so the branches below are uniform across the warp and the
    // attack modes that do not take them pay nothing but the compare.

    if (COMBS_IS_MIDDLE)
    {
      if (COMBS_PRE (il_pos).pw_len > 0)
      {
        ctx1 = ctx0_pre;

        md4_update_global_utf16le (&ctx1, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        md4_update_global_utf16le (&ctx1, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) md4_update_global_utf16le (&ctx1, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) md4_update_global_utf16le (&ctx1, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    md4_update_global_utf16le (&ctx1, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    md4_final (&ctx1);

    md4_ctx_t ctx;

    md4_init (&ctx);

    ctx.w0[0] = ctx1.h[0];
    ctx.w0[1] = ctx1.h[1];
    ctx.w0[2] = ctx1.h[2];
    ctx.w0[3] = ctx1.h[3];

    ctx.len = 16;

    md4_update_utf16le (&ctx, s, salt_len);

    md4_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
