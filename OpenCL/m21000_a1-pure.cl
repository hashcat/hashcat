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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

KERNEL_FQ KERNEL_FA void m21000_mxx (KERN_ATTR_BASIC ())
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

  sha512_ctx_t ctx00;

  sha512_init (&ctx00);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  sha512_ctx_t ctx00_pre = ctx00;

  sha512_update_global_swap (&ctx00, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha512_ctx_t ctx0 = ctx00;

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
        ctx0 = ctx00_pre;

        sha512_update_global_swap (&ctx0, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        sha512_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) sha512_update_global_swap (&ctx0, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) sha512_update_global_swap (&ctx0, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    sha512_update_global_swap (&ctx0, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    sha512_final (&ctx0);

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    u32 final[32] = { 0 };

    final[ 0] = h32_from_64_S (ctx0.h[0]);
    final[ 1] = l32_from_64_S (ctx0.h[0]);
    final[ 2] = h32_from_64_S (ctx0.h[1]);
    final[ 3] = l32_from_64_S (ctx0.h[1]);
    final[ 4] = h32_from_64_S (ctx0.h[2]);
    final[ 5] = l32_from_64_S (ctx0.h[2]);
    final[ 6] = h32_from_64_S (ctx0.h[3]);
    final[ 7] = l32_from_64_S (ctx0.h[3]);
    final[ 8] = h32_from_64_S (ctx0.h[4]);
    final[ 9] = l32_from_64_S (ctx0.h[4]);
    final[10] = h32_from_64_S (ctx0.h[5]);
    final[11] = l32_from_64_S (ctx0.h[5]);
    final[12] = h32_from_64_S (ctx0.h[6]);
    final[13] = l32_from_64_S (ctx0.h[6]);
    final[14] = h32_from_64_S (ctx0.h[7]);
    final[15] = l32_from_64_S (ctx0.h[7]);

    sha512_update (&ctx, final, 64);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m21000_sxx (KERN_ATTR_BASIC ())
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

  sha512_ctx_t ctx00;

  sha512_init (&ctx00);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  sha512_ctx_t ctx00_pre = ctx00;

  sha512_update_global_swap (&ctx00, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha512_ctx_t ctx0 = ctx00;

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
        ctx0 = ctx00_pre;

        sha512_update_global_swap (&ctx0, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        sha512_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) sha512_update_global_swap (&ctx0, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) sha512_update_global_swap (&ctx0, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    sha512_update_global_swap (&ctx0, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    sha512_final (&ctx0);

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    u32 final[32] = { 0 };

    final[ 0] = h32_from_64_S (ctx0.h[0]);
    final[ 1] = l32_from_64_S (ctx0.h[0]);
    final[ 2] = h32_from_64_S (ctx0.h[1]);
    final[ 3] = l32_from_64_S (ctx0.h[1]);
    final[ 4] = h32_from_64_S (ctx0.h[2]);
    final[ 5] = l32_from_64_S (ctx0.h[2]);
    final[ 6] = h32_from_64_S (ctx0.h[3]);
    final[ 7] = l32_from_64_S (ctx0.h[3]);
    final[ 8] = h32_from_64_S (ctx0.h[4]);
    final[ 9] = l32_from_64_S (ctx0.h[4]);
    final[10] = h32_from_64_S (ctx0.h[5]);
    final[11] = l32_from_64_S (ctx0.h[5]);
    final[12] = h32_from_64_S (ctx0.h[6]);
    final[13] = l32_from_64_S (ctx0.h[6]);
    final[14] = h32_from_64_S (ctx0.h[7]);
    final[15] = l32_from_64_S (ctx0.h[7]);

    sha512_update (&ctx, final, 64);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
