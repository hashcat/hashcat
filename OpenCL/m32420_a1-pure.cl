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

KERNEL_FQ KERNEL_FA void m32420_mxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  sha512_ctx_t ctx0_pre = ctx0;

  sha512_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha512_ctx_t ctx1 = ctx0;

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

        sha512_update_global_swap (&ctx1, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        sha512_update_global_swap (&ctx1, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) sha512_update_global_swap (&ctx1, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) sha512_update_global_swap (&ctx1, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    sha512_update_global_swap (&ctx1, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    sha512_final (&ctx1);

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    w0[0] = h32_from_64_S (ctx1.h[0]);
    w0[1] = l32_from_64_S (ctx1.h[0]);
    w0[2] = h32_from_64_S (ctx1.h[1]);
    w0[3] = l32_from_64_S (ctx1.h[1]);
    w1[0] = h32_from_64_S (ctx1.h[2]);
    w1[1] = l32_from_64_S (ctx1.h[2]);
    w1[2] = h32_from_64_S (ctx1.h[3]);
    w1[3] = l32_from_64_S (ctx1.h[3]);
    w2[0] = h32_from_64_S (ctx1.h[4]);
    w2[1] = l32_from_64_S (ctx1.h[4]);
    w2[2] = h32_from_64_S (ctx1.h[5]);
    w2[3] = l32_from_64_S (ctx1.h[5]);
    w3[0] = h32_from_64_S (ctx1.h[6]);
    w3[1] = l32_from_64_S (ctx1.h[6]);
    w3[2] = h32_from_64_S (ctx1.h[7]);
    w3[3] = l32_from_64_S (ctx1.h[7]);
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

KERNEL_FQ KERNEL_FA void m32420_sxx (KERN_ATTR_BASIC ())
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  sha512_ctx_t ctx0_pre = ctx0;

  sha512_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha512_ctx_t ctx1 = ctx0;

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

        sha512_update_global_swap (&ctx1, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        sha512_update_global_swap (&ctx1, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) sha512_update_global_swap (&ctx1, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) sha512_update_global_swap (&ctx1, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    sha512_update_global_swap (&ctx1, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    sha512_final (&ctx1);

    sha512_ctx_t ctx;

    sha512_init (&ctx);

    w0[0] = h32_from_64_S (ctx1.h[0]);
    w0[1] = l32_from_64_S (ctx1.h[0]);
    w0[2] = h32_from_64_S (ctx1.h[1]);
    w0[3] = l32_from_64_S (ctx1.h[1]);
    w1[0] = h32_from_64_S (ctx1.h[2]);
    w1[1] = l32_from_64_S (ctx1.h[2]);
    w1[2] = h32_from_64_S (ctx1.h[3]);
    w1[3] = l32_from_64_S (ctx1.h[3]);
    w2[0] = h32_from_64_S (ctx1.h[4]);
    w2[1] = l32_from_64_S (ctx1.h[4]);
    w2[2] = h32_from_64_S (ctx1.h[5]);
    w2[3] = l32_from_64_S (ctx1.h[5]);
    w3[0] = h32_from_64_S (ctx1.h[6]);
    w3[1] = l32_from_64_S (ctx1.h[6]);
    w3[2] = h32_from_64_S (ctx1.h[7]);
    w3[3] = l32_from_64_S (ctx1.h[7]);
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
