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
#include M2S(INCLUDE_PATH/inc_hash_streebog512.cl)
#endif

KERNEL_FQ KERNEL_FA void m11800_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef REAL_SHM

  LOCAL_VK u64a s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob512_sl64;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  streebog512_ctx_t ctx0;

  streebog512_init (&ctx0, s_sbob_sl64);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  streebog512_ctx_t ctx0_pre = ctx0;

  streebog512_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    streebog512_ctx_t ctx = ctx0;

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
        ctx = ctx0_pre;

        streebog512_update_global_swap (&ctx, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        streebog512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) streebog512_update_global_swap (&ctx, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) streebog512_update_global_swap (&ctx, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    streebog512_update_global_swap (&ctx, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    streebog512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[0]);
    const u32 r1 = h32_from_64_S (ctx.h[0]);
    const u32 r2 = l32_from_64_S (ctx.h[1]);
    const u32 r3 = h32_from_64_S (ctx.h[1]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m11800_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef REAL_SHM

  LOCAL_VK u64a s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob512_sl64;

  #endif

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

  streebog512_ctx_t ctx0;

  streebog512_init (&ctx0, s_sbob_sl64);

  // -a 12 may put a piece of mask in front of the base word, and the context below can then not
  // be reused. This is the same context one update earlier, so whatever went in before the base
  // word still goes in only once.

  streebog512_ctx_t ctx0_pre = ctx0;

  streebog512_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    streebog512_ctx_t ctx = ctx0;

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
        ctx = ctx0_pre;

        streebog512_update_global_swap (&ctx, COMBS_PRE (il_pos).i, COMBS_PRE (il_pos).pw_len);
        streebog512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
      }

      if (COMBS_MID  (il_pos).pw_len > 0) streebog512_update_global_swap (&ctx, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      if (COMBS_WORD (il_pos).pw_len > 0) streebog512_update_global_swap (&ctx, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
    }

    streebog512_update_global_swap (&ctx, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);

    streebog512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[0]);
    const u32 r1 = h32_from_64_S (ctx.h[0]);
    const u32 r2 = l32_from_64_S (ctx.h[1]);
    const u32 r3 = h32_from_64_S (ctx.h[1]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
