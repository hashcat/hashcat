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
#include M2S(INCLUDE_PATH/inc_hash_streebog512.cl)
#endif

KERNEL_FQ void m11800_mxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    streebog512_ctx_t ctx;

    streebog512_init (&ctx, s_sbob_sl64);

    streebog512_update_swap (&ctx, tmp.i, tmp.pw_len);

    streebog512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[0]);
    const u32 r1 = h32_from_64_S (ctx.h[0]);
    const u32 r2 = l32_from_64_S (ctx.h[1]);
    const u32 r3 = h32_from_64_S (ctx.h[1]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m11800_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    streebog512_ctx_t ctx;

    streebog512_init (&ctx, s_sbob_sl64);

    streebog512_update_swap (&ctx, tmp.i, tmp.pw_len);

    streebog512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[0]);
    const u32 r1 = h32_from_64_S (ctx.h[0]);
    const u32 r2 = l32_from_64_S (ctx.h[1]);
    const u32 r3 = h32_from_64_S (ctx.h[1]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
