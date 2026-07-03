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

KERNEL_FQ KERNEL_FA void m89100_mxx (KERN_ATTR_BASIC ())
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

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  md4_update_global_utf16le (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md4_ctx_t ctx = ctx0;

    md4_update_global_utf16le (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md4_final (&ctx);

    u32 t[16] = { 0 };
    t[0] = (ctx.h[0] & 0x000000ff) <<  0 | (ctx.h[0] & 0x0000ff00) <<  8;
    t[1] = (ctx.h[0] & 0x00ff0000) >> 16 | (ctx.h[0] & 0xff000000) >>  8;
    t[2] = (ctx.h[1] & 0x000000ff) <<  0 | (ctx.h[1] & 0x0000ff00) <<  8;
    t[3] = (ctx.h[1] & 0x00ff0000) >> 16 | (ctx.h[1] & 0xff000000) >>  8;
    t[4] = (ctx.h[2] & 0x000000ff) <<  0 | (ctx.h[2] & 0x0000ff00) <<  8;
    t[5] = (ctx.h[2] & 0x00ff0000) >> 16 | (ctx.h[2] & 0xff000000) >>  8;
    t[6] = (ctx.h[3] & 0x000000ff) <<  0 | (ctx.h[3] & 0x0000ff00) <<  8;
    t[7] = (ctx.h[3] & 0x00ff0000) >> 16 | (ctx.h[3] & 0xff000000) >>  8;

    md4_ctx_t ctx2;
    md4_init   (&ctx2);
    md4_update (&ctx2, t, 32);
    md4_final  (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m89100_sxx (KERN_ATTR_BASIC ())
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

  md4_ctx_t ctx0;

  md4_init (&ctx0);

  md4_update_global_utf16le (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md4_ctx_t ctx = ctx0;

    md4_update_global_utf16le (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md4_final (&ctx);

    u32 t[16] = { 0 };
    t[0] = (ctx.h[0] & 0x000000ff) <<  0 | (ctx.h[0] & 0x0000ff00) <<  8;
    t[1] = (ctx.h[0] & 0x00ff0000) >> 16 | (ctx.h[0] & 0xff000000) >>  8;
    t[2] = (ctx.h[1] & 0x000000ff) <<  0 | (ctx.h[1] & 0x0000ff00) <<  8;
    t[3] = (ctx.h[1] & 0x00ff0000) >> 16 | (ctx.h[1] & 0xff000000) >>  8;
    t[4] = (ctx.h[2] & 0x000000ff) <<  0 | (ctx.h[2] & 0x0000ff00) <<  8;
    t[5] = (ctx.h[2] & 0x00ff0000) >> 16 | (ctx.h[2] & 0xff000000) >>  8;
    t[6] = (ctx.h[3] & 0x000000ff) <<  0 | (ctx.h[3] & 0x0000ff00) <<  8;
    t[7] = (ctx.h[3] & 0x00ff0000) >> 16 | (ctx.h[3] & 0xff000000) >>  8;

    md4_ctx_t ctx2;
    md4_init   (&ctx2);
    md4_update (&ctx2, t, 32);
    md4_final  (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
