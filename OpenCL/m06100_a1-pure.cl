/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_whirlpool.cl"
#endif

KERNEL_FQ void m06100_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT[8][256];
  LOCAL_VK u64 s_RC[16];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT[0][i] = MT[0][i];
    s_MT[1][i] = MT[1][i];
    s_MT[2][i] = MT[2][i];
    s_MT[3][i] = MT[3][i];
    s_MT[4][i] = MT[4][i];
    s_MT[5][i] = MT[5][i];
    s_MT[6][i] = MT[6][i];
    s_MT[7][i] = MT[7][i];
  }

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_RC[i] = RC[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_MT)[256] = MT;
  CONSTANT_AS u64a  *s_RC       = RC;

  #endif

  if (gid >= gid_max) return;

  /**
   * base
   */

  whirlpool_ctx_t ctx0;

  whirlpool_init (&ctx0, s_MT, s_RC);

  whirlpool_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    whirlpool_ctx_t ctx = ctx0;

    whirlpool_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    whirlpool_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m06100_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_MT[8][256];
  LOCAL_VK u64 s_RC[16];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_MT[0][i] = MT[0][i];
    s_MT[1][i] = MT[1][i];
    s_MT[2][i] = MT[2][i];
    s_MT[3][i] = MT[3][i];
    s_MT[4][i] = MT[4][i];
    s_MT[5][i] = MT[5][i];
    s_MT[6][i] = MT[6][i];
    s_MT[7][i] = MT[7][i];
  }

  for (u32 i = lid; i < 16; i += lsz)
  {
    s_RC[i] = RC[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_MT)[256] = MT;
  CONSTANT_AS u64a  *s_RC       = RC;

  #endif

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  whirlpool_ctx_t ctx0;

  whirlpool_init (&ctx0, s_MT, s_RC);

  whirlpool_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    whirlpool_ctx_t ctx = ctx0;

    whirlpool_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    whirlpool_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
