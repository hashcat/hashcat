/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_whirlpool.cl"

__kernel void m06100_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  __local u32 s_Ch[8][256];
  __local u32 s_Cl[8][256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_Ch[0][i] = Ch[0][i];
    s_Ch[1][i] = Ch[1][i];
    s_Ch[2][i] = Ch[2][i];
    s_Ch[3][i] = Ch[3][i];
    s_Ch[4][i] = Ch[4][i];
    s_Ch[5][i] = Ch[5][i];
    s_Ch[6][i] = Ch[6][i];
    s_Ch[7][i] = Ch[7][i];

    s_Cl[0][i] = Cl[0][i];
    s_Cl[1][i] = Cl[1][i];
    s_Cl[2][i] = Cl[2][i];
    s_Cl[3][i] = Cl[3][i];
    s_Cl[4][i] = Cl[4][i];
    s_Cl[5][i] = Cl[5][i];
    s_Cl[6][i] = Cl[6][i];
    s_Cl[7][i] = Cl[7][i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    whirlpool_ctx_t ctx;

    whirlpool_init (&ctx, s_Ch, s_Cl);

    whirlpool_update_swap (&ctx, tmp.i, tmp.pw_len);

    whirlpool_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m06100_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared
   */

  __local u32 s_Ch[8][256];
  __local u32 s_Cl[8][256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_Ch[0][i] = Ch[0][i];
    s_Ch[1][i] = Ch[1][i];
    s_Ch[2][i] = Ch[2][i];
    s_Ch[3][i] = Ch[3][i];
    s_Ch[4][i] = Ch[4][i];
    s_Ch[5][i] = Ch[5][i];
    s_Ch[6][i] = Ch[6][i];
    s_Ch[7][i] = Ch[7][i];

    s_Cl[0][i] = Cl[0][i];
    s_Cl[1][i] = Cl[1][i];
    s_Cl[2][i] = Cl[2][i];
    s_Cl[3][i] = Cl[3][i];
    s_Cl[4][i] = Cl[4][i];
    s_Cl[5][i] = Cl[5][i];
    s_Cl[6][i] = Cl[6][i];
    s_Cl[7][i] = Cl[7][i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    whirlpool_ctx_t ctx;

    whirlpool_init (&ctx, s_Ch, s_Cl);

    whirlpool_update_swap (&ctx, tmp.i, tmp.pw_len);

    whirlpool_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
