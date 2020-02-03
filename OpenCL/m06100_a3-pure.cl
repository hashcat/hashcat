/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_whirlpool.cl"
#endif

KERNEL_FQ void m06100_mxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    whirlpool_ctx_vector_t ctx;

    whirlpool_init_vector (&ctx, s_MT, s_RC);

    whirlpool_update_vector (&ctx, w, pw_len);

    whirlpool_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m06100_sxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    whirlpool_ctx_vector_t ctx;

    whirlpool_init_vector (&ctx, s_MT, s_RC);

    whirlpool_update_vector (&ctx, w, pw_len);

    whirlpool_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
