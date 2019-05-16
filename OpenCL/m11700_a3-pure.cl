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
#include "inc_simd.cl"
#include "inc_hash_streebog256.cl"
#endif

KERNEL_FQ void m11700_mxx (KERN_ATTR_VECTOR ())
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
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob256_sl64;

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

    streebog256_ctx_vector_t ctx;

    streebog256_init_vector (&ctx, s_sbob_sl64);

    streebog256_update_vector_swap (&ctx, w, pw_len);

    streebog256_final_vector (&ctx);

    const u32x r0 = l32_from_64 (ctx.h[0]);
    const u32x r1 = h32_from_64 (ctx.h[0]);
    const u32x r2 = l32_from_64 (ctx.h[1]);
    const u32x r3 = h32_from_64 (ctx.h[1]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m11700_sxx (KERN_ATTR_VECTOR ())
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
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob256_sl64;

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

    streebog256_ctx_vector_t ctx;

    streebog256_init_vector (&ctx, s_sbob_sl64);

    streebog256_update_vector_swap (&ctx, w, pw_len);

    streebog256_final_vector (&ctx);

    const u32x r0 = l32_from_64 (ctx.h[0]);
    const u32x r1 = h32_from_64 (ctx.h[0]);
    const u32x r2 = l32_from_64 (ctx.h[1]);
    const u32x r3 = h32_from_64 (ctx.h[1]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
