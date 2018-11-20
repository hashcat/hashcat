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
#include "inc_scalar.cl"
#include "inc_hash_md5.cl"
#include "inc_hash_sha1.cl"

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

__kernel void m04400_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len & 255);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx1 = ctx0;

    sha1_update_global_swap (&ctx1, combs_buf[il_pos].i, combs_buf[il_pos].pw_len & 255);

    sha1_final (&ctx1);

    const u32 a = ctx1.h[0];
    const u32 b = ctx1.h[1];
    const u32 c = ctx1.h[2];
    const u32 d = ctx1.h[3];
    const u32 e = ctx1.h[4];

    md5_ctx_t ctx;

    md5_init (&ctx);

    ctx.w0[0] = uint_to_hex_lower8 ((a >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((a >> 16) & 255) << 16;
    ctx.w0[1] = uint_to_hex_lower8 ((a >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((a >>  0) & 255) << 16;
    ctx.w0[2] = uint_to_hex_lower8 ((b >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((b >> 16) & 255) << 16;
    ctx.w0[3] = uint_to_hex_lower8 ((b >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((b >>  0) & 255) << 16;
    ctx.w1[0] = uint_to_hex_lower8 ((c >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((c >> 16) & 255) << 16;
    ctx.w1[1] = uint_to_hex_lower8 ((c >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((c >>  0) & 255) << 16;
    ctx.w1[2] = uint_to_hex_lower8 ((d >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((d >> 16) & 255) << 16;
    ctx.w1[3] = uint_to_hex_lower8 ((d >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((d >>  0) & 255) << 16;
    ctx.w2[0] = uint_to_hex_lower8 ((e >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((e >> 16) & 255) << 16;
    ctx.w2[1] = uint_to_hex_lower8 ((e >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((e >>  0) & 255) << 16;

    ctx.len = 40;

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m04400_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
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

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len & 255);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx1 = ctx0;

    sha1_update_global_swap (&ctx1, combs_buf[il_pos].i, combs_buf[il_pos].pw_len & 255);

    sha1_final (&ctx1);

    const u32 a = ctx1.h[0];
    const u32 b = ctx1.h[1];
    const u32 c = ctx1.h[2];
    const u32 d = ctx1.h[3];
    const u32 e = ctx1.h[4];

    md5_ctx_t ctx;

    md5_init (&ctx);

    ctx.w0[0] = uint_to_hex_lower8 ((a >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((a >> 16) & 255) << 16;
    ctx.w0[1] = uint_to_hex_lower8 ((a >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((a >>  0) & 255) << 16;
    ctx.w0[2] = uint_to_hex_lower8 ((b >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((b >> 16) & 255) << 16;
    ctx.w0[3] = uint_to_hex_lower8 ((b >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((b >>  0) & 255) << 16;
    ctx.w1[0] = uint_to_hex_lower8 ((c >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((c >> 16) & 255) << 16;
    ctx.w1[1] = uint_to_hex_lower8 ((c >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((c >>  0) & 255) << 16;
    ctx.w1[2] = uint_to_hex_lower8 ((d >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((d >> 16) & 255) << 16;
    ctx.w1[3] = uint_to_hex_lower8 ((d >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((d >>  0) & 255) << 16;
    ctx.w2[0] = uint_to_hex_lower8 ((e >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((e >> 16) & 255) << 16;
    ctx.w2[1] = uint_to_hex_lower8 ((e >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((e >>  0) & 255) << 16;

    ctx.len = 40;

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
