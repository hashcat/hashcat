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
#include "inc_hash_md5.cl"
#include "inc_hash_sha1.cl"
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

KERNEL_FQ void m20900_mxx (KERN_ATTR_BASIC ())
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

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  sha1_ctx_t ctx00;

  sha1_init (&ctx00);

  sha1_update_global_swap (&ctx00, pws[gid].i, pws[gid].pw_len);

  md5_ctx_t ctx11;

  md5_init (&ctx11);

  md5_update_global (&ctx11, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
	
  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx0 = ctx00;

    sha1_update_global_swap (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_final (&ctx0);

    const u32 a0 = ctx0.h[0];
    const u32 b0 = ctx0.h[1];
    const u32 c0 = ctx0.h[2];
    const u32 d0 = ctx0.h[3];
    const u32 e0 = ctx0.h[4];

    md5_ctx_t ctx1 = ctx11;

    md5_update_global (&ctx1, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx1);

    const u32 a1 = hc_swap32 (ctx1.h[0]);
    const u32 b1 = hc_swap32 (ctx1.h[1]);
    const u32 c1 = hc_swap32 (ctx1.h[2]);
    const u32 d1 = hc_swap32 (ctx1.h[3]);

    md5_ctx_t ctx;

    md5_init (&ctx);

    w0[0] = uint_to_hex_lower8 ((a0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((a0 >> 16) & 255) << 16;
    w0[1] = uint_to_hex_lower8 ((a0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((a0 >>  0) & 255) << 16;
    w0[2] = uint_to_hex_lower8 ((b0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((b0 >> 16) & 255) << 16;
    w0[3] = uint_to_hex_lower8 ((b0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((b0 >>  0) & 255) << 16;
    w1[0] = uint_to_hex_lower8 ((c0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((c0 >> 16) & 255) << 16;
    w1[1] = uint_to_hex_lower8 ((c0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((c0 >>  0) & 255) << 16;
    w1[2] = uint_to_hex_lower8 ((d0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((d0 >> 16) & 255) << 16;
    w1[3] = uint_to_hex_lower8 ((d0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((d0 >>  0) & 255) << 16;
    w2[0] = uint_to_hex_lower8 ((e0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((e0 >> 16) & 255) << 16;
    w2[1] = uint_to_hex_lower8 ((e0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((e0 >>  0) & 255) << 16;

    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_update_64 (&ctx, w0, w1, w2, w3, 40);

    w0[0] = uint_to_hex_lower8 ((a1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((a1 >> 16) & 255) << 16;
    w0[1] = uint_to_hex_lower8 ((a1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((a1 >>  0) & 255) << 16;
    w0[2] = uint_to_hex_lower8 ((b1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((b1 >> 16) & 255) << 16;
    w0[3] = uint_to_hex_lower8 ((b1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((b1 >>  0) & 255) << 16;
    w1[0] = uint_to_hex_lower8 ((c1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((c1 >> 16) & 255) << 16;
    w1[1] = uint_to_hex_lower8 ((c1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((c1 >>  0) & 255) << 16;
    w1[2] = uint_to_hex_lower8 ((d1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((d1 >> 16) & 255) << 16;
    w1[3] = uint_to_hex_lower8 ((d1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((d1 >>  0) & 255) << 16;

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_update_64 (&ctx, w0, w1, w2, w3, 32);

    w0[0] = uint_to_hex_lower8 ((a0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((a0 >> 16) & 255) << 16;
    w0[1] = uint_to_hex_lower8 ((a0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((a0 >>  0) & 255) << 16;
    w0[2] = uint_to_hex_lower8 ((b0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((b0 >> 16) & 255) << 16;
    w0[3] = uint_to_hex_lower8 ((b0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((b0 >>  0) & 255) << 16;
    w1[0] = uint_to_hex_lower8 ((c0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((c0 >> 16) & 255) << 16;
    w1[1] = uint_to_hex_lower8 ((c0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((c0 >>  0) & 255) << 16;
    w1[2] = uint_to_hex_lower8 ((d0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((d0 >> 16) & 255) << 16;
    w1[3] = uint_to_hex_lower8 ((d0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((d0 >>  0) & 255) << 16;
    w2[0] = uint_to_hex_lower8 ((e0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((e0 >> 16) & 255) << 16;
    w2[1] = uint_to_hex_lower8 ((e0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((e0 >>  0) & 255) << 16;

    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_update_64 (&ctx, w0, w1, w2, w3, 40);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m20900_sxx (KERN_ATTR_BASIC ())
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

  LOCAL_VK u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

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

  sha1_ctx_t ctx00;

  sha1_init (&ctx00);

  sha1_update_global_swap (&ctx00, pws[gid].i, pws[gid].pw_len);

  md5_ctx_t ctx11;

  md5_init (&ctx11);

  md5_update_global (&ctx11, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx0 = ctx00;

    sha1_update_global_swap (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_final (&ctx0);

    const u32 a0 = ctx0.h[0];
    const u32 b0 = ctx0.h[1];
    const u32 c0 = ctx0.h[2];
    const u32 d0 = ctx0.h[3];
    const u32 e0 = ctx0.h[4];

    md5_ctx_t ctx1 = ctx11;

    md5_update_global (&ctx1, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx1);

    const u32 a1 = hc_swap32 (ctx1.h[0]);
    const u32 b1 = hc_swap32 (ctx1.h[1]);
    const u32 c1 = hc_swap32 (ctx1.h[2]);
    const u32 d1 = hc_swap32 (ctx1.h[3]);

    md5_ctx_t ctx;

    md5_init (&ctx);

    w0[0] = uint_to_hex_lower8 ((a0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((a0 >> 16) & 255) << 16;
    w0[1] = uint_to_hex_lower8 ((a0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((a0 >>  0) & 255) << 16;
    w0[2] = uint_to_hex_lower8 ((b0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((b0 >> 16) & 255) << 16;
    w0[3] = uint_to_hex_lower8 ((b0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((b0 >>  0) & 255) << 16;
    w1[0] = uint_to_hex_lower8 ((c0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((c0 >> 16) & 255) << 16;
    w1[1] = uint_to_hex_lower8 ((c0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((c0 >>  0) & 255) << 16;
    w1[2] = uint_to_hex_lower8 ((d0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((d0 >> 16) & 255) << 16;
    w1[3] = uint_to_hex_lower8 ((d0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((d0 >>  0) & 255) << 16;
    w2[0] = uint_to_hex_lower8 ((e0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((e0 >> 16) & 255) << 16;
    w2[1] = uint_to_hex_lower8 ((e0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((e0 >>  0) & 255) << 16;

    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_update_64 (&ctx, w0, w1, w2, w3, 40);

    w0[0] = uint_to_hex_lower8 ((a1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((a1 >> 16) & 255) << 16;
    w0[1] = uint_to_hex_lower8 ((a1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((a1 >>  0) & 255) << 16;
    w0[2] = uint_to_hex_lower8 ((b1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((b1 >> 16) & 255) << 16;
    w0[3] = uint_to_hex_lower8 ((b1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((b1 >>  0) & 255) << 16;
    w1[0] = uint_to_hex_lower8 ((c1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((c1 >> 16) & 255) << 16;
    w1[1] = uint_to_hex_lower8 ((c1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((c1 >>  0) & 255) << 16;
    w1[2] = uint_to_hex_lower8 ((d1 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((d1 >> 16) & 255) << 16;
    w1[3] = uint_to_hex_lower8 ((d1 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((d1 >>  0) & 255) << 16;

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_update_64 (&ctx, w0, w1, w2, w3, 32);

    w0[0] = uint_to_hex_lower8 ((a0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((a0 >> 16) & 255) << 16;
    w0[1] = uint_to_hex_lower8 ((a0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((a0 >>  0) & 255) << 16;
    w0[2] = uint_to_hex_lower8 ((b0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((b0 >> 16) & 255) << 16;
    w0[3] = uint_to_hex_lower8 ((b0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((b0 >>  0) & 255) << 16;
    w1[0] = uint_to_hex_lower8 ((c0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((c0 >> 16) & 255) << 16;
    w1[1] = uint_to_hex_lower8 ((c0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((c0 >>  0) & 255) << 16;
    w1[2] = uint_to_hex_lower8 ((d0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((d0 >> 16) & 255) << 16;
    w1[3] = uint_to_hex_lower8 ((d0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((d0 >>  0) & 255) << 16;
    w2[0] = uint_to_hex_lower8 ((e0 >> 24) & 255) <<  0
          | uint_to_hex_lower8 ((e0 >> 16) & 255) << 16;
    w2[1] = uint_to_hex_lower8 ((e0 >>  8) & 255) <<  0
          | uint_to_hex_lower8 ((e0 >>  0) & 255) << 16;

    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_update_64 (&ctx, w0, w1, w2, w3, 40);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
