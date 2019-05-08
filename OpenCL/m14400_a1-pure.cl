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
#include "inc_hash_sha1.cl"
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

KERNEL_FQ void m14400_mxx (KERN_ATTR_BASIC ())
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

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  u32 d20[4];
  u32 d21[4];
  u32 d22[4];
  u32 d23[4];

  d20[0] = 0x2d2d0000;
  d20[1] = 0;
  d20[2] = 0;
  d20[3] = 0;
  d21[0] = 0;
  d21[1] = 0;
  d21[2] = 0;
  d21[3] = 0;
  d22[0] = 0;
  d22[1] = 0;
  d22[2] = 0;
  d22[3] = 0;
  d23[0] = 0;
  d23[1] = 0;
  d23[2] = 0;
  d23[3] = 0;

  sha1_update_64 (&ctx0, d20, d21, d22, d23, 2);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  u32 d40[4];
  u32 d41[4];
  u32 d42[4];
  u32 d43[4];

  d40[0] = 0x2d2d2d2d;
  d40[1] = 0;
  d40[2] = 0;
  d40[3] = 0;
  d41[0] = 0;
  d41[1] = 0;
  d41[2] = 0;
  d41[3] = 0;
  d42[0] = 0;
  d42[1] = 0;
  d42[2] = 0;
  d42[3] = 0;
  d43[0] = 0;
  d43[1] = 0;
  d43[2] = 0;
  d43[3] = 0;

  sha1_update_64 (&ctx0, d20, d21, d22, d23, 2);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx1 = ctx0;

    d20[0] = 0x2d2d0000;
    d20[1] = 0;
    d20[2] = 0;
    d20[3] = 0;
    d21[0] = 0;
    d21[1] = 0;
    d21[2] = 0;
    d21[3] = 0;
    d22[0] = 0;
    d22[1] = 0;
    d22[2] = 0;
    d22[3] = 0;
    d23[0] = 0;
    d23[1] = 0;
    d23[2] = 0;
    d23[3] = 0;

    sha1_update_64 (&ctx1, d20, d21, d22, d23, 2);

    sha1_update_global_swap (&ctx1, pws[gid].i, pws[gid].pw_len);

    sha1_update_global_swap (&ctx1, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    d40[0] = 0x2d2d2d2d;
    d40[1] = 0;
    d40[2] = 0;
    d40[3] = 0;
    d41[0] = 0;
    d41[1] = 0;
    d41[2] = 0;
    d41[3] = 0;
    d42[0] = 0;
    d42[1] = 0;
    d42[2] = 0;
    d42[3] = 0;
    d43[0] = 0;
    d43[1] = 0;
    d43[2] = 0;
    d43[3] = 0;

    sha1_update_64 (&ctx1, d40, d41, d42, d43, 4);

    sha1_final (&ctx1);

    u32 a = ctx1.h[0];
    u32 b = ctx1.h[1];
    u32 c = ctx1.h[2];
    u32 d = ctx1.h[3];
    u32 e = ctx1.h[4];

    sha1_ctx_t ctx;

    for (int i = 1; i < 10; i++)
    {
      ctx = ctx0;

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
      w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
      w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
      w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
      w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
      w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
      w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
      w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
      w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
      w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      sha1_update_64 (&ctx, w0, w1, w2, w3, 40);

      d20[0] = 0x2d2d0000;
      d20[1] = 0;
      d20[2] = 0;
      d20[3] = 0;
      d21[0] = 0;
      d21[1] = 0;
      d21[2] = 0;
      d21[3] = 0;
      d22[0] = 0;
      d22[1] = 0;
      d22[2] = 0;
      d22[3] = 0;
      d23[0] = 0;
      d23[1] = 0;
      d23[2] = 0;
      d23[3] = 0;

      sha1_update_64 (&ctx, d20, d21, d22, d23, 2);

      sha1_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

      sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

      d40[0] = 0x2d2d2d2d;
      d40[1] = 0;
      d40[2] = 0;
      d40[3] = 0;
      d41[0] = 0;
      d41[1] = 0;
      d41[2] = 0;
      d41[3] = 0;
      d42[0] = 0;
      d42[1] = 0;
      d42[2] = 0;
      d42[3] = 0;
      d43[0] = 0;
      d43[1] = 0;
      d43[2] = 0;
      d43[3] = 0;

      sha1_update_64 (&ctx, d40, d41, d42, d43, 4);

      sha1_final (&ctx);

      a = ctx.h[0];
      b = ctx.h[1];
      c = ctx.h[2];
      d = ctx.h[3];
      e = ctx.h[4];
    }

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m14400_sxx (KERN_ATTR_BASIC ())
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

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
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

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  u32 d20[4];
  u32 d21[4];
  u32 d22[4];
  u32 d23[4];

  d20[0] = 0x2d2d0000;
  d20[1] = 0;
  d20[2] = 0;
  d20[3] = 0;
  d21[0] = 0;
  d21[1] = 0;
  d21[2] = 0;
  d21[3] = 0;
  d22[0] = 0;
  d22[1] = 0;
  d22[2] = 0;
  d22[3] = 0;
  d23[0] = 0;
  d23[1] = 0;
  d23[2] = 0;
  d23[3] = 0;

  sha1_update_64 (&ctx0, d20, d21, d22, d23, 2);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  u32 d40[4];
  u32 d41[4];
  u32 d42[4];
  u32 d43[4];

  d40[0] = 0x2d2d2d2d;
  d40[1] = 0;
  d40[2] = 0;
  d40[3] = 0;
  d41[0] = 0;
  d41[1] = 0;
  d41[2] = 0;
  d41[3] = 0;
  d42[0] = 0;
  d42[1] = 0;
  d42[2] = 0;
  d42[3] = 0;
  d43[0] = 0;
  d43[1] = 0;
  d43[2] = 0;
  d43[3] = 0;

  sha1_update_64 (&ctx0, d20, d21, d22, d23, 2);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx1 = ctx0;

    d20[0] = 0x2d2d0000;
    d20[1] = 0;
    d20[2] = 0;
    d20[3] = 0;
    d21[0] = 0;
    d21[1] = 0;
    d21[2] = 0;
    d21[3] = 0;
    d22[0] = 0;
    d22[1] = 0;
    d22[2] = 0;
    d22[3] = 0;
    d23[0] = 0;
    d23[1] = 0;
    d23[2] = 0;
    d23[3] = 0;

    sha1_update_64 (&ctx1, d20, d21, d22, d23, 2);

    sha1_update_global_swap (&ctx1, pws[gid].i, pws[gid].pw_len);

    sha1_update_global_swap (&ctx1, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    d40[0] = 0x2d2d2d2d;
    d40[1] = 0;
    d40[2] = 0;
    d40[3] = 0;
    d41[0] = 0;
    d41[1] = 0;
    d41[2] = 0;
    d41[3] = 0;
    d42[0] = 0;
    d42[1] = 0;
    d42[2] = 0;
    d42[3] = 0;
    d43[0] = 0;
    d43[1] = 0;
    d43[2] = 0;
    d43[3] = 0;

    sha1_update_64 (&ctx1, d40, d41, d42, d43, 4);

    sha1_final (&ctx1);

    u32 a = ctx1.h[0];
    u32 b = ctx1.h[1];
    u32 c = ctx1.h[2];
    u32 d = ctx1.h[3];
    u32 e = ctx1.h[4];

    sha1_ctx_t ctx;

    for (int i = 1; i < 10; i++)
    {
      ctx = ctx0;

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
      w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
      w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
      w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
      w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
      w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
      w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
      w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
      w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
            | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
      w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
            | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      sha1_update_64 (&ctx, w0, w1, w2, w3, 40);

      d20[0] = 0x2d2d0000;
      d20[1] = 0;
      d20[2] = 0;
      d20[3] = 0;
      d21[0] = 0;
      d21[1] = 0;
      d21[2] = 0;
      d21[3] = 0;
      d22[0] = 0;
      d22[1] = 0;
      d22[2] = 0;
      d22[3] = 0;
      d23[0] = 0;
      d23[1] = 0;
      d23[2] = 0;
      d23[3] = 0;

      sha1_update_64 (&ctx, d20, d21, d22, d23, 2);

      sha1_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

      sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

      d40[0] = 0x2d2d2d2d;
      d40[1] = 0;
      d40[2] = 0;
      d40[3] = 0;
      d41[0] = 0;
      d41[1] = 0;
      d41[2] = 0;
      d41[3] = 0;
      d42[0] = 0;
      d42[1] = 0;
      d42[2] = 0;
      d42[3] = 0;
      d43[0] = 0;
      d43[1] = 0;
      d43[2] = 0;
      d43[3] = 0;

      sha1_update_64 (&ctx, d40, d41, d42, d43, 4);

      sha1_final (&ctx);

      a = ctx.h[0];
      b = ctx.h[1];
      c = ctx.h[2];
      d = ctx.h[3];
      e = ctx.h[4];
    }

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
