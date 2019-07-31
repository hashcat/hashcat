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
#include "inc_hash_sha256.cl"
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

KERNEL_FQ void m20710_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 s[64] = { 0 };

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }

  sha256_ctx_t ctx1;

  sha256_init (&ctx1);

  sha256_update_global_swap (&ctx1, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha256_ctx_t ctx0 = ctx1;

    sha256_update_global_swap (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha256_final (&ctx0);

    const u32 a = ctx0.h[0];
    const u32 b = ctx0.h[1];
    const u32 c = ctx0.h[2];
    const u32 d = ctx0.h[3];
    const u32 e = ctx0.h[4];
    const u32 f = ctx0.h[5];
    const u32 g = ctx0.h[6];
    const u32 h = ctx0.h[7];

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
    w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w2[2] = uint_to_hex_lower8_le ((f >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((f >> 24) & 255) << 16;
    w2[3] = uint_to_hex_lower8_le ((f >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((f >>  8) & 255) << 16;
    w3[0] = uint_to_hex_lower8_le ((g >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((g >> 24) & 255) << 16;
    w3[1] = uint_to_hex_lower8_le ((g >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((g >>  8) & 255) << 16;
    w3[2] = uint_to_hex_lower8_le ((h >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((h >> 24) & 255) << 16;
    w3[3] = uint_to_hex_lower8_le ((h >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((h >>  8) & 255) << 16;

    sha256_update_64 (&ctx, w0, w1, w2, w3, 64);

    sha256_update (&ctx, s, salt_len);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m20710_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
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

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }

  sha256_ctx_t ctx1;

  sha256_init (&ctx1);

  sha256_update_global_swap (&ctx1, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha256_ctx_t ctx0 = ctx1;

    sha256_update_global_swap (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha256_final (&ctx0);

    const u32 a = ctx0.h[0];
    const u32 b = ctx0.h[1];
    const u32 c = ctx0.h[2];
    const u32 d = ctx0.h[3];
    const u32 e = ctx0.h[4];
    const u32 f = ctx0.h[5];
    const u32 g = ctx0.h[6];
    const u32 h = ctx0.h[7];

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
    w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    w2[2] = uint_to_hex_lower8_le ((f >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((f >> 24) & 255) << 16;
    w2[3] = uint_to_hex_lower8_le ((f >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((f >>  8) & 255) << 16;
    w3[0] = uint_to_hex_lower8_le ((g >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((g >> 24) & 255) << 16;
    w3[1] = uint_to_hex_lower8_le ((g >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((g >>  8) & 255) << 16;
    w3[2] = uint_to_hex_lower8_le ((h >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((h >> 24) & 255) << 16;
    w3[3] = uint_to_hex_lower8_le ((h >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((h >>  8) & 255) << 16;

    sha256_update_64 (&ctx, w0, w1, w2, w3, 64);

    sha256_update (&ctx, s, salt_len);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
