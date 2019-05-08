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
#include "inc_rp.h"
#include "inc_rp.cl"
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

KERNEL_FQ void m18500_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md5_ctx_t ctx0;

    md5_init (&ctx0);

    md5_update (&ctx0, tmp.i, tmp.pw_len);

    md5_final (&ctx0);

    const u32 a = ctx0.h[0];
    const u32 b = ctx0.h[1];
    const u32 c = ctx0.h[2];
    const u32 d = ctx0.h[3];

    md5_ctx_t ctx1;

    md5_init (&ctx1);

    ctx1.w0[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
               | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
    ctx1.w0[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
               | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
    ctx1.w0[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
               | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
    ctx1.w0[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
               | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
    ctx1.w1[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
               | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
    ctx1.w1[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
               | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
    ctx1.w1[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
               | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
    ctx1.w1[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
               | uint_to_hex_lower8 ((d >> 24) & 255) << 16;
    ctx1.len = 32;

    md5_final (&ctx1);

    const u32 e = ctx1.h[0];
    const u32 f = ctx1.h[1];
    const u32 g = ctx1.h[2];
    const u32 h = ctx1.h[3];

    sha1_ctx_t ctx2;

    sha1_init (&ctx2);

    ctx2.w0[0] = hc_swap32(uint_to_hex_lower8 ((e >>  0) & 255) <<  0
                      | uint_to_hex_lower8 ((e >>  8) & 255) << 16);
    ctx2.w0[1] = hc_swap32(uint_to_hex_lower8 ((e >> 16) & 255) <<  0
                      | uint_to_hex_lower8 ((e >> 24) & 255) << 16);
    ctx2.w0[2] = hc_swap32(uint_to_hex_lower8 ((f >>  0) & 255) <<  0
                      | uint_to_hex_lower8 ((f >>  8) & 255) << 16);
    ctx2.w0[3] = hc_swap32(uint_to_hex_lower8 ((f >> 16) & 255) <<  0
                      | uint_to_hex_lower8 ((f >> 24) & 255) << 16);
    ctx2.w1[0] = hc_swap32(uint_to_hex_lower8 ((g >>  0) & 255) <<  0
                      | uint_to_hex_lower8 ((g >>  8) & 255) << 16);
    ctx2.w1[1] = hc_swap32(uint_to_hex_lower8 ((g >> 16) & 255) <<  0
                      | uint_to_hex_lower8 ((g >> 24) & 255) << 16);
    ctx2.w1[2] = hc_swap32(uint_to_hex_lower8 ((h >>  0) & 255) <<  0
                      | uint_to_hex_lower8 ((h >>  8) & 255) << 16);
    ctx2.w1[3] = hc_swap32(uint_to_hex_lower8 ((h >> 16) & 255) <<  0
                      | uint_to_hex_lower8 ((h >> 24) & 255) << 16);
    ctx2.len = 32;

    sha1_final (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m18500_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    md5_ctx_t ctx0;

    md5_init (&ctx0);

    md5_update (&ctx0, tmp.i, tmp.pw_len);

    md5_final (&ctx0);

    const u32 a = ctx0.h[0];
    const u32 b = ctx0.h[1];
    const u32 c = ctx0.h[2];
    const u32 d = ctx0.h[3];

    md5_ctx_t ctx1;

    md5_init (&ctx1);

    ctx1.w0[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
               | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
    ctx1.w0[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
               | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
    ctx1.w0[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
               | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
    ctx1.w0[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
               | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
    ctx1.w1[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
               | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
    ctx1.w1[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
               | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
    ctx1.w1[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
               | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
    ctx1.w1[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
               | uint_to_hex_lower8 ((d >> 24) & 255) << 16;
    ctx1.len = 32;

    md5_final (&ctx1);

    const u32 e = ctx1.h[0];
    const u32 f = ctx1.h[1];
    const u32 g = ctx1.h[2];
    const u32 h = ctx1.h[3];

    sha1_ctx_t ctx2;

    sha1_init (&ctx2);

    ctx2.w0[0] = hc_swap32(uint_to_hex_lower8 ((e >>  0) & 255) <<  0
                      | uint_to_hex_lower8 ((e >>  8) & 255) << 16);
    ctx2.w0[1] = hc_swap32(uint_to_hex_lower8 ((e >> 16) & 255) <<  0
                      | uint_to_hex_lower8 ((e >> 24) & 255) << 16);
    ctx2.w0[2] = hc_swap32(uint_to_hex_lower8 ((f >>  0) & 255) <<  0
                      | uint_to_hex_lower8 ((f >>  8) & 255) << 16);
    ctx2.w0[3] = hc_swap32(uint_to_hex_lower8 ((f >> 16) & 255) <<  0
                      | uint_to_hex_lower8 ((f >> 24) & 255) << 16);
    ctx2.w1[0] = hc_swap32(uint_to_hex_lower8 ((g >>  0) & 255) <<  0
                      | uint_to_hex_lower8 ((g >>  8) & 255) << 16);
    ctx2.w1[1] = hc_swap32(uint_to_hex_lower8 ((g >> 16) & 255) <<  0
                      | uint_to_hex_lower8 ((g >> 24) & 255) << 16);
    ctx2.w1[2] = hc_swap32(uint_to_hex_lower8 ((h >>  0) & 255) <<  0
                      | uint_to_hex_lower8 ((h >>  8) & 255) << 16);
    ctx2.w1[3] = hc_swap32(uint_to_hex_lower8 ((h >> 16) & 255) <<  0
                      | uint_to_hex_lower8 ((h >> 24) & 255) << 16);
    ctx2.len = 32;

    sha1_final (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
