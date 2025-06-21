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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) make_u32x (b_bin2asc[(i)])
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) make_u32x (b_bin2asc[(i).s0], b_bin2asc[(i).s1])
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) make_u32x (b_bin2asc[(i).s0], b_bin2asc[(i).s1], b_bin2asc[(i).s2], b_bin2asc[(i).s3])
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) make_u32x (b_bin2asc[(i).s0], b_bin2asc[(i).s1], b_bin2asc[(i).s2], b_bin2asc[(i).s3], b_bin2asc[(i).s4], b_bin2asc[(i).s5], b_bin2asc[(i).s6], b_bin2asc[(i).s7])
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) make_u32x (b_bin2asc[(i).s0], b_bin2asc[(i).s1], b_bin2asc[(i).s2], b_bin2asc[(i).s3], b_bin2asc[(i).s4], b_bin2asc[(i).s5], b_bin2asc[(i).s6], b_bin2asc[(i).s7], b_bin2asc[(i).s8], b_bin2asc[(i).s9], b_bin2asc[(i).sa], b_bin2asc[(i).sb], b_bin2asc[(i).sc], b_bin2asc[(i).sd], b_bin2asc[(i).se], b_bin2asc[(i).sf])
#define uint_to_hex_lower8_le(i) make_u32x (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

KERNEL_FQ void m32800_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc tables
   */

  LOCAL_VK u32 l_bin2asc[256];
  LOCAL_VK u32 b_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
    b_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
md5_ctx_t ctx0 = ctx;

    md5_update_global (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx0);

    u32 a = ctx0.h[0];
    u32 b = ctx0.h[1];
    u32 c = ctx0.h[2];
    u32 d = ctx0.h[3];

    sha1_ctx_t ctx1;

    sha1_init (&ctx1);

    ctx1.w0[0] = uint_to_hex_lower8_le ((a >>  8) & 255) <<  0
              | uint_to_hex_lower8_le ((a >>  0) & 255) << 16;
    ctx1.w0[1] = uint_to_hex_lower8_le ((a >> 24) & 255) <<  0
              | uint_to_hex_lower8_le ((a >> 16) & 255) << 16;
    ctx1.w0[2] = uint_to_hex_lower8_le ((b >>  8) & 255) <<  0
              | uint_to_hex_lower8_le ((b >>  0) & 255) << 16;
    ctx1.w0[3] = uint_to_hex_lower8_le ((b >> 24) & 255) <<  0
              | uint_to_hex_lower8_le ((b >> 16) & 255) << 16;
    ctx1.w1[0] = uint_to_hex_lower8_le ((c >>  8) & 255) <<  0
              | uint_to_hex_lower8_le ((c >>  0) & 255) << 16;
    ctx1.w1[1] = uint_to_hex_lower8_le ((c >> 24) & 255) <<  0
              | uint_to_hex_lower8_le ((c >> 16) & 255) << 16;
    ctx1.w1[2] = uint_to_hex_lower8_le ((d >>  8) & 255) <<  0
              | uint_to_hex_lower8_le ((d >>  0) & 255) << 16;
    ctx1.w1[3] = uint_to_hex_lower8_le ((d >> 24) & 255) <<  0
              | uint_to_hex_lower8_le ((d >> 16) & 255) << 16;

    ctx1.len = 32;

    sha1_final (&ctx1);

    a = ctx1.h[0];
    b = ctx1.h[1];
    c = ctx1.h[2];
    d = ctx1.h[3];
    const u32 e = ctx1.h[4];

    md5_ctx_t ctx2;

    md5_init (&ctx2);

    ctx2.w0[0] = uint_to_hex_lower8 ((a >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((a >> 16) & 255) << 16;
    ctx2.w0[1] = uint_to_hex_lower8 ((a >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((a >>  0) & 255) << 16;
    ctx2.w0[2] = uint_to_hex_lower8 ((b >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((b >> 16) & 255) << 16;
    ctx2.w0[3] = uint_to_hex_lower8 ((b >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((b >>  0) & 255) << 16;
    ctx2.w1[0] = uint_to_hex_lower8 ((c >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((c >> 16) & 255) << 16;
    ctx2.w1[1] = uint_to_hex_lower8 ((c >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((c >>  0) & 255) << 16;
    ctx2.w1[2] = uint_to_hex_lower8 ((d >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((d >> 16) & 255) << 16;
    ctx2.w1[3] = uint_to_hex_lower8 ((d >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((d >>  0) & 255) << 16;
    ctx2.w2[0] = uint_to_hex_lower8 ((e >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((e >> 16) & 255) << 16;
    ctx2.w2[1] = uint_to_hex_lower8 ((e >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((e >>  0) & 255) << 16;

    ctx2.len = 40;

    md5_final (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m32800_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc tables
   */

  LOCAL_VK u32 l_bin2asc[256];
  LOCAL_VK u32 b_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 0
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 8;
    b_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

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

  md5_ctx_t ctx;

  md5_init (&ctx);

  md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md5_ctx_t ctx0 = ctx;

    md5_update_global (&ctx0, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx0);

    u32 a = ctx0.h[0];
    u32 b = ctx0.h[1];
    u32 c = ctx0.h[2];
    u32 d = ctx0.h[3];

    sha1_ctx_t ctx1;

    sha1_init (&ctx1);

    ctx1.w0[0] = uint_to_hex_lower8_le ((a >>  8) & 255) <<  0
              | uint_to_hex_lower8_le ((a >>  0) & 255) << 16;
    ctx1.w0[1] = uint_to_hex_lower8_le ((a >> 24) & 255) <<  0
              | uint_to_hex_lower8_le ((a >> 16) & 255) << 16;
    ctx1.w0[2] = uint_to_hex_lower8_le ((b >>  8) & 255) <<  0
              | uint_to_hex_lower8_le ((b >>  0) & 255) << 16;
    ctx1.w0[3] = uint_to_hex_lower8_le ((b >> 24) & 255) <<  0
              | uint_to_hex_lower8_le ((b >> 16) & 255) << 16;
    ctx1.w1[0] = uint_to_hex_lower8_le ((c >>  8) & 255) <<  0
              | uint_to_hex_lower8_le ((c >>  0) & 255) << 16;
    ctx1.w1[1] = uint_to_hex_lower8_le ((c >> 24) & 255) <<  0
              | uint_to_hex_lower8_le ((c >> 16) & 255) << 16;
    ctx1.w1[2] = uint_to_hex_lower8_le ((d >>  8) & 255) <<  0
              | uint_to_hex_lower8_le ((d >>  0) & 255) << 16;
    ctx1.w1[3] = uint_to_hex_lower8_le ((d >> 24) & 255) <<  0
              | uint_to_hex_lower8_le ((d >> 16) & 255) << 16;

    ctx1.len = 32;

    sha1_final (&ctx1);

    a = ctx1.h[0];
    b = ctx1.h[1];
    c = ctx1.h[2];
    d = ctx1.h[3];
    const u32 e = ctx1.h[4];

    md5_ctx_t ctx2;

    md5_init (&ctx2);

    ctx2.w0[0] = uint_to_hex_lower8 ((a >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((a >> 16) & 255) << 16;
    ctx2.w0[1] = uint_to_hex_lower8 ((a >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((a >>  0) & 255) << 16;
    ctx2.w0[2] = uint_to_hex_lower8 ((b >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((b >> 16) & 255) << 16;
    ctx2.w0[3] = uint_to_hex_lower8 ((b >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((b >>  0) & 255) << 16;
    ctx2.w1[0] = uint_to_hex_lower8 ((c >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((c >> 16) & 255) << 16;
    ctx2.w1[1] = uint_to_hex_lower8 ((c >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((c >>  0) & 255) << 16;
    ctx2.w1[2] = uint_to_hex_lower8 ((d >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((d >> 16) & 255) << 16;
    ctx2.w1[3] = uint_to_hex_lower8 ((d >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((d >>  0) & 255) << 16;
    ctx2.w2[0] = uint_to_hex_lower8 ((e >> 24) & 255) <<  0
              | uint_to_hex_lower8 ((e >> 16) & 255) << 16;
    ctx2.w2[1] = uint_to_hex_lower8 ((e >>  8) & 255) <<  0
              | uint_to_hex_lower8 ((e >>  0) & 255) << 16;

    ctx2.len = 40;

    md5_final (&ctx2);

    const u32 r0 = ctx2.h[DGST_R0];
    const u32 r1 = ctx2.h[DGST_R1];
    const u32 r2 = ctx2.h[DGST_R2];
    const u32 r3 = ctx2.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
