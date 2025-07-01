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
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
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

KERNEL_FQ KERNEL_FA void m04400_mxx (KERN_ATTR_RULES ())
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

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_ctx_t ctx0;

    sha1_init (&ctx0);

    sha1_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha1_final (&ctx0);

    const u32 a = ctx0.h[0];
    const u32 b = ctx0.h[1];
    const u32 c = ctx0.h[2];
    const u32 d = ctx0.h[3];
    const u32 e = ctx0.h[4];

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

KERNEL_FQ KERNEL_FA void m04400_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha1_ctx_t ctx0;

    sha1_init (&ctx0);

    sha1_update_swap (&ctx0, tmp.i, tmp.pw_len);

    sha1_final (&ctx0);

    const u32 a = ctx0.h[0];
    const u32 b = ctx0.h[1];
    const u32 c = ctx0.h[2];
    const u32 d = ctx0.h[3];
    const u32 e = ctx0.h[4];

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
