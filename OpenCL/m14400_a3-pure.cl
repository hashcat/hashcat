/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
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

KERNEL_FQ void m14400_mxx (KERN_ATTR_VECTOR ())
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

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

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

  sha1_update_global_swap (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

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

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0lr = w0l | w0r;

    w[0] = w0lr;

    sha1_ctx_vector_t ctx1;

    sha1_init_vector_from_scalar (&ctx1, &ctx0);

    u32x dx20[4];
    u32x dx21[4];
    u32x dx22[4];
    u32x dx23[4];

    dx20[0] = 0x2d2d0000;
    dx20[1] = 0;
    dx20[2] = 0;
    dx20[3] = 0;
    dx21[0] = 0;
    dx21[1] = 0;
    dx21[2] = 0;
    dx21[3] = 0;
    dx22[0] = 0;
    dx22[1] = 0;
    dx22[2] = 0;
    dx22[3] = 0;
    dx23[0] = 0;
    dx23[1] = 0;
    dx23[2] = 0;
    dx23[3] = 0;

    sha1_update_vector_64 (&ctx1, dx20, dx21, dx22, dx23, 2);

    sha1_update_vector_swap (&ctx1, w, pw_len);

    u32x dx40[4];
    u32x dx41[4];
    u32x dx42[4];
    u32x dx43[4];

    dx40[0] = 0x2d2d2d2d;
    dx40[1] = 0;
    dx40[2] = 0;
    dx40[3] = 0;
    dx41[0] = 0;
    dx41[1] = 0;
    dx41[2] = 0;
    dx41[3] = 0;
    dx42[0] = 0;
    dx42[1] = 0;
    dx42[2] = 0;
    dx42[3] = 0;
    dx43[0] = 0;
    dx43[1] = 0;
    dx43[2] = 0;
    dx43[3] = 0;

    sha1_update_vector_64 (&ctx1, dx40, dx41, dx42, dx43, 4);

    sha1_final_vector (&ctx1);

    u32x a = ctx1.h[0];
    u32x b = ctx1.h[1];
    u32x c = ctx1.h[2];
    u32x d = ctx1.h[3];
    u32x e = ctx1.h[4];

    sha1_ctx_vector_t ctx;

    for (int i = 1; i < 10; i++)
    {
      sha1_init_vector_from_scalar (&ctx, &ctx0);

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

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

      sha1_update_vector_64 (&ctx, w0, w1, w2, w3, 40);

      dx20[0] = 0x2d2d0000;
      dx20[1] = 0;
      dx20[2] = 0;
      dx20[3] = 0;
      dx21[0] = 0;
      dx21[1] = 0;
      dx21[2] = 0;
      dx21[3] = 0;
      dx22[0] = 0;
      dx22[1] = 0;
      dx22[2] = 0;
      dx22[3] = 0;
      dx23[0] = 0;
      dx23[1] = 0;
      dx23[2] = 0;
      dx23[3] = 0;

      sha1_update_vector_64 (&ctx, dx20, dx21, dx22, dx23, 2);

      sha1_update_vector_swap (&ctx, w, pw_len);

      dx40[0] = 0x2d2d2d2d;
      dx40[1] = 0;
      dx40[2] = 0;
      dx40[3] = 0;
      dx41[0] = 0;
      dx41[1] = 0;
      dx41[2] = 0;
      dx41[3] = 0;
      dx42[0] = 0;
      dx42[1] = 0;
      dx42[2] = 0;
      dx42[3] = 0;
      dx43[0] = 0;
      dx43[1] = 0;
      dx43[2] = 0;
      dx43[3] = 0;

      sha1_update_vector_64 (&ctx, dx40, dx41, dx42, dx43, 4);

      sha1_final_vector (&ctx);

      a = ctx.h[0];
      b = ctx.h[1];
      c = ctx.h[2];
      d = ctx.h[3];
      e = ctx.h[4];
    }

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m14400_sxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

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

  sha1_update_global_swap (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

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

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0lr = w0l | w0r;

    w[0] = w0lr;

    sha1_ctx_vector_t ctx1;

    sha1_init_vector_from_scalar (&ctx1, &ctx0);

    u32x dx20[4];
    u32x dx21[4];
    u32x dx22[4];
    u32x dx23[4];

    dx20[0] = 0x2d2d0000;
    dx20[1] = 0;
    dx20[2] = 0;
    dx20[3] = 0;
    dx21[0] = 0;
    dx21[1] = 0;
    dx21[2] = 0;
    dx21[3] = 0;
    dx22[0] = 0;
    dx22[1] = 0;
    dx22[2] = 0;
    dx22[3] = 0;
    dx23[0] = 0;
    dx23[1] = 0;
    dx23[2] = 0;
    dx23[3] = 0;

    sha1_update_vector_64 (&ctx1, dx20, dx21, dx22, dx23, 2);

    sha1_update_vector_swap (&ctx1, w, pw_len);

    u32x dx40[4];
    u32x dx41[4];
    u32x dx42[4];
    u32x dx43[4];

    dx40[0] = 0x2d2d2d2d;
    dx40[1] = 0;
    dx40[2] = 0;
    dx40[3] = 0;
    dx41[0] = 0;
    dx41[1] = 0;
    dx41[2] = 0;
    dx41[3] = 0;
    dx42[0] = 0;
    dx42[1] = 0;
    dx42[2] = 0;
    dx42[3] = 0;
    dx43[0] = 0;
    dx43[1] = 0;
    dx43[2] = 0;
    dx43[3] = 0;

    sha1_update_vector_64 (&ctx1, dx40, dx41, dx42, dx43, 4);

    sha1_final_vector (&ctx1);

    u32x a = ctx1.h[0];
    u32x b = ctx1.h[1];
    u32x c = ctx1.h[2];
    u32x d = ctx1.h[3];
    u32x e = ctx1.h[4];

    sha1_ctx_vector_t ctx;

    for (int i = 1; i < 10; i++)
    {
      sha1_init_vector_from_scalar (&ctx, &ctx0);

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

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

      sha1_update_vector_64 (&ctx, w0, w1, w2, w3, 40);

      dx20[0] = 0x2d2d0000;
      dx20[1] = 0;
      dx20[2] = 0;
      dx20[3] = 0;
      dx21[0] = 0;
      dx21[1] = 0;
      dx21[2] = 0;
      dx21[3] = 0;
      dx22[0] = 0;
      dx22[1] = 0;
      dx22[2] = 0;
      dx22[3] = 0;
      dx23[0] = 0;
      dx23[1] = 0;
      dx23[2] = 0;
      dx23[3] = 0;

      sha1_update_vector_64 (&ctx, dx20, dx21, dx22, dx23, 2);

      sha1_update_vector_swap (&ctx, w, pw_len);

      dx40[0] = 0x2d2d2d2d;
      dx40[1] = 0;
      dx40[2] = 0;
      dx40[3] = 0;
      dx41[0] = 0;
      dx41[1] = 0;
      dx41[2] = 0;
      dx41[3] = 0;
      dx42[0] = 0;
      dx42[1] = 0;
      dx42[2] = 0;
      dx42[3] = 0;
      dx43[0] = 0;
      dx43[1] = 0;
      dx43[2] = 0;
      dx43[3] = 0;

      sha1_update_vector_64 (&ctx, dx40, dx41, dx42, dx43, 4);

      sha1_final_vector (&ctx);

      a = ctx.h[0];
      b = ctx.h[1];
      c = ctx.h[2];
      d = ctx.h[3];
      e = ctx.h[4];
    }

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
