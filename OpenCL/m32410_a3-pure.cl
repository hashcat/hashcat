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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
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

KERNEL_FQ void m32410_mxx (KERN_ATTR_VECTOR ())
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

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0_final = w0l | w0r;

    w[0] = w0_final;

    sha512_ctx_vector_t ctx0;

    sha512_init_vector (&ctx0);

    sha512_update_vector (&ctx0, w, pw_len);

    sha512_final_vector (&ctx0);

    const u64x a = ctx0.h[0];
    const u64x b = ctx0.h[1];
    const u64x c = ctx0.h[2];
    const u64x d = ctx0.h[3];
    const u64x e = ctx0.h[4];
    const u64x f = ctx0.h[5];
    const u64x g = ctx0.h[6];
    const u64x h = ctx0.h[7];

    sha512_ctx_vector_t ctx;

    sha512_init_vector (&ctx);

    w0[0] = uint_to_hex_lower8 ((a >> 56) & 255) << 16
          | uint_to_hex_lower8 ((a >> 48) & 255) <<  0;
    w0[1] = uint_to_hex_lower8 ((a >> 40) & 255) << 16
          | uint_to_hex_lower8 ((a >> 32) & 255) <<  0;
    w0[2] = uint_to_hex_lower8 ((a >> 24) & 255) << 16
          | uint_to_hex_lower8 ((a >> 16) & 255) <<  0;
    w0[3] = uint_to_hex_lower8 ((a >>  8) & 255) << 16
          | uint_to_hex_lower8 ((a >>  0) & 255) <<  0;
    w1[0] = uint_to_hex_lower8 ((b >> 56) & 255) << 16
          | uint_to_hex_lower8 ((b >> 48) & 255) <<  0;
    w1[1] = uint_to_hex_lower8 ((b >> 40) & 255) << 16
          | uint_to_hex_lower8 ((b >> 32) & 255) <<  0;
    w1[2] = uint_to_hex_lower8 ((b >> 24) & 255) << 16
          | uint_to_hex_lower8 ((b >> 16) & 255) <<  0;
    w1[3] = uint_to_hex_lower8 ((b >>  8) & 255) << 16
          | uint_to_hex_lower8 ((b >>  0) & 255) <<  0;
    w2[0] = uint_to_hex_lower8 ((c >> 56) & 255) << 16
          | uint_to_hex_lower8 ((c >> 48) & 255) <<  0;
    w2[1] = uint_to_hex_lower8 ((c >> 40) & 255) << 16
          | uint_to_hex_lower8 ((c >> 32) & 255) <<  0;
    w2[2] = uint_to_hex_lower8 ((c >> 24) & 255) << 16
          | uint_to_hex_lower8 ((c >> 16) & 255) <<  0;
    w2[3] = uint_to_hex_lower8 ((c >>  8) & 255) << 16
          | uint_to_hex_lower8 ((c >>  0) & 255) <<  0;
    w3[0] = uint_to_hex_lower8 ((d >> 56) & 255) << 16
          | uint_to_hex_lower8 ((d >> 48) & 255) <<  0;
    w3[1] = uint_to_hex_lower8 ((d >> 40) & 255) << 16
          | uint_to_hex_lower8 ((d >> 32) & 255) <<  0;
    w3[2] = uint_to_hex_lower8 ((d >> 24) & 255) << 16
          | uint_to_hex_lower8 ((d >> 16) & 255) <<  0;
    w3[3] = uint_to_hex_lower8 ((d >>  8) & 255) << 16
          | uint_to_hex_lower8 ((d >>  0) & 255) <<  0;
    w4[0] = uint_to_hex_lower8 ((e >> 56) & 255) << 16
          | uint_to_hex_lower8 ((e >> 48) & 255) <<  0;
    w4[1] = uint_to_hex_lower8 ((e >> 40) & 255) << 16
          | uint_to_hex_lower8 ((e >> 32) & 255) <<  0;
    w4[2] = uint_to_hex_lower8 ((e >> 24) & 255) << 16
          | uint_to_hex_lower8 ((e >> 16) & 255) <<  0;
    w4[3] = uint_to_hex_lower8 ((e >>  8) & 255) << 16
          | uint_to_hex_lower8 ((e >>  0) & 255) <<  0;
    w5[0] = uint_to_hex_lower8 ((f >> 56) & 255) << 16
          | uint_to_hex_lower8 ((f >> 48) & 255) <<  0;
    w5[1] = uint_to_hex_lower8 ((f >> 40) & 255) << 16
          | uint_to_hex_lower8 ((f >> 32) & 255) <<  0;
    w5[2] = uint_to_hex_lower8 ((f >> 24) & 255) << 16
          | uint_to_hex_lower8 ((f >> 16) & 255) <<  0;
    w5[3] = uint_to_hex_lower8 ((f >>  8) & 255) << 16
          | uint_to_hex_lower8 ((f >>  0) & 255) <<  0;
    w6[0] = uint_to_hex_lower8 ((g >> 56) & 255) << 16
          | uint_to_hex_lower8 ((g >> 48) & 255) <<  0;
    w6[1] = uint_to_hex_lower8 ((g >> 40) & 255) << 16
          | uint_to_hex_lower8 ((g >> 32) & 255) <<  0;
    w6[2] = uint_to_hex_lower8 ((g >> 24) & 255) << 16
          | uint_to_hex_lower8 ((g >> 16) & 255) <<  0;
    w6[3] = uint_to_hex_lower8 ((g >>  8) & 255) << 16
          | uint_to_hex_lower8 ((g >>  0) & 255) <<  0;
    w7[0] = uint_to_hex_lower8 ((h >> 56) & 255) << 16
          | uint_to_hex_lower8 ((h >> 48) & 255) <<  0;
    w7[1] = uint_to_hex_lower8 ((h >> 40) & 255) << 16
          | uint_to_hex_lower8 ((h >> 32) & 255) <<  0;
    w7[2] = uint_to_hex_lower8 ((h >> 24) & 255) << 16
          | uint_to_hex_lower8 ((h >> 16) & 255) <<  0;
    w7[3] = uint_to_hex_lower8 ((h >>  8) & 255) << 16
          | uint_to_hex_lower8 ((h >>  0) & 255) <<  0;

    sha512_update_vector_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);

    sha512_update_vector (&ctx, s, salt_len);

    sha512_final_vector (&ctx);

    const u32x r0 = l32_from_64 (ctx.h[7]);
    const u32x r1 = h32_from_64 (ctx.h[7]);
    const u32x r2 = l32_from_64 (ctx.h[3]);
    const u32x r3 = h32_from_64 (ctx.h[3]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m32410_sxx (KERN_ATTR_VECTOR ())
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

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0_final = w0l | w0r;

    w[0] = w0_final;

    sha512_ctx_vector_t ctx0;

    sha512_init_vector (&ctx0);

    sha512_update_vector (&ctx0, w, pw_len);

    sha512_final_vector (&ctx0);

    const u64x a = ctx0.h[0];
    const u64x b = ctx0.h[1];
    const u64x c = ctx0.h[2];
    const u64x d = ctx0.h[3];
    const u64x e = ctx0.h[4];
    const u64x f = ctx0.h[5];
    const u64x g = ctx0.h[6];
    const u64x h = ctx0.h[7];

    sha512_ctx_vector_t ctx;

    sha512_init_vector (&ctx);

    w0[0] = uint_to_hex_lower8 ((a >> 56) & 255) << 16
          | uint_to_hex_lower8 ((a >> 48) & 255) <<  0;
    w0[1] = uint_to_hex_lower8 ((a >> 40) & 255) << 16
          | uint_to_hex_lower8 ((a >> 32) & 255) <<  0;
    w0[2] = uint_to_hex_lower8 ((a >> 24) & 255) << 16
          | uint_to_hex_lower8 ((a >> 16) & 255) <<  0;
    w0[3] = uint_to_hex_lower8 ((a >>  8) & 255) << 16
          | uint_to_hex_lower8 ((a >>  0) & 255) <<  0;
    w1[0] = uint_to_hex_lower8 ((b >> 56) & 255) << 16
          | uint_to_hex_lower8 ((b >> 48) & 255) <<  0;
    w1[1] = uint_to_hex_lower8 ((b >> 40) & 255) << 16
          | uint_to_hex_lower8 ((b >> 32) & 255) <<  0;
    w1[2] = uint_to_hex_lower8 ((b >> 24) & 255) << 16
          | uint_to_hex_lower8 ((b >> 16) & 255) <<  0;
    w1[3] = uint_to_hex_lower8 ((b >>  8) & 255) << 16
          | uint_to_hex_lower8 ((b >>  0) & 255) <<  0;
    w2[0] = uint_to_hex_lower8 ((c >> 56) & 255) << 16
          | uint_to_hex_lower8 ((c >> 48) & 255) <<  0;
    w2[1] = uint_to_hex_lower8 ((c >> 40) & 255) << 16
          | uint_to_hex_lower8 ((c >> 32) & 255) <<  0;
    w2[2] = uint_to_hex_lower8 ((c >> 24) & 255) << 16
          | uint_to_hex_lower8 ((c >> 16) & 255) <<  0;
    w2[3] = uint_to_hex_lower8 ((c >>  8) & 255) << 16
          | uint_to_hex_lower8 ((c >>  0) & 255) <<  0;
    w3[0] = uint_to_hex_lower8 ((d >> 56) & 255) << 16
          | uint_to_hex_lower8 ((d >> 48) & 255) <<  0;
    w3[1] = uint_to_hex_lower8 ((d >> 40) & 255) << 16
          | uint_to_hex_lower8 ((d >> 32) & 255) <<  0;
    w3[2] = uint_to_hex_lower8 ((d >> 24) & 255) << 16
          | uint_to_hex_lower8 ((d >> 16) & 255) <<  0;
    w3[3] = uint_to_hex_lower8 ((d >>  8) & 255) << 16
          | uint_to_hex_lower8 ((d >>  0) & 255) <<  0;
    w4[0] = uint_to_hex_lower8 ((e >> 56) & 255) << 16
          | uint_to_hex_lower8 ((e >> 48) & 255) <<  0;
    w4[1] = uint_to_hex_lower8 ((e >> 40) & 255) << 16
          | uint_to_hex_lower8 ((e >> 32) & 255) <<  0;
    w4[2] = uint_to_hex_lower8 ((e >> 24) & 255) << 16
          | uint_to_hex_lower8 ((e >> 16) & 255) <<  0;
    w4[3] = uint_to_hex_lower8 ((e >>  8) & 255) << 16
          | uint_to_hex_lower8 ((e >>  0) & 255) <<  0;
    w5[0] = uint_to_hex_lower8 ((f >> 56) & 255) << 16
          | uint_to_hex_lower8 ((f >> 48) & 255) <<  0;
    w5[1] = uint_to_hex_lower8 ((f >> 40) & 255) << 16
          | uint_to_hex_lower8 ((f >> 32) & 255) <<  0;
    w5[2] = uint_to_hex_lower8 ((f >> 24) & 255) << 16
          | uint_to_hex_lower8 ((f >> 16) & 255) <<  0;
    w5[3] = uint_to_hex_lower8 ((f >>  8) & 255) << 16
          | uint_to_hex_lower8 ((f >>  0) & 255) <<  0;
    w6[0] = uint_to_hex_lower8 ((g >> 56) & 255) << 16
          | uint_to_hex_lower8 ((g >> 48) & 255) <<  0;
    w6[1] = uint_to_hex_lower8 ((g >> 40) & 255) << 16
          | uint_to_hex_lower8 ((g >> 32) & 255) <<  0;
    w6[2] = uint_to_hex_lower8 ((g >> 24) & 255) << 16
          | uint_to_hex_lower8 ((g >> 16) & 255) <<  0;
    w6[3] = uint_to_hex_lower8 ((g >>  8) & 255) << 16
          | uint_to_hex_lower8 ((g >>  0) & 255) <<  0;
    w7[0] = uint_to_hex_lower8 ((h >> 56) & 255) << 16
          | uint_to_hex_lower8 ((h >> 48) & 255) <<  0;
    w7[1] = uint_to_hex_lower8 ((h >> 40) & 255) << 16
          | uint_to_hex_lower8 ((h >> 32) & 255) <<  0;
    w7[2] = uint_to_hex_lower8 ((h >> 24) & 255) << 16
          | uint_to_hex_lower8 ((h >> 16) & 255) <<  0;
    w7[3] = uint_to_hex_lower8 ((h >>  8) & 255) << 16
          | uint_to_hex_lower8 ((h >>  0) & 255) <<  0;

    sha512_update_vector_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);

    sha512_update_vector (&ctx, s, salt_len);

    sha512_final_vector (&ctx);

    const u32x r0 = l32_from_64 (ctx.h[7]);
    const u32x r1 = h32_from_64 (ctx.h[7]);
    const u32x r2 = l32_from_64 (ctx.h[3]);
    const u32x r3 = h32_from_64 (ctx.h[3]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
