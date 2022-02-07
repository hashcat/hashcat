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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
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

KERNEL_FQ void m20710_mxx (KERN_ATTR_VECTOR ())
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

  u32x _w0[4];
  u32x _w1[4];
  u32x _w2[4];
  u32x _w3[4];

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
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

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx0;

    sha256_init_vector (&ctx0);

    sha256_update_vector (&ctx0, w, pw_len);

    sha256_final_vector (&ctx0);

    const u32x a = ctx0.h[0];
    const u32x b = ctx0.h[1];
    const u32x c = ctx0.h[2];
    const u32x d = ctx0.h[3];
    const u32x e = ctx0.h[4];
    const u32x f = ctx0.h[5];
    const u32x g = ctx0.h[6];
    const u32x h = ctx0.h[7];

    sha256_ctx_vector_t ctx;

    sha256_init_vector (&ctx);

    _w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    _w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    _w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    _w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    _w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    _w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
    _w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    _w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    _w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    _w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    _w2[2] = uint_to_hex_lower8_le ((f >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((f >> 24) & 255) << 16;
    _w2[3] = uint_to_hex_lower8_le ((f >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((f >>  8) & 255) << 16;
    _w3[0] = uint_to_hex_lower8_le ((g >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((g >> 24) & 255) << 16;
    _w3[1] = uint_to_hex_lower8_le ((g >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((g >>  8) & 255) << 16;
    _w3[2] = uint_to_hex_lower8_le ((h >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((h >> 24) & 255) << 16;
    _w3[3] = uint_to_hex_lower8_le ((h >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((h >>  8) & 255) << 16;

    sha256_update_vector_64 (&ctx, _w0, _w1, _w2, _w3, 64);

    sha256_update_vector (&ctx, s, salt_len);

    sha256_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m20710_sxx (KERN_ATTR_VECTOR ())
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

  u32x _w0[4];
  u32x _w1[4];
  u32x _w2[4];
  u32x _w3[4];

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32x s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
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

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx0;

    sha256_init_vector (&ctx0);

    sha256_update_vector (&ctx0, w, pw_len);

    sha256_final_vector (&ctx0);

    const u32x a = ctx0.h[0];
    const u32x b = ctx0.h[1];
    const u32x c = ctx0.h[2];
    const u32x d = ctx0.h[3];
    const u32x e = ctx0.h[4];
    const u32x f = ctx0.h[5];
    const u32x g = ctx0.h[6];
    const u32x h = ctx0.h[7];

    sha256_ctx_vector_t ctx;

    sha256_init_vector (&ctx);

    _w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
    _w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
    _w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
    _w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
    _w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
    _w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
    _w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
    _w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
    _w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
    _w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
    _w2[2] = uint_to_hex_lower8_le ((f >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((f >> 24) & 255) << 16;
    _w2[3] = uint_to_hex_lower8_le ((f >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((f >>  8) & 255) << 16;
    _w3[0] = uint_to_hex_lower8_le ((g >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((g >> 24) & 255) << 16;
    _w3[1] = uint_to_hex_lower8_le ((g >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((g >>  8) & 255) << 16;
    _w3[2] = uint_to_hex_lower8_le ((h >> 16) & 255) <<  0 | uint_to_hex_lower8_le ((h >> 24) & 255) << 16;
    _w3[3] = uint_to_hex_lower8_le ((h >>  0) & 255) <<  0 | uint_to_hex_lower8_le ((h >>  8) & 255) << 16;

    sha256_update_vector_64 (&ctx, _w0, _w1, _w2, _w3, 64);

    sha256_update_vector (&ctx, s, salt_len);

    sha256_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
