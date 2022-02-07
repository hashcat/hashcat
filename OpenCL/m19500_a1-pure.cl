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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

typedef struct devise_hash
{
  u32 salt_buf[64];
  int salt_len;

  u32 site_key_buf[64];
  int site_key_len;

} devise_hash_t;

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

KERNEL_FQ void m19500_mxx (KERN_ATTR_ESALT (devise_hash_t))
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

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const int salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt_len;

  const int site_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].site_key_len;

  u32 s[64] = { 0 };
  u32 k[64] = { 0 };

  const u32 glue[16] = { 0x2d2d0000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (esalt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  for (int i = 0, idx = 0; i < site_key_len; i += 4, idx += 1)
  {
    k[idx] = hc_swap32_S (esalt_bufs[SALT_POS_HOST].site_key_buf[idx]);
  }

  // precompute some stuff

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update             (&ctx0, k, site_key_len);
  sha1_update             (&ctx0, glue, 2);
  sha1_update             (&ctx0, s, salt_len);
  sha1_update             (&ctx0, glue, 2);
  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx = ctx0;

    sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    sha1_update             (&ctx, glue, 2);
    sha1_update             (&ctx, k, site_key_len);

    sha1_final (&ctx);

    for (u32 iter = 0; iter < 9; iter++)
    {
      const u32 a = ctx.h[0];
      const u32 b = ctx.h[1];
      const u32 c = ctx.h[2];
      const u32 d = ctx.h[3];
      const u32 e = ctx.h[4];

      sha1_init (&ctx);

      ctx.w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
      ctx.w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
      ctx.w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
      ctx.w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
      ctx.w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
      ctx.w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
      ctx.w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
      ctx.w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
      ctx.w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
      ctx.w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
      ctx.w2[2] = glue[0];

      ctx.len = 40 + 2;

      sha1_update (&ctx, s, salt_len);
      sha1_update (&ctx, glue, 2);
      sha1_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
      sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
      sha1_update (&ctx, glue, 2);
      sha1_update (&ctx, k, site_key_len);

      sha1_final (&ctx);
    }

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m19500_sxx (KERN_ATTR_ESALT (devise_hash_t))
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

  const int salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt_len;

  const int site_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].site_key_len;

  u32 s[64] = { 0 };
  u32 k[64] = { 0 };

  const u32 glue[16] = { 0x2d2d0000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (esalt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  for (int i = 0, idx = 0; i < site_key_len; i += 4, idx += 1)
  {
    k[idx] = hc_swap32_S (esalt_bufs[SALT_POS_HOST].site_key_buf[idx]);
  }

  // precompute some stuff

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update             (&ctx0, k, site_key_len);
  sha1_update             (&ctx0, glue, 2);
  sha1_update             (&ctx0, s, salt_len);
  sha1_update             (&ctx0, glue, 2);
  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx = ctx0;

    sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    sha1_update             (&ctx, glue, 2);
    sha1_update             (&ctx, k, site_key_len);

    sha1_final (&ctx);

    for (u32 iter = 0; iter < 9; iter++)
    {
      const u32 a = ctx.h[0];
      const u32 b = ctx.h[1];
      const u32 c = ctx.h[2];
      const u32 d = ctx.h[3];
      const u32 e = ctx.h[4];

      sha1_init (&ctx);

      ctx.w0[0] = uint_to_hex_lower8_le ((a >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((a >> 24) & 255) << 16;
      ctx.w0[1] = uint_to_hex_lower8_le ((a >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((a >>  8) & 255) << 16;
      ctx.w0[2] = uint_to_hex_lower8_le ((b >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((b >> 24) & 255) << 16;
      ctx.w0[3] = uint_to_hex_lower8_le ((b >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((b >>  8) & 255) << 16;
      ctx.w1[0] = uint_to_hex_lower8_le ((c >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((c >> 24) & 255) << 16;
      ctx.w1[1] = uint_to_hex_lower8_le ((c >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((c >>  8) & 255) << 16;
      ctx.w1[2] = uint_to_hex_lower8_le ((d >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((d >> 24) & 255) << 16;
      ctx.w1[3] = uint_to_hex_lower8_le ((d >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((d >>  8) & 255) << 16;
      ctx.w2[0] = uint_to_hex_lower8_le ((e >> 16) & 255) <<  0
                | uint_to_hex_lower8_le ((e >> 24) & 255) << 16;
      ctx.w2[1] = uint_to_hex_lower8_le ((e >>  0) & 255) <<  0
                | uint_to_hex_lower8_le ((e >>  8) & 255) << 16;
      ctx.w2[2] = glue[0];

      ctx.len = 40 + 2;

      sha1_update (&ctx, s, salt_len);
      sha1_update (&ctx, glue, 2);
      sha1_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
      sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
      sha1_update (&ctx, glue, 2);
      sha1_update (&ctx, k, site_key_len);

      sha1_final (&ctx);
    }

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
