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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

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

typedef struct symfony_sha512_tmp
{
  u32 digest_buf[32];
} symfony_sha512_tmp;

KERNEL_FQ KERNEL_FA void m35800_init (KERN_ATTR_TMPS (symfony_sha512_tmp))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_swap (&ctx0, w, pw_len);

  sha512_final (&ctx0);

  for (int i = 0; i < 8; i++)
  {
    u32 hi = h32_from_64_S(ctx0.h[i]);
    u32 lo = l32_from_64_S(ctx0.h[i]);

    tmps[gid].digest_buf[i * 4 + 0] = uint_to_hex_lower8_le((hi >> 16) & 255) << 0 | uint_to_hex_lower8_le((hi >> 24) & 255) << 16;
    tmps[gid].digest_buf[i * 4 + 1] = uint_to_hex_lower8_le((hi >>  0) & 255) << 0 | uint_to_hex_lower8_le((hi >>  8) & 255) << 16;
    tmps[gid].digest_buf[i * 4 + 2] = uint_to_hex_lower8_le((lo >> 16) & 255) << 0 | uint_to_hex_lower8_le((lo >> 24) & 255) << 16;
    tmps[gid].digest_buf[i * 4 + 3] = uint_to_hex_lower8_le((lo >>  0) & 255) << 0 | uint_to_hex_lower8_le((lo >>  8) & 255) << 16;
  }
}

KERNEL_FQ KERNEL_FA void m35800_loop (KERN_ATTR_TMPS (symfony_sha512_tmp))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  /**
   * digest
   */

  u32 digest[32];

  for (u32 i = 0; i < 32; i++)
  {
    digest[i] = tmps[gid].digest_buf[i];
  }

  /**
   * loop
   */

  for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
  {
    sha512_ctx_t ctx;

    sha512_init (&ctx);

    sha512_update (&ctx, digest, 128);

    if (j > 4999)
    {
      sha512_update (&ctx, s, salt_len);
    }   

    sha512_final (&ctx);

    for (int k = 0; k < 8; k++)
    {
      u32 hi = h32_from_64_S(ctx.h[k]);
      u32 lo = l32_from_64_S(ctx.h[k]);

      digest[k * 4 + 0] = uint_to_hex_lower8_le((hi >> 16) & 255) << 0 | uint_to_hex_lower8_le((hi >> 24) & 255) << 16;
      digest[k * 4 + 1] = uint_to_hex_lower8_le((hi >>  0) & 255) << 0 | uint_to_hex_lower8_le((hi >>  8) & 255) << 16;
      digest[k * 4 + 2] = uint_to_hex_lower8_le((lo >> 16) & 255) << 0 | uint_to_hex_lower8_le((lo >> 24) & 255) << 16;
      digest[k * 4 + 3] = uint_to_hex_lower8_le((lo >>  0) & 255) << 0 | uint_to_hex_lower8_le((lo >>  8) & 255) << 16;
    }
  }

  for (u32 i = 0; i < 32; i++)
  {
    tmps[gid].digest_buf[i] = digest[i];
  }
}

KERNEL_FQ KERNEL_FA void m35800_comp (KERN_ATTR_TMPS (symfony_sha512_tmp))
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

  u32 buf[32];

  for (u32 i = 0; i < 32; i++)
  {
    buf[i] = tmps[gid].digest_buf[i];
  }

  sha256_ctx_t ctx;
  
  sha256_init (&ctx);

  sha256_update (&ctx, buf, 128);

  sha256_final (&ctx);

  const u32 r0 = ctx.h[DGST_R0];
  const u32 r1 = ctx.h[DGST_R1];
  const u32 r2 = ctx.h[DGST_R2];
  const u32 r3 = ctx.h[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}