/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * MODIFIED: This kernel intercepts the incoming password and replaces it
 * with the 32-character hex representation of its own MD5 hash.
 * The rest of the original phpass algorithm then runs on this new data.
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

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

typedef struct phpass_tmp
{
  u32 digest_buf[4];
  u32 md5_buf[8];
} phpass_tmp_t;

KERNEL_FQ void m35700_init (KERN_ATTR_TMPS (phpass_tmp_t))
{
  /**
   * base
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

  md5_ctx_t pw_ctx;

  md5_init (&pw_ctx);

  md5_update_global (&pw_ctx, pws[gid].i, pws[gid].pw_len);

  md5_final (&pw_ctx);

  u32 a = pw_ctx.h[0];
  u32 b = pw_ctx.h[1];
  u32 c = pw_ctx.h[2];
  u32 d = pw_ctx.h[3];

  u32 w[16];

  w[ 0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
        | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
  w[ 1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
        | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
  w[ 2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
        | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
  w[ 3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
        | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
  w[ 4] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
        | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
  w[ 5] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
        | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
  w[ 6] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
        | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
  w[ 7] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
        | uint_to_hex_lower8 ((d >> 24) & 255) << 16;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  tmps[gid].md5_buf[0] = w[0];
  tmps[gid].md5_buf[1] = w[1];
  tmps[gid].md5_buf[2] = w[2];
  tmps[gid].md5_buf[3] = w[3];
  tmps[gid].md5_buf[4] = w[4];
  tmps[gid].md5_buf[5] = w[5];
  tmps[gid].md5_buf[6] = w[6];
  tmps[gid].md5_buf[7] = w[7];

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update_global (&md5_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  md5_update (&md5_ctx, w, 32);

  md5_final (&md5_ctx);

  u32 digest[4];

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ void m35700_loop (KERN_ATTR_TMPS (phpass_tmp_t))
{
  /**
  * base
  */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[8];

  w[0] = tmps[gid].md5_buf[0];
  w[1] = tmps[gid].md5_buf[1];
  w[2] = tmps[gid].md5_buf[2];
  w[3] = tmps[gid].md5_buf[3];
  w[4] = tmps[gid].md5_buf[4];
  w[5] = tmps[gid].md5_buf[5];
  w[6] = tmps[gid].md5_buf[6];
  w[7] = tmps[gid].md5_buf[7];

  const u32 pw_len = 32;

  u32 digest[4];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  /**
  * loop
  */

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_ctx.w0[0] = digest[0];
  md5_ctx.w0[1] = digest[1];
  md5_ctx.w0[2] = digest[2];
  md5_ctx.w0[3] = digest[3];
  md5_ctx.w1[0] = w[0];
  md5_ctx.w1[1] = w[1];
  md5_ctx.w1[2] = w[2];
  md5_ctx.w1[3] = w[3];
  md5_ctx.w2[0] = w[4];
  md5_ctx.w2[1] = w[5];
  md5_ctx.w2[2] = w[6];
  md5_ctx.w2[3] = w[7];

  md5_ctx.len = 48;

  md5_final (&md5_ctx);

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];

  if ((16 + pw_len + 1) >= 56)
  {
    for (u32 i = 1; i < LOOP_CNT; i++)
    {
      md5_init (&md5_ctx);

      md5_ctx.w0[0] = digest[0];
      md5_ctx.w0[1] = digest[1];
      md5_ctx.w0[2] = digest[2];
      md5_ctx.w0[3] = digest[3];
      md5_ctx.w1[0] = w[0];
      md5_ctx.w1[1] = w[1];
      md5_ctx.w1[2] = w[2];
      md5_ctx.w1[3] = w[3];
      md5_ctx.w2[0] = w[4];
      md5_ctx.w2[1] = w[5];
      md5_ctx.w2[2] = w[6];
      md5_ctx.w2[3] = w[7];

      md5_ctx.len = 48;

      md5_final (&md5_ctx);

      digest[0] = md5_ctx.h[0];
      digest[1] = md5_ctx.h[1];
      digest[2] = md5_ctx.h[2];
      digest[3] = md5_ctx.h[3];
    }
  }
  else
  {
    for (u32 i = 1; i < LOOP_CNT; i++)
    {
      md5_ctx.w0[0] = digest[0];
      md5_ctx.w0[1] = digest[1];
      md5_ctx.w0[2] = digest[2];
      md5_ctx.w0[3] = digest[3];

      digest[0] = MD5M_A;
      digest[1] = MD5M_B;
      digest[2] = MD5M_C;
      digest[3] = MD5M_D;

      md5_transform (md5_ctx.w0, md5_ctx.w1, md5_ctx.w2, md5_ctx.w3, digest);
    }
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ void m35700_comp (KERN_ATTR_TMPS (phpass_tmp_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}