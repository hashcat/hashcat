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
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3], u_bin2asc[(i).s4], u_bin2asc[(i).s5], u_bin2asc[(i).s6], u_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_upper8(i) make_u32x (u_bin2asc[(i).s0], u_bin2asc[(i).s1], u_bin2asc[(i).s2], u_bin2asc[(i).s3], u_bin2asc[(i).s4], u_bin2asc[(i).s5], u_bin2asc[(i).s6], u_bin2asc[(i).s7], u_bin2asc[(i).s8], u_bin2asc[(i).s9], u_bin2asc[(i).sa], u_bin2asc[(i).sb], u_bin2asc[(i).sc], u_bin2asc[(i).sd], u_bin2asc[(i).se], u_bin2asc[(i).sf])
#endif

typedef struct md5_double_salt
{
  u32 salt1_buf[64];
  int salt1_len;

  u32 salt2_buf[64];
  int salt2_len;

} md5_double_salt_t;

KERNEL_FQ void m03730_mxx (KERN_ATTR_ESALT (md5_double_salt_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc uppercase array
   */

  LOCAL_VK u32 u_bin2asc[256];

  for (u32 j = lid; j < 256; j += lsz)
  {
    const u32 i0 = (j >> 0) & 15;
    const u32 i1 = (j >> 4) & 15;

    u_bin2asc[j] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[idx];
  }

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt2_len);

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md5_ctx_t ctx1 = ctx0;

    md5_update_global (&ctx1, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx1);

    const u32 a = ctx1.h[0];
    const u32 b = ctx1.h[1];
    const u32 c = ctx1.h[2];
    const u32 d = ctx1.h[3];

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = uint_to_hex_upper8 ((a >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((a >>  8) & 255) << 16;
    w0[1] = uint_to_hex_upper8 ((a >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((a >> 24) & 255) << 16;
    w0[2] = uint_to_hex_upper8 ((b >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((b >>  8) & 255) << 16;
    w0[3] = uint_to_hex_upper8 ((b >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((b >> 24) & 255) << 16;
    w1[0] = uint_to_hex_upper8 ((c >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((c >>  8) & 255) << 16;
    w1[1] = uint_to_hex_upper8 ((c >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((c >> 24) & 255) << 16;
    w1[2] = uint_to_hex_upper8 ((d >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((d >>  8) & 255) << 16;
    w1[3] = uint_to_hex_upper8 ((d >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((d >> 24) & 255) << 16;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update (&ctx, s, salt_len);

    md5_update_64 (&ctx, w0, w1, w2, w3, 32);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m03730_sxx (KERN_ATTR_ESALT (md5_double_salt_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * bin2asc uppercase array
   */

  LOCAL_VK u32 u_bin2asc[256];

  for (u32 j = lid; j < 256; j += lsz)
  {
    const u32 i0 = (j >> 0) & 15;
    const u32 i1 = (j >> 4) & 15;

    u_bin2asc[j] = ((i0 < 10) ? '0' + i0 : 'A' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'A' - 10 + i1) << 0;
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

  const u32 salt_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf[idx];
  }

  /**
   * base
   */

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt2_len);

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    md5_ctx_t ctx1 = ctx0;

    md5_update_global (&ctx1, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx1);

    const u32 a = ctx1.h[0];
    const u32 b = ctx1.h[1];
    const u32 c = ctx1.h[2];
    const u32 d = ctx1.h[3];

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = uint_to_hex_upper8 ((a >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((a >>  8) & 255) << 16;
    w0[1] = uint_to_hex_upper8 ((a >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((a >> 24) & 255) << 16;
    w0[2] = uint_to_hex_upper8 ((b >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((b >>  8) & 255) << 16;
    w0[3] = uint_to_hex_upper8 ((b >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((b >> 24) & 255) << 16;
    w1[0] = uint_to_hex_upper8 ((c >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((c >>  8) & 255) << 16;
    w1[1] = uint_to_hex_upper8 ((c >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((c >> 24) & 255) << 16;
    w1[2] = uint_to_hex_upper8 ((d >>  0) & 255) <<  0
          | uint_to_hex_upper8 ((d >>  8) & 255) << 16;
    w1[3] = uint_to_hex_upper8 ((d >> 16) & 255) <<  0
          | uint_to_hex_upper8 ((d >> 24) & 255) << 16;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_ctx_t ctx;

    md5_init (&ctx);

    md5_update (&ctx, s, salt_len);

    md5_update_64 (&ctx, w0, w1, w2, w3, 32);

    md5_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
