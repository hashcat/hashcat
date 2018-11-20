/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"

#if   VECT_SIZE == 1
#define uint_to_hex_lower8_le(i) (u32x) (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8_le(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8_le(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8_le(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8_le(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

__kernel void m11200_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len & 255;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0lr = w0l | w0r;

    w[0] = w0lr;

    sha1_ctx_vector_t ctx2;

    sha1_init_vector (&ctx2);

    sha1_update_vector (&ctx2, w, pw_len);

    sha1_final_vector (&ctx2);

    u32x a = ctx2.h[0];
    u32x b = ctx2.h[1];
    u32x c = ctx2.h[2];
    u32x d = ctx2.h[3];
    u32x e = ctx2.h[4];

    const u32x a_sav = a;
    const u32x b_sav = b;
    const u32x c_sav = c;
    const u32x d_sav = d;
    const u32x e_sav = e;

    sha1_ctx_vector_t ctx1;

    sha1_init_vector (&ctx1);

    ctx1.w0[0] = a;
    ctx1.w0[1] = b;
    ctx1.w0[2] = c;
    ctx1.w0[3] = d;
    ctx1.w1[0] = e;

    ctx1.len = 20;

    sha1_final_vector (&ctx1);

    a = ctx1.h[0];
    b = ctx1.h[1];
    c = ctx1.h[2];
    d = ctx1.h[3];
    e = ctx1.h[4];

    sha1_ctx_vector_t ctx;

    sha1_init_vector_from_scalar (&ctx, &ctx0);

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = a;
    w0[1] = b;
    w0[2] = c;
    w0[3] = d;
    w1[0] = e;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_update_vector_64 (&ctx, w0, w1, w2, w3, 20);

    sha1_final_vector (&ctx);

    ctx.h[0] ^= a_sav;
    ctx.h[1] ^= b_sav;
    ctx.h[2] ^= c_sav;
    ctx.h[3] ^= d_sav;
    ctx.h[4] ^= e_sav;

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

__kernel void m11200_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

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

  const u32 pw_len = pws[gid].pw_len & 255;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0lr = w0l | w0r;

    w[0] = w0lr;

    sha1_ctx_vector_t ctx2;

    sha1_init_vector (&ctx2);

    sha1_update_vector (&ctx2, w, pw_len);

    sha1_final_vector (&ctx2);

    u32x a = ctx2.h[0];
    u32x b = ctx2.h[1];
    u32x c = ctx2.h[2];
    u32x d = ctx2.h[3];
    u32x e = ctx2.h[4];

    const u32x a_sav = a;
    const u32x b_sav = b;
    const u32x c_sav = c;
    const u32x d_sav = d;
    const u32x e_sav = e;

    sha1_ctx_vector_t ctx1;

    sha1_init_vector (&ctx1);

    ctx1.w0[0] = a;
    ctx1.w0[1] = b;
    ctx1.w0[2] = c;
    ctx1.w0[3] = d;
    ctx1.w1[0] = e;

    ctx1.len = 20;

    sha1_final_vector (&ctx1);

    a = ctx1.h[0];
    b = ctx1.h[1];
    c = ctx1.h[2];
    d = ctx1.h[3];
    e = ctx1.h[4];

    sha1_ctx_vector_t ctx;

    sha1_init_vector_from_scalar (&ctx, &ctx0);

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = a;
    w0[1] = b;
    w0[2] = c;
    w0[3] = d;
    w1[0] = e;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_update_vector_64 (&ctx, w0, w1, w2, w3, 20);

    sha1_final_vector (&ctx);

    ctx.h[0] ^= a_sav;
    ctx.h[1] ^= b_sav;
    ctx.h[2] ^= c_sav;
    ctx.h[3] ^= d_sav;
    ctx.h[4] ^= e_sav;

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
