/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"
#include "inc_hash_ripemd160.cl"
#endif

KERNEL_FQ void m21920_mxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  sha256_ctx_t ctx_base;

  sha256_init (&ctx_base);

  sha256_update_global_swap (&ctx_base, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  u32x _w0[4];
  u32x _w1[4];
  u32x _w2[4];
  u32x _w3[4];

  u32x _v0[4];
  u32x _v1[4];
  u32x _v2[4];
  u32x _v3[4];

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx_inner;

    sha256_init_vector (&ctx_inner);

    sha256_update_vector_swap (&ctx_inner, w, pw_len);

    sha256_final_vector (&ctx_inner);

    sha256_ctx_vector_t ctx_mid;

    sha256_init_vector_from_scalar (&ctx_mid, &ctx_base);

    _w0[0] = ctx_inner.h[0];
    _w0[1] = ctx_inner.h[1];
    _w0[2] = ctx_inner.h[2];
    _w0[3] = ctx_inner.h[3];
    _w1[0] = ctx_inner.h[4];
    _w1[1] = ctx_inner.h[5];
    _w1[2] = ctx_inner.h[6];
    _w1[3] = ctx_inner.h[7];

    _w2[0] = 0;
    _w2[1] = 0;
    _w2[2] = 0;
    _w2[3] = 0;
    _w3[0] = 0;
    _w3[1] = 0;
    _w3[2] = 0;
    _w3[3] = 0;

    sha256_update_vector_64 (&ctx_mid, _w0, _w1, _w2, _w3, 32);

    sha256_final_vector (&ctx_mid);

    _v0[0] = hc_swap32(ctx_mid.h[0]);
    _v0[1] = hc_swap32(ctx_mid.h[1]);
    _v0[2] = hc_swap32(ctx_mid.h[2]);
    _v0[3] = hc_swap32(ctx_mid.h[3]);
    _v1[0] = hc_swap32(ctx_mid.h[4]);
    _v1[1] = hc_swap32(ctx_mid.h[5]);
    _v1[2] = hc_swap32(ctx_mid.h[6]);
    _v1[3] = hc_swap32(ctx_mid.h[7]);

    _v2[0] = 0;
    _v2[1] = 0;
    _v2[2] = 0;
    _v2[3] = 0;
    _v3[0] = 0;
    _v3[1] = 0;
    _v3[2] = 0;
    _v3[3] = 0;

    ripemd160_ctx_vector_t ctx;

    ripemd160_init_vector (&ctx);

    ripemd160_update_vector_64 (&ctx, _v0, _v1, _v2, _v3, 32);

    ripemd160_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m21920_sxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  sha256_ctx_t ctx_base;

  sha256_init (&ctx_base);

  sha256_update_global_swap (&ctx_base, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  u32x _w0[4];
  u32x _w1[4];
  u32x _w2[4];
  u32x _w3[4];

  u32x _v0[4];
  u32x _v1[4];
  u32x _v2[4];
  u32x _v3[4];
  
  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx_inner;

    sha256_init_vector (&ctx_inner);

    sha256_update_vector_swap (&ctx_inner, w, pw_len);

    sha256_final_vector (&ctx_inner);

    sha256_ctx_vector_t ctx_mid;

    sha256_init_vector_from_scalar (&ctx_mid, &ctx_base);

    _w0[0] = ctx_inner.h[0];
    _w0[1] = ctx_inner.h[1];
    _w0[2] = ctx_inner.h[2];
    _w0[3] = ctx_inner.h[3];
    _w1[0] = ctx_inner.h[4];
    _w1[1] = ctx_inner.h[5];
    _w1[2] = ctx_inner.h[6];
    _w1[3] = ctx_inner.h[7];

    _w2[0] = 0;
    _w2[1] = 0;
    _w2[2] = 0;
    _w2[3] = 0;
    _w3[0] = 0;
    _w3[1] = 0;
    _w3[2] = 0;
    _w3[3] = 0;

    sha256_update_vector_64 (&ctx_mid, _w0, _w1, _w2, _w3, 32);

    sha256_final_vector (&ctx_mid);

    _v0[0] = hc_swap32(ctx_mid.h[0]);
    _v0[1] = hc_swap32(ctx_mid.h[1]);
    _v0[2] = hc_swap32(ctx_mid.h[2]);
    _v0[3] = hc_swap32(ctx_mid.h[3]);
    _v1[0] = hc_swap32(ctx_mid.h[4]);
    _v1[1] = hc_swap32(ctx_mid.h[5]);
    _v1[2] = hc_swap32(ctx_mid.h[6]);
    _v1[3] = hc_swap32(ctx_mid.h[7]);

    _v2[0] = 0;
    _v2[1] = 0;
    _v2[2] = 0;
    _v2[3] = 0;
    _v3[0] = 0;
    _v3[1] = 0;
    _v3[2] = 0;
    _v3[3] = 0;

    ripemd160_ctx_vector_t ctx;

    ripemd160_init_vector (&ctx);

    ripemd160_update_vector_64 (&ctx, _v0, _v1, _v2, _v3, 32);

    ripemd160_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
