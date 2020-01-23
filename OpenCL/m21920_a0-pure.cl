/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha256.cl"
#include "inc_hash_ripemd160.cl"
#endif

KERNEL_FQ void m21920_mxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  sha256_ctx_t ctx_base;

  sha256_init (&ctx_base);

  sha256_update_global_swap (&ctx_base, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 v0[4];
  u32 v1[4];
  u32 v2[4];
  u32 v3[4];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx_inner;

    sha256_init (&ctx_inner);

    sha256_update_swap (&ctx_inner, tmp.i, tmp.pw_len);

    sha256_final (&ctx_inner);

    sha256_ctx_t ctx_mid = ctx_base;

    w0[0] = ctx_inner.h[0];
    w0[1] = ctx_inner.h[1];
    w0[2] = ctx_inner.h[2];
    w0[3] = ctx_inner.h[3];
    w1[0] = ctx_inner.h[4];
    w1[1] = ctx_inner.h[5];
    w1[2] = ctx_inner.h[6];
    w1[3] = ctx_inner.h[7];

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_update_64 (&ctx_mid, w0, w1, w2, w3, 32);

    sha256_final (&ctx_mid);

    v0[0] = ctx_mid.h[0];
    v0[1] = ctx_mid.h[1];
    v0[2] = ctx_mid.h[2];
    v0[3] = ctx_mid.h[3];
    v1[0] = ctx_mid.h[4];
    v1[1] = ctx_mid.h[5];
    v1[2] = ctx_mid.h[6];
    v1[3] = ctx_mid.h[7];

    v2[0] = 0;
    v2[1] = 0;
    v2[2] = 0;
    v2[3] = 0;
    v3[0] = 0;
    v3[1] = 0;
    v3[2] = 0;
    v3[3] = 0;

    ripemd160_ctx_t ctx;

    ripemd160_init (&ctx);

    ripemd160_update_64 (&ctx, v0, v1, v2, v3, 32);

    ripemd160_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m21920_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  sha256_ctx_t ctx_base;

  sha256_init (&ctx_base);

  sha256_update_global_swap (&ctx_base, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 v0[4];
  u32 v1[4];
  u32 v2[4];
  u32 v3[4];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx_inner;

    sha256_init (&ctx_inner);

    sha256_update_swap (&ctx_inner, tmp.i, tmp.pw_len);

    sha256_final (&ctx_inner);

    sha256_ctx_t ctx_mid = ctx_base;

    w0[0] = ctx_inner.h[0];
    w0[1] = ctx_inner.h[1];
    w0[2] = ctx_inner.h[2];
    w0[3] = ctx_inner.h[3];
    w1[0] = ctx_inner.h[4];
    w1[1] = ctx_inner.h[5];
    w1[2] = ctx_inner.h[6];
    w1[3] = ctx_inner.h[7];

    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    printf("w0[0] = %x\n", w0[0]);

    sha256_update_64 (&ctx_mid, w0, w1, w2, w3, 32);

    sha256_final (&ctx_mid);

    v0[0] = hc_swap32_S(ctx_mid.h[0]);
    v0[1] = hc_swap32_S(ctx_mid.h[1]);
    v0[2] = hc_swap32_S(ctx_mid.h[2]);
    v0[3] = hc_swap32_S(ctx_mid.h[3]);
    v1[0] = hc_swap32_S(ctx_mid.h[4]);
    v1[1] = hc_swap32_S(ctx_mid.h[5]);
    v1[2] = hc_swap32_S(ctx_mid.h[6]);
    v1[3] = hc_swap32_S(ctx_mid.h[7]);

    v2[0] = 0;
    v2[1] = 0;
    v2[2] = 0;
    v2[3] = 0;
    v3[0] = 0;
    v3[1] = 0;
    v3[2] = 0;
    v3[3] = 0;

    printf("v0[0] = %x\n", v0[0]);

    ripemd160_ctx_t ctx;

    ripemd160_init (&ctx);

    ripemd160_update_64 (&ctx, v0, v1, v2, v3, 32);

    ripemd160_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];
    
    printf("r0 = %x\n", r0);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
