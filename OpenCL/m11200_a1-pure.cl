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
#include "inc_scalar.cl"
#include "inc_hash_sha1.cl"
#endif

KERNEL_FQ void m11200_mxx (KERN_ATTR_BASIC ())
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

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha1_ctx_t ctx2l;

  sha1_init (&ctx2l);

  sha1_update_global_swap (&ctx2l, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx2 = ctx2l;

    sha1_update_global_swap (&ctx2, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_final (&ctx2);

    u32 a = ctx2.h[0];
    u32 b = ctx2.h[1];
    u32 c = ctx2.h[2];
    u32 d = ctx2.h[3];
    u32 e = ctx2.h[4];

    const u32 a_sav = a;
    const u32 b_sav = b;
    const u32 c_sav = c;
    const u32 d_sav = d;
    const u32 e_sav = e;

    sha1_ctx_t ctx1;

    sha1_init (&ctx1);

    ctx1.w0[0] = a;
    ctx1.w0[1] = b;
    ctx1.w0[2] = c;
    ctx1.w0[3] = d;
    ctx1.w1[0] = e;

    ctx1.len = 20;

    sha1_final (&ctx1);

    a = ctx1.h[0];
    b = ctx1.h[1];
    c = ctx1.h[2];
    d = ctx1.h[3];
    e = ctx1.h[4];

    sha1_ctx_t ctx = ctx0;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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

    sha1_update_64 (&ctx, w0, w1, w2, w3, 20);

    sha1_final (&ctx);

    ctx.h[0] ^= a_sav;
    ctx.h[1] ^= b_sav;
    ctx.h[2] ^= c_sav;
    ctx.h[3] ^= d_sav;
    ctx.h[4] ^= e_sav;

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m11200_sxx (KERN_ATTR_BASIC ())
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

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha1_ctx_t ctx2l;

  sha1_init (&ctx2l);

  sha1_update_global_swap (&ctx2l, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx2 = ctx2l;

    sha1_update_global_swap (&ctx2, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_final (&ctx2);

    u32 a = ctx2.h[0];
    u32 b = ctx2.h[1];
    u32 c = ctx2.h[2];
    u32 d = ctx2.h[3];
    u32 e = ctx2.h[4];

    const u32 a_sav = a;
    const u32 b_sav = b;
    const u32 c_sav = c;
    const u32 d_sav = d;
    const u32 e_sav = e;

    sha1_ctx_t ctx1;

    sha1_init (&ctx1);

    ctx1.w0[0] = a;
    ctx1.w0[1] = b;
    ctx1.w0[2] = c;
    ctx1.w0[3] = d;
    ctx1.w1[0] = e;

    ctx1.len = 20;

    sha1_final (&ctx1);

    a = ctx1.h[0];
    b = ctx1.h[1];
    c = ctx1.h[2];
    d = ctx1.h[3];
    e = ctx1.h[4];

    sha1_ctx_t ctx = ctx0;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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

    sha1_update_64 (&ctx, w0, w1, w2, w3, 20);

    sha1_final (&ctx);

    ctx.h[0] ^= a_sav;
    ctx.h[1] ^= b_sav;
    ctx.h[2] ^= c_sav;
    ctx.h[3] ^= d_sav;
    ctx.h[4] ^= e_sav;

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
