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

KERNEL_FQ void m32900_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  u32 buf[5];

  sha1_ctx_t ctx1;
  sha1_init (&ctx1);

  sha1_ctx_t ctx0 = ctx1;

  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx2 = ctx0;

    sha1_update_global_swap (&ctx2, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_update (&ctx2, s, salt_len);

    sha1_final (&ctx2);

    buf[0] = ctx2.h[0];
    buf[1] = ctx2.h[1];
    buf[2] = ctx2.h[2];
    buf[3] = ctx2.h[3];
    buf[4] = ctx2.h[4];

    for (int i = 0; i < salt_iter; i++)
    {
      sha1_ctx_t ctx = ctx1;
      
      ctx.w0[0] = (buf[0]);
      ctx.w0[1] = (buf[1]);
      ctx.w0[2] = (buf[2]);
      ctx.w0[3] = (buf[3]);
      ctx.w1[0] = (buf[4]);

      ctx.len = 20;

      sha1_final (&ctx);

      buf[0] = ctx.h[0];
      buf[1] = ctx.h[1];
      buf[2] = ctx.h[2];
      buf[3] = ctx.h[3];
      buf[4] = ctx.h[4];
    }

    const u32 r0 = buf[DGST_R0];
    const u32 r1 = buf[DGST_R1];
    const u32 r2 = buf[DGST_R2];
    const u32 r3 = buf[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m32900_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[idx]);
  }

  const u32 salt_iter = salt_bufs[SALT_POS_HOST].salt_iter;

  u32 buf[5];

  sha1_ctx_t ctx1;
  sha1_init (&ctx1);

  sha1_ctx_t ctx0 = ctx1;

  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx2 = ctx0;

    sha1_update_global_swap (&ctx2, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_update (&ctx2, s, salt_len);

    sha1_final (&ctx2);

    buf[0] = ctx2.h[0];
    buf[1] = ctx2.h[1];
    buf[2] = ctx2.h[2];
    buf[3] = ctx2.h[3];
    buf[4] = ctx2.h[4];

    for (int i = 0; i < salt_iter; i++)
    {
      sha1_ctx_t ctx = ctx1;
      
      ctx.w0[0] = (buf[0]);
      ctx.w0[1] = (buf[1]);
      ctx.w0[2] = (buf[2]);
      ctx.w0[3] = (buf[3]);
      ctx.w1[0] = (buf[4]);

      ctx.len = 20;

      sha1_final (&ctx);

      buf[0] = ctx.h[0];
      buf[1] = ctx.h[1];
      buf[2] = ctx.h[2];
      buf[3] = ctx.h[3];
      buf[4] = ctx.h[4];
    }

    const u32 r0 = buf[DGST_R0];
    const u32 r1 = buf[DGST_R1];
    const u32 r2 = buf[DGST_R2];
    const u32 r3 = buf[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
