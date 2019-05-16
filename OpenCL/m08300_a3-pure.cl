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
#include "inc_hash_sha1.cl"
#endif

KERNEL_FQ void m08300_mxx (KERN_ATTR_VECTOR ())
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

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32 (salt_bufs[salt_pos].salt_buf[idx]);
  }

  const u32 salt_len_pc = salt_bufs[salt_pos].salt_len_pc;

  u32x s_pc[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len_pc; i += 4, idx += 1)
  {
    s_pc[idx] = hc_swap32 (salt_bufs[salt_pos].salt_buf_pc[idx]);
  }

  const u32 salt_iter = salt_bufs[salt_pos].salt_iter;

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx1;

    sha1_init_vector (&ctx1);

    ctx1.w0[0] = (pw_len & 0xff) << 24;

    ctx1.len = 1;

    sha1_update_vector (&ctx1, w, pw_len);

    sha1_update_vector (&ctx1, s_pc, salt_len_pc + 1);

    sha1_update_vector (&ctx1, s, salt_len);

    sha1_final_vector (&ctx1);

    u32x digest[5];

    digest[0] = ctx1.h[0];
    digest[1] = ctx1.h[1];
    digest[2] = ctx1.h[2];
    digest[3] = ctx1.h[3];
    digest[4] = ctx1.h[4];

    // iterations

    for (u32 i = 0; i < salt_iter; i++)
    {
      sha1_ctx_vector_t ctx;

      sha1_init_vector (&ctx);

      ctx.w0[0] = digest[0];
      ctx.w0[1] = digest[1];
      ctx.w0[2] = digest[2];
      ctx.w0[3] = digest[3];
      ctx.w1[0] = digest[4];

      ctx.len = 20;

      sha1_update_vector (&ctx, s, salt_len);

      sha1_final_vector (&ctx);

      digest[0] = ctx.h[0];
      digest[1] = ctx.h[1];
      digest[2] = ctx.h[2];
      digest[3] = ctx.h[3];
      digest[4] = ctx.h[4];
    }

    const u32x r0 = digest[DGST_R0];
    const u32x r1 = digest[DGST_R1];
    const u32x r2 = digest[DGST_R2];
    const u32x r3 = digest[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m08300_sxx (KERN_ATTR_VECTOR ())
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

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32x s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32 (salt_bufs[salt_pos].salt_buf[idx]);
  }

  const u32 salt_len_pc = salt_bufs[salt_pos].salt_len_pc;

  u32x s_pc[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len_pc; i += 4, idx += 1)
  {
    s_pc[idx] = hc_swap32 (salt_bufs[salt_pos].salt_buf_pc[idx]);
  }

  const u32 salt_iter = salt_bufs[salt_pos].salt_iter;

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx1;

    sha1_init_vector (&ctx1);

    ctx1.w0[0] = (pw_len & 0xff) << 24;

    ctx1.len = 1;

    sha1_update_vector (&ctx1, w, pw_len);

    sha1_update_vector (&ctx1, s_pc, salt_len_pc + 1);

    sha1_update_vector (&ctx1, s, salt_len);

    sha1_final_vector (&ctx1);

    u32x digest[5];

    digest[0] = ctx1.h[0];
    digest[1] = ctx1.h[1];
    digest[2] = ctx1.h[2];
    digest[3] = ctx1.h[3];
    digest[4] = ctx1.h[4];

    // iterations

    for (u32 i = 0; i < salt_iter; i++)
    {
      sha1_ctx_vector_t ctx;

      sha1_init_vector (&ctx);

      ctx.w0[0] = digest[0];
      ctx.w0[1] = digest[1];
      ctx.w0[2] = digest[2];
      ctx.w0[3] = digest[3];
      ctx.w1[0] = digest[4];

      ctx.len = 20;

      sha1_update_vector (&ctx, s, salt_len);

      sha1_final_vector (&ctx);

      digest[0] = ctx.h[0];
      digest[1] = ctx.h[1];
      digest[2] = ctx.h[2];
      digest[3] = ctx.h[3];
      digest[4] = ctx.h[4];
    }

    const u32x r0 = digest[DGST_R0];
    const u32x r1 = digest[DGST_R1];
    const u32x r2 = digest[DGST_R2];
    const u32x r3 = digest[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
