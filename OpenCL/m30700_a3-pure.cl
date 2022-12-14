/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

KERNEL_FQ void m30700_mxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 IV_A = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  const u32 IV_B = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];
  const u32 IV_C = salt_bufs[SALT_POS_HOST].salt_buf_pc[2];
  const u32 IV_D = salt_bufs[SALT_POS_HOST].salt_buf_pc[3];
  const u32 IV_E = salt_bufs[SALT_POS_HOST].salt_buf_pc[4];
  const u32 IV_F = salt_bufs[SALT_POS_HOST].salt_buf_pc[5];
  const u32 IV_G = salt_bufs[SALT_POS_HOST].salt_buf_pc[6];
  const u32 IV_H = salt_bufs[SALT_POS_HOST].salt_buf_pc[7];

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx;

    sha256_init_vector (&ctx);

    ctx.h[0] = IV_A;
    ctx.h[1] = IV_B;
    ctx.h[2] = IV_C;
    ctx.h[3] = IV_D;
    ctx.h[4] = IV_E;
    ctx.h[5] = IV_F;
    ctx.h[6] = IV_G;
    ctx.h[7] = IV_H;

    sha256_update_vector (&ctx, w, pw_len);

    sha256_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m30700_sxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 IV_A = salt_bufs[SALT_POS_HOST].salt_buf_pc[0];
  const u32 IV_B = salt_bufs[SALT_POS_HOST].salt_buf_pc[1];
  const u32 IV_C = salt_bufs[SALT_POS_HOST].salt_buf_pc[2];
  const u32 IV_D = salt_bufs[SALT_POS_HOST].salt_buf_pc[3];
  const u32 IV_E = salt_bufs[SALT_POS_HOST].salt_buf_pc[4];
  const u32 IV_F = salt_bufs[SALT_POS_HOST].salt_buf_pc[5];
  const u32 IV_G = salt_bufs[SALT_POS_HOST].salt_buf_pc[6];
  const u32 IV_H = salt_bufs[SALT_POS_HOST].salt_buf_pc[7];

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_ctx_vector_t ctx;

    sha256_init_vector (&ctx);

    ctx.h[0] = IV_A;
    ctx.h[1] = IV_B;
    ctx.h[2] = IV_C;
    ctx.h[3] = IV_D;
    ctx.h[4] = IV_E;
    ctx.h[5] = IV_F;
    ctx.h[6] = IV_G;
    ctx.h[7] = IV_H;

    sha256_update_vector (&ctx, w, pw_len);

    sha256_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
