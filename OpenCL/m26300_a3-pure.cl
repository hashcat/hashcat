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

KERNEL_FQ void m26300_mxx (KERN_ATTR_VECTOR ())
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

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_swap (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

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

    sha256_init_vector_from_scalar (&ctx, &ctx0);

    sha256_update_vector (&ctx, w, pw_len);

    /**
     * pepper
     */

    u32x p0[4];
    u32x p1[4];
    u32x p2[4];
    u32x p3[4];

    p0[0] = hc_swap32 (FORTIGATE_A);
    p0[1] = hc_swap32 (FORTIGATE_B);
    p0[2] = hc_swap32 (FORTIGATE_C);
    p0[3] = hc_swap32 (FORTIGATE_D);
    p1[0] = hc_swap32 (FORTIGATE_E);
    p1[1] = hc_swap32 (FORTIGATE_F);
    p1[2] = 0;
    p1[3] = 0;
    p2[0] = 0;
    p2[1] = 0;
    p2[2] = 0;
    p2[3] = 0;
    p3[0] = 0;
    p3[1] = 0;
    p3[2] = 0;
    p3[3] = 0;

    sha256_update_vector_64 (&ctx, p0, p1, p2, p3, 24);

    sha256_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m26300_sxx (KERN_ATTR_VECTOR ())
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

  sha256_ctx_t ctx0;

  sha256_init (&ctx0);

  sha256_update_global_swap (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

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

    sha256_init_vector_from_scalar (&ctx, &ctx0);

    sha256_update_vector (&ctx, w, pw_len);

    /**
     * pepper
     */

    u32x p0[4];
    u32x p1[4];
    u32x p2[4];
    u32x p3[4];

    p0[0] = hc_swap32 (FORTIGATE_A);
    p0[1] = hc_swap32 (FORTIGATE_B);
    p0[2] = hc_swap32 (FORTIGATE_C);
    p0[3] = hc_swap32 (FORTIGATE_D);
    p1[0] = hc_swap32 (FORTIGATE_E);
    p1[1] = hc_swap32 (FORTIGATE_F);
    p1[2] = 0;
    p1[3] = 0;
    p2[0] = 0;
    p2[1] = 0;
    p2[2] = 0;
    p2[3] = 0;
    p3[0] = 0;
    p3[1] = 0;
    p3[2] = 0;
    p3[3] = 0;

    sha256_update_vector_64 (&ctx, p0, p1, p2, p3, 24);

    sha256_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
