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
#include M2S(INCLUDE_PATH/inc_hash_blake2b.cl)
#endif

KERNEL_FQ void m00620_mxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

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

  blake2b_ctx_t ctx0;

  blake2b_init (&ctx0);

  blake2b_update_global (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    blake2b_ctx_vector_t ctx;

    blake2b_init_vector_from_scalar   (&ctx, &ctx0);

    blake2b_update_vector (&ctx, w, pw_len);

    blake2b_final_vector  (&ctx);

    const u32x r0 = h32_from_64 (ctx.h[0]);
    const u32x r1 = l32_from_64 (ctx.h[0]);
    const u32x r2 = h32_from_64 (ctx.h[1]);
    const u32x r3 = l32_from_64 (ctx.h[1]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m00620_sxx (KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

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

  blake2b_ctx_t ctx0;

  blake2b_init (&ctx0);

  blake2b_update_global (&ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    blake2b_ctx_vector_t ctx;

    blake2b_init_vector_from_scalar   (&ctx, &ctx0);

    blake2b_update_vector (&ctx, w, pw_len);

    blake2b_final_vector  (&ctx);

    const u32x r0 = h32_from_64 (ctx.h[0]);
    const u32x r1 = l32_from_64 (ctx.h[0]);
    const u32x r2 = h32_from_64 (ctx.h[1]);
    const u32x r3 = l32_from_64 (ctx.h[1]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

