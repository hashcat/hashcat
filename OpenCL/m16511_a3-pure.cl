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
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

typedef struct jwt
{
  u32 salt_buf[1024];
  u32 salt_len;

  u32 signature_len;

} jwt_t;

KERNEL_FQ void m16511_mxx (KERN_ATTR_VECTOR_ESALT (jwt_t))
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

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_hmac_ctx_t ctx;

    sha256_hmac_init (&ctx, w, pw_len);

    sha256_hmac_update_global_swap (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

    sha256_hmac_final (&ctx);

    const u32x r0 = ctx.opad.h[DGST_R0];
    const u32x r1 = ctx.opad.h[DGST_R1];
    const u32x r2 = ctx.opad.h[DGST_R2];
    const u32x r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m16511_sxx (KERN_ATTR_VECTOR_ESALT (jwt_t))
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

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha256_hmac_ctx_t ctx;

    sha256_hmac_init (&ctx, w, pw_len);

    sha256_hmac_update_global_swap (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt_len);

    sha256_hmac_final (&ctx);

    const u32x r0 = ctx.opad.h[DGST_R0];
    const u32x r1 = ctx.opad.h[DGST_R1];
    const u32x r2 = ctx.opad.h[DGST_R2];
    const u32x r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
