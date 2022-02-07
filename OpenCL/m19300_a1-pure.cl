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

typedef struct sha1_double_salt
{
  u32 salt1_buf[64];
  int salt1_len;

  u32 salt2_buf[64];
  int salt2_len;

} sha1_double_salt_t;

KERNEL_FQ void m19300_mxx (KERN_ATTR_ESALT (sha1_double_salt_t))
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

  const int salt2_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_len;

  u32 s2[64] = { 0 };

  for (int i = 0, idx = 0; i < salt2_len; i += 4, idx += 1)
  {
    s2[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[idx]);
  }

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt1_len);

  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx = ctx0;

    sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_update (&ctx, s2, salt2_len);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m19300_sxx (KERN_ATTR_ESALT (sha1_double_salt_t))
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

  const int salt2_len = esalt_bufs[DIGESTS_OFFSET_HOST].salt2_len;

  u32 s2[64] = { 0 };

  for (int i = 0, idx = 0; i < salt2_len; i += 4, idx += 1)
  {
    s2[idx] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].salt2_buf[idx]);
  }

  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].salt1_buf, esalt_bufs[DIGESTS_OFFSET_HOST].salt1_len);

  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    sha1_ctx_t ctx = ctx0;

    sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_update (&ctx, s2, salt2_len);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
