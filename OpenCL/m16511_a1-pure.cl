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
#include "inc_hash_sha256.cl"
#endif

typedef struct jwt
{
  u32 salt_buf[1024];
  u32 salt_len;

  u32 signature_len;

} jwt_t;

KERNEL_FQ void m16511_mxx (KERN_ATTR_ESALT (jwt_t))
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

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = hc_swap32_S (pws[gid].i[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;

    u32 c[64];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int idx = 0; idx < 64; idx++)
    {
      c[idx] = hc_swap32_S (combs_buf[il_pos].i[idx]);
    }

    switch_buffer_by_offset_1x64_be_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 64; i++)
    {
      c[i] |= w[i];
    }

    sha256_hmac_ctx_t ctx;

    sha256_hmac_init (&ctx, c, pw_len + comb_len);

    sha256_hmac_update_global_swap (&ctx, esalt_bufs[digests_offset].salt_buf, esalt_bufs[digests_offset].salt_len);

    sha256_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m16511_sxx (KERN_ATTR_ESALT (jwt_t))
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

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = hc_swap32_S (pws[gid].i[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    const u32 comb_len = combs_buf[il_pos].pw_len;

    u32 c[64];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int idx = 0; idx < 64; idx++)
    {
      c[idx] = hc_swap32_S (combs_buf[il_pos].i[idx]);
    }

    switch_buffer_by_offset_1x64_be_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 64; i++)
    {
      c[i] |= w[i];
    }

    sha256_hmac_ctx_t ctx;

    sha256_hmac_init (&ctx, c, pw_len + comb_len);

    sha256_hmac_update_global_swap (&ctx, esalt_bufs[digests_offset].salt_buf, esalt_bufs[digests_offset].salt_len);

    sha256_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
