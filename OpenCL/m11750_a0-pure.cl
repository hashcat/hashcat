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
#include "inc_hash_streebog256.cl"
#endif

KERNEL_FQ void m11750_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef REAL_SHM

  LOCAL_VK u64a s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob256_sl64;

  #endif

  if (gid >= gid_max) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    streebog256_hmac_ctx_t ctx;

    streebog256_hmac_init_swap (&ctx, tmp.i, tmp.pw_len, s_sbob_sl64);

    streebog256_hmac_update (&ctx, s, salt_len);

    streebog256_hmac_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.opad.h[0]);
    const u32 r1 = h32_from_64_S (ctx.opad.h[0]);
    const u32 r2 = l32_from_64_S (ctx.opad.h[1]);
    const u32 r3 = h32_from_64_S (ctx.opad.h[1]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m11750_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef REAL_SHM

  LOCAL_VK u64a s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob256_sl64[0][i];
    s_sbob_sl64[1][i] = sbob256_sl64[1][i];
    s_sbob_sl64[2][i] = sbob256_sl64[2][i];
    s_sbob_sl64[3][i] = sbob256_sl64[3][i];
    s_sbob_sl64[4][i] = sbob256_sl64[4][i];
    s_sbob_sl64[5][i] = sbob256_sl64[5][i];
    s_sbob_sl64[6][i] = sbob256_sl64[6][i];
    s_sbob_sl64[7][i] = sbob256_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob256_sl64;

  #endif

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

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    streebog256_hmac_ctx_t ctx;

    streebog256_hmac_init_swap (&ctx, tmp.i, tmp.pw_len, s_sbob_sl64);

    streebog256_hmac_update (&ctx, s, salt_len);

    streebog256_hmac_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.opad.h[0]);
    const u32 r1 = h32_from_64_S (ctx.opad.h[0]);
    const u32 r2 = l32_from_64_S (ctx.opad.h[1]);
    const u32 r3 = h32_from_64_S (ctx.opad.h[1]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
