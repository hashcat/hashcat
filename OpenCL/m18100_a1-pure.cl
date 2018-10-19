/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha1.cl"

__kernel void m18100_mxx (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
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

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = swap32_S (pws[gid].i[idx]);
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
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
      c[idx] = swap32_S (combs_buf[il_pos].i[idx]);
    }

    switch_buffer_by_offset_1x64_be_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 64; i++)
    {
      c[i] |= w[i];
    }

    sha1_hmac_ctx_t ctx;

    sha1_hmac_init (&ctx, c, pw_len + comb_len);

    sha1_hmac_update (&ctx, s, salt_len);

    sha1_hmac_final (&ctx);

    // calculate the offset using the least 4 bits of the last byte of our hash
    const u32x otp_offset = ctx.opad.h[4] & 0xf;

    // initialize a buffer for the otp code
    u32 otp_code = 0;

    // grab 4 consecutive bytes of the hash, starting at offset
    // on some systems, &3 is faster than %4, so we will use it in our switch()
    switch (otp_offset & 3)
    {
    case 1:
      otp_code = ((ctx.opad.h[otp_offset/4] & 0x00ffffff) <<  8) | ((ctx.opad.h[otp_offset/4+1] & 0xff000000) >> 24);
      break;
    case 2:
      otp_code = ((ctx.opad.h[otp_offset/4] & 0x0000ffff) << 16) | ((ctx.opad.h[otp_offset/4+1] & 0xffff0000) >> 16);
      break;
    case 3:
      otp_code = ((ctx.opad.h[otp_offset/4] & 0x000000ff) << 24) | ((ctx.opad.h[otp_offset/4+1] & 0xffffff00) >>  8);
      break;
    default:
      otp_code = ctx.opad.h[otp_offset/4];
      break;
    }
    // take only the lower 31 bits
    otp_code &= 0x7fffffff;
    // we want to generate only 6 digits of code
    otp_code %= 1000000;

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SCALAR (otp_code, 0, 0, 0);
  }
}

__kernel void m18100_sxx (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
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

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = swap32_S (pws[gid].i[idx]);
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
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
      c[idx] = swap32_S (combs_buf[il_pos].i[idx]);
    }

    switch_buffer_by_offset_1x64_be_S (c, pw_len);

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 64; i++)
    {
      c[i] |= w[i];
    }

    sha1_hmac_ctx_t ctx;

    sha1_hmac_init (&ctx, c, pw_len + comb_len);

    sha1_hmac_update (&ctx, s, salt_len);

    sha1_hmac_final (&ctx);

    // calculate the offset using the least 4 bits of the last byte of our hash
    const u32x otp_offset = ctx.opad.h[4] & 0xf;

    // initialize a buffer for the otp code
    u32 otp_code = 0;

    // grab 4 consecutive bytes of the hash, starting at offset
    // on some systems, &3 is faster than %4, so we will use it in our switch()
    switch (otp_offset & 3)
    {
    case 1:
      otp_code = ((ctx.opad.h[otp_offset/4] & 0x00ffffff) <<  8) | ((ctx.opad.h[otp_offset/4+1] & 0xff000000) >> 24);
      break;
    case 2:
      otp_code = ((ctx.opad.h[otp_offset/4] & 0x0000ffff) << 16) | ((ctx.opad.h[otp_offset/4+1] & 0xffff0000) >> 16);
      break;
    case 3:
      otp_code = ((ctx.opad.h[otp_offset/4] & 0x000000ff) << 24) | ((ctx.opad.h[otp_offset/4+1] & 0xffffff00) >>  8);
      break;
    default:
      otp_code = ctx.opad.h[otp_offset/4];
      break;
    }
    // take only the lower 31 bits
    otp_code &= 0x7fffffff;
    // we want to generate only 6 digits of code
    otp_code %= 1000000;

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SCALAR (otp_code, 0, 0, 0);
  }
}
