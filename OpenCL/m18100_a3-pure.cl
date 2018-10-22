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
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"

__kernel void m18100_mxx (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __constant const u32x *words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
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

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = 8;

  u32x s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_hmac_ctx_vector_t ctx;

    sha1_hmac_init_vector (&ctx, w, pw_len);

    sha1_hmac_update_vector (&ctx, s, salt_len);

    sha1_hmac_final_vector (&ctx);

    // initialize a buffer for the otp code
    u32 otp_code = 0;

    // grab 4 consecutive bytes of the hash, starting at offset
    switch (ctx.opad.h[4] & 15)
    {
      case  0: otp_code = ctx.opad.h[0];                              break;
      case  1: otp_code = ctx.opad.h[0] <<  8 | ctx.opad.h[1] >> 24;  break;
      case  2: otp_code = ctx.opad.h[0] << 16 | ctx.opad.h[1] >> 16;  break;
      case  3: otp_code = ctx.opad.h[0] << 24 | ctx.opad.h[1] >>  8;  break;
      case  4: otp_code = ctx.opad.h[1];                              break;
      case  5: otp_code = ctx.opad.h[1] <<  8 | ctx.opad.h[2] >> 24;  break;
      case  6: otp_code = ctx.opad.h[1] << 16 | ctx.opad.h[2] >> 16;  break;
      case  7: otp_code = ctx.opad.h[1] << 24 | ctx.opad.h[2] >>  8;  break;
      case  8: otp_code = ctx.opad.h[2];                              break;
      case  9: otp_code = ctx.opad.h[2] <<  8 | ctx.opad.h[3] >> 24;  break;
      case 10: otp_code = ctx.opad.h[2] << 16 | ctx.opad.h[3] >> 16;  break;
      case 11: otp_code = ctx.opad.h[2] << 24 | ctx.opad.h[3] >>  8;  break;
      case 12: otp_code = ctx.opad.h[3];                              break;
      case 13: otp_code = ctx.opad.h[3] <<  8 | ctx.opad.h[4] >> 24;  break;
      case 14: otp_code = ctx.opad.h[3] << 16 | ctx.opad.h[4] >> 16;  break;
      case 15: otp_code = ctx.opad.h[3] << 24 | ctx.opad.h[4] >>  8;  break;
    }

    // take only the lower 31 bits
    otp_code &= 0x7fffffff;

    // we want to generate only 6 digits of code
    otp_code %= 1000000;

    COMPARE_M_SIMD (otp_code, 0, 0, 0);
  }
}

__kernel void m18100_sxx (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __constant const u32x *words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
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

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = 8;

  u32x s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_hmac_ctx_vector_t ctx;

    sha1_hmac_init_vector (&ctx, w, pw_len);

    sha1_hmac_update_vector (&ctx, s, salt_len);

    sha1_hmac_final_vector (&ctx);

    // initialize a buffer for the otp code
    u32 otp_code = 0;

    // grab 4 consecutive bytes of the hash, starting at offset
    switch (ctx.opad.h[4] & 15)
    {
      case  0: otp_code = ctx.opad.h[0];                              break;
      case  1: otp_code = ctx.opad.h[0] <<  8 | ctx.opad.h[1] >> 24;  break;
      case  2: otp_code = ctx.opad.h[0] << 16 | ctx.opad.h[1] >> 16;  break;
      case  3: otp_code = ctx.opad.h[0] << 24 | ctx.opad.h[1] >>  8;  break;
      case  4: otp_code = ctx.opad.h[1];                              break;
      case  5: otp_code = ctx.opad.h[1] <<  8 | ctx.opad.h[2] >> 24;  break;
      case  6: otp_code = ctx.opad.h[1] << 16 | ctx.opad.h[2] >> 16;  break;
      case  7: otp_code = ctx.opad.h[1] << 24 | ctx.opad.h[2] >>  8;  break;
      case  8: otp_code = ctx.opad.h[2];                              break;
      case  9: otp_code = ctx.opad.h[2] <<  8 | ctx.opad.h[3] >> 24;  break;
      case 10: otp_code = ctx.opad.h[2] << 16 | ctx.opad.h[3] >> 16;  break;
      case 11: otp_code = ctx.opad.h[2] << 24 | ctx.opad.h[3] >>  8;  break;
      case 12: otp_code = ctx.opad.h[3];                              break;
      case 13: otp_code = ctx.opad.h[3] <<  8 | ctx.opad.h[4] >> 24;  break;
      case 14: otp_code = ctx.opad.h[3] << 16 | ctx.opad.h[4] >> 16;  break;
      case 15: otp_code = ctx.opad.h[3] << 24 | ctx.opad.h[4] >>  8;  break;
    }

    // take only the lower 31 bits
    otp_code &= 0x7fffffff;

    // we want to generate only 6 digits of code
    otp_code %= 1000000;

    COMPARE_S_SIMD (otp_code, 0, 0, 0);
  }
}
