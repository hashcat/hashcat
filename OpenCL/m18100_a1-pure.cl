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

__kernel void m18100_mxx (KERN_ATTR_BASIC ())
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

  const u32 pw_len = pws[gid].pw_len & 255;

  u32 w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = swap32_S (pws[gid].i[idx]);
  }

  const u32 salt_len = 8;

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

    COMPARE_M_SCALAR (otp_code, 0, 0, 0);
  }
}

__kernel void m18100_sxx (KERN_ATTR_BASIC ())
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

  const u32 pw_len = pws[gid].pw_len & 255;

  u32 w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = swap32_S (pws[gid].i[idx]);
  }

  const u32 salt_len = 8;

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

    COMPARE_S_SCALAR (otp_code, 0, 0, 0);
  }
}
