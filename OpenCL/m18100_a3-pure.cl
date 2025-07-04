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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif

DECLSPEC void _totp_calculate (PRIVATE_AS u32x *code, PRIVATE_AS const u32x *w, const u32 pw_len, PRIVATE_AS const u32x *s, const u32 salt_len)
{
  sha1_hmac_ctx_vector_t ctx;

  sha1_hmac_init_vector (&ctx, w, pw_len);

  sha1_hmac_update_vector (&ctx, s, salt_len);

  sha1_hmac_final_vector (&ctx);

  // initialize a buffer for the otp code
  u32x otp_code = 0;

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
  *code = otp_code % 1000000;
}

KERNEL_FQ KERNEL_FA void m18100_mxx (KERN_ATTR_VECTOR ())
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

  const u32 count = salt_bufs[SALT_POS_HOST].salt_len / 16;

  u32x s[64] = { 0 };

  for (u32 i = 0; i < count; i += 1)
  {
    s[16 * i + 0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[4 * i + 0]);
    s[16 * i + 1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[4 * i + 1]);
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  if (count == 1)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      u32x otp_code0;

      _totp_calculate (&otp_code0, w, pw_len, s, 8);

      COMPARE_M_SIMD (otp_code0, 0, 0, 0);
    }
  }
  else if (count == 2)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      u32x otp_code0, otp_code1;

      _totp_calculate (&otp_code0, w, pw_len, s +  0, 8);
      _totp_calculate (&otp_code1, w, pw_len, s + 16, 8);

      COMPARE_M_SIMD (otp_code0, otp_code1, 0, 0);
    }
  }
  else if (count == 3)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      u32x otp_code0, otp_code1, otp_code2;

      _totp_calculate (&otp_code0, w, pw_len, s +  0, 8);
      _totp_calculate (&otp_code1, w, pw_len, s + 16, 8);
      _totp_calculate (&otp_code2, w, pw_len, s + 32, 8);

      COMPARE_M_SIMD (otp_code0, otp_code1, otp_code2, 0);
    }
  }
  else if (count == 4)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      u32x otp_code0, otp_code1, otp_code2, otp_code3;

      _totp_calculate (&otp_code0, w, pw_len, s +  0, 8);
      _totp_calculate (&otp_code1, w, pw_len, s + 16, 8);
      _totp_calculate (&otp_code2, w, pw_len, s + 32, 8);
      _totp_calculate (&otp_code3, w, pw_len, s + 48, 8);

      COMPARE_M_SIMD (otp_code0, otp_code1, otp_code2, otp_code3);
    }
  }
}

KERNEL_FQ KERNEL_FA void m18100_sxx (KERN_ATTR_VECTOR ())
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

  const u32 count = salt_bufs[SALT_POS_HOST].salt_len / 16;

  u32x s[64] = { 0 };

  for (u32 i = 0; i < count; i += 1)
  {
    s[16 * i + 0] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[4 * i + 0]);
    s[16 * i + 1] = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[4 * i + 1]);
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  if (count == 1)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      u32x otp_code0;

      _totp_calculate (&otp_code0, w, pw_len, s, 8);

      COMPARE_S_SIMD (otp_code0, 0, 0, 0);
    }
  }
  else if (count == 2)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      u32x otp_code0, otp_code1;

      _totp_calculate (&otp_code0, w, pw_len, s, 8);

      if (MATCHES_ONE_VS(otp_code0, search[0]))
      {
        _totp_calculate (&otp_code1, w, pw_len, s + 16, 8);

        COMPARE_S_SIMD (otp_code0, otp_code1, 0, 0);
      }
    }
  }
  else if (count == 3)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      u32x otp_code0, otp_code1, otp_code2;

      _totp_calculate (&otp_code0, w, pw_len, s, 8);

      if (MATCHES_ONE_VS(otp_code0, search[0]))
      {
        _totp_calculate (&otp_code1, w, pw_len, s + 16, 8);

        if (MATCHES_ONE_VS(otp_code1, search[1]))
        {
          _totp_calculate (&otp_code2, w, pw_len, s + 32, 8);

          COMPARE_S_SIMD (otp_code0, otp_code1, otp_code2, 0);
        }
      }
    }
  }
  else if (count == 4)
  {
    for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
    {
      const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

      const u32x w0 = w0l | w0r;

      w[0] = w0;

      u32x otp_code0, otp_code1, otp_code2, otp_code3;

      _totp_calculate (&otp_code0, w, pw_len, s, 8);

      if (MATCHES_ONE_VS(otp_code0, search[0]))
      {
        _totp_calculate (&otp_code1, w, pw_len, s + 16, 8);

        if (MATCHES_ONE_VS(otp_code1, search[1]))
        {
          _totp_calculate (&otp_code2, w, pw_len, s + 32, 8);

          if (MATCHES_ONE_VS(otp_code2, search[2]))
          {
            _totp_calculate (&otp_code3, w, pw_len, s + 48, 8);

            COMPARE_S_SIMD (otp_code0, otp_code1, otp_code2, otp_code3);
          }
        }
      }
    }
  }
}
