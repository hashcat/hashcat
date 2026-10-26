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

// The message is always the 8 byte counter in s[0] and s[1], so the final blocks of the inner and
// the outer hash are fixed apart from a few words, and both are written out here. Handing s to
// sha1_hmac_update_vector () and sha1_hmac_final_vector () computes the same blocks, but Intel's
// compiler then spills this kernel heavily, which cost it most of its speed on an Arc A770.

DECLSPEC void _totp_calculate (PRIVATE_AS u32x *code, PRIVATE_AS const u32x *w, const u32 pw_len, PRIVATE_AS const u32x *s)
{
  sha1_hmac_ctx_vector_t ctx;

  sha1_hmac_init_vector (&ctx, w, pw_len);

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  w0[0] = s[0];
  w0[1] = s[1];
  w0[2] = 0x80000000;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 8) * 8;

  sha1_transform_vector (w0, w1, w2, w3, ctx.ipad.h);

  w0[0] = ctx.ipad.h[0];
  w0[1] = ctx.ipad.h[1];
  w0[2] = ctx.ipad.h[2];
  w0[3] = ctx.ipad.h[3];
  w1[0] = ctx.ipad.h[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  sha1_transform_vector (w0, w1, w2, w3, ctx.opad.h);

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

      _totp_calculate (&otp_code0, w, pw_len, s);

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

      _totp_calculate (&otp_code0, w, pw_len, s +  0);
      _totp_calculate (&otp_code1, w, pw_len, s + 16);

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

      _totp_calculate (&otp_code0, w, pw_len, s +  0);
      _totp_calculate (&otp_code1, w, pw_len, s + 16);
      _totp_calculate (&otp_code2, w, pw_len, s + 32);

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

      _totp_calculate (&otp_code0, w, pw_len, s +  0);
      _totp_calculate (&otp_code1, w, pw_len, s + 16);
      _totp_calculate (&otp_code2, w, pw_len, s + 32);
      _totp_calculate (&otp_code3, w, pw_len, s + 48);

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

      _totp_calculate (&otp_code0, w, pw_len, s);

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

      _totp_calculate (&otp_code0, w, pw_len, s);

      if (MATCHES_ONE_VS(otp_code0, search[0]))
      {
        _totp_calculate (&otp_code1, w, pw_len, s + 16);

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

      _totp_calculate (&otp_code0, w, pw_len, s);

      if (MATCHES_ONE_VS(otp_code0, search[0]))
      {
        _totp_calculate (&otp_code1, w, pw_len, s + 16);

        if (MATCHES_ONE_VS(otp_code1, search[1]))
        {
          _totp_calculate (&otp_code2, w, pw_len, s + 32);

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

      _totp_calculate (&otp_code0, w, pw_len, s);

      if (MATCHES_ONE_VS(otp_code0, search[0]))
      {
        _totp_calculate (&otp_code1, w, pw_len, s + 16);

        if (MATCHES_ONE_VS(otp_code1, search[1]))
        {
          _totp_calculate (&otp_code2, w, pw_len, s + 32);

          if (MATCHES_ONE_VS(otp_code2, search[2]))
          {
            _totp_calculate (&otp_code3, w, pw_len, s + 48);

            COMPARE_S_SIMD (otp_code0, otp_code1, otp_code2, otp_code3);
          }
        }
      }
    }
  }
}
