/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_aes.h"
#include "inc_cipher_aes-gcm.h"

DECLSPEC void AES_GCM_shift_right_block(uchar *block)
{
  u32 val;

  uchar16 *v = (uchar16 *) block;
  uint4   *p = (uint4 *) block;

  val = hc_swap32_S (p[0].w);
  val >>= 1;
  if (v[0].sb & 0x01) val |= 0x80000000;
  p[0].w = hc_swap32_S (val);

  val = hc_swap32_S (p[0].z);
  val >>= 1;
  if (v[0].s7 & 0x01) val |= 0x80000000;
  p[0].z = hc_swap32_S (val);

  val = hc_swap32_S (p[0].y);
  val >>= 1;
  if (v[0].s3 & 0x01) val |= 0x80000000;
  p[0].y = hc_swap32_S (val);

  val = hc_swap32_S (p[0].x);
  val >>= 1;
  p[0].x = hc_swap32_S (val);
}

DECLSPEC void AES_GCM_inc32 (u32 *block)
{
  block[3] += 0x00000001;
}

DECLSPEC void AES_GCM_xor_block (u32 *dst, const u32 *src)
{
  *dst++ ^= *src++;
  *dst++ ^= *src++;
  *dst++ ^= *src++;
  *dst++ ^= *src++;
}

DECLSPEC void AES_GCM_gf_mult (const uchar16 *x, const uchar16 *y, uchar16 *z)
{
  u32 i, j, k;

  z[0] = 0;
  uchar16 v = y[0].s32107654ba98fedc;

  u8 x_char[16] = { x[0].s3, x[0].s2, x[0].s1, x[0].s0, x[0].s7, x[0].s6, x[0].s5, x[0].s4, x[0].sb, x[0].sa, x[0].s9, x[0].s8, x[0].sf, x[0].se, x[0].sd, x[0].sc };

  u8 *v_char = (u8 *) &v;

  for (i = 0; i < 16; i++)
  {
    for (j = 0; j < 8; j++)
    {
      if (x_char[i] & 1 << (7 - j))
      {
        z[0] ^= v;
      }

      if (v.sf & 0x01)
      {
        AES_GCM_shift_right_block(v_char);
        v.s0 ^= 0xe1;
      }
      else
      {
        AES_GCM_shift_right_block(v_char);
      }
    }
  }
}

DECLSPEC void AES_GCM_ghash (const u32 *subkey, const u32 *in, u32 in_len, u32 *out)
{
  u32 m = in_len / 16;

  u32 *xpos = in;

  u32 tmp[4] = { 0 };

  for (u32 i = 0; i < m; i++)
  {
    AES_GCM_xor_block (out, xpos);

    xpos += 4;

    AES_GCM_gf_mult (out, subkey, tmp);

    tmp[0] = hc_swap32_S (tmp[0]);
    tmp[1] = hc_swap32_S (tmp[1]);
    tmp[2] = hc_swap32_S (tmp[2]);
    tmp[3] = hc_swap32_S (tmp[3]);

    out[0] = tmp[0];
    out[1] = tmp[1];
    out[2] = tmp[2];
    out[3] = tmp[3];
  }

  if (in + (in_len/4) > xpos)
  {
    u32 last = in + (in_len/4) - xpos;

    for (u32 i = 0; i < last; i++)
    {
      tmp[i] = xpos[i];
    }

    for (u32 i = last; i < 4; i++)
    {
      tmp[i] = 0;
    }

    AES_GCM_xor_block (out, tmp);

    AES_GCM_gf_mult (out, subkey, tmp);

    out[0] = tmp[0];
    out[1] = tmp[1];
    out[2] = tmp[2];
    out[3] = tmp[3];
  }
}

DECLSPEC void AES_GCM_Init (const u32 *ukey, u32 key_len, u32 *key, u32 *subkey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  if (key_len == 128)
  {
    AES128_set_encrypt_key (key, ukey, s_te0, s_te1, s_te2, s_te3);

    AES192_encrypt (key, subkey, subkey, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
  else if (key_len == 192)
  {
    AES192_set_encrypt_key (key, ukey, s_te0, s_te1, s_te2, s_te3);

    AES192_encrypt (key, subkey, subkey, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
  else if (key_len == 256)
  {
    AES256_set_encrypt_key (key, ukey, s_te0, s_te1, s_te2, s_te3);

    AES256_encrypt (key, subkey, subkey, s_te0, s_te1, s_te2, s_te3, s_te4);
  }
}

DECLSPEC void AES_GCM_Prepare_J0 (const u32 *iv, u32 iv_len, const u32 *subkey, u32 *J0)
{
  if (iv_len == 12)
  {
    J0[0] = iv[0];
    J0[1] = iv[1];
    J0[2] = iv[2];
    J0[3] = 0x00000001;
  }
  else
  {
    J0[0] = iv[0];
    J0[1] = iv[1];
    J0[2] = iv[2];
    J0[3] = iv[3];

    u32 len_buf[4] = { 0 };

    len_buf[3] = iv_len * 8;

    AES_GCM_ghash (subkey, len_buf, 16, J0);
  }
}

DECLSPEC void AES_GCM_gctr (const u32 *key, const u32 *iv, const u32 *in, u32 in_len, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  const u32 *xpos = in;
  u32 *ypos = out;

  u32 n = in_len / 16;

  u32 iv_buf[4] = { iv[0], iv[1], iv[2], iv[3] };

  for (u32 i = 0; i < n; i++)
  {
    AES256_encrypt (key, iv_buf, ypos, s_te0, s_te1, s_te2, s_te3, s_te4);

    AES_GCM_xor_block (ypos, xpos);

    xpos += 4;
    ypos += 4;

    AES_GCM_inc32 (iv_buf);
  }

  u32 last = in + (in_len/4) - xpos;

  if (last)
  {
    u32 tmp[4] = { 0 };

    AES256_encrypt (key, iv_buf, tmp, s_te0, s_te1, s_te2, s_te3, s_te4);

    if (last >= 1) *ypos++ = *xpos++ ^ tmp[0];
    if (last >= 2) *ypos++ = *xpos++ ^ tmp[1];
    if (last >= 3) *ypos++ = *xpos++ ^ tmp[2];
  }
}

DECLSPEC void AES_GCM_GCTR (u32 *key, u32 *J0, u32 *in, u32 in_len, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 J0_incr[4] = {
    J0[0],
    J0[1],
    J0[2],
    J0[3],
  };

  AES_GCM_gctr (key, J0_incr, in, in_len, out, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void AES_GCM_GHASH (const u32 *subkey, const u32 *aad_buf, u32 aad_len, u32 *enc_buf, u32 enc_len, u32 *out)
{
  u32 len_buf[4] = { 0 };

  out[0] = 0;
  out[1] = 0;
  out[2] = 0;
  out[3] = 0;

  AES_GCM_ghash (subkey, aad_buf, aad_len, out);

  // untested swap
  /*
  out[0] = hc_swap32_S (out[0]);
  out[1] = hc_swap32_S (out[1]);
  out[2] = hc_swap32_S (out[2]);
  out[3] = hc_swap32_S (out[3]);
  */

  AES_GCM_ghash (subkey, enc_buf, enc_len, out);

  out[0] = hc_swap32_S (out[0]);
  out[1] = hc_swap32_S (out[1]);
  out[2] = hc_swap32_S (out[2]);
  out[3] = hc_swap32_S (out[3]);

  len_buf[0] = aad_len * 8;
  len_buf[3] = enc_len * 8;

  AES_GCM_ghash (subkey, len_buf, 16, out);
}
