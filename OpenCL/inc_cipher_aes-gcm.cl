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

DECLSPEC void AES_GCM_inc32 (PRIVATE_AS u32 *block)
{
  block[3] += 1;
}

DECLSPEC void AES_GCM_xor_block (PRIVATE_AS u32 *dst, PRIVATE_AS const u32 *src)
{
  dst[0] ^= src[0];
  dst[1] ^= src[1];
  dst[2] ^= src[2];
  dst[3] ^= src[3];
}

DECLSPEC void AES_GCM_gf_mult (PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *y, PRIVATE_AS u32 *z)
{
  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  u32 t[4];

  t[0] = y[0];
  t[1] = y[1];
  t[2] = y[2];
  t[3] = y[3];

  for (int i = 0; i < 4; i++)
  {
    const u32 tv = x[i];

    for (int j = 0; j < 32; j++)
    {
      if ((tv >> (31 - j)) & 1)
      {
        z[0] ^= t[0];
        z[1] ^= t[1];
        z[2] ^= t[2];
        z[3] ^= t[3];
      }

      const int m = t[3] & 1; // save lost bit

      t[3] = (t[2] << 31) | (t[3] >> 1);
      t[2] = (t[1] << 31) | (t[2] >> 1);
      t[1] = (t[0] << 31) | (t[1] >> 1);
      t[0] =            0 | (t[0] >> 1);

      t[0] ^= m * 0xe1000000;
    }
  }
}

DECLSPEC void AES_GCM_ghash (PRIVATE_AS const u32 *subkey, PRIVATE_AS const u32 *in, int in_len, PRIVATE_AS u32 *out)
{
  int i;
  int j;

  for (i = 0, j = 0; i < in_len - 15; i += 16, j += 4)
  {
    u32 t2[4];

    t2[0] = in[j + 0];
    t2[1] = in[j + 1];
    t2[2] = in[j + 2];
    t2[3] = in[j + 3];

    AES_GCM_xor_block (out, t2);

    u32 tmp[4];

    AES_GCM_gf_mult (out, subkey, tmp);

    out[0] = tmp[0];
    out[1] = tmp[1];
    out[2] = tmp[2];
    out[3] = tmp[3];
  }

  const int left = in_len - i;

  if (left > 0)
  {
    u32 t2[4];

    t2[0] = (left >  0) ? in[j + 0] : 0;
    t2[1] = (left >  4) ? in[j + 1] : 0;
    t2[2] = (left >  8) ? in[j + 2] : 0;
    t2[3] = (left > 12) ? in[j + 3] : 0;

    AES_GCM_xor_block (out, t2);

    u32 tmp[4];

    AES_GCM_gf_mult (out, subkey, tmp);

    out[0] = tmp[0];
    out[1] = tmp[1];
    out[2] = tmp[2];
    out[3] = tmp[3];
  }
}

DECLSPEC void AES_GCM_ghash_global (PRIVATE_AS const u32 *subkey, GLOBAL_AS const u32 *in, int in_len, PRIVATE_AS u32 *out)
{
  int i;
  int j;

  for (i = 0, j = 0; i < in_len - 15; i += 16, j += 4)
  {
    u32 t2[4];

    t2[0] = in[j + 0];
    t2[1] = in[j + 1];
    t2[2] = in[j + 2];
    t2[3] = in[j + 3];

    AES_GCM_xor_block (out, t2);

    u32 tmp[4];

    AES_GCM_gf_mult (out, subkey, tmp);

    out[0] = tmp[0];
    out[1] = tmp[1];
    out[2] = tmp[2];
    out[3] = tmp[3];
  }

  const int left = in_len - i;

  if (left > 0)
  {
    u32 t2[4];

    t2[0] = (left >  0) ? in[j + 0] : 0;
    t2[1] = (left >  4) ? in[j + 1] : 0;
    t2[2] = (left >  8) ? in[j + 2] : 0;
    t2[3] = (left > 12) ? in[j + 3] : 0;

    AES_GCM_xor_block (out, t2);

    u32 tmp[4];

    AES_GCM_gf_mult (out, subkey, tmp);

    out[0] = tmp[0];
    out[1] = tmp[1];
    out[2] = tmp[2];
    out[3] = tmp[3];
  }
}

DECLSPEC void AES_GCM_Init (PRIVATE_AS  const u32 *ukey, int key_len, PRIVATE_AS u32 *key, PRIVATE_AS u32 *subkey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
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

DECLSPEC void AES_GCM_Prepare_J0 (PRIVATE_AS const u32 *iv, int iv_len, PRIVATE_AS const u32 *subkey, PRIVATE_AS u32 *J0)
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
    AES_GCM_ghash (subkey, iv, iv_len, J0);

    u32 len_buf[4] = { 0 };

    len_buf[3] = iv_len * 8;

    AES_GCM_ghash (subkey, len_buf, 16, J0);
  }
}

DECLSPEC void AES_GCM_gctr (PRIVATE_AS const u32 *key, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *in, int in_len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  PRIVATE_AS const u32 *xpos = (PRIVATE_AS u32 *) in;
  PRIVATE_AS       u32 *ypos = (PRIVATE_AS u32 *) out;

  u32 iv_buf[4];

  iv_buf[0] = iv[0];
  iv_buf[1] = iv[1];
  iv_buf[2] = iv[2];
  iv_buf[3] = iv[3];

  const u32 n = in_len / 16;

  for (u32 i = 0; i < n; i++)
  {
    AES256_encrypt (key, iv_buf, ypos, s_te0, s_te1, s_te2, s_te3, s_te4);

    AES_GCM_xor_block (ypos, xpos);

    xpos += 4;
    ypos += 4;

    AES_GCM_inc32 (iv_buf);
  }

  // this is not byte accurate but 4-byte accurate. needs fix?

  int last = in + (in_len/4) - xpos;

  if (last)
  {
    u32 tmp[4] = { 0 };

    AES256_encrypt (key, iv_buf, tmp, s_te0, s_te1, s_te2, s_te3, s_te4);

    if (last >= 1) *ypos++ = *xpos++ ^ tmp[0];
    if (last >= 2) *ypos++ = *xpos++ ^ tmp[1];
    if (last >= 3) *ypos++ = *xpos++ ^ tmp[2];
  }
}

DECLSPEC void AES_GCM_GCTR (PRIVATE_AS u32 *key, PRIVATE_AS u32 *J0, PRIVATE_AS const u32 *in, int in_len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 J0_incr[4];

  J0_incr[0] = J0[0];
  J0_incr[1] = J0[1];
  J0_incr[2] = J0[2];
  J0_incr[3] = J0[3];

  AES_GCM_gctr (key, J0_incr, in, in_len, out, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void AES_GCM_GHASH (PRIVATE_AS const u32 *subkey, PRIVATE_AS const u32 *aad_buf, int aad_len, PRIVATE_AS const u32 *enc_buf, int enc_len, PRIVATE_AS u32 *out)
{
  out[0] = 0;
  out[1] = 0;
  out[2] = 0;
  out[3] = 0;

  AES_GCM_ghash (subkey, aad_buf, aad_len, out);

  AES_GCM_ghash (subkey, enc_buf, enc_len, out);

  u32 len_buf[4];

  // still not fully correct if len > 32 bit
  len_buf[0] = aad_len >> 29;
  len_buf[1] = aad_len <<  3;
  len_buf[2] = enc_len >> 29;
  len_buf[3] = enc_len <<  3;

  AES_GCM_ghash (subkey, len_buf, 16, out);
}

DECLSPEC void AES_GCM_GHASH_GLOBAL (PRIVATE_AS const u32 *subkey, PRIVATE_AS const u32 *aad_buf, int aad_len, GLOBAL_AS const u32 *enc_buf, int enc_len, PRIVATE_AS u32 *out)
{
  out[0] = 0;
  out[1] = 0;
  out[2] = 0;
  out[3] = 0;

  AES_GCM_ghash (subkey, aad_buf, aad_len, out);

  AES_GCM_ghash_global (subkey, enc_buf, enc_len, out);

  u32 len_buf[4];

  // still not fully correct if len > 32 bit
  len_buf[0] = aad_len >> 29;
  len_buf[1] = aad_len <<  3;
  len_buf[2] = enc_len >> 29;
  len_buf[3] = enc_len <<  3;

  AES_GCM_ghash (subkey, len_buf, 16, out);
}
