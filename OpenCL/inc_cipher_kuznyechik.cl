/*                                                                *
 * This is an OpenCL implementation of the encryption algorithm:  *
 *                                                                *
 *   GOST R 34.12-2015 Kuznyechik by A.S.Kuzmin and A.A.Nechaev   *
 *                                                                *
 * Author of the original C implementation:                       *
 *                                                                *
 *   Markku-Juhani O. Saarinen <mjos@iki.fi>                      *
 *   https://github.com/mjosaarinen/kuznechik                     *
 *                                                                *
 * Adapted for GPU use with hashcat by Ruslan Yushaev.            *
 *                                                                *
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_cipher_kuznyechik.h"

#define extract_byte(x,n) (((x) >> (8 * (n))) & 0xff)

#define k_lookup(w,sbox)                      \
  for (int i = 0; i < 4; i++)                 \
    w[i] = sbox[extract_byte (w[i], 0)] <<  0 \
         | sbox[extract_byte (w[i], 1)] <<  8 \
         | sbox[extract_byte (w[i], 2)] << 16 \
         | sbox[extract_byte (w[i], 3)] << 24

#define k_xor(n)                      \
  for (int i = (n); i > 0; i /= 2)    \
  {                                   \
    z ^= x * (i % 2);                 \
    x = (x << 1) ^ ((x >> 7) * 0xc3); \
    x &= 0xff;                        \
  }

DECLSPEC void kuznyechik_linear (u32 *w)
{
  // used in k_xor macro
  u32 x;
  u32 z;

  for (int i = 0; i < 16; i++)
  {
    z = 0;

    // k_xor (1) yields the same result as a simple xor
    x = extract_byte (w[3], 3); z ^= x;
    x = extract_byte (w[3], 2); k_xor (148);
    x = extract_byte (w[3], 1); k_xor (32);
    x = extract_byte (w[3], 0); k_xor (133);
    x = extract_byte (w[2], 3); k_xor (16);
    x = extract_byte (w[2], 2); k_xor (194);
    x = extract_byte (w[2], 1); k_xor (192);
    x = extract_byte (w[2], 0); z ^= x;
    x = extract_byte (w[1], 3); k_xor (251);
    x = extract_byte (w[1], 2); z ^= x;
    x = extract_byte (w[1], 1); k_xor (192);
    x = extract_byte (w[1], 0); k_xor (194);
    x = extract_byte (w[0], 3); k_xor (16);
    x = extract_byte (w[0], 2); k_xor (133);
    x = extract_byte (w[0], 1); k_xor (32);
    x = extract_byte (w[0], 0); k_xor (148);

    // right-shift data block, prepend calculated byte
    w[3] = (w[3] << 8) | (w[2] >> 24);
    w[2] = (w[2] << 8) | (w[1] >> 24);
    w[1] = (w[1] << 8) | (w[0] >> 24);
    w[0] = (w[0] << 8) | z;
  }
}

DECLSPEC void kuznyechik_linear_inv (u32 *w)
{
  // used in k_xor macro
  u32 x;
  u32 z;

  for (int i = 0; i < 16; i++)
  {
    z = extract_byte (w[0], 0);

    //left-shift data block
    w[0] = (w[0] >> 8) | (w[1] << 24);
    w[1] = (w[1] >> 8) | (w[2] << 24);
    w[2] = (w[2] >> 8) | (w[3] << 24);
    w[3] = (w[3] >> 8);

    x = extract_byte (w[0], 0); k_xor (148);
    x = extract_byte (w[0], 1); k_xor (32);
    x = extract_byte (w[0], 2); k_xor (133);
    x = extract_byte (w[0], 3); k_xor (16);
    x = extract_byte (w[1], 0); k_xor (194);
    x = extract_byte (w[1], 1); k_xor (192);
    x = extract_byte (w[1], 2); z ^= x;
    x = extract_byte (w[1], 3); k_xor (251);
    x = extract_byte (w[2], 0); z ^= x;
    x = extract_byte (w[2], 1); k_xor (192);
    x = extract_byte (w[2], 2); k_xor (194);
    x = extract_byte (w[2], 3); k_xor (16);
    x = extract_byte (w[3], 0); k_xor (133);
    x = extract_byte (w[3], 1); k_xor (32);
    x = extract_byte (w[3], 2); k_xor (148);

    //append calculated byte
    w[3] |= (z << 24);
  }
}

DECLSPEC void kuznyechik_set_key (u32 *ks, const u32 *ukey)
{
  u32 counter[4];
  u32 x[4];
  u32 y[4];
  u32 z[4];

  x[0] = ukey[0];
  x[1] = ukey[1];
  x[2] = ukey[2];
  x[3] = ukey[3];

  y[0] = ukey[4];
  y[1] = ukey[5];
  y[2] = ukey[6];
  y[3] = ukey[7];

  ks[0] = ukey[0];
  ks[1] = ukey[1];
  ks[2] = ukey[2];
  ks[3] = ukey[3];
  ks[4] = ukey[4];
  ks[5] = ukey[5];
  ks[6] = ukey[6];
  ks[7] = ukey[7];

  for (int i = 1; i <= 32; i++)
  {
    counter[0] = 0;
    counter[1] = 0;
    counter[2] = 0;
    counter[3] = (i << 24);

    kuznyechik_linear (counter);

    z[0] = x[0] ^ counter[0];
    z[1] = x[1] ^ counter[1];
    z[2] = x[2] ^ counter[2];
    z[3] = x[3] ^ counter[3];

    k_lookup (z, k_sbox);

    kuznyechik_linear (z);

    z[0] ^= y[0];
    z[1] ^= y[1];
    z[2] ^= y[2];
    z[3] ^= y[3];

    y[0] = x[0];
    y[1] = x[1];
    y[2] = x[2];
    y[3] = x[3];

    x[0] = z[0];
    x[1] = z[1];
    x[2] = z[2];
    x[3] = z[3];

    if ((i & 7) == 0)
    {
      ks[i + 0] = x[0];
      ks[i + 1] = x[1];
      ks[i + 2] = x[2];
      ks[i + 3] = x[3];

      ks[i + 4] = y[0];
      ks[i + 5] = y[1];
      ks[i + 6] = y[2];
      ks[i + 7] = y[3];
    }
  }
}

DECLSPEC void kuznyechik_encrypt (const u32 *ks, const u32 *in, u32 *out)
{
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];

  for (int i = 0; i < 9; i++)
  {
    out[0] ^= ks[4 * i + 0];
    out[1] ^= ks[4 * i + 1];
    out[2] ^= ks[4 * i + 2];
    out[3] ^= ks[4 * i + 3];

    k_lookup (out, k_sbox);

    kuznyechik_linear (out);
  }

  out[0] ^= ks[4 * 9 + 0];
  out[1] ^= ks[4 * 9 + 1];
  out[2] ^= ks[4 * 9 + 2];
  out[3] ^= ks[4 * 9 + 3];
}

DECLSPEC void kuznyechik_decrypt (const u32 *ks, const u32 *in, u32 *out)
{
  out[0] = in[0];
  out[1] = in[1];
  out[2] = in[2];
  out[3] = in[3];

  out[0] ^= ks[4 * 9 + 0];
  out[1] ^= ks[4 * 9 + 1];
  out[2] ^= ks[4 * 9 + 2];
  out[3] ^= ks[4 * 9 + 3];

  for (int i = 8; i >= 0; i--)
  {
    kuznyechik_linear_inv (out);

    k_lookup (out, k_sbox_inv);

    out[0] ^= ks[4 * i + 0];
    out[1] ^= ks[4 * i + 1];
    out[2] ^= ks[4 * i + 2];
    out[3] ^= ks[4 * i + 3];
  }
}

#undef k_xor
#undef k_lookup
#undef extract_byte
