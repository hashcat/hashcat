/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// XSalsa20 stream cipher and Poly1305 one-time authenticator (NaCl secretbox
// primitives), after the TweetNaCl public-domain reference.

#define XSALSA20_ROTL32(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

CONSTANT_VK u8 xsalsa20_sigma[16] = { 101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107 };

CONSTANT_VK u32 poly1305_minusp[17] = { 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252 };

DECLSPEC u32 xsalsa20_ld32 (const u8 *x)
{
  u32 u = x[3];
  u = (u << 8) | x[2];
  u = (u << 8) | x[1];

  return (u << 8) | x[0];
}

DECLSPEC u32 xsalsa20_ld32_c (CONSTANT_AS const u8 *x)
{
  u32 u = x[3];
  u = (u << 8) | x[2];
  u = (u << 8) | x[1];

  return (u << 8) | x[0];
}

DECLSPEC void xsalsa20_st32 (u8 *x, u32 u)
{
  x[0] = u; u >>= 8;
  x[1] = u; u >>= 8;
  x[2] = u; u >>= 8;
  x[3] = u;
}

DECLSPEC void salsa20_core (u8 *out, const u8 *in, const u8 *k, CONSTANT_AS const u8 *c, const int h)
{
  u32 w[16];
  u32 x[16];
  u32 y[16];
  u32 t[4];

  for (int i = 0; i < 4; i++)
  {
    x[5 * i]      = xsalsa20_ld32_c (c + 4 * i);
    x[1 + i]      = xsalsa20_ld32 (k + 4 * i);
    x[6 + i]      = xsalsa20_ld32 (in + 4 * i);
    x[11 + i]     = xsalsa20_ld32 (k + 16 + 4 * i);
  }

  for (int i = 0; i < 16; i++) y[i] = x[i];

  for (int i = 0; i < 20; i++)
  {
    for (int j = 0; j < 4; j++)
    {
      for (int m = 0; m < 4; m++) t[m] = x[(5 * j + 4 * m) % 16];

      t[1] ^= XSALSA20_ROTL32 (t[0] + t[3],  7);
      t[2] ^= XSALSA20_ROTL32 (t[1] + t[0],  9);
      t[3] ^= XSALSA20_ROTL32 (t[2] + t[1], 13);
      t[0] ^= XSALSA20_ROTL32 (t[3] + t[2], 18);

      for (int m = 0; m < 4; m++) w[4 * j + (j + m) % 4] = t[m];
    }

    for (int m = 0; m < 16; m++) x[m] = w[m];
  }

  if (h)
  {
    for (int i = 0; i < 16; i++) x[i] += y[i];

    for (int i = 0; i < 4; i++)
    {
      x[5 * i] -= xsalsa20_ld32_c (c + 4 * i);
      x[6 + i] -= xsalsa20_ld32 (in + 4 * i);
    }

    for (int i = 0; i < 4; i++)
    {
      xsalsa20_st32 (out + 4 * i,      x[5 * i]);
      xsalsa20_st32 (out + 16 + 4 * i, x[6 + i]);
    }
  }
  else
  {
    for (int i = 0; i < 16; i++) xsalsa20_st32 (out + 4 * i, x[i] + y[i]);
  }
}

DECLSPEC void hsalsa20 (u8 *out, const u8 *in, const u8 *k)
{
  salsa20_core (out, in, k, xsalsa20_sigma, 1);
}

DECLSPEC void salsa20_xor (u8 *c, MAYBE_UNUSED const u8 *m, u64 b, const u8 *n, const u8 *k)
{
  if (b == 0) return;

  u8 z[16];
  u8 x[64];

  for (int i = 0; i < 16; i++) z[i] = 0;
  for (int i = 0; i < 8;  i++) z[i] = n[i];

  while (b >= 64)
  {
    salsa20_core (x, z, k, xsalsa20_sigma, 0);

    for (int i = 0; i < 64; i++) c[i] = (m ? m[i] : 0) ^ x[i];

    u32 u = 1;

    for (int i = 8; i < 16; i++)
    {
      u += (u32) z[i];
      z[i] = u;
      u >>= 8;
    }

    b -= 64;
    c += 64;

    if (m) m += 64;
  }

  if (b)
  {
    salsa20_core (x, z, k, xsalsa20_sigma, 0);

    for (u32 i = 0; i < b; i++) c[i] = (m ? m[i] : 0) ^ x[i];
  }
}

// XSalsa20 stream: 24-byte nonce, key derived through HSalsa20

DECLSPEC void xsalsa20_stream (u8 *c, u64 d, const u8 *n, const u8 *k)
{
  u8 s[32];

  hsalsa20 (s, n, k);

  salsa20_xor (c, 0, d, n + 16, s);
}

DECLSPEC void poly1305_add (u32 *h, const u32 *c)
{
  u32 u = 0;

  for (int j = 0; j < 17; j++)
  {
    u += h[j] + c[j];
    h[j] = u & 255;
    u >>= 8;
  }
}

DECLSPEC void poly1305_auth (u8 *out, const u8 *m, u64 n, const u8 *k)
{
  u32 x[17];
  u32 r[17];
  u32 h[17];
  u32 c[17];
  u32 g[17];

  for (int j = 0; j < 17; j++) r[j] = h[j] = 0;

  for (int j = 0; j < 16; j++) r[j] = k[j];

  r[ 3] &= 15;
  r[ 4] &= 252;
  r[ 7] &= 15;
  r[ 8] &= 252;
  r[11] &= 15;
  r[12] &= 252;
  r[15] &= 15;

  while (n > 0)
  {
    for (int j = 0; j < 17; j++) c[j] = 0;

    u32 j;

    for (j = 0; (j < 16) && (j < n); j++) c[j] = m[j];

    c[j] = 1;

    m += j;
    n -= j;

    poly1305_add (h, c);

    for (int i = 0; i < 17; i++)
    {
      x[i] = 0;

      for (j = 0; j < 17; j++) x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
    }

    for (int i = 0; i < 17; i++) h[i] = x[i];

    u32 u = 0;

    for (int j = 0; j < 16; j++)
    {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }

    u += h[16];
    h[16] = u & 3;
    u = 5 * (u >> 2);

    for (int j = 0; j < 16; j++)
    {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }

    u += h[16];
    h[16] = u;
  }

  for (int j = 0; j < 17; j++) g[j] = h[j];

  u32 minusp_priv[17];

  for (int j = 0; j < 17; j++) minusp_priv[j] = poly1305_minusp[j];

  poly1305_add (h, minusp_priv);

  const u32 s = -(h[16] >> 7);

  for (int j = 0; j < 17; j++) h[j] ^= s & (g[j] ^ h[j]);

  for (int j = 0; j < 16; j++) c[j] = k[j + 16];

  c[16] = 0;

  poly1305_add (h, c);

  for (int j = 0; j < 16; j++) out[j] = h[j];
}
