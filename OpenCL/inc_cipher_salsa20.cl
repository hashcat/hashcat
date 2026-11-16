/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_salsa20.h"

// Salsa20 and the XSalsa20 stream (NaCl), word-oriented: keys, nonces and
// outputs are u32 arrays holding the LE-packed bytes of the byte string.

#define SALSA20_C0 0x61707865
#define SALSA20_C1 0x3320646e
#define SALSA20_C2 0x79622d32
#define SALSA20_C3 0x6b206574

#define SALSA20_QR(a,b,c,d)          \
{                                    \
  b ^= hc_rotl32_S ((a) + (d),  7);  \
  c ^= hc_rotl32_S ((b) + (a),  9);  \
  d ^= hc_rotl32_S ((c) + (b), 13);  \
  a ^= hc_rotl32_S ((d) + (c), 18);  \
}

DECLSPEC void salsa20_20 (PRIVATE_AS u32 *x)
{
  for (int i = 0; i < 10; i++)
  {
    SALSA20_QR (x[ 0], x[ 4], x[ 8], x[12]);
    SALSA20_QR (x[ 5], x[ 9], x[13], x[ 1]);
    SALSA20_QR (x[10], x[14], x[ 2], x[ 6]);
    SALSA20_QR (x[15], x[ 3], x[ 7], x[11]);

    SALSA20_QR (x[ 0], x[ 1], x[ 2], x[ 3]);
    SALSA20_QR (x[ 5], x[ 6], x[ 7], x[ 4]);
    SALSA20_QR (x[10], x[11], x[ 8], x[ 9]);
    SALSA20_QR (x[15], x[12], x[13], x[14]);
  }
}

// HSalsa20: k is the 8-word key, n the first 16 bytes of the XSalsa20 nonce
// (4 words), out the 8-word subkey

DECLSPEC void hsalsa20 (PRIVATE_AS const u32 *k, PRIVATE_AS const u32 *n, PRIVATE_AS u32 *out)
{
  u32 x[16];

  x[ 0] = SALSA20_C0;
  x[ 1] = k[0];
  x[ 2] = k[1];
  x[ 3] = k[2];
  x[ 4] = k[3];
  x[ 5] = SALSA20_C1;
  x[ 6] = n[0];
  x[ 7] = n[1];
  x[ 8] = n[2];
  x[ 9] = n[3];
  x[10] = SALSA20_C2;
  x[11] = k[4];
  x[12] = k[5];
  x[13] = k[6];
  x[14] = k[7];
  x[15] = SALSA20_C3;

  salsa20_20 (x);

  out[0] = x[ 0];
  out[1] = x[ 5];
  out[2] = x[10];
  out[3] = x[15];
  out[4] = x[ 6];
  out[5] = x[ 7];
  out[6] = x[ 8];
  out[7] = x[ 9];
}

// one 64-byte keystream block: 8-word key, 2-word nonce, 2-word block counter

DECLSPEC void salsa20_block (PRIVATE_AS const u32 *k, PRIVATE_AS const u32 *n, PRIVATE_AS const u32 *c, PRIVATE_AS u32 *out)
{
  u32 x[16];

  x[ 0] = SALSA20_C0;
  x[ 1] = k[0];
  x[ 2] = k[1];
  x[ 3] = k[2];
  x[ 4] = k[3];
  x[ 5] = SALSA20_C1;
  x[ 6] = n[0];
  x[ 7] = n[1];
  x[ 8] = c[0];
  x[ 9] = c[1];
  x[10] = SALSA20_C2;
  x[11] = k[4];
  x[12] = k[5];
  x[13] = k[6];
  x[14] = k[7];
  x[15] = SALSA20_C3;

  u32 y[16];

  for (int i = 0; i < 16; i++) y[i] = x[i];

  salsa20_20 (x);

  for (int i = 0; i < 16; i++) out[i] = x[i] + y[i];
}

// XSalsa20 stream: subkey = HSalsa20 (k, n[0..3]), then the Salsa20 stream
// under the subkey with nonce n[4..5]. out_len is in bytes, a multiple of 4;
// out receives out_len / 4 words.

DECLSPEC void xsalsa20_stream (PRIVATE_AS u32 *out, const u32 out_len, PRIVATE_AS const u32 *n, PRIVATE_AS const u32 *k)
{
  u32 subkey[8];

  hsalsa20 (k, n, subkey);

  u32 sn[2];

  sn[0] = n[4];
  sn[1] = n[5];

  u32 ctr[2];

  ctr[0] = 0;
  ctr[1] = 0;

  const u32 words = out_len / 4;

  for (u32 off = 0; off < words; off += 16)
  {
    u32 block[16];

    salsa20_block (subkey, sn, ctr, block);

    ctr[0]++;

    if (ctr[0] == 0) ctr[1]++;

    for (u32 i = 0; i < 16; i++)
    {
      if (off + i >= words) break;

      out[off + i] = block[i];
    }
  }
}
