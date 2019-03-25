/*                                                                *
 * This is an OpenCL implementation of the encryption algorithm:  *
 *                                                                *
 *   Camellia by Kazumaro Aoki, Masayuki Kanda, Shiho Moriai,     *
 *               Tetsuya Ichikawa, Mitsuru Matsui,                *
 *               Junko Nakajima and Toshio Tokita                 *
 *                                                                *
 * http://info.isl.ntt.co.jp/crypt/eng/camellia/technology.html   *
 *                                                                *
 * Copyright of the ANSI-C implementation:                        *
 *                                                                *
 *   Mitsubishi Electric Corp 2000-2001                           *
 *                                                                *
 * Adapted for GPU use with hashcat by Ruslan Yushaev.            *
 *                                                                *
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_cipher_camellia.h"

#define c_sbox1(n) c_sbox[(n)]
#define c_sbox2(n) (((c_sbox[(n)] >> 7) ^ (c_sbox[(n)] << 1)) & 0xff)
#define c_sbox3(n) (((c_sbox[(n)] >> 1) ^ (c_sbox[(n)] << 7)) & 0xff)
#define c_sbox4(n) c_sbox[(((n) << 1) ^ ((n) >> 7)) & 0xff]

#define cam_rotate(a,b,n) hc_swap32_S ((u[(a)] << (n)) ^ (u[(b)] >> (32 - (n))))

#define extract_byte(x,n) (((x) >> (8 * (n))) & 0xff)

DECLSPEC void cam_feistel (const u32 *x, const u32 *k, u32 *y)
{
  u32 b[8];

  b[0] = c_sbox1 (extract_byte (x[0], 0) ^ extract_byte (k[0], 0));
  b[1] = c_sbox2 (extract_byte (x[0], 1) ^ extract_byte (k[0], 1));
  b[2] = c_sbox3 (extract_byte (x[0], 2) ^ extract_byte (k[0], 2));
  b[3] = c_sbox4 (extract_byte (x[0], 3) ^ extract_byte (k[0], 3));
  b[4] = c_sbox2 (extract_byte (x[1], 0) ^ extract_byte (k[1], 0));
  b[5] = c_sbox3 (extract_byte (x[1], 1) ^ extract_byte (k[1], 1));
  b[6] = c_sbox4 (extract_byte (x[1], 2) ^ extract_byte (k[1], 2));
  b[7] = c_sbox1 (extract_byte (x[1], 3) ^ extract_byte (k[1], 3));

  u32 tmp[2];

  tmp[0] = (b[0] ^ b[2] ^ b[3] ^ b[5] ^ b[6] ^ b[7]) << 0
         | (b[0] ^ b[1] ^ b[3] ^ b[4] ^ b[6] ^ b[7]) << 8
         | (b[0] ^ b[1] ^ b[2] ^ b[4] ^ b[5] ^ b[7]) << 16
         | (b[1] ^ b[2] ^ b[3] ^ b[4] ^ b[5] ^ b[6]) << 24;

  tmp[1] = (b[0] ^ b[1] ^ b[5] ^ b[6] ^ b[7]) << 0
         | (b[1] ^ b[2] ^ b[4] ^ b[6] ^ b[7]) << 8
         | (b[2] ^ b[3] ^ b[4] ^ b[5] ^ b[7]) << 16
         | (b[0] ^ b[3] ^ b[4] ^ b[5] ^ b[6]) << 24;

  y[0] ^= tmp[0];
  y[1] ^= tmp[1];
}

DECLSPEC void cam_fl (u32 *x, const u32 *kl, const u32 *kr)
{
  u32 t[4];
  u32 u[4];
  u32 v[4];

  t[0] = hc_swap32_S (x[0]);
  t[1] = hc_swap32_S (x[1]);
  t[2] = hc_swap32_S (x[2]);
  t[3] = hc_swap32_S (x[3]);

  u[0] = hc_swap32_S (kl[0]);
  u[1] = hc_swap32_S (kl[1]);
  u[2] = hc_swap32_S (kl[2]);
  u[3] = hc_swap32_S (kl[3]);

  v[0] = hc_swap32_S (kr[0]);
  v[1] = hc_swap32_S (kr[1]);
  v[2] = hc_swap32_S (kr[2]);
  v[3] = hc_swap32_S (kr[3]);

  t[1] ^= (t[0] & u[0]) << 1;
  t[1] ^= (t[0] & u[0]) >> 31;

  t[0] ^= t[1] | u[1];
  t[2] ^= t[3] | v[1];

  t[3] ^= (t[2] & v[0]) << 1;
  t[3] ^= (t[2] & v[0]) >> 31;

  x[0] = hc_swap32_S (t[0]);
  x[1] = hc_swap32_S (t[1]);
  x[2] = hc_swap32_S (t[2]);
  x[3] = hc_swap32_S (t[3]);
}

DECLSPEC void camellia256_set_key (u32 *ks, const u32 *ukey)
{
  const u32 sigma[12] =
  {
    0x7f669ea0, 0x8b90cc3b, 0x58e87ab6, 0xb273aa4c,
    0x2f37efc6, 0xbe824fe9, 0xa553ff54, 0x1c6fd3f1,
    0xfa27e510, 0x1d2d68de, 0xc28856b0, 0xfdc1e6b3
  };

  u32 tmp[8];

  tmp[0] = ukey[0] ^ ukey[4];
  tmp[1] = ukey[1] ^ ukey[5];
  tmp[2] = ukey[2] ^ ukey[6];
  tmp[3] = ukey[3] ^ ukey[7];

  cam_feistel (&tmp[0], &sigma[0], &tmp[2]);
  cam_feistel (&tmp[2], &sigma[2], &tmp[0]);

  tmp[0] ^= ukey[0];
  tmp[1] ^= ukey[1];
  tmp[2] ^= ukey[2];
  tmp[3] ^= ukey[3];

  cam_feistel (&tmp[0], &sigma[4], &tmp[2]);
  cam_feistel (&tmp[2], &sigma[6], &tmp[0]);

  tmp[4] = tmp[0] ^ ukey[4];
  tmp[5] = tmp[1] ^ ukey[5];
  tmp[6] = tmp[2] ^ ukey[6];
  tmp[7] = tmp[3] ^ ukey[7];

  cam_feistel (&tmp[4], &sigma[8],  &tmp[6]);
  cam_feistel (&tmp[6], &sigma[10], &tmp[4]);

  // used in cam_rotate macro
  u32 u[16];

  u[0] = hc_swap32_S (ukey[0]);
  u[1] = hc_swap32_S (ukey[1]);
  u[2] = hc_swap32_S (ukey[2]);
  u[3] = hc_swap32_S (ukey[3]);

  u[4] = hc_swap32_S (tmp[0]);
  u[5] = hc_swap32_S (tmp[1]);
  u[6] = hc_swap32_S (tmp[2]);
  u[7] = hc_swap32_S (tmp[3]);

  u[8]  = hc_swap32_S (ukey[4]);
  u[9]  = hc_swap32_S (ukey[5]);
  u[10] = hc_swap32_S (ukey[6]);
  u[11] = hc_swap32_S (ukey[7]);

  u[12] = hc_swap32_S (tmp[4]);
  u[13] = hc_swap32_S (tmp[5]);
  u[14] = hc_swap32_S (tmp[6]);
  u[15] = hc_swap32_S (tmp[7]);

  ks[0] = hc_swap32_S (u[0]);
  ks[1] = hc_swap32_S (u[1]);
  ks[2] = hc_swap32_S (u[2]);
  ks[3] = hc_swap32_S (u[3]);
  ks[4] = hc_swap32_S (u[12]);
  ks[5] = hc_swap32_S (u[13]);
  ks[6] = hc_swap32_S (u[14]);
  ks[7] = hc_swap32_S (u[15]);

  ks[8]  = cam_rotate (8,  9,  15);
  ks[9]  = cam_rotate (9,  10, 15);
  ks[10] = cam_rotate (10, 11, 15);
  ks[11] = cam_rotate (11, 8,  15);
  ks[12] = cam_rotate (4,  5,  15);
  ks[13] = cam_rotate (5,  6,  15);
  ks[14] = cam_rotate (6,  7,  15);
  ks[15] = cam_rotate (7,  4,  15);

  ks[16] = cam_rotate (8,  9,  30);
  ks[17] = cam_rotate (9,  10, 30);
  ks[18] = cam_rotate (10, 11, 30);
  ks[19] = cam_rotate (11, 8,  30);
  ks[20] = cam_rotate (12, 13, 30);
  ks[21] = cam_rotate (13, 14, 30);
  ks[22] = cam_rotate (14, 15, 30);
  ks[23] = cam_rotate (15, 12, 30);

  ks[24] = cam_rotate (1, 2, 13);
  ks[25] = cam_rotate (2, 3, 13);
  ks[26] = cam_rotate (3, 0, 13);
  ks[27] = cam_rotate (0, 1, 13);
  ks[28] = cam_rotate (5, 6, 13);
  ks[29] = cam_rotate (6, 7, 13);
  ks[30] = cam_rotate (7, 4, 13);
  ks[31] = cam_rotate (4, 5, 13);

  ks[32] = cam_rotate (1,  2,  28);
  ks[33] = cam_rotate (2,  3,  28);
  ks[34] = cam_rotate (3,  0,  28);
  ks[35] = cam_rotate (0,  1,  28);
  ks[36] = cam_rotate (9,  10, 28);
  ks[37] = cam_rotate (10, 11, 28);
  ks[38] = cam_rotate (11, 8,  28);
  ks[39] = cam_rotate (8,  9,  28);
  ks[40] = cam_rotate (13, 14, 28);
  ks[41] = cam_rotate (14, 15, 28);
  ks[42] = cam_rotate (15, 12, 28);
  ks[43] = cam_rotate (12, 13, 28);

  ks[44] = cam_rotate (2, 3, 13);
  ks[45] = cam_rotate (3, 0, 13);
  ks[46] = cam_rotate (0, 1, 13);
  ks[47] = cam_rotate (1, 2, 13);
  ks[48] = cam_rotate (6, 7, 13);
  ks[49] = cam_rotate (7, 4, 13);
  ks[50] = cam_rotate (4, 5, 13);
  ks[51] = cam_rotate (5, 6, 13);

  ks[52] = cam_rotate (10, 11, 30);
  ks[53] = cam_rotate (11, 8,  30);
  ks[54] = cam_rotate (8,  9,  30);
  ks[55] = cam_rotate (9,  10, 30);
  ks[56] = cam_rotate (6,  7,  30);
  ks[57] = cam_rotate (7,  4,  30);
  ks[58] = cam_rotate (4,  5,  30);
  ks[59] = cam_rotate (5,  6,  30);

  ks[60] = cam_rotate (3,  0,  15);
  ks[61] = cam_rotate (0,  1,  15);
  ks[62] = cam_rotate (1,  2,  15);
  ks[63] = cam_rotate (2,  3,  15);
  ks[64] = cam_rotate (15, 12, 15);
  ks[65] = cam_rotate (12, 13, 15);
  ks[66] = cam_rotate (13, 14, 15);
  ks[67] = cam_rotate (14, 15, 15);
}

DECLSPEC void camellia256_encrypt (const u32 *ks, const u32 *in, u32 *out)
{
  out[0] = in[0] ^ ks[0];
  out[1] = in[1] ^ ks[1];
  out[2] = in[2] ^ ks[2];
  out[3] = in[3] ^ ks[3];

  cam_feistel (&out[0], &ks[4],  &out[2]);
  cam_feistel (&out[2], &ks[6],  &out[0]);
  cam_feistel (&out[0], &ks[8],  &out[2]);
  cam_feistel (&out[2], &ks[10], &out[0]);
  cam_feistel (&out[0], &ks[12], &out[2]);
  cam_feistel (&out[2], &ks[14], &out[0]);

  cam_fl (out, &ks[16], &ks[18]);

  cam_feistel (&out[0], &ks[20], &out[2]);
  cam_feistel (&out[2], &ks[22], &out[0]);
  cam_feistel (&out[0], &ks[24], &out[2]);
  cam_feistel (&out[2], &ks[26], &out[0]);
  cam_feistel (&out[0], &ks[28], &out[2]);
  cam_feistel (&out[2], &ks[30], &out[0]);

  cam_fl (out, &ks[32], &ks[34]);

  cam_feistel (&out[0], &ks[36], &out[2]);
  cam_feistel (&out[2], &ks[38], &out[0]);
  cam_feistel (&out[0], &ks[40], &out[2]);
  cam_feistel (&out[2], &ks[42], &out[0]);
  cam_feistel (&out[0], &ks[44], &out[2]);
  cam_feistel (&out[2], &ks[46], &out[0]);

  cam_fl (out, &ks[48], &ks[50]);

  cam_feistel (&out[0], &ks[52], &out[2]);
  cam_feistel (&out[2], &ks[54], &out[0]);
  cam_feistel (&out[0], &ks[56], &out[2]);
  cam_feistel (&out[2], &ks[58], &out[0]);
  cam_feistel (&out[0], &ks[60], &out[2]);
  cam_feistel (&out[2], &ks[62], &out[0]);

  u32 tmp[2];

  tmp[0] = out[0];
  tmp[1] = out[1];

  out[0] = out[2] ^ ks[64];
  out[1] = out[3] ^ ks[65];
  out[2] = tmp[0] ^ ks[66];
  out[3] = tmp[1] ^ ks[67];
}

DECLSPEC void camellia256_decrypt (const u32 *ks, const u32 *in, u32 *out)
{
  out[0] = in[0] ^ ks[64];
  out[1] = in[1] ^ ks[65];
  out[2] = in[2] ^ ks[66];
  out[3] = in[3] ^ ks[67];

  cam_feistel (&out[0], &ks[62], &out[2]);
  cam_feistel (&out[2], &ks[60], &out[0]);
  cam_feistel (&out[0], &ks[58], &out[2]);
  cam_feistel (&out[2], &ks[56], &out[0]);
  cam_feistel (&out[0], &ks[54], &out[2]);
  cam_feistel (&out[2], &ks[52], &out[0]);

  cam_fl (out, &ks[50], &ks[48]);

  cam_feistel (&out[0], &ks[46], &out[2]);
  cam_feistel (&out[2], &ks[44], &out[0]);
  cam_feistel (&out[0], &ks[42], &out[2]);
  cam_feistel (&out[2], &ks[40], &out[0]);
  cam_feistel (&out[0], &ks[38], &out[2]);
  cam_feistel (&out[2], &ks[36], &out[0]);

  cam_fl (out, &ks[34], &ks[32]);

  cam_feistel (&out[0], &ks[30], &out[2]);
  cam_feistel (&out[2], &ks[28], &out[0]);
  cam_feistel (&out[0], &ks[26], &out[2]);
  cam_feistel (&out[2], &ks[24], &out[0]);
  cam_feistel (&out[0], &ks[22], &out[2]);
  cam_feistel (&out[2], &ks[20], &out[0]);

  cam_fl (out, &ks[18], &ks[16]);

  cam_feistel (&out[0], &ks[14], &out[2]);
  cam_feistel (&out[2], &ks[12], &out[0]);
  cam_feistel (&out[0], &ks[10], &out[2]);
  cam_feistel (&out[2], &ks[8],  &out[0]);
  cam_feistel (&out[0], &ks[6],  &out[2]);
  cam_feistel (&out[2], &ks[4],  &out[0]);

  u32 tmp[2];

  tmp[0] = out[0];
  tmp[1] = out[1];

  out[0] = out[2] ^ ks[0];
  out[1] = out[3] ^ ks[1];
  out[2] = tmp[0] ^ ks[2];
  out[3] = tmp[1] ^ ks[3];
}

#undef c_sbox1
#undef c_sbox2
#undef c_sbox3
#undef c_sbox4

#undef cam_rotate

#undef extract_byte
