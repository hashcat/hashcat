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
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_camellia.h"

CONSTANT_VK u32a c_sbox[256] =
{
  0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5,
  0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
  0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21,
  0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
  0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce,
  0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
  0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d,
  0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
  0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d,
  0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
  0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05,
  0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
  0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c,
  0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
  0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91,
  0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
  0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97,
  0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
  0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb,
  0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
  0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33,
  0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
  0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b,
  0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
  0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e,
  0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
  0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba,
  0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
  0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a,
  0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
  0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1,
  0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e
};

#define c_sbox1(n) c_sbox[(n)]
#define c_sbox2(n) (((c_sbox[(n)] >> 7) ^ (c_sbox[(n)] << 1)) & 0xff)
#define c_sbox3(n) (((c_sbox[(n)] >> 1) ^ (c_sbox[(n)] << 7)) & 0xff)
#define c_sbox4(n) c_sbox[(((n) << 1) ^ ((n) >> 7)) & 0xff]

#define cam_rotate(a,b,n) hc_swap32_S ((u[(a)] << (n)) ^ (u[(b)] >> (32 - (n))))

DECLSPEC void cam_feistel (PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *k, PRIVATE_AS u32 *y)
{
  const u32 xk0 = x[0] ^ k[0];
  const u32 xk1 = x[1] ^ k[1];

  const u32 b0 = c_sbox1 (unpack_v8a_from_v32_S (xk0));
  const u32 b1 = c_sbox2 (unpack_v8b_from_v32_S (xk0));
  const u32 b2 = c_sbox3 (unpack_v8c_from_v32_S (xk0));
  const u32 b3 = c_sbox4 (unpack_v8d_from_v32_S (xk0));
  const u32 b4 = c_sbox2 (unpack_v8a_from_v32_S (xk1));
  const u32 b5 = c_sbox3 (unpack_v8b_from_v32_S (xk1));
  const u32 b6 = c_sbox4 (unpack_v8c_from_v32_S (xk1));
  const u32 b7 = c_sbox1 (unpack_v8d_from_v32_S (xk1));

  /*
  const u32 t0a = b0 ^      b2 ^ b3 ^      b5 ^ b6 ^ b7;
  const u32 t0b = b0 ^ b1 ^      b3 ^ b4 ^      b6 ^ b7;
  const u32 t0c = b0 ^ b1 ^ b2 ^      b4 ^ b5 ^      b7;
  const u32 t0d =      b1 ^ b2 ^ b3 ^ b4 ^ b5 ^ b6     ;

  const u32 t1a = b0 ^ b1 ^                b5 ^ b6 ^ b7;
  const u32 t1b =      b1 ^ b2 ^      b4 ^      b6 ^ b7;
  const u32 t1c =           b2 ^ b3 ^ b4 ^ b5 ^      b7;
  const u32 t1d = b0 ^           b3 ^ b4 ^ b5 ^ b6     ;
  */

  const u32 b14 = b1 ^ b4;
  const u32 b25 = b2 ^ b5;
  const u32 b36 = b3 ^ b6;
  const u32 b07 = b0 ^ b7;

  const u32 b01234567 = b14 ^ b25 ^ b36 ^ b07;

  const u32 t0a = b01234567 ^ b14;
  const u32 t0b = b01234567 ^ b25;
  const u32 t0c = b01234567 ^ b36;
  const u32 t0d = b01234567 ^ b07;

  /*
  const u32 t1a = b01234567 ^ b2 ^ b3 ^ b4;
  const u32 t1b = b01234567 ^ b0 ^ b3 ^ b5;
  const u32 t1c = b01234567 ^ b0 ^ b1 ^ b6;
  const u32 t1d = b01234567 ^ b1 ^ b2 ^ b7;
  */

  const u32 b0_234567 = b01234567 ^ b1;
  const u32 b012_4567 = b01234567 ^ b3;

  const u32 t1a = b012_4567 ^ b2 ^ b4;
  const u32 t1b = b012_4567 ^ b0 ^ b5;
  const u32 t1c = b0_234567 ^ b0 ^ b6;
  const u32 t1d = b0_234567 ^ b2 ^ b7;

  const u32 t0 = (t0a <<  0)
               | (t0b <<  8)
               | (t0c << 16)
               | (t0d << 24);

  const u32 t1 = (t1a <<  0)
               | (t1b <<  8)
               | (t1c << 16)
               | (t1d << 24);

  y[0] ^= t0;
  y[1] ^= t1;
}

DECLSPEC void cam_fl (PRIVATE_AS u32 *x, PRIVATE_AS const u32 *kl, PRIVATE_AS const u32 *kr)
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

DECLSPEC void camellia256_set_key (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *ukey)
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

DECLSPEC void camellia256_encrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out)
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

DECLSPEC void camellia256_decrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out)
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
