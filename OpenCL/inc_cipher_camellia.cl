/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Camellia is the 128 bit block cipher designed by Kazumaro Aoki, Tetsuya Ichikawa, Masayuki Kanda,
 * Mitsuru Matsui, Shiho Moriai, Junko Nakajima and Toshio Tokita.
 *
 * This was written from the algorithm description in RFC 3713, "A Description of the Camellia
 * Encryption Algorithm", https://www.rfc-editor.org/rfc/rfc3713.txt. Section 2.2 is the key
 * schedule, section 2.3 the rounds, and section 2.4 the F, FL and FLINV functions together with
 * the SBOX1 table. The example data in Appendix A is what it was checked against.
 */

// Only the 256 bit key size is here, because that is the only one hashcat asks for: the VeraCrypt
// legacy cascades and BestCrypt.
//
// Two things about the shape of the code. A word holds four bytes of the block in the order they
// arrived, so the first byte of the block sits in bits 0 to 7, and hc_swap32_S () is what turns a
// word into the number the RFC's shifts and rotations are written against. Everything else is
// bitwise and does not care. And the F function's eight output equations share subexpressions, so
// they are grouped here rather than written out one XOR at a time. The values are the same ones.

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_camellia.h"

// SBOX1 of section 2.4.1. SBOX2, SBOX3 and SBOX4 are that same table read differently, which is how
// the RFC defines them, so one table is all that is stored.

CONSTANT_VK u32a camellia_sbox1[256] =
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

// SBOX2[x] = SBOX1[x] <<< 1, SBOX3[x] = SBOX1[x] <<< 7 and SBOX4[x] = SBOX1[x <<< 1], where <<< is
// an 8 bit rotation. Section 2.4.1 again.

#define CAMELLIA_SBOX1(x) camellia_sbox1[(x)]
#define CAMELLIA_SBOX2(x) (((camellia_sbox1[(x)] << 1) | (camellia_sbox1[(x)] >> 7)) & 0xff)
#define CAMELLIA_SBOX3(x) (((camellia_sbox1[(x)] << 7) | (camellia_sbox1[(x)] >> 1)) & 0xff)
#define CAMELLIA_SBOX4(x) camellia_sbox1[(((x) << 1) | ((x) >> 7)) & 0xff]

// One 128 bit left rotation of a key, as four words, taking the two halves the RFC's subkey table
// asks for. w is how many whole words the rotation moves and s what is left over, so KA <<< 45 is
// w = 1 and s = 13. Every rotation in section 2.2 other than the two by 0 leaves an s between 1 and
// 31, and the two by 0 are a copy and are written as one. k is a key as four numbers and the four
// words written out are in this file's byte order.

#define CAMELLIA_ROTL128(dst,k,w,s)                                                            \
  do {                                                                                         \
    (dst)[0] = hc_swap32_S (((k)[((w) + 0) & 3] << (s)) | ((k)[((w) + 1) & 3] >> (32 - (s)))); \
    (dst)[1] = hc_swap32_S (((k)[((w) + 1) & 3] << (s)) | ((k)[((w) + 2) & 3] >> (32 - (s)))); \
    (dst)[2] = hc_swap32_S (((k)[((w) + 2) & 3] << (s)) | ((k)[((w) + 3) & 3] >> (32 - (s)))); \
    (dst)[3] = hc_swap32_S (((k)[((w) + 3) & 3] << (s)) | ((k)[((w) + 0) & 3] >> (32 - (s)))); \
  } while (0)

// One Feistel round, which is the RFC's "D2 = D2 ^ F(D1, k)": the F function of section 2.4.1 with
// its result XORed into the other half.
//
// The RFC numbers the eight bytes of F_IN from its most significant end, and that is the order the
// bytes of the block lie in here, so t1 is the low byte of x[0] and t8 the high byte of x[1].

DECLSPEC void camellia_feistel (PRIVATE_AS const u32 *x, PRIVATE_AS const u32 *ke, PRIVATE_AS u32 *y)
{
  const u32 x0 = x[0] ^ ke[0];
  const u32 x1 = x[1] ^ ke[1];

  const u32 t1 = CAMELLIA_SBOX1 (unpack_v8a_from_v32_S (x0));
  const u32 t2 = CAMELLIA_SBOX2 (unpack_v8b_from_v32_S (x0));
  const u32 t3 = CAMELLIA_SBOX3 (unpack_v8c_from_v32_S (x0));
  const u32 t4 = CAMELLIA_SBOX4 (unpack_v8d_from_v32_S (x0));
  const u32 t5 = CAMELLIA_SBOX2 (unpack_v8a_from_v32_S (x1));
  const u32 t6 = CAMELLIA_SBOX3 (unpack_v8b_from_v32_S (x1));
  const u32 t7 = CAMELLIA_SBOX4 (unpack_v8c_from_v32_S (x1));
  const u32 t8 = CAMELLIA_SBOX1 (unpack_v8d_from_v32_S (x1));

  // The RFC writes the output bytes as
  //
  //   y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8      y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8
  //   y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8      y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8
  //   y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8      y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8
  //   y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7      y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7
  //
  // Each of the first four leaves out one of the four pairs (t1,t8), (t2,t5), (t3,t6) and (t4,t7),
  // so all four are the XOR of everything with one pair put back. The other four leave out three
  // values each and share a term in the same way.

  const u32 t18 = t1 ^ t8;
  const u32 t25 = t2 ^ t5;
  const u32 t36 = t3 ^ t6;
  const u32 t47 = t4 ^ t7;

  const u32 a = t18 ^ t25 ^ t36 ^ t47;

  const u32 y1 = a ^ t25;
  const u32 y2 = a ^ t36;
  const u32 y3 = a ^ t47;
  const u32 y4 = a ^ t18;

  const u32 a2 = a ^ t2;
  const u32 a4 = a ^ t4;

  const u32 y5 = a4 ^ t3 ^ t5;
  const u32 y6 = a4 ^ t1 ^ t6;
  const u32 y7 = a2 ^ t1 ^ t7;
  const u32 y8 = a2 ^ t3 ^ t8;

  y[0] ^= (y1 <<  0) | (y2 <<  8) | (y3 << 16) | (y4 << 24);
  y[1] ^= (y5 <<  0) | (y6 <<  8) | (y7 << 16) | (y8 << 24);
}

// The FL function on the left half and the FLINV function on the right half, which is where the
// rounds in section 2.3.2 always put them, so the two are one step here. Section 2.4.2 defines both.
//
// Only the one bit rotation cares about byte order, so it is the only place that swaps.

DECLSPEC void camellia_fl (PRIVATE_AS u32 *x, PRIVATE_AS const u32 *ke1, PRIVATE_AS const u32 *ke2)
{
  // FL: x2 = x2 ^ ((x1 & k1) <<< 1), then x1 = x1 ^ (x2 | k2)

  const u32 fl = hc_swap32_S (x[0] & ke1[0]);

  x[1] ^= hc_swap32_S (hc_rotl32_S (fl, 1));
  x[0] ^= x[1] | ke1[1];

  // FLINV: y1 = y1 ^ (y2 | k2), then y2 = y2 ^ ((y1 & k1) <<< 1)

  x[2] ^= x[3] | ke2[1];

  const u32 flinv = hc_swap32_S (x[2] & ke2[0]);

  x[3] ^= hc_swap32_S (hc_rotl32_S (flinv, 1));
}

DECLSPEC void camellia256_set_key (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *ukey)
{
  // Sigma1 to Sigma6 of section 2.2, each 64 bit constant as its two 32 bit halves in this file's
  // byte order. The RFC writes them as 0xA09E667F3BCC908B, 0xB67AE8584CAA73B2, 0xC6EF372FE94F82BE,
  // 0x54FF53A5F1D36F1C, 0x10E527FADE682D1D and 0xB05688C2B3E6C1FD.

  const u32 sigma[12] =
  {
    0x7f669ea0, 0x8b90cc3b, 0x58e87ab6, 0xb273aa4c,
    0x2f37efc6, 0xbe824fe9, 0xa553ff54, 0x1c6fd3f1,
    0xfa27e510, 0x1d2d68de, 0xc28856b0, 0xfdc1e6b3
  };

  // For a 256 bit key, KL is its leftmost 128 bits and KR its rightmost. KA and KB come out of the
  // six Feistel steps below, with d holding the RFC's D1 and D2 side by side.

  u32 d[4];

  d[0] = ukey[0] ^ ukey[4];
  d[1] = ukey[1] ^ ukey[5];
  d[2] = ukey[2] ^ ukey[6];
  d[3] = ukey[3] ^ ukey[7];

  camellia_feistel (&d[0], &sigma[0], &d[2]);  // D2 = D2 ^ F (D1, Sigma1)
  camellia_feistel (&d[2], &sigma[2], &d[0]);  // D1 = D1 ^ F (D2, Sigma2)

  d[0] ^= ukey[0];                             // D1 = D1 ^ (KL >> 64)
  d[1] ^= ukey[1];
  d[2] ^= ukey[2];                             // D2 = D2 ^ (KL & MASK64)
  d[3] ^= ukey[3];

  camellia_feistel (&d[0], &sigma[4], &d[2]);  // D2 = D2 ^ F (D1, Sigma3)
  camellia_feistel (&d[2], &sigma[6], &d[0]);  // D1 = D1 ^ F (D2, Sigma4)

  // KA is now in d. Two more Feistel steps turn KA and KR into KB, which e ends up holding.

  u32 e[4];

  e[0] = d[0] ^ ukey[4];
  e[1] = d[1] ^ ukey[5];
  e[2] = d[2] ^ ukey[6];
  e[3] = d[3] ^ ukey[7];

  camellia_feistel (&e[0], &sigma[8],  &e[2]); // D2 = D2 ^ F (D1, Sigma5)
  camellia_feistel (&e[2], &sigma[10], &e[0]); // D1 = D1 ^ F (D2, Sigma6)

  // The subkey table of section 2.2 rotates all four keys, and a rotation is arithmetic, so the
  // four are taken as numbers here. The two subkey pairs that are not rotated are a copy instead.

  u32 kl[4];
  u32 kr[4];
  u32 ka[4];
  u32 kb[4];

  kl[0] = hc_swap32_S (ukey[0]);
  kl[1] = hc_swap32_S (ukey[1]);
  kl[2] = hc_swap32_S (ukey[2]);
  kl[3] = hc_swap32_S (ukey[3]);

  kr[0] = hc_swap32_S (ukey[4]);
  kr[1] = hc_swap32_S (ukey[5]);
  kr[2] = hc_swap32_S (ukey[6]);
  kr[3] = hc_swap32_S (ukey[7]);

  ka[0] = hc_swap32_S (d[0]);
  ka[1] = hc_swap32_S (d[1]);
  ka[2] = hc_swap32_S (d[2]);
  ka[3] = hc_swap32_S (d[3]);

  kb[0] = hc_swap32_S (e[0]);
  kb[1] = hc_swap32_S (e[1]);
  kb[2] = hc_swap32_S (e[2]);
  kb[3] = hc_swap32_S (e[3]);

  ks[0] = ukey[0];  // kw1, kw2 = KL <<< 0
  ks[1] = ukey[1];
  ks[2] = ukey[2];
  ks[3] = ukey[3];

  ks[4] = e[0];     // k1, k2 = KB <<< 0
  ks[5] = e[1];
  ks[6] = e[2];
  ks[7] = e[3];

  CAMELLIA_ROTL128 (&ks[8],  kr, 0, 15);  // k3,  k4  = KR <<<  15
  CAMELLIA_ROTL128 (&ks[12], ka, 0, 15);  // k5,  k6  = KA <<<  15
  CAMELLIA_ROTL128 (&ks[16], kr, 0, 30);  // ke1, ke2 = KR <<<  30
  CAMELLIA_ROTL128 (&ks[20], kb, 0, 30);  // k7,  k8  = KB <<<  30
  CAMELLIA_ROTL128 (&ks[24], kl, 1, 13);  // k9,  k10 = KL <<<  45
  CAMELLIA_ROTL128 (&ks[28], ka, 1, 13);  // k11, k12 = KA <<<  45
  CAMELLIA_ROTL128 (&ks[32], kl, 1, 28);  // ke3, ke4 = KL <<<  60
  CAMELLIA_ROTL128 (&ks[36], kr, 1, 28);  // k13, k14 = KR <<<  60
  CAMELLIA_ROTL128 (&ks[40], kb, 1, 28);  // k15, k16 = KB <<<  60
  CAMELLIA_ROTL128 (&ks[44], kl, 2, 13);  // k17, k18 = KL <<<  77
  CAMELLIA_ROTL128 (&ks[48], ka, 2, 13);  // ke5, ke6 = KA <<<  77
  CAMELLIA_ROTL128 (&ks[52], kr, 2, 30);  // k19, k20 = KR <<<  94
  CAMELLIA_ROTL128 (&ks[56], ka, 2, 30);  // k21, k22 = KA <<<  94
  CAMELLIA_ROTL128 (&ks[60], kl, 3, 15);  // k23, k24 = KL <<< 111
  CAMELLIA_ROTL128 (&ks[64], kb, 3, 15);  // kw3, kw4 = KB <<< 111
}

// The 24 rounds of section 2.3.2, with the FL and FLINV pair after every sixth. out holds D1 in its
// first two words and D2 in its last two.

DECLSPEC void camellia256_encrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out)
{
  out[0] = in[0] ^ ks[0];  // prewhitening with kw1 and kw2
  out[1] = in[1] ^ ks[1];
  out[2] = in[2] ^ ks[2];
  out[3] = in[3] ^ ks[3];

  camellia_feistel (&out[0], &ks[4],  &out[2]);  // rounds 1 to 6, k1 to k6
  camellia_feistel (&out[2], &ks[6],  &out[0]);
  camellia_feistel (&out[0], &ks[8],  &out[2]);
  camellia_feistel (&out[2], &ks[10], &out[0]);
  camellia_feistel (&out[0], &ks[12], &out[2]);
  camellia_feistel (&out[2], &ks[14], &out[0]);

  camellia_fl (out, &ks[16], &ks[18]);           // ke1 and ke2

  camellia_feistel (&out[0], &ks[20], &out[2]);  // rounds 7 to 12, k7 to k12
  camellia_feistel (&out[2], &ks[22], &out[0]);
  camellia_feistel (&out[0], &ks[24], &out[2]);
  camellia_feistel (&out[2], &ks[26], &out[0]);
  camellia_feistel (&out[0], &ks[28], &out[2]);
  camellia_feistel (&out[2], &ks[30], &out[0]);

  camellia_fl (out, &ks[32], &ks[34]);           // ke3 and ke4

  camellia_feistel (&out[0], &ks[36], &out[2]);  // rounds 13 to 18, k13 to k18
  camellia_feistel (&out[2], &ks[38], &out[0]);
  camellia_feistel (&out[0], &ks[40], &out[2]);
  camellia_feistel (&out[2], &ks[42], &out[0]);
  camellia_feistel (&out[0], &ks[44], &out[2]);
  camellia_feistel (&out[2], &ks[46], &out[0]);

  camellia_fl (out, &ks[48], &ks[50]);           // ke5 and ke6

  camellia_feistel (&out[0], &ks[52], &out[2]);  // rounds 19 to 24, k19 to k24
  camellia_feistel (&out[2], &ks[54], &out[0]);
  camellia_feistel (&out[0], &ks[56], &out[2]);
  camellia_feistel (&out[2], &ks[58], &out[0]);
  camellia_feistel (&out[0], &ks[60], &out[2]);
  camellia_feistel (&out[2], &ks[62], &out[0]);

  // postwhitening with kw3 and kw4, and the two halves change places on the way out

  u32 tmp[2];

  tmp[0] = out[0];
  tmp[1] = out[1];

  out[0] = out[2] ^ ks[64];
  out[1] = out[3] ^ ks[65];
  out[2] = tmp[0] ^ ks[66];
  out[3] = tmp[1] ^ ks[67];
}

// The same rounds with the subkeys taken in the order section 2.3.3 gives for decryption, which is
// the encryption order reversed and the two members of each FL and FLINV pair exchanged.

DECLSPEC void camellia256_decrypt (PRIVATE_AS const u32 *ks, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out)
{
  out[0] = in[0] ^ ks[64];
  out[1] = in[1] ^ ks[65];
  out[2] = in[2] ^ ks[66];
  out[3] = in[3] ^ ks[67];

  camellia_feistel (&out[0], &ks[62], &out[2]);
  camellia_feistel (&out[2], &ks[60], &out[0]);
  camellia_feistel (&out[0], &ks[58], &out[2]);
  camellia_feistel (&out[2], &ks[56], &out[0]);
  camellia_feistel (&out[0], &ks[54], &out[2]);
  camellia_feistel (&out[2], &ks[52], &out[0]);

  camellia_fl (out, &ks[50], &ks[48]);

  camellia_feistel (&out[0], &ks[46], &out[2]);
  camellia_feistel (&out[2], &ks[44], &out[0]);
  camellia_feistel (&out[0], &ks[42], &out[2]);
  camellia_feistel (&out[2], &ks[40], &out[0]);
  camellia_feistel (&out[0], &ks[38], &out[2]);
  camellia_feistel (&out[2], &ks[36], &out[0]);

  camellia_fl (out, &ks[34], &ks[32]);

  camellia_feistel (&out[0], &ks[30], &out[2]);
  camellia_feistel (&out[2], &ks[28], &out[0]);
  camellia_feistel (&out[0], &ks[26], &out[2]);
  camellia_feistel (&out[2], &ks[24], &out[0]);
  camellia_feistel (&out[0], &ks[22], &out[2]);
  camellia_feistel (&out[2], &ks[20], &out[0]);

  camellia_fl (out, &ks[18], &ks[16]);

  camellia_feistel (&out[0], &ks[14], &out[2]);
  camellia_feistel (&out[2], &ks[12], &out[0]);
  camellia_feistel (&out[0], &ks[10], &out[2]);
  camellia_feistel (&out[2], &ks[8],  &out[0]);
  camellia_feistel (&out[0], &ks[6],  &out[2]);
  camellia_feistel (&out[2], &ks[4],  &out[0]);

  u32 tmp[2];

  tmp[0] = out[0];
  tmp[1] = out[1];

  out[0] = out[2] ^ ks[0];
  out[1] = out[3] ^ ks[1];
  out[2] = tmp[0] ^ ks[2];
  out[3] = tmp[1] ^ ks[3];
}

#undef CAMELLIA_SBOX1
#undef CAMELLIA_SBOX2
#undef CAMELLIA_SBOX3
#undef CAMELLIA_SBOX4

#undef CAMELLIA_ROTL128
