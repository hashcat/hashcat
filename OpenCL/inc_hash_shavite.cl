/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_shavite.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off.

// SHAvite-3 reads its message words little endian and uses AES tables in the same byte order. The
// tables te0 to te3 of inc_cipher_aes.cl hold the same words byte swapped. Everything besides the
// AES rounds is XOR, so the transforms swap the chaining value, the message words and the counter
// instead, and run the AES rounds in the form of inc_cipher_aes.cl. The chaining value stays
// swapped between blocks, and final swaps it back.

// The chaining values for digests of 28 and 32 bytes, and of 48 and 64 bytes

CONSTANT_VK u32a shavite256_iv[2][8] =
{
  { 0x6774f31c, 0x990ae210, 0xc87d4274, 0xc9546371, 0x62b2aea8, 0x4b5801d8, 0x1b702860, 0x842f3017 },
  { 0x49bb3e47, 0x2674860d, 0xa8b392ac, 0x021ac4e6, 0x409283cf, 0x620e5d86, 0x6d929dcb, 0x96cc2a8b },
};

CONSTANT_VK u32a shavite512_iv[2][16] =
{
  { 0x83df1545, 0xf9aaec13, 0xf4803cb0, 0x11fe1f47, 0xda6cd269, 0x4f53fcd7, 0x950529a2, 0x97908147,
    0xb0a4d7af, 0x2b9132bf, 0x226e607d, 0x3c0f8d7c, 0x487b3f0f, 0x04363e22, 0x0155c99c, 0xec2e20d3 },
  { 0x72fccdd8, 0x79ca4727, 0x128a077b, 0x40d55aec, 0xd1901a06, 0x430ae307, 0xb29f5cd1, 0xdf07fbfc,
    0x8e45d73d, 0x681ab538, 0xbde86578, 0xdd577e47, 0xe275eade, 0x502d9fcd, 0xb9357178, 0x022a4b9a },
};

#if   VECT_SIZE == 1
#define SHAVITE_BOX(S,i) (S)[(i)]
#elif VECT_SIZE == 2
#define SHAVITE_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define SHAVITE_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define SHAVITE_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define SHAVITE_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

#define SHAVITE_BOX_S(S,i) (S)[(i)]

// One AES round without the round key, in place on a 128 bit state of 4 words

#define SHAVITE_AES_COL(BOX,T,Y,A,B,C,D)                                        \
{                                                                               \
  const T i0 = ((A) >> 24) & 0xff;                                              \
  const T i1 = ((B) >> 16) & 0xff;                                              \
  const T i2 = ((C) >>  8) & 0xff;                                              \
  const T i3 = ((D) >>  0) & 0xff;                                              \
                                                                                \
  Y = BOX (s_te0, i0) ^ BOX (s_te1, i1) ^ BOX (s_te2, i2) ^ BOX (s_te3, i3);    \
}

#define SHAVITE_AES(BOX,T,X0,X1,X2,X3)                                          \
{                                                                               \
  T y0;                                                                         \
  T y1;                                                                         \
  T y2;                                                                         \
  T y3;                                                                         \
                                                                                \
  SHAVITE_AES_COL (BOX, T, y0, X0, X1, X2, X3);                                 \
  SHAVITE_AES_COL (BOX, T, y1, X1, X2, X3, X0);                                 \
  SHAVITE_AES_COL (BOX, T, y2, X2, X3, X0, X1);                                 \
  SHAVITE_AES_COL (BOX, T, y3, X3, X0, X1, X2);                                 \
                                                                                \
  X0 = y0;                                                                      \
  X1 = y1;                                                                      \
  X2 = y2;                                                                      \
  X3 = y3;                                                                      \
}

// The message expansion produces the round keys in chunks of 4 words. RK keeps the last N words,
// so that chunk k sits at word 4k modulo N. A nonlinear chunk is an AES round over the chunk N / 4
// places back, rotated by one word, XOR the chunk before it. A linear chunk is the chunk N / 4
// places back XOR the words 3 (N = 16) or 7 (N = 32) places back.

#define SHAVITE_KS_NL(BOX,T,RK,N,S)                                             \
{                                                                               \
  T x0 = RK[(S) + 1];                                                           \
  T x1 = RK[(S) + 2];                                                           \
  T x2 = RK[(S) + 3];                                                           \
  T x3 = RK[(S) + 0];                                                           \
                                                                                \
  SHAVITE_AES (BOX, T, x0, x1, x2, x3);                                         \
                                                                                \
  RK[(S) + 0] = x0 ^ RK[((S) + (N) - 4) % (N)];                                 \
  RK[(S) + 1] = x1 ^ RK[((S) + (N) - 3) % (N)];                                 \
  RK[(S) + 2] = x2 ^ RK[((S) + (N) - 2) % (N)];                                 \
  RK[(S) + 3] = x3 ^ RK[((S) + (N) - 1) % (N)];                                 \
}

#define SHAVITE256_KS_L(RK,S)                                                   \
{                                                                               \
  RK[(S) + 0] ^= RK[((S) + 13) % 16];                                           \
  RK[(S) + 1] ^= RK[((S) + 14) % 16];                                           \
  RK[(S) + 2] ^= RK[((S) + 15) % 16];                                           \
  RK[(S) + 3] ^= RK[((S) +  0) % 16];                                           \
}

#define SHAVITE512_KS_L(RK,S)                                                   \
{                                                                               \
  RK[(S) + 0] ^= RK[((S) + 25) % 32];                                           \
  RK[(S) + 1] ^= RK[((S) + 26) % 32];                                           \
  RK[(S) + 2] ^= RK[((S) + 27) % 32];                                           \
  RK[(S) + 3] ^= RK[((S) + 28) % 32];                                           \
}

#define SHAVITE512_KS_NL8(BOX,T,RK)                                             \
{                                                                               \
  SHAVITE_KS_NL (BOX, T, RK, 32,  0);                                           \
  SHAVITE_KS_NL (BOX, T, RK, 32,  4);                                           \
  SHAVITE_KS_NL (BOX, T, RK, 32,  8);                                           \
  SHAVITE_KS_NL (BOX, T, RK, 32, 12);                                           \
  SHAVITE_KS_NL (BOX, T, RK, 32, 16);                                           \
  SHAVITE_KS_NL (BOX, T, RK, 32, 20);                                           \
  SHAVITE_KS_NL (BOX, T, RK, 32, 24);                                           \
  SHAVITE_KS_NL (BOX, T, RK, 32, 28);                                           \
}

#define SHAVITE512_KS_L8(RK)                                                    \
{                                                                               \
  SHAVITE512_KS_L (RK,  0);                                                     \
  SHAVITE512_KS_L (RK,  4);                                                     \
  SHAVITE512_KS_L (RK,  8);                                                     \
  SHAVITE512_KS_L (RK, 12);                                                     \
  SHAVITE512_KS_L (RK, 16);                                                     \
  SHAVITE512_KS_L (RK, 20);                                                     \
  SHAVITE512_KS_L (RK, 24);                                                     \
  SHAVITE512_KS_L (RK, 28);                                                     \
}

#define SHAVITE_XOR4(D,S,V0,V1,V2,V3)                                           \
{                                                                               \
  D[(S) + 0] ^= (V0);                                                           \
  D[(S) + 1] ^= (V1);                                                           \
  D[(S) + 2] ^= (V2);                                                           \
  D[(S) + 3] ^= (V3);                                                           \
}

#define SHAVITE_XK(RK,K)                                                        \
{                                                                               \
  x0 ^= RK[(K) + 0];                                                            \
  x1 ^= RK[(K) + 1];                                                            \
  x2 ^= RK[(K) + 2];                                                            \
  x3 ^= RK[(K) + 3];                                                            \
}

// The Feistel round function: AES rounds over the 4 words of P at R, keyed by the chunks at K0 and
// on, XOR into the 4 words of P at L. The small variant takes 3 AES rounds, the big one 4.

#define SHAVITE256_F(BOX,T,P,RK,L,R,K0,K1,K2)                                   \
{                                                                               \
  T x0 = P[(R) + 0] ^ RK[(K0) + 0];                                             \
  T x1 = P[(R) + 1] ^ RK[(K0) + 1];                                             \
  T x2 = P[(R) + 2] ^ RK[(K0) + 2];                                             \
  T x3 = P[(R) + 3] ^ RK[(K0) + 3];                                             \
                                                                                \
  SHAVITE_AES (BOX, T, x0, x1, x2, x3);                                         \
  SHAVITE_XK (RK, K1);                                                          \
  SHAVITE_AES (BOX, T, x0, x1, x2, x3);                                         \
  SHAVITE_XK (RK, K2);                                                          \
  SHAVITE_AES (BOX, T, x0, x1, x2, x3);                                         \
                                                                                \
  SHAVITE_XOR4 (P, L, x0, x1, x2, x3);                                          \
}

#define SHAVITE512_F(BOX,T,P,RK,L,R,K)                                          \
{                                                                               \
  T x0 = P[(R) + 0] ^ RK[(K) + 0];                                              \
  T x1 = P[(R) + 1] ^ RK[(K) + 1];                                              \
  T x2 = P[(R) + 2] ^ RK[(K) + 2];                                              \
  T x3 = P[(R) + 3] ^ RK[(K) + 3];                                              \
                                                                                \
  SHAVITE_AES (BOX, T, x0, x1, x2, x3);                                         \
  SHAVITE_XK (RK, (K) + 4);                                                     \
  SHAVITE_AES (BOX, T, x0, x1, x2, x3);                                         \
  SHAVITE_XK (RK, (K) + 8);                                                     \
  SHAVITE_AES (BOX, T, x0, x1, x2, x3);                                         \
  SHAVITE_XK (RK, (K) + 12);                                                    \
  SHAVITE_AES (BOX, T, x0, x1, x2, x3);                                         \
                                                                                \
  SHAVITE_XOR4 (P, L, x0, x1, x2, x3);                                          \
}

// 12 Feistel rounds on 2 halves of 4 words. Round r takes chunks 3r to 3r + 2 of the 36. Chunks
// 0 to 3 are the message. From chunk 4 on, runs of 4 nonlinear and 4 linear chunks alternate. The
// bit counter enters chunks 4, 14, 21 and 31.

#define SHAVITE256_TRANSFORM(BOX,T,SWAP,H,W,CNT0,CNT1)                          \
{                                                                               \
  T rk[16];                                                                     \
                                                                                \
  for (int i = 0; i < 16; i++) rk[i] = SWAP (W[i]);                             \
                                                                                \
  T p[8];                                                                       \
                                                                                \
  for (int i = 0; i < 8; i++) p[i] = H[i];                                      \
                                                                                \
  const u32 c0 = hc_swap32_S (CNT0);                                            \
  const u32 c1 = hc_swap32_S (CNT1);                                            \
                                                                                \
  SHAVITE256_F (BOX, T, p, rk, 0, 4,  0,  4,  8);                               \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 16,  0);                                           \
  SHAVITE_XOR4 (rk,  0, c0, ~c1, 0, 0);                                         \
  SHAVITE_KS_NL (BOX, T, rk, 16,  4);                                           \
  SHAVITE256_F (BOX, T, p, rk, 4, 0, 12,  0,  4);                               \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 16,  8);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 16, 12);                                           \
  SHAVITE256_KS_L (rk,  0);                                                     \
  SHAVITE256_F (BOX, T, p, rk, 0, 4,  8, 12,  0);                               \
                                                                                \
  SHAVITE256_KS_L (rk,  4);                                                     \
  SHAVITE256_KS_L (rk,  8);                                                     \
  SHAVITE256_KS_L (rk, 12);                                                     \
  SHAVITE256_F (BOX, T, p, rk, 4, 0,  4,  8, 12);                               \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 16,  0);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 16,  4);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 16,  8);                                           \
  SHAVITE_XOR4 (rk,  8, 0, c1, ~c0, 0);                                         \
  SHAVITE256_F (BOX, T, p, rk, 0, 4,  0,  4,  8);                               \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 16, 12);                                           \
  SHAVITE256_KS_L (rk,  0);                                                     \
  SHAVITE256_KS_L (rk,  4);                                                     \
  SHAVITE256_F (BOX, T, p, rk, 4, 0, 12,  0,  4);                               \
                                                                                \
  SHAVITE256_KS_L (rk,  8);                                                     \
  SHAVITE256_KS_L (rk, 12);                                                     \
  SHAVITE_KS_NL (BOX, T, rk, 16,  0);                                           \
  SHAVITE256_F (BOX, T, p, rk, 0, 4,  8, 12,  0);                               \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 16,  4);                                           \
  SHAVITE_XOR4 (rk,  4, 0, 0, c1, ~c0);                                         \
  SHAVITE_KS_NL (BOX, T, rk, 16,  8);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 16, 12);                                           \
  SHAVITE256_F (BOX, T, p, rk, 4, 0,  4,  8, 12);                               \
                                                                                \
  SHAVITE256_KS_L (rk,  0);                                                     \
  SHAVITE256_KS_L (rk,  4);                                                     \
  SHAVITE256_KS_L (rk,  8);                                                     \
  SHAVITE256_F (BOX, T, p, rk, 0, 4,  0,  4,  8);                               \
                                                                                \
  SHAVITE256_KS_L (rk, 12);                                                     \
  SHAVITE_KS_NL (BOX, T, rk, 16,  0);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 16,  4);                                           \
  SHAVITE256_F (BOX, T, p, rk, 4, 0, 12,  0,  4);                               \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 16,  8);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 16, 12);                                           \
  SHAVITE_XOR4 (rk, 12, c0, 0, 0, ~c1);                                         \
  SHAVITE256_KS_L (rk,  0);                                                     \
  SHAVITE256_F (BOX, T, p, rk, 0, 4,  8, 12,  0);                               \
                                                                                \
  SHAVITE256_KS_L (rk,  4);                                                     \
  SHAVITE256_KS_L (rk,  8);                                                     \
  SHAVITE256_KS_L (rk, 12);                                                     \
  SHAVITE256_F (BOX, T, p, rk, 4, 0,  4,  8, 12);                               \
                                                                                \
  for (int i = 0; i < 8; i++) H[i] ^= p[i];                                     \
}

// 14 rounds on 4 quarters of 4 words. Each round XORs F of the second quarter into the first and
// F of the fourth into the third, then the quarters rotate by one place, which the arguments
// follow instead of moving words. Round r takes chunks 8r to 8r + 7 of the 112, which always sit
// at words 0 to 31 of the window. Chunks 0 to 7 are the message. From chunk 8 on, odd rounds
// expand nonlinear chunks and even rounds linear ones. The bit counter enters chunks 8, 41, 79
// and 110, and its upper 64 bits are 0.

#define SHAVITE512_TRANSFORM(BOX,T,SWAP,H,W,CNT0,CNT1)                          \
{                                                                               \
  T rk[32];                                                                     \
                                                                                \
  for (int i = 0; i < 32; i++) rk[i] = SWAP (W[i]);                             \
                                                                                \
  T p[16];                                                                      \
                                                                                \
  for (int i = 0; i < 16; i++) p[i] = H[i];                                     \
                                                                                \
  const u32 c0 = hc_swap32_S (CNT0);                                            \
  const u32 c1 = hc_swap32_S (CNT1);                                            \
                                                                                \
  SHAVITE512_F (BOX, T, p, rk,  0,  4,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  8, 12, 16);                                     \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 32,  0);                                           \
  SHAVITE_XOR4 (rk,  0, c0, c1, 0, 0xffffffff);                                 \
  SHAVITE_KS_NL (BOX, T, rk, 32,  4);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32,  8);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 12);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 16);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 20);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 24);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 28);                                           \
  SHAVITE512_F (BOX, T, p, rk, 12,  0,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  4,  8, 16);                                     \
                                                                                \
  SHAVITE512_KS_L8 (rk);                                                        \
  SHAVITE512_F (BOX, T, p, rk,  8, 12,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  0,  4, 16);                                     \
                                                                                \
  SHAVITE512_KS_NL8 (BOX, T, rk);                                               \
  SHAVITE512_F (BOX, T, p, rk,  4,  8,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk, 12,  0, 16);                                     \
                                                                                \
  SHAVITE512_KS_L8 (rk);                                                        \
  SHAVITE512_F (BOX, T, p, rk,  0,  4,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  8, 12, 16);                                     \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 32,  0);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32,  4);                                           \
  SHAVITE_XOR4 (rk,  4, 0, 0, c1, ~c0);                                         \
  SHAVITE_KS_NL (BOX, T, rk, 32,  8);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 12);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 16);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 20);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 24);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 28);                                           \
  SHAVITE512_F (BOX, T, p, rk, 12,  0,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  4,  8, 16);                                     \
                                                                                \
  SHAVITE512_KS_L8 (rk);                                                        \
  SHAVITE512_F (BOX, T, p, rk,  8, 12,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  0,  4, 16);                                     \
                                                                                \
  SHAVITE512_KS_NL8 (BOX, T, rk);                                               \
  SHAVITE512_F (BOX, T, p, rk,  4,  8,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk, 12,  0, 16);                                     \
                                                                                \
  SHAVITE512_KS_L8 (rk);                                                        \
  SHAVITE512_F (BOX, T, p, rk,  0,  4,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  8, 12, 16);                                     \
                                                                                \
  SHAVITE512_KS_NL8 (BOX, T, rk);                                               \
  SHAVITE_XOR4 (rk, 28, 0, 0, c0, ~c1);                                         \
  SHAVITE512_F (BOX, T, p, rk, 12,  0,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  4,  8, 16);                                     \
                                                                                \
  SHAVITE512_KS_L8 (rk);                                                        \
  SHAVITE512_F (BOX, T, p, rk,  8, 12,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  0,  4, 16);                                     \
                                                                                \
  SHAVITE512_KS_NL8 (BOX, T, rk);                                               \
  SHAVITE512_F (BOX, T, p, rk,  4,  8,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk, 12,  0, 16);                                     \
                                                                                \
  SHAVITE512_KS_L8 (rk);                                                        \
  SHAVITE512_F (BOX, T, p, rk,  0,  4,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  8, 12, 16);                                     \
                                                                                \
  SHAVITE_KS_NL (BOX, T, rk, 32,  0);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32,  4);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32,  8);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 12);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 16);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 20);                                           \
  SHAVITE_KS_NL (BOX, T, rk, 32, 24);                                           \
  SHAVITE_XOR4 (rk, 24, c1, c0, 0, 0xffffffff);                                 \
  SHAVITE_KS_NL (BOX, T, rk, 32, 28);                                           \
  SHAVITE512_F (BOX, T, p, rk, 12,  0,  0);                                     \
  SHAVITE512_F (BOX, T, p, rk,  4,  8, 16);                                     \
                                                                                \
  for (int i = 0; i < 4; i++)                                                   \
  {                                                                             \
    H[ 0 + i] ^= p[ 8 + i];                                                     \
    H[ 4 + i] ^= p[12 + i];                                                     \
    H[ 8 + i] ^= p[ 0 + i];                                                     \
    H[12 + i] ^= p[ 4 + i];                                                     \
  }                                                                             \
}

// A transform is several thousand instructions, and every update and final reaches it. Kept out
// of line, it is compiled once rather than once per call site, which makes a kernel that uses all
// of the updates build 6 to 13 times faster.
//
// The transforms take the context rather than pointers to its h and m. A pointer to m is a stack
// address plus an offset. When the AMDGPU backend resolves stack offsets it can turn that sum into
// an invalid copy, which crashes a later pass of the compiler.

DECLSPEC HC_NOINLINE_ALWAYS void shavite256_transform (PRIVATE_AS shavite256_ctx_t *ctx, const u32 cnt0, const u32 cnt1)
{
  SHM_TYPE const u32 *s_te0 = ctx->s_te0;
  SHM_TYPE const u32 *s_te1 = ctx->s_te1;
  SHM_TYPE const u32 *s_te2 = ctx->s_te2;
  SHM_TYPE const u32 *s_te3 = ctx->s_te3;

  SHAVITE256_TRANSFORM (SHAVITE_BOX_S, u32, hc_swap32_S, ctx->h, ctx->m, cnt0, cnt1);
}

DECLSPEC void shavite256_init (PRIVATE_AS shavite256_ctx_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  const int iv = (dlen == 28) ? 0 : 1;

  for (int i = 0; i <  8; i++) ctx->h[i] = hc_swap32_S (shavite256_iv[iv][i]);
  for (int i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;

  ctx->s_te0 = s_te0;
  ctx->s_te1 = s_te1;
  ctx->s_te2 = s_te2;
  ctx->s_te3 = s_te3;
}

// The counter of a block is the number of message bits up to its end.

DECLSPEC void shavite256_block (PRIVATE_AS shavite256_ctx_t *ctx)
{
  ctx->cnt += 64;

  shavite256_transform (ctx, ctx->cnt << 3, ctx->cnt >> 29);

  for (int i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void shavite256_absorb (PRIVATE_AS shavite256_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->m[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[idx + 1] |= x >> ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  shavite256_block (ctx);

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void shavite256_update (PRIVATE_AS shavite256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shavite256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void shavite256_absorb_utf16le (PRIVATE_AS shavite256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  shavite256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) shavite256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void shavite256_update_utf16le (PRIVATE_AS shavite256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      shavite256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shavite256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void shavite256_update_global (PRIVATE_AS shavite256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shavite256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void shavite256_update_global_utf16le (PRIVATE_AS shavite256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      shavite256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shavite256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding is a 0x80 byte and zeros up to byte 54, then the message length in bits as a 64 bit
// and the digest length in bits as a 16 bit number, both little endian. When these do not fit
// behind the message, they take a block of their own. The counter of a block that holds no
// message bits is 0. A context with invalid UTF-8 input produces a digest with every bit flipped,
// so that no candidate matches it by chance.

DECLSPEC void shavite256_final (PRIVATE_AS shavite256_ctx_t *ctx)
{
  const int pos = ctx->pos;

  const u32 bytes = ctx->cnt + (u32) pos;

  const u32 bits0 = bytes << 3;
  const u32 bits1 = bytes >> 29;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  u32 cnt0 = bits0;
  u32 cnt1 = bits1;

  if (pos >= 54)
  {
    shavite256_transform (ctx, bits0, bits1);

    for (int i = 0; i < 16; i++) ctx->m[i] = 0;
  }

  if ((pos == 0) || (pos >= 54))
  {
    cnt0 = 0;
    cnt1 = 0;
  }

  const u32 dbits = (u32) ctx->dlen * 8;

  ctx->m[13] |= bits0 << 16;
  ctx->m[14]  = (bits0 >> 16) | (bits1 << 16);
  ctx->m[15]  = (bits1 >> 16) | (dbits << 16);

  shavite256_transform (ctx, cnt0, cnt1);

  for (int i = 0; i < 8; i++) ctx->h[i] = hc_swap32_S (ctx->h[i]);

  if (ctx->len < 0)
  {
    for (int i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC HC_NOINLINE_ALWAYS void shavite256_transform_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx, const u32 cnt0, const u32 cnt1)
{
  SHM_TYPE const u32 *s_te0 = ctx->s_te0;
  SHM_TYPE const u32 *s_te1 = ctx->s_te1;
  SHM_TYPE const u32 *s_te2 = ctx->s_te2;
  SHM_TYPE const u32 *s_te3 = ctx->s_te3;

  SHAVITE256_TRANSFORM (SHAVITE_BOX, u32x, hc_swap32, ctx->h, ctx->m, cnt0, cnt1);
}

DECLSPEC void shavite256_init_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  const int iv = (dlen == 28) ? 0 : 1;

  for (int i = 0; i <  8; i++) ctx->h[i] = make_u32x (hc_swap32_S (shavite256_iv[iv][i]));
  for (int i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;

  ctx->s_te0 = s_te0;
  ctx->s_te1 = s_te1;
  ctx->s_te2 = s_te2;
  ctx->s_te3 = s_te3;
}

DECLSPEC void shavite256_block_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx)
{
  ctx->cnt += 64;

  shavite256_transform_vector (ctx, ctx->cnt << 3, ctx->cnt >> 29);

  for (int i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void shavite256_absorb_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->m[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[idx + 1] |= x >> ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  shavite256_block_vector (ctx);

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void shavite256_update_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    shavite256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void shavite256_update_vector_utf16le (PRIVATE_AS shavite256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    shavite256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) shavite256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void shavite256_final_vector (PRIVATE_AS shavite256_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  const u32 bytes = ctx->cnt + (u32) pos;

  const u32 bits0 = bytes << 3;
  const u32 bits1 = bytes >> 29;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  u32 cnt0 = bits0;
  u32 cnt1 = bits1;

  if (pos >= 54)
  {
    shavite256_transform_vector (ctx, bits0, bits1);

    for (int i = 0; i < 16; i++) ctx->m[i] = 0;
  }

  if ((pos == 0) || (pos >= 54))
  {
    cnt0 = 0;
    cnt1 = 0;
  }

  const u32 dbits = (u32) ctx->dlen * 8;

  ctx->m[13] |= bits0 << 16;
  ctx->m[14]  = make_u32x ((bits0 >> 16) | (bits1 << 16));
  ctx->m[15]  = make_u32x ((bits1 >> 16) | (dbits << 16));

  shavite256_transform_vector (ctx, cnt0, cnt1);

  for (int i = 0; i < 8; i++) ctx->h[i] = hc_swap32 (ctx->h[i]);
}

DECLSPEC HC_NOINLINE_ALWAYS void shavite512_transform (PRIVATE_AS shavite512_ctx_t *ctx, const u32 cnt0, const u32 cnt1)
{
  SHM_TYPE const u32 *s_te0 = ctx->s_te0;
  SHM_TYPE const u32 *s_te1 = ctx->s_te1;
  SHM_TYPE const u32 *s_te2 = ctx->s_te2;
  SHM_TYPE const u32 *s_te3 = ctx->s_te3;

  SHAVITE512_TRANSFORM (SHAVITE_BOX_S, u32, hc_swap32_S, ctx->h, ctx->m, cnt0, cnt1);
}

DECLSPEC void shavite512_init (PRIVATE_AS shavite512_ctx_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  const int iv = (dlen == 48) ? 0 : 1;

  for (int i = 0; i < 16; i++) ctx->h[i] = hc_swap32_S (shavite512_iv[iv][i]);
  for (int i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;

  ctx->s_te0 = s_te0;
  ctx->s_te1 = s_te1;
  ctx->s_te2 = s_te2;
  ctx->s_te3 = s_te3;
}

DECLSPEC void shavite512_block (PRIVATE_AS shavite512_ctx_t *ctx)
{
  ctx->cnt += 128;

  shavite512_transform (ctx, ctx->cnt << 3, ctx->cnt >> 29);

  for (int i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void shavite512_absorb (PRIVATE_AS shavite512_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->m[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[idx + 1] |= x >> ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  shavite512_block (ctx);

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void shavite512_update (PRIVATE_AS shavite512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shavite512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void shavite512_absorb_utf16le (PRIVATE_AS shavite512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  shavite512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) shavite512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void shavite512_update_utf16le (PRIVATE_AS shavite512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      shavite512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shavite512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void shavite512_update_global (PRIVATE_AS shavite512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shavite512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void shavite512_update_global_utf16le (PRIVATE_AS shavite512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      shavite512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shavite512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// As for the small variant, with the length fields from byte 110 on: a 128 bit message length and
// the 16 bit digest length.

DECLSPEC void shavite512_final (PRIVATE_AS shavite512_ctx_t *ctx)
{
  const int pos = ctx->pos;

  const u32 bytes = ctx->cnt + (u32) pos;

  const u32 bits0 = bytes << 3;
  const u32 bits1 = bytes >> 29;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  u32 cnt0 = bits0;
  u32 cnt1 = bits1;

  if (pos >= 110)
  {
    shavite512_transform (ctx, bits0, bits1);

    for (int i = 0; i < 32; i++) ctx->m[i] = 0;
  }

  if ((pos == 0) || (pos >= 110))
  {
    cnt0 = 0;
    cnt1 = 0;
  }

  const u32 dbits = (u32) ctx->dlen * 8;

  ctx->m[27] |= bits0 << 16;
  ctx->m[28]  = (bits0 >> 16) | (bits1 << 16);
  ctx->m[29]  = (bits1 >> 16);
  ctx->m[30]  = 0;
  ctx->m[31]  = (dbits << 16);

  shavite512_transform (ctx, cnt0, cnt1);

  for (int i = 0; i < 16; i++) ctx->h[i] = hc_swap32_S (ctx->h[i]);

  if (ctx->len < 0)
  {
    for (int i = 0; i < 16; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// Each lane runs the scalar transform. The AES table reads load one word per lane in any case, and a
// vector form of the fully unrolled rounds takes Intel's CPU compiler tens of minutes to build.

DECLSPEC HC_NOINLINE_ALWAYS void shavite512_transform_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx, const u32 cnt0, const u32 cnt1)
{
  #if VECT_SIZE == 1
  SHM_TYPE const u32 *s_te0 = ctx->s_te0;
  SHM_TYPE const u32 *s_te1 = ctx->s_te1;
  SHM_TYPE const u32 *s_te2 = ctx->s_te2;
  SHM_TYPE const u32 *s_te3 = ctx->s_te3;

  SHAVITE512_TRANSFORM (SHAVITE_BOX, u32x, hc_swap32, ctx->h, ctx->m, cnt0, cnt1);
  #else
  for (int lane = 0; lane < VECT_SIZE; lane++)
  {
    shavite512_ctx_t c;

    for (int i = 0; i < 16; i++) c.h[i] = ((PRIVATE_AS const u32 *) &ctx->h[i])[lane];
    for (int i = 0; i < 32; i++) c.m[i] = ((PRIVATE_AS const u32 *) &ctx->m[i])[lane];

    c.s_te0 = ctx->s_te0;
    c.s_te1 = ctx->s_te1;
    c.s_te2 = ctx->s_te2;
    c.s_te3 = ctx->s_te3;

    shavite512_transform (&c, cnt0, cnt1);

    for (int i = 0; i < 16; i++) ((PRIVATE_AS u32 *) &ctx->h[i])[lane] = c.h[i];
  }
  #endif
}

DECLSPEC void shavite512_init_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  const int iv = (dlen == 48) ? 0 : 1;

  for (int i = 0; i < 16; i++) ctx->h[i] = make_u32x (hc_swap32_S (shavite512_iv[iv][i]));
  for (int i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;

  ctx->s_te0 = s_te0;
  ctx->s_te1 = s_te1;
  ctx->s_te2 = s_te2;
  ctx->s_te3 = s_te3;
}

DECLSPEC void shavite512_block_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx)
{
  ctx->cnt += 128;

  shavite512_transform_vector (ctx, ctx->cnt << 3, ctx->cnt >> 29);

  for (int i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void shavite512_absorb_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->m[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[idx + 1] |= x >> ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  shavite512_block_vector (ctx);

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void shavite512_update_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    shavite512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void shavite512_update_vector_utf16le (PRIVATE_AS shavite512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    shavite512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) shavite512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void shavite512_final_vector (PRIVATE_AS shavite512_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  const u32 bytes = ctx->cnt + (u32) pos;

  const u32 bits0 = bytes << 3;
  const u32 bits1 = bytes >> 29;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  u32 cnt0 = bits0;
  u32 cnt1 = bits1;

  if (pos >= 110)
  {
    shavite512_transform_vector (ctx, bits0, bits1);

    for (int i = 0; i < 32; i++) ctx->m[i] = 0;
  }

  if ((pos == 0) || (pos >= 110))
  {
    cnt0 = 0;
    cnt1 = 0;
  }

  const u32 dbits = (u32) ctx->dlen * 8;

  ctx->m[27] |= bits0 << 16;
  ctx->m[28]  = make_u32x ((bits0 >> 16) | (bits1 << 16));
  ctx->m[29]  = make_u32x (bits1 >> 16);
  ctx->m[30]  = 0;
  ctx->m[31]  = make_u32x (dbits << 16);

  shavite512_transform_vector (ctx, cnt0, cnt1);

  for (int i = 0; i < 16; i++) ctx->h[i] = hc_swap32 (ctx->h[i]);
}
