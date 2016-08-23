//#include <cpu-sha1.h>
#include "bit_ops.h"
#include "inc_hash_constants.h"

/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

typedef u32(*sha_func) (u32 x, u32 y, u32 z);

u32 SHA1_F0(u32 x, u32 y, u32 z);
inline u32 SHA1_F0(u32 x, u32 y, u32 z) {
  return z ^ (x & (y ^ z));
}

u32 SHA1_F1(u32 x, u32 y, u32 z);
inline u32 SHA1_F1(u32 x, u32 y, u32 z) {
  return (x ^ y ^ z);
}

u32 SHA1_F2(u32 x, u32 y, u32 z);
inline u32 SHA1_F2(u32 x, u32 y, u32 z) {
  return ((x& y) | (z& (x ^ y)));
}

void SHA1_STEP(sha_func f, u32 K, u32 a, u32 *b, u32 c, u32 d, u32 *e, u32 x);
inline void SHA1_STEP(sha_func f, u32 K, u32 a, u32 *b, u32 c, u32 d, u32 *e, u32 x)
{
  (*e) += K;
  (*e) += x;
  (*e) += f(*b, c, d);
  (*e) += rotl32(a, 5u);
  (*b) = rotl32(*b, 30u);
}

void sha1_64(uint block[16], uint digest[5])
{
  u32 A = digest[0];
  u32 B = digest[1];
  u32 C = digest[2];
  u32 D = digest[3];
  u32 E = digest[4];

  u32 w0_t = block[0];
  u32 w1_t = block[1];
  u32 w2_t = block[2];
  u32 w3_t = block[3];
  u32 w4_t = block[4];
  u32 w5_t = block[5];
  u32 w6_t = block[6];
  u32 w7_t = block[7];
  u32 w8_t = block[8];
  u32 w9_t = block[9];
  u32 wa_t = block[10];
  u32 wb_t = block[11];
  u32 wc_t = block[12];
  u32 wd_t = block[13];
  u32 we_t = block[14];
  u32 wf_t = block[15];




  SHA1_STEP(SHA1_F0, SHA1C00, A, &B, C, D, &E, w0_t);
  SHA1_STEP(SHA1_F0, SHA1C00, E, &A, B, C, &D, w1_t);
  SHA1_STEP(SHA1_F0, SHA1C00, D, &E, A, B, &C, w2_t);
  SHA1_STEP(SHA1_F0, SHA1C00, C, &D, E, A, &B, w3_t);
  SHA1_STEP(SHA1_F0, SHA1C00, B, &C, D, E, &A, w4_t);
  SHA1_STEP(SHA1_F0, SHA1C00, A, &B, C, D, &E, w5_t);
  SHA1_STEP(SHA1_F0, SHA1C00, E, &A, B, C, &D, w6_t);
  SHA1_STEP(SHA1_F0, SHA1C00, D, &E, A, B, &C, w7_t);
  SHA1_STEP(SHA1_F0, SHA1C00, C, &D, E, A, &B, w8_t);
  SHA1_STEP(SHA1_F0, SHA1C00, B, &C, D, E, &A, w9_t);
  SHA1_STEP(SHA1_F0, SHA1C00, A, &B, C, D, &E, wa_t);
  SHA1_STEP(SHA1_F0, SHA1C00, E, &A, B, C, &D, wb_t);
  SHA1_STEP(SHA1_F0, SHA1C00, D, &E, A, B, &C, wc_t);
  SHA1_STEP(SHA1_F0, SHA1C00, C, &D, E, A, &B, wd_t);
  SHA1_STEP(SHA1_F0, SHA1C00, B, &C, D, E, &A, we_t);
  SHA1_STEP(SHA1_F0, SHA1C00, A, &B, C, D, &E, wf_t);

  w0_t = rotl32((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u);
  SHA1_STEP(SHA1_F0, SHA1C00, E, &A, B, C, &D, w0_t);
  w1_t = rotl32((we_t ^ w9_t ^ w3_t ^ w1_t), 1u);
  SHA1_STEP(SHA1_F0, SHA1C00, D, &E, A, B, &C, w1_t);
  w2_t = rotl32((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u);
  SHA1_STEP(SHA1_F0, SHA1C00, C, &D, E, A, &B, w2_t);
  w3_t = rotl32((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u);
  SHA1_STEP(SHA1_F0, SHA1C00, B, &C, D, E, &A, w3_t);

  w4_t = rotl32((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, A, &B, C, D, &E, w4_t);
  w5_t = rotl32((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, E, &A, B, C, &D, w5_t);
  w6_t = rotl32((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, D, &E, A, B, &C, w6_t);
  w7_t = rotl32((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, C, &D, E, A, &B, w7_t);
  w8_t = rotl32((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, B, &C, D, E, &A, w8_t);
  w9_t = rotl32((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, A, &B, C, D, &E, w9_t);
  wa_t = rotl32((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, E, &A, B, C, &D, wa_t);
  wb_t = rotl32((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, D, &E, A, B, &C, wb_t);
  wc_t = rotl32((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, C, &D, E, A, &B, wc_t);
  wd_t = rotl32((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, B, &C, D, E, &A, wd_t);
  we_t = rotl32((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, A, &B, C, D, &E, we_t);
  wf_t = rotl32((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, E, &A, B, C, &D, wf_t);
  w0_t = rotl32((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, D, &E, A, B, &C, w0_t);
  w1_t = rotl32((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, C, &D, E, A, &B, w1_t);
  w2_t = rotl32((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, B, &C, D, E, &A, w2_t);
  w3_t = rotl32((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, A, &B, C, D, &E, w3_t);
  w4_t = rotl32((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, E, &A, B, C, &D, w4_t);
  w5_t = rotl32((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, D, &E, A, B, &C, w5_t);
  w6_t = rotl32((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, C, &D, E, A, &B, w6_t);
  w7_t = rotl32((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP(SHA1_F1, SHA1C01, B, &C, D, E, &A, w7_t);

  w8_t = rotl32((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, A, &B, C, D, &E, w8_t);
  w9_t = rotl32((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, E, &A, B, C, &D, w9_t);
  wa_t = rotl32((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, D, &E, A, B, &C, wa_t);
  wb_t = rotl32((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, C, &D, E, A, &B, wb_t);
  wc_t = rotl32((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, B, &C, D, E, &A, wc_t);
  wd_t = rotl32((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, A, &B, C, D, &E, wd_t);
  we_t = rotl32((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, E, &A, B, C, &D, we_t);
  wf_t = rotl32((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, D, &E, A, B, &C, wf_t);
  w0_t = rotl32((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, C, &D, E, A, &B, w0_t);
  w1_t = rotl32((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, B, &C, D, E, &A, w1_t);
  w2_t = rotl32((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, A, &B, C, D, &E, w2_t);
  w3_t = rotl32((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, E, &A, B, C, &D, w3_t);
  w4_t = rotl32((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, D, &E, A, B, &C, w4_t);
  w5_t = rotl32((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, C, &D, E, A, &B, w5_t);
  w6_t = rotl32((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, B, &C, D, E, &A, w6_t);
  w7_t = rotl32((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, A, &B, C, D, &E, w7_t);
  w8_t = rotl32((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, E, &A, B, C, &D, w8_t);
  w9_t = rotl32((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, D, &E, A, B, &C, w9_t);
  wa_t = rotl32((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, C, &D, E, A, &B, wa_t);
  wb_t = rotl32((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP(SHA1_F2, SHA1C02, B, &C, D, E, &A, wb_t);

  wc_t = rotl32((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, A, &B, C, D, &E, wc_t);
  wd_t = rotl32((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, E, &A, B, C, &D, wd_t);
  we_t = rotl32((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, D, &E, A, B, &C, we_t);
  wf_t = rotl32((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, C, &D, E, A, &B, wf_t);
  w0_t = rotl32((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, B, &C, D, E, &A, w0_t);
  w1_t = rotl32((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, A, &B, C, D, &E, w1_t);
  w2_t = rotl32((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, E, &A, B, C, &D, w2_t);
  w3_t = rotl32((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, D, &E, A, B, &C, w3_t);
  w4_t = rotl32((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, C, &D, E, A, &B, w4_t);
  w5_t = rotl32((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, B, &C, D, E, &A, w5_t);
  w6_t = rotl32((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, A, &B, C, D, &E, w6_t);
  w7_t = rotl32((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, E, &A, B, C, &D, w7_t);
  w8_t = rotl32((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, D, &E, A, B, &C, w8_t);
  w9_t = rotl32((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, C, &D, E, A, &B, w9_t);
  wa_t = rotl32((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, B, &C, D, E, &A, wa_t);
  wb_t = rotl32((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, A, &B, C, D, &E, wb_t);
  wc_t = rotl32((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, E, &A, B, C, &D, wc_t);
  wd_t = rotl32((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, D, &E, A, B, &C, wd_t);
  we_t = rotl32((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, C, &D, E, A, &B, we_t);
  wf_t = rotl32((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP(SHA1_F1, SHA1C03, B, &C, D, E, &A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}
