/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

__constant u32a k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

void sha256_transform (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[8])
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];
  u32 f = digest[5];
  u32 g = digest[6];
  u32 h = digest[7];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha256[i +  0]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha256[i +  1]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha256[i +  2]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha256[i +  3]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha256[i +  4]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha256[i +  5]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha256[i +  6]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha256[i +  7]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha256[i +  8]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha256[i +  9]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha256[i + 10]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha256[i + 11]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha256[i + 12]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha256[i + 13]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, k_sha256[i + 14]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha256[i + 15]); \
  }

  ROUND_STEP (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

void hmac_sha256_pad (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[8], u32 opad[8])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA256M_A;
  ipad[1] = SHA256M_B;
  ipad[2] = SHA256M_C;
  ipad[3] = SHA256M_D;
  ipad[4] = SHA256M_E;
  ipad[5] = SHA256M_F;
  ipad[6] = SHA256M_G;
  ipad[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA256M_A;
  opad[1] = SHA256M_B;
  opad[2] = SHA256M_C;
  opad[3] = SHA256M_D;
  opad[4] = SHA256M_E;
  opad[5] = SHA256M_F;
  opad[6] = SHA256M_G;
  opad[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, opad);
}

void hmac_sha256_run (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[8], u32 opad[8], u32 digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform (w0, w1, w2, w3, digest);
}

void memcat8 (u32 block0[4], u32 block1[4], u32 block2[4], u32 block3[4], const u32 block_len, const u32 append[2])
{
  switch (block_len)
  {
    case 0:
      block0[0] = append[0];
      block0[1] = append[1];
      break;

    case 1:
      block0[0] = block0[0]       | append[0] <<  8;
      block0[1] = append[0] >> 24 | append[1] <<  8;
      block0[2] = append[1] >> 24;
      break;

    case 2:
      block0[0] = block0[0]       | append[0] << 16;
      block0[1] = append[0] >> 16 | append[1] << 16;
      block0[2] = append[1] >> 16;
      break;

    case 3:
      block0[0] = block0[0]       | append[0] << 24;
      block0[1] = append[0] >>  8 | append[1] << 24;
      block0[2] = append[1] >>  8;
      break;

    case 4:
      block0[1] = append[0];
      block0[2] = append[1];
      break;

    case 5:
      block0[1] = block0[1]       | append[0] <<  8;
      block0[2] = append[0] >> 24 | append[1] <<  8;
      block0[3] = append[1] >> 24;
      break;

    case 6:
      block0[1] = block0[1]       | append[0] << 16;
      block0[2] = append[0] >> 16 | append[1] << 16;
      block0[3] = append[1] >> 16;
      break;

    case 7:
      block0[1] = block0[1]       | append[0] << 24;
      block0[2] = append[0] >>  8 | append[1] << 24;
      block0[3] = append[1] >>  8;
      break;

    case 8:
      block0[2] = append[0];
      block0[3] = append[1];
      break;

    case 9:
      block0[2] = block0[2]       | append[0] <<  8;
      block0[3] = append[0] >> 24 | append[1] <<  8;
      block1[0] = append[1] >> 24;
      break;

    case 10:
      block0[2] = block0[2]       | append[0] << 16;
      block0[3] = append[0] >> 16 | append[1] << 16;
      block1[0] = append[1] >> 16;
      break;

    case 11:
      block0[2] = block0[2]       | append[0] << 24;
      block0[3] = append[0] >>  8 | append[1] << 24;
      block1[0] = append[1] >>  8;
      break;

    case 12:
      block0[3] = append[0];
      block1[0] = append[1];
      break;

    case 13:
      block0[3] = block0[3]       | append[0] <<  8;
      block1[0] = append[0] >> 24 | append[1] <<  8;
      block1[1] = append[1] >> 24;
      break;

    case 14:
      block0[3] = block0[3]       | append[0] << 16;
      block1[0] = append[0] >> 16 | append[1] << 16;
      block1[1] = append[1] >> 16;
      break;

    case 15:
      block0[3] = block0[3]       | append[0] << 24;
      block1[0] = append[0] >>  8 | append[1] << 24;
      block1[1] = append[1] >>  8;
      break;

    case 16:
      block1[0] = append[0];
      block1[1] = append[1];
      break;

    case 17:
      block1[0] = block1[0]       | append[0] <<  8;
      block1[1] = append[0] >> 24 | append[1] <<  8;
      block1[2] = append[1] >> 24;
      break;

    case 18:
      block1[0] = block1[0]       | append[0] << 16;
      block1[1] = append[0] >> 16 | append[1] << 16;
      block1[2] = append[1] >> 16;
      break;

    case 19:
      block1[0] = block1[0]       | append[0] << 24;
      block1[1] = append[0] >>  8 | append[1] << 24;
      block1[2] = append[1] >>  8;
      break;

    case 20:
      block1[1] = append[0];
      block1[2] = append[1];
      break;

    case 21:
      block1[1] = block1[1]       | append[0] <<  8;
      block1[2] = append[0] >> 24 | append[1] <<  8;
      block1[3] = append[1] >> 24;
      break;

    case 22:
      block1[1] = block1[1]       | append[0] << 16;
      block1[2] = append[0] >> 16 | append[1] << 16;
      block1[3] = append[1] >> 16;
      break;

    case 23:
      block1[1] = block1[1]       | append[0] << 24;
      block1[2] = append[0] >>  8 | append[1] << 24;
      block1[3] = append[1] >>  8;
      break;

    case 24:
      block1[2] = append[0];
      block1[3] = append[1];
      break;

    case 25:
      block1[2] = block1[2]       | append[0] <<  8;
      block1[3] = append[0] >> 24 | append[1] <<  8;
      block2[0] = append[1] >> 24;
      break;

    case 26:
      block1[2] = block1[2]       | append[0] << 16;
      block1[3] = append[0] >> 16 | append[1] << 16;
      block2[0] = append[1] >> 16;
      break;

    case 27:
      block1[2] = block1[2]       | append[0] << 24;
      block1[3] = append[0] >>  8 | append[1] << 24;
      block2[0] = append[1] >>  8;
      break;

    case 28:
      block1[3] = append[0];
      block2[0] = append[1];
      break;

    case 29:
      block1[3] = block1[3]       | append[0] <<  8;
      block2[0] = append[0] >> 24 | append[1] <<  8;
      block2[1] = append[1] >> 24;
      break;

    case 30:
      block1[3] = block1[3]       | append[0] << 16;
      block2[0] = append[0] >> 16 | append[1] << 16;
      block2[1] = append[1] >> 16;
      break;

    case 31:
      block1[3] = block1[3]       | append[0] << 24;
      block2[0] = append[0] >>  8 | append[1] << 24;
      block2[1] = append[1] >>  8;
      break;

    case 32:
      block2[0] = append[0];
      block2[1] = append[1];
      break;

    case 33:
      block2[0] = block2[0]       | append[0] <<  8;
      block2[1] = append[0] >> 24 | append[1] <<  8;
      block2[2] = append[1] >> 24;
      break;

    case 34:
      block2[0] = block2[0]       | append[0] << 16;
      block2[1] = append[0] >> 16 | append[1] << 16;
      block2[2] = append[1] >> 16;
      break;

    case 35:
      block2[0] = block2[0]       | append[0] << 24;
      block2[1] = append[0] >>  8 | append[1] << 24;
      block2[2] = append[1] >>  8;
      break;

    case 36:
      block2[1] = append[0];
      block2[2] = append[1];
      break;

    case 37:
      block2[1] = block2[1]       | append[0] <<  8;
      block2[2] = append[0] >> 24 | append[1] <<  8;
      block2[3] = append[1] >> 24;
      break;

    case 38:
      block2[1] = block2[1]       | append[0] << 16;
      block2[2] = append[0] >> 16 | append[1] << 16;
      block2[3] = append[1] >> 16;
      break;

    case 39:
      block2[1] = block2[1]       | append[0] << 24;
      block2[2] = append[0] >>  8 | append[1] << 24;
      block2[3] = append[1] >>  8;
      break;

    case 40:
      block2[2] = append[0];
      block2[3] = append[1];
      break;

    case 41:
      block2[2] = block2[2]       | append[0] <<  8;
      block2[3] = append[0] >> 24 | append[1] <<  8;
      block3[0] = append[1] >> 24;
      break;

    case 42:
      block2[2] = block2[2]       | append[0] << 16;
      block2[3] = append[0] >> 16 | append[1] << 16;
      block3[0] = append[1] >> 16;
      break;

    case 43:
      block2[2] = block2[2]       | append[0] << 24;
      block2[3] = append[0] >>  8 | append[1] << 24;
      block3[0] = append[1] >>  8;
      break;

    case 44:
      block2[3] = append[0];
      block3[0] = append[1];
      break;

    case 45:
      block2[3] = block2[3]       | append[0] <<  8;
      block3[0] = append[0] >> 24 | append[1] <<  8;
      block3[1] = append[1] >> 24;
      break;

    case 46:
      block2[3] = block2[3]       | append[0] << 16;
      block3[0] = append[0] >> 16 | append[1] << 16;
      block3[1] = append[1] >> 16;
      break;

    case 47:
      block2[3] = block2[3]       | append[0] << 24;
      block3[0] = append[0] >>  8 | append[1] << 24;
      block3[1] = append[1] >>  8;
      break;

    case 48:
      block3[0] = append[0];
      block3[1] = append[1];
      break;

    case 49:
      block3[0] = block3[0]       | append[0] <<  8;
      block3[1] = append[0] >> 24 | append[1] <<  8;
      block3[2] = append[1] >> 24;
      break;

    case 50:
      block3[0] = block3[0]       | append[0] << 16;
      block3[1] = append[0] >> 16 | append[1] << 16;
      block3[2] = append[1] >> 16;
      break;

    case 51:
      block3[0] = block3[0]       | append[0] << 24;
      block3[1] = append[0] >>  8 | append[1] << 24;
      block3[2] = append[1] >>  8;
      break;

    case 52:
      block3[1] = append[0];
      block3[2] = append[1];
      break;

    case 53:
      block3[1] = block3[1]       | append[0] <<  8;
      block3[2] = append[0] >> 24 | append[1] <<  8;
      block3[3] = append[1] >> 24;
      break;

    case 54:
      block3[1] = block3[1]       | append[0] << 16;
      block3[2] = append[0] >> 16 | append[1] << 16;
      block3[3] = append[1] >> 16;
      break;

    case 55:
      block3[1] = block3[1]       | append[0] << 24;
      block3[2] = append[0] >>  8 | append[1] << 24;
      block3[3] = append[1] >>  8;
      break;

    case 56:
      block3[2] = append[0];
      block3[3] = append[1];
      break;
  }
}

uint4 swap32_4 (uint4 v)
{
  return (rotate ((v & 0x00FF00FF), 24u) | rotate ((v & 0xFF00FF00),  8u));
}

#define GET_SCRYPT_CNT(r,p) (2 * (r) * 16 * (p))
#define GET_SMIX_CNT(r,N)   (2 * (r) * 16 * (N))
#define GET_STATE_CNT(r)    (2 * (r) * 16)

#define SCRYPT_CNT  GET_SCRYPT_CNT (SCRYPT_R, SCRYPT_P)
#define SCRYPT_CNT4 (SCRYPT_CNT / 4)
#define STATE_CNT   GET_STATE_CNT  (SCRYPT_R)
#define STATE_CNT4  (STATE_CNT / 4)

#define ADD_ROTATE_XOR(r,i1,i2,s) (r) ^= rotate ((i1) + (i2), (s));

#define SALSA20_2R()                \
{                                   \
  ADD_ROTATE_XOR (X1, X0, X3,  7);  \
  ADD_ROTATE_XOR (X2, X1, X0,  9);  \
  ADD_ROTATE_XOR (X3, X2, X1, 13);  \
  ADD_ROTATE_XOR (X0, X3, X2, 18);  \
                                    \
  X1 = X1.s3012;                    \
  X2 = X2.s2301;                    \
  X3 = X3.s1230;                    \
                                    \
  ADD_ROTATE_XOR (X3, X0, X1,  7);  \
  ADD_ROTATE_XOR (X2, X3, X0,  9);  \
  ADD_ROTATE_XOR (X1, X2, X3, 13);  \
  ADD_ROTATE_XOR (X0, X1, X2, 18);  \
                                    \
  X1 = X1.s1230;                    \
  X2 = X2.s2301;                    \
  X3 = X3.s3012;                    \
}

#define SALSA20_8_XOR() \
{                       \
  R0 = R0 ^ Y0;         \
  R1 = R1 ^ Y1;         \
  R2 = R2 ^ Y2;         \
  R3 = R3 ^ Y3;         \
                        \
  uint4 X0 = R0;        \
  uint4 X1 = R1;        \
  uint4 X2 = R2;        \
  uint4 X3 = R3;        \
                        \
  SALSA20_2R ();        \
  SALSA20_2R ();        \
  SALSA20_2R ();        \
  SALSA20_2R ();        \
                        \
  R0 = R0 + X0;         \
  R1 = R1 + X1;         \
  R2 = R2 + X2;         \
  R3 = R3 + X3;         \
}

void salsa_r (uint4 *TI)
{
  uint4 R0 = TI[STATE_CNT4 - 4];
  uint4 R1 = TI[STATE_CNT4 - 3];
  uint4 R2 = TI[STATE_CNT4 - 2];
  uint4 R3 = TI[STATE_CNT4 - 1];

  uint4 TO[STATE_CNT4];

  int idx_y  = 0;
  int idx_r1 = 0;
  int idx_r2 = SCRYPT_R * 4;

  for (int i = 0; i < SCRYPT_R; i++)
  {
    uint4 Y0;
    uint4 Y1;
    uint4 Y2;
    uint4 Y3;

    Y0 = TI[idx_y++];
    Y1 = TI[idx_y++];
    Y2 = TI[idx_y++];
    Y3 = TI[idx_y++];

    SALSA20_8_XOR ();

    TO[idx_r1++] = R0;
    TO[idx_r1++] = R1;
    TO[idx_r1++] = R2;
    TO[idx_r1++] = R3;

    Y0 = TI[idx_y++];
    Y1 = TI[idx_y++];
    Y2 = TI[idx_y++];
    Y3 = TI[idx_y++];

    SALSA20_8_XOR ();

    TO[idx_r2++] = R0;
    TO[idx_r2++] = R1;
    TO[idx_r2++] = R2;
    TO[idx_r2++] = R3;
  }

  #pragma unroll
  for (int i = 0; i < STATE_CNT4; i++)
  {
    TI[i] = TO[i];
  }
}

void scrypt_smix (uint4 *X, uint4 *T, __global uint4 *V0, __global uint4 *V1, __global uint4 *V2, __global uint4 *V3)
{
  #define Coord(xd4,y,z) (((xd4) * ySIZE * zSIZE) + ((y) * zSIZE) + (z))
  #define CO Coord(xd4,y,z)

  const u32 ySIZE = SCRYPT_N / SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT4;

  const u32 x = get_global_id (0);

  const u32 xd4 = x / 4;
  const u32 xm4 = x & 3;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i += 4)
  {
    T[0] = (uint4) (X[i + 0].x, X[i + 1].y, X[i + 2].z, X[i + 3].w);
    T[1] = (uint4) (X[i + 1].x, X[i + 2].y, X[i + 3].z, X[i + 0].w);
    T[2] = (uint4) (X[i + 2].x, X[i + 3].y, X[i + 0].z, X[i + 1].w);
    T[3] = (uint4) (X[i + 3].x, X[i + 0].y, X[i + 1].z, X[i + 2].w);

    X[i + 0] = T[0];
    X[i + 1] = T[1];
    X[i + 2] = T[2];
    X[i + 3] = T[3];
  }

  for (u32 y = 0; y < ySIZE; y++)
  {
    switch (xm4)
    {
      case 0: for (u32 z = 0; z < zSIZE; z++) V0[CO] = X[z]; break;
      case 1: for (u32 z = 0; z < zSIZE; z++) V1[CO] = X[z]; break;
      case 2: for (u32 z = 0; z < zSIZE; z++) V2[CO] = X[z]; break;
      case 3: for (u32 z = 0; z < zSIZE; z++) V3[CO] = X[z]; break;
    }

    for (u32 i = 0; i < SCRYPT_TMTO; i++) salsa_r (X);
  }

  for (u32 i = 0; i < SCRYPT_N; i++)
  {
    const u32 k = X[zSIZE - 4].x & (SCRYPT_N - 1);

    const u32 y = k / SCRYPT_TMTO;

    const u32 km = k - (y * SCRYPT_TMTO);

    switch (xm4)
    {
      case 0: for (u32 z = 0; z < zSIZE; z++) T[z] = V0[CO]; break;
      case 1: for (u32 z = 0; z < zSIZE; z++) T[z] = V1[CO]; break;
      case 2: for (u32 z = 0; z < zSIZE; z++) T[z] = V2[CO]; break;
      case 3: for (u32 z = 0; z < zSIZE; z++) T[z] = V3[CO]; break;
    }

    for (u32 i = 0; i < km; i++) salsa_r (T);

    for (u32 z = 0; z < zSIZE; z++) X[z] ^= T[z];

    salsa_r (X);
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < STATE_CNT4; i += 4)
  {
    T[0] = (uint4) (X[i + 0].x, X[i + 3].y, X[i + 2].z, X[i + 1].w);
    T[1] = (uint4) (X[i + 1].x, X[i + 0].y, X[i + 3].z, X[i + 2].w);
    T[2] = (uint4) (X[i + 2].x, X[i + 1].y, X[i + 0].z, X[i + 3].w);
    T[3] = (uint4) (X[i + 3].x, X[i + 2].y, X[i + 1].z, X[i + 0].w);

    X[i + 0] = T[0];
    X[i + 1] = T[1];
    X[i + 2] = T[2];
    X[i + 3] = T[3];
  }
}

__kernel void m08900_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global scrypt_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global uint4 *d_scryptV0_buf, __global uint4 *d_scryptV1_buf, __global uint4 *d_scryptV2_buf, __global uint4 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  /**
   * salt
   */

  u32 salt_buf0[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_buf1[4];

  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[7];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * 1st pbkdf2, creates B
   */

  w0[0] = swap32 (w0[0]);
  w0[1] = swap32 (w0[1]);
  w0[2] = swap32 (w0[2]);
  w0[3] = swap32 (w0[3]);
  w1[0] = swap32 (w1[0]);
  w1[1] = swap32 (w1[1]);
  w1[2] = swap32 (w1[2]);
  w1[3] = swap32 (w1[3]);
  w2[0] = swap32 (w2[0]);
  w2[1] = swap32 (w2[1]);
  w2[2] = swap32 (w2[2]);
  w2[3] = swap32 (w2[3]);
  w3[0] = swap32 (w3[0]);
  w3[1] = swap32 (w3[1]);
  w3[2] = swap32 (w3[2]);
  w3[3] = swap32 (w3[3]);

  u32 ipad[8];
  u32 opad[8];

  hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

  for (u32 i = 0, j = 0, k = 0; i < SCRYPT_CNT; i += 8, j += 1, k += 2)
  {
    w0[0] = salt_buf0[0];
    w0[1] = salt_buf0[1];
    w0[2] = salt_buf0[2];
    w0[3] = salt_buf0[3];
    w1[0] = salt_buf1[0];
    w1[1] = salt_buf1[1];
    w1[2] = salt_buf1[2];
    w1[3] = salt_buf1[3];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    u32 append[2];

    append[0] = swap32 (j + 1);
    append[1] = 0x80;

    memcat8 (w0, w1, w2, w3, salt_len, append);

    w0[0] = swap32 (w0[0]);
    w0[1] = swap32 (w0[1]);
    w0[2] = swap32 (w0[2]);
    w0[3] = swap32 (w0[3]);
    w1[0] = swap32 (w1[0]);
    w1[1] = swap32 (w1[1]);
    w1[2] = swap32 (w1[2]);
    w1[3] = swap32 (w1[3]);
    w2[0] = swap32 (w2[0]);
    w2[1] = swap32 (w2[1]);
    w2[2] = swap32 (w2[2]);
    w2[3] = swap32 (w2[3]);
    w3[0] = swap32 (w3[0]);
    w3[1] = swap32 (w3[1]);
    w3[2] = 0;
    w3[3] = (64 + salt_len + 4) * 8;

    u32 digest[8];

    hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

    const uint4 tmp0 = (uint4) (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = (uint4) (digest[4], digest[5], digest[6], digest[7]);

    barrier (CLK_GLOBAL_MEM_FENCE);

    tmps[gid].P[k + 0] = tmp0;
    tmps[gid].P[k + 1] = tmp1;
  }
}

__kernel void m08900_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global scrypt_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global uint4 *d_scryptV0_buf, __global uint4 *d_scryptV1_buf, __global uint4 *d_scryptV2_buf, __global uint4 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  uint4 X[STATE_CNT4];
  uint4 T[STATE_CNT4];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int z = 0; z < STATE_CNT4; z++) X[z] = swap32_4 (tmps[gid].P[z]);

  scrypt_smix (X, T, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int z = 0; z < STATE_CNT4; z++) tmps[gid].P[z] = swap32_4 (X[z]);

  #if SCRYPT_P >= 1
  for (int i = STATE_CNT4; i < SCRYPT_CNT4; i += STATE_CNT4)
  {
    for (int z = 0; z < STATE_CNT4; z++) X[z] = swap32_4 (tmps[gid].P[i + z]);

    scrypt_smix (X, T, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf);

    for (int z = 0; z < STATE_CNT4; z++) tmps[gid].P[i + z] = swap32_4 (X[z]);
  }
  #endif
}

__kernel void m08900_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global scrypt_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global uint4 *d_scryptV0_buf, __global uint4 *d_scryptV1_buf, __global uint4 *d_scryptV2_buf, __global uint4 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];

  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  /**
   * 2nd pbkdf2, creates B
   */

  w0[0] = swap32 (w0[0]);
  w0[1] = swap32 (w0[1]);
  w0[2] = swap32 (w0[2]);
  w0[3] = swap32 (w0[3]);
  w1[0] = swap32 (w1[0]);
  w1[1] = swap32 (w1[1]);
  w1[2] = swap32 (w1[2]);
  w1[3] = swap32 (w1[3]);
  w2[0] = swap32 (w2[0]);
  w2[1] = swap32 (w2[1]);
  w2[2] = swap32 (w2[2]);
  w2[3] = swap32 (w2[3]);
  w3[0] = swap32 (w3[0]);
  w3[1] = swap32 (w3[1]);
  w3[2] = swap32 (w3[2]);
  w3[3] = swap32 (w3[3]);

  u32 ipad[8];
  u32 opad[8];

  hmac_sha256_pad (w0, w1, w2, w3, ipad, opad);

  for (u32 l = 0; l < SCRYPT_CNT4; l += 4)
  {
    barrier (CLK_GLOBAL_MEM_FENCE);

    uint4 tmp;

    tmp = tmps[gid].P[l + 0];

    w0[0] = tmp.s0;
    w0[1] = tmp.s1;
    w0[2] = tmp.s2;
    w0[3] = tmp.s3;

    tmp = tmps[gid].P[l + 1];

    w1[0] = tmp.s0;
    w1[1] = tmp.s1;
    w1[2] = tmp.s2;
    w1[3] = tmp.s3;

    tmp = tmps[gid].P[l + 2];

    w2[0] = tmp.s0;
    w2[1] = tmp.s1;
    w2[2] = tmp.s2;
    w2[3] = tmp.s3;

    tmp = tmps[gid].P[l + 3];

    w3[0] = tmp.s0;
    w3[1] = tmp.s1;
    w3[2] = tmp.s2;
    w3[3] = tmp.s3;

    sha256_transform (w0, w1, w2, w3, ipad);
  }

  w0[0] = 0x00000001;
  w0[1] = 0x80000000;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + (SCRYPT_CNT * 4) + 4) * 8;

  u32 digest[8];

  hmac_sha256_run (w0, w1, w2, w3, ipad, opad, digest);

  const u32 r0 = swap32 (digest[DGST_R0]);
  const u32 r1 = swap32 (digest[DGST_R1]);
  const u32 r2 = swap32 (digest[DGST_R2]);
  const u32 r3 = swap32 (digest[DGST_R3]);

  #define il_pos 0

  #include COMPARE_M
}
