/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define _SHA256_

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

__constant u32 k_sha256[64] =
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

#if 1

void sha256_transform (const u32 w[16], u32 digest[8])
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];
  u32 f = digest[5];
  u32 g = digest[6];
  u32 h = digest[7];

  u32 w0_t = swap32 (w[ 0]);
  u32 w1_t = swap32 (w[ 1]);
  u32 w2_t = swap32 (w[ 2]);
  u32 w3_t = swap32 (w[ 3]);
  u32 w4_t = swap32 (w[ 4]);
  u32 w5_t = swap32 (w[ 5]);
  u32 w6_t = swap32 (w[ 6]);
  u32 w7_t = swap32 (w[ 7]);
  u32 w8_t = swap32 (w[ 8]);
  u32 w9_t = swap32 (w[ 9]);
  u32 wa_t = swap32 (w[10]);
  u32 wb_t = swap32 (w[11]);
  u32 wc_t = swap32 (w[12]);
  u32 wd_t = swap32 (w[13]);
  u32 we_t = swap32 (w[14]);
  u32 wf_t = swap32 (w[15]);

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

void sha256_transform_no14 (const u32 w[16], u32 digest[8])
{
  u32 w_t[16];

  w_t[ 0] = w[ 0];
  w_t[ 1] = w[ 1];
  w_t[ 2] = w[ 2];
  w_t[ 3] = w[ 3];
  w_t[ 4] = w[ 4];
  w_t[ 5] = w[ 5];
  w_t[ 6] = w[ 6];
  w_t[ 7] = w[ 7];
  w_t[ 8] = w[ 8];
  w_t[ 9] = w[ 9];
  w_t[10] = w[10];
  w_t[11] = w[11];
  w_t[12] = w[12];
  w_t[13] = w[13];
  w_t[14] = 0;
  w_t[15] = w[15];

  sha256_transform (w_t, digest);
}

void init_ctx (u32 digest[8])
{
  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;
}

void bzero16 (u32 block[16])
{
  block[ 0] = 0;
  block[ 1] = 0;
  block[ 2] = 0;
  block[ 3] = 0;
  block[ 4] = 0;
  block[ 5] = 0;
  block[ 6] = 0;
  block[ 7] = 0;
  block[ 8] = 0;
  block[ 9] = 0;
  block[10] = 0;
  block[11] = 0;
  block[12] = 0;
  block[13] = 0;
  block[14] = 0;
  block[15] = 0;
}

void bswap8 (u32 block[16])
{
  block[ 0] = swap32 (block[ 0]);
  block[ 1] = swap32 (block[ 1]);
  block[ 2] = swap32 (block[ 2]);
  block[ 3] = swap32 (block[ 3]);
  block[ 4] = swap32 (block[ 4]);
  block[ 5] = swap32 (block[ 5]);
  block[ 6] = swap32 (block[ 6]);
  block[ 7] = swap32 (block[ 7]);
}

u32 memcat16 (u32 block[16], const u32 block_len, const u32 append[4], const u32 append_len)
{
  const u32 mod = block_len & 3;
  const u32 div = block_len / 4;

  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if defined IS_AMD || defined IS_GENERIC
  const int offset_minus_4 = 4 - block_len;

  tmp0 = amd_bytealign (append[0],         0, offset_minus_4);
  tmp1 = amd_bytealign (append[1], append[0], offset_minus_4);
  tmp2 = amd_bytealign (append[2], append[1], offset_minus_4);
  tmp3 = amd_bytealign (append[3], append[2], offset_minus_4);
  tmp4 = amd_bytealign (        0, append[3], offset_minus_4);

  if (mod == 0)
  {
    tmp0 = tmp1;
    tmp1 = tmp2;
    tmp2 = tmp3;
    tmp3 = tmp4;
    tmp4 = 0;
  }
  #endif

  #ifdef IS_NV
  const int offset_minus_4 = 4 - (block_len & 3);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  tmp0 = __byte_perm (        0, append[0], selector);
  tmp1 = __byte_perm (append[0], append[1], selector);
  tmp2 = __byte_perm (append[1], append[2], selector);
  tmp3 = __byte_perm (append[2], append[3], selector);
  tmp4 = __byte_perm (append[3],         0, selector);
  #endif

  switch (div)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              block[ 2]  = tmp2;
              block[ 3]  = tmp3;
              block[ 4]  = tmp4;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              block[ 3]  = tmp2;
              block[ 4]  = tmp3;
              block[ 5]  = tmp4;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              block[ 4]  = tmp2;
              block[ 5]  = tmp3;
              block[ 6]  = tmp4;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              block[ 5]  = tmp2;
              block[ 6]  = tmp3;
              block[ 7]  = tmp4;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              block[ 6]  = tmp2;
              block[ 7]  = tmp3;
              block[ 8]  = tmp4;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              block[ 7]  = tmp2;
              block[ 8]  = tmp3;
              block[ 9]  = tmp4;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              block[ 8]  = tmp2;
              block[ 9]  = tmp3;
              block[10]  = tmp4;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              block[ 9]  = tmp2;
              block[10]  = tmp3;
              block[11]  = tmp4;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              block[10]  = tmp2;
              block[11]  = tmp3;
              block[12]  = tmp4;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              block[11]  = tmp2;
              block[12]  = tmp3;
              block[13]  = tmp4;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              block[12]  = tmp2;
              block[13]  = tmp3;
              block[14]  = tmp4;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              block[13]  = tmp2;
              block[14]  = tmp3;
              block[15]  = tmp4;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              block[14]  = tmp2;
              block[15]  = tmp3;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              block[15]  = tmp2;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              break;
    case 15:  block[15] |= tmp0;
              break;
  }

  u32 new_len = block_len + append_len;

  return new_len;
}

u32 memcat16c (u32 block[16], const u32 block_len, const u32 append[4], const u32 append_len, u32 digest[8])
{
  const u32 mod = block_len & 3;
  const u32 div = block_len / 4;

  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if defined IS_AMD || defined IS_GENERIC
  const int offset_minus_4 = 4 - block_len;

  tmp0 = amd_bytealign (append[0],         0, offset_minus_4);
  tmp1 = amd_bytealign (append[1], append[0], offset_minus_4);
  tmp2 = amd_bytealign (append[2], append[1], offset_minus_4);
  tmp3 = amd_bytealign (append[3], append[2], offset_minus_4);
  tmp4 = amd_bytealign (        0, append[3], offset_minus_4);

  if (mod == 0)
  {
    tmp0 = tmp1;
    tmp1 = tmp2;
    tmp2 = tmp3;
    tmp3 = tmp4;
    tmp4 = 0;
  }
  #endif

  #ifdef IS_NV
  const int offset_minus_4 = 4 - (block_len & 3);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  tmp0 = __byte_perm (        0, append[0], selector);
  tmp1 = __byte_perm (append[0], append[1], selector);
  tmp2 = __byte_perm (append[1], append[2], selector);
  tmp3 = __byte_perm (append[2], append[3], selector);
  tmp4 = __byte_perm (append[3],         0, selector);
  #endif

  u32 carry[4] = { 0, 0, 0, 0 };

  switch (div)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              block[ 2]  = tmp2;
              block[ 3]  = tmp3;
              block[ 4]  = tmp4;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              block[ 3]  = tmp2;
              block[ 4]  = tmp3;
              block[ 5]  = tmp4;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              block[ 4]  = tmp2;
              block[ 5]  = tmp3;
              block[ 6]  = tmp4;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              block[ 5]  = tmp2;
              block[ 6]  = tmp3;
              block[ 7]  = tmp4;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              block[ 6]  = tmp2;
              block[ 7]  = tmp3;
              block[ 8]  = tmp4;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              block[ 7]  = tmp2;
              block[ 8]  = tmp3;
              block[ 9]  = tmp4;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              block[ 8]  = tmp2;
              block[ 9]  = tmp3;
              block[10]  = tmp4;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              block[ 9]  = tmp2;
              block[10]  = tmp3;
              block[11]  = tmp4;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              block[10]  = tmp2;
              block[11]  = tmp3;
              block[12]  = tmp4;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              block[11]  = tmp2;
              block[12]  = tmp3;
              block[13]  = tmp4;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              block[12]  = tmp2;
              block[13]  = tmp3;
              block[14]  = tmp4;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              block[13]  = tmp2;
              block[14]  = tmp3;
              block[15]  = tmp4;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              block[14]  = tmp2;
              block[15]  = tmp3;
              carry[ 0]  = tmp4;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              block[15]  = tmp2;
              carry[ 0]  = tmp3;
              carry[ 1]  = tmp4;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              carry[ 0]  = tmp2;
              carry[ 1]  = tmp3;
              carry[ 2]  = tmp4;
              break;
    case 15:  block[15] |= tmp0;
              carry[ 0]  = tmp1;
              carry[ 1]  = tmp2;
              carry[ 2]  = tmp3;
              carry[ 3]  = tmp4;
              break;
  }

  u32 new_len = block_len + append_len;

  if (new_len >= 64)
  {
    new_len -= 64;

    sha256_transform (block, digest);

    bzero16 (block);

    block[0] = carry[0];
    block[1] = carry[1];
    block[2] = carry[2];
    block[3] = carry[3];
  }

  return new_len;
}

u32 memcat20 (u32 block[20], const u32 block_len, const u32 append[4], const u32 append_len)
{
  const u32 mod = block_len & 3;
  const u32 div = block_len / 4;

  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if defined IS_AMD || defined IS_GENERIC
  const int offset_minus_4 = 4 - block_len;

  tmp0 = amd_bytealign (append[0],         0, offset_minus_4);
  tmp1 = amd_bytealign (append[1], append[0], offset_minus_4);
  tmp2 = amd_bytealign (append[2], append[1], offset_minus_4);
  tmp3 = amd_bytealign (append[3], append[2], offset_minus_4);
  tmp4 = amd_bytealign (        0, append[3], offset_minus_4);

  if (mod == 0)
  {
    tmp0 = tmp1;
    tmp1 = tmp2;
    tmp2 = tmp3;
    tmp3 = tmp4;
    tmp4 = 0;
  }
  #endif

  #ifdef IS_NV
  const int offset_minus_4 = 4 - (block_len & 3);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  tmp0 = __byte_perm (        0, append[0], selector);
  tmp1 = __byte_perm (append[0], append[1], selector);
  tmp2 = __byte_perm (append[1], append[2], selector);
  tmp3 = __byte_perm (append[2], append[3], selector);
  tmp4 = __byte_perm (append[3],         0, selector);
  #endif

  switch (div)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              block[ 2]  = tmp2;
              block[ 3]  = tmp3;
              block[ 4]  = tmp4;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              block[ 3]  = tmp2;
              block[ 4]  = tmp3;
              block[ 5]  = tmp4;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              block[ 4]  = tmp2;
              block[ 5]  = tmp3;
              block[ 6]  = tmp4;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              block[ 5]  = tmp2;
              block[ 6]  = tmp3;
              block[ 7]  = tmp4;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              block[ 6]  = tmp2;
              block[ 7]  = tmp3;
              block[ 8]  = tmp4;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              block[ 7]  = tmp2;
              block[ 8]  = tmp3;
              block[ 9]  = tmp4;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              block[ 8]  = tmp2;
              block[ 9]  = tmp3;
              block[10]  = tmp4;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              block[ 9]  = tmp2;
              block[10]  = tmp3;
              block[11]  = tmp4;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              block[10]  = tmp2;
              block[11]  = tmp3;
              block[12]  = tmp4;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              block[11]  = tmp2;
              block[12]  = tmp3;
              block[13]  = tmp4;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              block[12]  = tmp2;
              block[13]  = tmp3;
              block[14]  = tmp4;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              block[13]  = tmp2;
              block[14]  = tmp3;
              block[15]  = tmp4;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              block[14]  = tmp2;
              block[15]  = tmp3;
              block[16]  = tmp4;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              block[15]  = tmp2;
              block[16]  = tmp3;
              block[17]  = tmp4;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              block[16]  = tmp2;
              block[17]  = tmp3;
              block[18]  = tmp4;
              break;
    case 15:  block[15] |= tmp0;
              block[16]  = tmp1;
              block[17]  = tmp2;
              block[18]  = tmp3;
              block[19]  = tmp4;
              break;
  }

  return block_len + append_len;
}

u32 memcat20_x80 (u32 block[20], const u32 block_len, const u32 append[4], const u32 append_len)
{
  const u32 mod = block_len & 3;
  const u32 div = block_len / 4;

  u32 tmp0;
  u32 tmp1;
  u32 tmp2;
  u32 tmp3;
  u32 tmp4;

  #if defined IS_AMD || defined IS_GENERIC
  const int offset_minus_4 = 4 - block_len;

  tmp0 = amd_bytealign (append[0],         0, offset_minus_4);
  tmp1 = amd_bytealign (append[1], append[0], offset_minus_4);
  tmp2 = amd_bytealign (append[2], append[1], offset_minus_4);
  tmp3 = amd_bytealign (append[3], append[2], offset_minus_4);
  tmp4 = amd_bytealign (     0x80, append[3], offset_minus_4);

  if (mod == 0)
  {
    tmp0 = tmp1;
    tmp1 = tmp2;
    tmp2 = tmp3;
    tmp3 = tmp4;
    tmp4 = 0x80;
  }
  #endif

  #ifdef IS_NV
  const int offset_minus_4 = 4 - (block_len & 3);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  tmp0 = __byte_perm (        0, append[0], selector);
  tmp1 = __byte_perm (append[0], append[1], selector);
  tmp2 = __byte_perm (append[1], append[2], selector);
  tmp3 = __byte_perm (append[2], append[3], selector);
  tmp4 = __byte_perm (append[3],      0x80, selector);
  #endif

  switch (div)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              block[ 2]  = tmp2;
              block[ 3]  = tmp3;
              block[ 4]  = tmp4;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              block[ 3]  = tmp2;
              block[ 4]  = tmp3;
              block[ 5]  = tmp4;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              block[ 4]  = tmp2;
              block[ 5]  = tmp3;
              block[ 6]  = tmp4;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              block[ 5]  = tmp2;
              block[ 6]  = tmp3;
              block[ 7]  = tmp4;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              block[ 6]  = tmp2;
              block[ 7]  = tmp3;
              block[ 8]  = tmp4;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              block[ 7]  = tmp2;
              block[ 8]  = tmp3;
              block[ 9]  = tmp4;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              block[ 8]  = tmp2;
              block[ 9]  = tmp3;
              block[10]  = tmp4;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              block[ 9]  = tmp2;
              block[10]  = tmp3;
              block[11]  = tmp4;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              block[10]  = tmp2;
              block[11]  = tmp3;
              block[12]  = tmp4;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              block[11]  = tmp2;
              block[12]  = tmp3;
              block[13]  = tmp4;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              block[12]  = tmp2;
              block[13]  = tmp3;
              block[14]  = tmp4;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              block[13]  = tmp2;
              block[14]  = tmp3;
              block[15]  = tmp4;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              block[14]  = tmp2;
              block[15]  = tmp3;
              block[16]  = tmp4;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              block[15]  = tmp2;
              block[16]  = tmp3;
              block[17]  = tmp4;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              block[16]  = tmp2;
              block[17]  = tmp3;
              block[18]  = tmp4;
              break;
    case 15:  block[15] |= tmp0;
              block[16]  = tmp1;
              block[17]  = tmp2;
              block[18]  = tmp3;
              block[19]  = tmp4;
              break;
  }

  return block_len + append_len;
}

__kernel void m07400_init (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha256crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[0];
  w0[1] = pws[gid].i[1];
  w0[2] = pws[gid].i[2];
  w0[3] = pws[gid].i[3];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * buffers
   */

  u32 block_len;     // never reaches > 64
  u32 transform_len; // required for w[15] = len * 8

  u32 block[16];

  u32 alt_result[8];
  u32 p_bytes[8];
  u32 s_bytes[8];

  /* Prepare for the real work.  */

  block_len = 0;

  bzero16 (block);

  /* Add key.  */

  block_len = memcat16 (block, block_len, w0, pw_len);

  /* Add salt.  */

  block_len = memcat16 (block, block_len, salt_buf, salt_len);

  /* Add key again.  */

  block_len = memcat16 (block, block_len, w0, pw_len);

  append_0x80_1x16 (block, block_len);

  block[15] = swap32 (block_len * 8);

  init_ctx (alt_result);

  sha256_transform (block, alt_result);

  bswap8 (alt_result);

  block_len = 0;

  bzero16 (block);

  u32 alt_result_tmp[8];

  alt_result_tmp[0] = alt_result[0];
  alt_result_tmp[1] = alt_result[1];
  alt_result_tmp[2] = alt_result[2];
  alt_result_tmp[3] = alt_result[3];
  alt_result_tmp[4] = 0;
  alt_result_tmp[5] = 0;
  alt_result_tmp[6] = 0;
  alt_result_tmp[7] = 0;

  truncate_block (alt_result_tmp, pw_len);

  /* Add the key string.  */

  block_len = memcat16 (block, block_len, w0, pw_len);

  /* The last part is the salt string.  This must be at most 8
     characters and it ends at the first `$' character (for
     compatibility with existing implementations).  */

  block_len = memcat16 (block, block_len, salt_buf, salt_len);

  /* Now get result of this (32 bytes) and add it to the other
     context.  */

  block_len = memcat16 (block, block_len, alt_result_tmp, pw_len);

  transform_len = block_len;

  /* Take the binary representation of the length of the key and for every
     1 add the alternate sum, for every 0 the key.  */

  alt_result_tmp[0] = alt_result[0];
  alt_result_tmp[1] = alt_result[1];
  alt_result_tmp[2] = alt_result[2];
  alt_result_tmp[3] = alt_result[3];
  alt_result_tmp[4] = alt_result[4];
  alt_result_tmp[5] = alt_result[5];
  alt_result_tmp[6] = alt_result[6];
  alt_result_tmp[7] = alt_result[7];

  init_ctx (alt_result);

  for (u32 j = pw_len; j; j >>= 1)
  {
    if (j & 1)
    {
      block_len = memcat16c (block, block_len, &alt_result_tmp[0], 16, alt_result);
      block_len = memcat16c (block, block_len, &alt_result_tmp[4], 16, alt_result);

      transform_len += 32;
    }
    else
    {
      block_len = memcat16c (block, block_len, w0, pw_len, alt_result);

      transform_len += pw_len;
    }
  }

  append_0x80_1x16 (block, block_len);

  if (block_len >= 56)
  {
    sha256_transform (block, alt_result);

    bzero16 (block);
  }

  block[15] = swap32 (transform_len * 8);

  sha256_transform (block, alt_result);

  bswap8 (alt_result);

  tmps[gid].alt_result[0] = alt_result[0];
  tmps[gid].alt_result[1] = alt_result[1];
  tmps[gid].alt_result[2] = alt_result[2];
  tmps[gid].alt_result[3] = alt_result[3];
  tmps[gid].alt_result[4] = alt_result[4];
  tmps[gid].alt_result[5] = alt_result[5];
  tmps[gid].alt_result[6] = alt_result[6];
  tmps[gid].alt_result[7] = alt_result[7];

  /* Start computation of P byte sequence.  */

  block_len = 0;

  transform_len = 0;

  bzero16 (block);

  /* For every character in the password add the entire password.  */

  init_ctx (p_bytes);

  for (u32 j = 0; j < pw_len; j++)
  {
    block_len = memcat16c (block, block_len, w0, pw_len, p_bytes);

    transform_len += pw_len;
  }

  /* Finish the digest.  */

  append_0x80_1x16 (block, block_len);

  if (block_len >= 56)
  {
    sha256_transform (block, p_bytes);

    bzero16 (block);
  }

  block[15] = swap32 (transform_len * 8);

  sha256_transform (block, p_bytes);

  bswap8 (p_bytes);

  truncate_block (p_bytes, pw_len);

  tmps[gid].p_bytes[0] = p_bytes[0];
  tmps[gid].p_bytes[1] = p_bytes[1];
  tmps[gid].p_bytes[2] = p_bytes[2];
  tmps[gid].p_bytes[3] = p_bytes[3];

  /* Start computation of S byte sequence.  */

  block_len = 0;

  transform_len = 0;

  bzero16 (block);

  /* For every character in the password add the entire password.  */

  init_ctx (s_bytes);

  for (u32 j = 0; j < 16 + (alt_result[0] & 0xff); j++)
  {
    block_len = memcat16c (block, block_len, salt_buf, salt_len, s_bytes);

    transform_len += salt_len;
  }

  /* Finish the digest.  */

  append_0x80_1x16 (block, block_len);

  if (block_len >= 56)
  {
    sha256_transform (block, s_bytes);

    bzero16 (block);
  }

  block[15] = swap32 (transform_len * 8);

  sha256_transform (block, s_bytes);

  bswap8 (s_bytes);

  truncate_block (s_bytes, salt_len);

  tmps[gid].s_bytes[0] = s_bytes[0];
  tmps[gid].s_bytes[1] = s_bytes[1];
  tmps[gid].s_bytes[2] = s_bytes[2];
  tmps[gid].s_bytes[3] = s_bytes[3];
}

__kernel void m07400_loop (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha256crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 pw_len = pws[gid].pw_len;

  /**
   * base
   */

  u32 p_bytes[4];

  p_bytes[0] = tmps[gid].p_bytes[0];
  p_bytes[1] = tmps[gid].p_bytes[1];
  p_bytes[2] = tmps[gid].p_bytes[2];
  p_bytes[3] = tmps[gid].p_bytes[3];

  u32 p_bytes_x80[4];

  p_bytes_x80[0] = tmps[gid].p_bytes[0];
  p_bytes_x80[1] = tmps[gid].p_bytes[1];
  p_bytes_x80[2] = tmps[gid].p_bytes[2];
  p_bytes_x80[3] = tmps[gid].p_bytes[3];

  append_0x80_1x4 (p_bytes_x80, pw_len);

  u32 s_bytes[4];

  s_bytes[0] = tmps[gid].s_bytes[0];
  s_bytes[1] = tmps[gid].s_bytes[1];
  s_bytes[2] = tmps[gid].s_bytes[2];
  s_bytes[3] = tmps[gid].s_bytes[3];

  u32 alt_result[8];

  alt_result[0] = tmps[gid].alt_result[0];
  alt_result[1] = tmps[gid].alt_result[1];
  alt_result[2] = tmps[gid].alt_result[2];
  alt_result[3] = tmps[gid].alt_result[3];
  alt_result[4] = tmps[gid].alt_result[4];
  alt_result[5] = tmps[gid].alt_result[5];
  alt_result[6] = tmps[gid].alt_result[6];
  alt_result[7] = tmps[gid].alt_result[7];

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  /* Repeatedly run the collected hash value through SHA256 to burn
     CPU cycles.  */

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    u32 tmp[8];

    init_ctx (tmp);

    u32 block[32];

    bzero16 (&block[ 0]);
    bzero16 (&block[16]);

    u32 block_len = 0;

    const u32 j1 = (j & 1) ? 1 : 0;
    const u32 j3 = (j % 3) ? 1 : 0;
    const u32 j7 = (j % 7) ? 1 : 0;

    if (j1)
    {
      block[0] = p_bytes[0];
      block[1] = p_bytes[1];
      block[2] = p_bytes[2];
      block[3] = p_bytes[3];

      block_len = pw_len;
    }
    else
    {
      block[0] = alt_result[0];
      block[1] = alt_result[1];
      block[2] = alt_result[2];
      block[3] = alt_result[3];
      block[4] = alt_result[4];
      block[5] = alt_result[5];
      block[6] = alt_result[6];
      block[7] = alt_result[7];

      block_len = 32;
    }

    if (j3)
    {
      block_len = memcat20 (block, block_len, s_bytes, salt_len);
    }

    if (j7)
    {
      block_len = memcat20 (block, block_len, p_bytes, pw_len);
    }

    if (j1)
    {
      block_len = memcat20     (block, block_len, &alt_result[0], 16);
      block_len = memcat20_x80 (block, block_len, &alt_result[4], 16);
    }
    else
    {
      block_len = memcat20 (block, block_len, p_bytes_x80, pw_len);
    }

    if (block_len >= 56)
    {
      sha256_transform (block, tmp);

      block[ 0] = block[16];
      block[ 1] = block[17];
      block[ 2] = block[18];
      block[ 3] = block[19];
      block[ 4] = 0;
      block[ 5] = 0;
      block[ 6] = 0;
      block[ 7] = 0;
      block[ 8] = 0;
      block[ 9] = 0;
      block[10] = 0;
      block[11] = 0;
      block[12] = 0;
      block[13] = 0;
      block[14] = 0;
      block[15] = 0;
    }

    block[15] = swap32 (block_len * 8);

    sha256_transform_no14 (block, tmp);

    bswap8 (tmp);

    alt_result[0] = tmp[0];
    alt_result[1] = tmp[1];
    alt_result[2] = tmp[2];
    alt_result[3] = tmp[3];
    alt_result[4] = tmp[4];
    alt_result[5] = tmp[5];
    alt_result[6] = tmp[6];
    alt_result[7] = tmp[7];
  }

  tmps[gid].alt_result[0] = alt_result[0];
  tmps[gid].alt_result[1] = alt_result[1];
  tmps[gid].alt_result[2] = alt_result[2];
  tmps[gid].alt_result[3] = alt_result[3];
  tmps[gid].alt_result[4] = alt_result[4];
  tmps[gid].alt_result[5] = alt_result[5];
  tmps[gid].alt_result[6] = alt_result[6];
  tmps[gid].alt_result[7] = alt_result[7];
}

__kernel void m07400_comp (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha256crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 lid = get_local_id (0);

  const u32 r0 = tmps[gid].alt_result[0];
  const u32 r1 = tmps[gid].alt_result[1];
  const u32 r2 = tmps[gid].alt_result[2];
  const u32 r3 = tmps[gid].alt_result[3];

  #define il_pos 0

  #include COMPARE_M
}

#else

// this is basically a much cleaner version, but apparently drops speeds by over 100% :(

#define PUTCHAR32_BE(a,p,c) ((u8 *)(a))[(p) ^ 3] = (u8) (c)
#define GETCHAR32_BE(a,p)   ((u8 *)(a))[(p) ^ 3]

typedef struct
{
  u32 state[8];
  u32 buf[32];
  int len;

} sha256_ctx_t;

void sha256_transform (const u32 w[16], u32 digest[8])
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];
  u32 f = digest[5];
  u32 g = digest[6];
  u32 h = digest[7];

  u32 w0_t = w[ 0];
  u32 w1_t = w[ 1];
  u32 w2_t = w[ 2];
  u32 w3_t = w[ 3];
  u32 w4_t = w[ 4];
  u32 w5_t = w[ 5];
  u32 w6_t = w[ 6];
  u32 w7_t = w[ 7];
  u32 w8_t = w[ 8];
  u32 w9_t = w[ 9];
  u32 wa_t = w[10];
  u32 wb_t = w[11];
  u32 wc_t = w[12];
  u32 wd_t = w[13];
  u32 we_t = w[14];
  u32 wf_t = w[15];

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

void sha256_init (sha256_ctx_t *sha256_ctx)
{
  sha256_ctx->state[0] = SHA256M_A;
  sha256_ctx->state[1] = SHA256M_B;
  sha256_ctx->state[2] = SHA256M_C;
  sha256_ctx->state[3] = SHA256M_D;
  sha256_ctx->state[4] = SHA256M_E;
  sha256_ctx->state[5] = SHA256M_F;
  sha256_ctx->state[6] = SHA256M_G;
  sha256_ctx->state[7] = SHA256M_H;

  sha256_ctx->len = 0;
}

void sha256_update (sha256_ctx_t *sha256_ctx, const u32 *buf, int len)
{
  int pos = sha256_ctx->len & 0x3f;

  sha256_ctx->len += len;

  if ((pos + len) < 64)
  {
    for (int i = 0; i < len; i++)
    {
      PUTCHAR32_BE (sha256_ctx->buf, pos++, GETCHAR32_BE (buf, i));
    }

    return;
  }

  int cnt = 64 - pos;

  for (int i = 0; i < cnt; i++)
  {
    PUTCHAR32_BE (sha256_ctx->buf, pos++, GETCHAR32_BE (buf, i));
  }

  sha256_transform (sha256_ctx->buf, sha256_ctx->state);

  len -= cnt;

  for (int i = 0; i < len; i++)
  {
    PUTCHAR32_BE (sha256_ctx->buf, i, GETCHAR32_BE (buf, cnt + i));
  }
}

void sha256_final (sha256_ctx_t *sha256_ctx)
{
  int pos = sha256_ctx->len & 0x3f;

  for (int i = pos; i < 64; i++)
  {
    PUTCHAR32_BE (sha256_ctx->buf, i, 0);
  }

  PUTCHAR32_BE (sha256_ctx->buf, pos, 0x80);

  if (pos >= 56)
  {
    sha256_transform (sha256_ctx->buf, sha256_ctx->state);

    sha256_ctx->buf[ 0] = 0;
    sha256_ctx->buf[ 1] = 0;
    sha256_ctx->buf[ 2] = 0;
    sha256_ctx->buf[ 3] = 0;
    sha256_ctx->buf[ 4] = 0;
    sha256_ctx->buf[ 5] = 0;
    sha256_ctx->buf[ 6] = 0;
    sha256_ctx->buf[ 7] = 0;
    sha256_ctx->buf[ 8] = 0;
    sha256_ctx->buf[ 9] = 0;
    sha256_ctx->buf[10] = 0;
    sha256_ctx->buf[11] = 0;
    sha256_ctx->buf[12] = 0;
    sha256_ctx->buf[13] = 0;
    sha256_ctx->buf[14] = 0;
    sha256_ctx->buf[15] = 0;
  }

  sha256_ctx->buf[15] = sha256_ctx->len * 8;

  sha256_transform (sha256_ctx->buf, sha256_ctx->state);
}

__kernel void m07400_init (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha256crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw[4];

  pw[0] = swap32 (pws[gid].i[0]);
  pw[1] = swap32 (pws[gid].i[1]);
  pw[2] = swap32 (pws[gid].i[2]);
  pw[3] = swap32 (pws[gid].i[3]);

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

  u32 salt[4];

  salt[0] = swap32 (salt_bufs[salt_pos].salt_buf[0]);
  salt[1] = swap32 (salt_bufs[salt_pos].salt_buf[1]);
  salt[2] = swap32 (salt_bufs[salt_pos].salt_buf[2]);
  salt[3] = swap32 (salt_bufs[salt_pos].salt_buf[3]);

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * begin
   */

  sha256_ctx_t sha256_ctx;

  sha256_init (&sha256_ctx);

  sha256_update (&sha256_ctx, pw, pw_len);
  sha256_update (&sha256_ctx, salt, salt_len);
  sha256_update (&sha256_ctx, pw, pw_len);

  sha256_final (&sha256_ctx);

  u32 tmp[8];

  tmp[0] = sha256_ctx.state[0];
  tmp[1] = sha256_ctx.state[1];
  tmp[2] = sha256_ctx.state[2];
  tmp[3] = sha256_ctx.state[3];
  tmp[4] = sha256_ctx.state[4];
  tmp[5] = sha256_ctx.state[5];
  tmp[6] = sha256_ctx.state[6];
  tmp[7] = sha256_ctx.state[7];

  sha256_init (&sha256_ctx);

  sha256_update (&sha256_ctx, pw, pw_len);
  sha256_update (&sha256_ctx, salt, salt_len);
  sha256_update (&sha256_ctx, tmp, pw_len);

  for (u32 j = pw_len; j; j >>= 1)
  {
    if (j & 1)
    {
      sha256_update (&sha256_ctx, tmp, 32);
    }
    else
    {
      sha256_update (&sha256_ctx, pw, pw_len);
    }
  }

  sha256_final (&sha256_ctx);

  tmps[gid].alt_result[0] = sha256_ctx.state[0];
  tmps[gid].alt_result[1] = sha256_ctx.state[1];
  tmps[gid].alt_result[2] = sha256_ctx.state[2];
  tmps[gid].alt_result[3] = sha256_ctx.state[3];
  tmps[gid].alt_result[4] = sha256_ctx.state[4];
  tmps[gid].alt_result[5] = sha256_ctx.state[5];
  tmps[gid].alt_result[6] = sha256_ctx.state[6];
  tmps[gid].alt_result[7] = sha256_ctx.state[7];

  // p_bytes

  sha256_init (&sha256_ctx);

  for (u32 j = 0; j < pw_len; j++)
  {
    sha256_update (&sha256_ctx, pw, pw_len);
  }

  sha256_final (&sha256_ctx);

  tmps[gid].p_bytes[0] = sha256_ctx.state[0];
  tmps[gid].p_bytes[1] = sha256_ctx.state[1];
  tmps[gid].p_bytes[2] = sha256_ctx.state[2];
  tmps[gid].p_bytes[3] = sha256_ctx.state[3];

  // s_bytes

  sha256_init (&sha256_ctx);

  for (u32 j = 0; j < 16 + ((tmps[gid].alt_result[0] >> 24) & 0xff); j++)
  {
    sha256_update (&sha256_ctx, salt, salt_len);
  }

  sha256_final (&sha256_ctx);

  tmps[gid].s_bytes[0] = sha256_ctx.state[0];
  tmps[gid].s_bytes[1] = sha256_ctx.state[1];
  tmps[gid].s_bytes[2] = sha256_ctx.state[2];
  tmps[gid].s_bytes[3] = sha256_ctx.state[3];
}

__kernel void m07400_loop (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha256crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 p_bytes0[4];

  p_bytes0[0] = tmps[gid].p_bytes[0];
  p_bytes0[1] = tmps[gid].p_bytes[1];
  p_bytes0[2] = tmps[gid].p_bytes[2];
  p_bytes0[3] = tmps[gid].p_bytes[3];

  const u32 pw_len = pws[gid].pw_len;

  u32 s_bytes0[4];

  s_bytes0[0] = tmps[gid].s_bytes[0];
  s_bytes0[1] = tmps[gid].s_bytes[1];
  s_bytes0[2] = tmps[gid].s_bytes[2];
  s_bytes0[3] = tmps[gid].s_bytes[3];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 wpc_len[8];

  wpc_len[0] = 32     +        0 +      0 + pw_len;
  wpc_len[1] = pw_len +        0 +      0 + 32;
  wpc_len[2] = 32     + salt_len +      0 + pw_len;
  wpc_len[3] = pw_len + salt_len +      0 + 32;
  wpc_len[4] = 32     +        0 + pw_len + pw_len;
  wpc_len[5] = pw_len +        0 + pw_len + 32;
  wpc_len[6] = 32     + salt_len + pw_len + pw_len;
  wpc_len[7] = pw_len + salt_len + pw_len + 32;

  u32 wpc[8][32] = { { 0 } };

  for (u32 i = 0; i < 8; i++)
  {
    u32 block_len = 0;

    if (i & 1)
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR32_BE (wpc[i], block_len++, GETCHAR32_BE (p_bytes0, j));
      }
    }
    else
    {
      block_len += 32;
    }

    if (i & 2)
    {
      for (u32 j = 0; j < salt_len; j++)
      {
        PUTCHAR32_BE (wpc[i], block_len++, GETCHAR32_BE (s_bytes0, j));
      }
    }

    if (i & 4)
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR32_BE (wpc[i], block_len++, GETCHAR32_BE (p_bytes0, j));
      }
    }

    if (i & 1)
    {
      block_len += 32;
    }
    else
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR32_BE (wpc[i], block_len++, GETCHAR32_BE (p_bytes0, j));
      }
    }

    PUTCHAR32_BE (wpc[i], block_len, 0x80);

    if (block_len < 56)
    {
      wpc[i][15] = block_len * 8;
    }
    else
    {
      wpc[i][31] = block_len * 8;
    }
  }

  /**
   * base
   */

  u32 alt_result[8];

  alt_result[0] = tmps[gid].alt_result[0];
  alt_result[1] = tmps[gid].alt_result[1];
  alt_result[2] = tmps[gid].alt_result[2];
  alt_result[3] = tmps[gid].alt_result[3];
  alt_result[4] = tmps[gid].alt_result[4];
  alt_result[5] = tmps[gid].alt_result[5];
  alt_result[6] = tmps[gid].alt_result[6];
  alt_result[7] = tmps[gid].alt_result[7];


  /* Repeatedly run the collected hash value through SHA256 to burn
     CPU cycles.  */

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    const u32 j1 = (j & 1) ? 1 : 0;
    const u32 j3 = (j % 3) ? 2 : 0;
    const u32 j7 = (j % 7) ? 4 : 0;

    const u32 pc = j1 + j3 + j7;

    u32 block[32];

    block[ 0] = wpc[pc][ 0];
    block[ 1] = wpc[pc][ 1];
    block[ 2] = wpc[pc][ 2];
    block[ 3] = wpc[pc][ 3];
    block[ 4] = wpc[pc][ 4];
    block[ 5] = wpc[pc][ 5];
    block[ 6] = wpc[pc][ 6];
    block[ 7] = wpc[pc][ 7];
    block[ 8] = wpc[pc][ 8];
    block[ 9] = wpc[pc][ 9];
    block[10] = wpc[pc][10];
    block[11] = wpc[pc][11];
    block[12] = wpc[pc][12];
    block[13] = wpc[pc][13];
    block[14] = wpc[pc][14];
    block[15] = wpc[pc][15];
    block[16] = wpc[pc][16];
    block[17] = wpc[pc][17];
    block[18] = wpc[pc][18];
    block[19] = wpc[pc][19];
    block[20] = wpc[pc][20];
    block[21] = wpc[pc][21];
    block[22] = wpc[pc][22];
    block[23] = wpc[pc][23];
    block[24] = wpc[pc][24];
    block[25] = wpc[pc][25];
    block[26] = wpc[pc][26];
    block[27] = wpc[pc][27];
    block[28] = wpc[pc][28];
    block[29] = wpc[pc][29];
    block[30] = wpc[pc][30];
    block[31] = wpc[pc][31];

    const u32 block_len = wpc_len[pc];

    if (j1)
    {
      #ifdef _unroll
      #pragma unroll
      #endif
      for (u32 k = 0, p = block_len - 32; k < 32; k++, p++)
      {
        PUTCHAR32_BE (block, p, GETCHAR32_BE (alt_result, k));
      }
    }
    else
    {
      block[0] = alt_result[0];
      block[1] = alt_result[1];
      block[2] = alt_result[2];
      block[3] = alt_result[3];
      block[4] = alt_result[4];
      block[5] = alt_result[5];
      block[6] = alt_result[6];
      block[7] = alt_result[7];
    }

    alt_result[0] = SHA256M_A;
    alt_result[1] = SHA256M_B;
    alt_result[2] = SHA256M_C;
    alt_result[3] = SHA256M_D;
    alt_result[4] = SHA256M_E;
    alt_result[5] = SHA256M_F;
    alt_result[6] = SHA256M_G;
    alt_result[7] = SHA256M_H;

    sha256_transform (block, alt_result);

    if (block_len >= 56)
    {
      sha256_transform (block + 16, alt_result);
    }
  }

  tmps[gid].alt_result[0] = alt_result[0];
  tmps[gid].alt_result[1] = alt_result[1];
  tmps[gid].alt_result[2] = alt_result[2];
  tmps[gid].alt_result[3] = alt_result[3];
  tmps[gid].alt_result[4] = alt_result[4];
  tmps[gid].alt_result[5] = alt_result[5];
  tmps[gid].alt_result[6] = alt_result[6];
  tmps[gid].alt_result[7] = alt_result[7];
}

__kernel void m07400_comp (__global pw_t *pws, __global kernel_rule_t *rules_buf, __global comb_t *combs_buf, __global bf_t *bfs_buf, __global sha256crypt_tmp_t *tmps, __global void *hooks, __global u32 *bitmaps_buf_s1_a, __global u32 *bitmaps_buf_s1_b, __global u32 *bitmaps_buf_s1_c, __global u32 *bitmaps_buf_s1_d, __global u32 *bitmaps_buf_s2_a, __global u32 *bitmaps_buf_s2_b, __global u32 *bitmaps_buf_s2_c, __global u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global digest_t *digests_buf, __global u32 *hashes_shown, __global salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 lid = get_local_id (0);

  const u32 r0 = swap32 (tmps[gid].alt_result[0]);
  const u32 r1 = swap32 (tmps[gid].alt_result[1]);
  const u32 r2 = swap32 (tmps[gid].alt_result[2]);
  const u32 r3 = swap32 (tmps[gid].alt_result[3]);

  #define il_pos 0

  #include COMPARE_M
}

#endif
