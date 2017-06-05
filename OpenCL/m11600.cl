/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"

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

u32 memcat8c_be (u32 block[16], const u32 block_len, const u32 append, const u32 append_len, u32 digest[8])
{
  const u32 mod = block_len & 3;
  const u32 div = block_len / 4;

  u32 tmp0;
  u32 tmp1;

  #ifdef IS_NV
  const int selector = (0x76543210 >> ((block_len & 3) * 4)) & 0xffff;

  tmp0 = __byte_perm (append, 0, selector);
  tmp1 = __byte_perm (0, append, selector);
  #endif

  #if defined IS_AMD || defined IS_GENERIC
  tmp0 = amd_bytealign (0, append, block_len);
  tmp1 = amd_bytealign (append, 0, block_len);
  #endif

  u32 carry = 0;

  switch (div)
  {
    case  0:  block[ 0] |= tmp0;
              block[ 1]  = tmp1;
              break;
    case  1:  block[ 1] |= tmp0;
              block[ 2]  = tmp1;
              break;
    case  2:  block[ 2] |= tmp0;
              block[ 3]  = tmp1;
              break;
    case  3:  block[ 3] |= tmp0;
              block[ 4]  = tmp1;
              break;
    case  4:  block[ 4] |= tmp0;
              block[ 5]  = tmp1;
              break;
    case  5:  block[ 5] |= tmp0;
              block[ 6]  = tmp1;
              break;
    case  6:  block[ 6] |= tmp0;
              block[ 7]  = tmp1;
              break;
    case  7:  block[ 7] |= tmp0;
              block[ 8]  = tmp1;
              break;
    case  8:  block[ 8] |= tmp0;
              block[ 9]  = tmp1;
              break;
    case  9:  block[ 9] |= tmp0;
              block[10]  = tmp1;
              break;
    case 10:  block[10] |= tmp0;
              block[11]  = tmp1;
              break;
    case 11:  block[11] |= tmp0;
              block[12]  = tmp1;
              break;
    case 12:  block[12] |= tmp0;
              block[13]  = tmp1;
              break;
    case 13:  block[13] |= tmp0;
              block[14]  = tmp1;
              break;
    case 14:  block[14] |= tmp0;
              block[15]  = tmp1;
              break;
    case 15:  block[15] |= tmp0;
              carry      = tmp1;
              break;
  }

  u32 new_len = block_len + append_len;

  if (new_len >= 64)
  {
    new_len -= 64;

    sha256_transform (block, digest);

    block[ 0] = carry;
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

  return new_len;
}

u32 memcat64c_be (u32 block[16], const u32 block_len, const u32 append[16], const u32 append_len, u32 digest[8])
{
  const u32 mod = block_len & 3;
  const u32 div = block_len / 4;

  u32 tmp00;
  u32 tmp01;
  u32 tmp02;
  u32 tmp03;
  u32 tmp04;
  u32 tmp05;
  u32 tmp06;
  u32 tmp07;
  u32 tmp08;
  u32 tmp09;
  u32 tmp10;
  u32 tmp11;
  u32 tmp12;
  u32 tmp13;
  u32 tmp14;
  u32 tmp15;
  u32 tmp16;

  #ifdef IS_NV
  const int selector = (0x76543210 >> ((block_len & 3) * 4)) & 0xffff;

  tmp00 = __byte_perm (append[ 0],          0, selector);
  tmp01 = __byte_perm (append[ 1], append[ 0], selector);
  tmp02 = __byte_perm (append[ 2], append[ 1], selector);
  tmp03 = __byte_perm (append[ 3], append[ 2], selector);
  tmp04 = __byte_perm (append[ 4], append[ 3], selector);
  tmp05 = __byte_perm (append[ 5], append[ 4], selector);
  tmp06 = __byte_perm (append[ 6], append[ 5], selector);
  tmp07 = __byte_perm (append[ 7], append[ 6], selector);
  tmp08 = __byte_perm (append[ 8], append[ 7], selector);
  tmp09 = __byte_perm (append[ 9], append[ 8], selector);
  tmp10 = __byte_perm (append[10], append[ 9], selector);
  tmp11 = __byte_perm (append[11], append[10], selector);
  tmp12 = __byte_perm (append[12], append[11], selector);
  tmp13 = __byte_perm (append[13], append[12], selector);
  tmp14 = __byte_perm (append[14], append[13], selector);
  tmp15 = __byte_perm (append[15], append[14], selector);
  tmp16 = __byte_perm (         0, append[15], selector);
  #endif

  #if defined IS_AMD || defined IS_GENERIC
  tmp00 = amd_bytealign (         0, append[ 0], block_len);
  tmp01 = amd_bytealign (append[ 0], append[ 1], block_len);
  tmp02 = amd_bytealign (append[ 1], append[ 2], block_len);
  tmp03 = amd_bytealign (append[ 2], append[ 3], block_len);
  tmp04 = amd_bytealign (append[ 3], append[ 4], block_len);
  tmp05 = amd_bytealign (append[ 4], append[ 5], block_len);
  tmp06 = amd_bytealign (append[ 5], append[ 6], block_len);
  tmp07 = amd_bytealign (append[ 6], append[ 7], block_len);
  tmp08 = amd_bytealign (append[ 7], append[ 8], block_len);
  tmp09 = amd_bytealign (append[ 8], append[ 9], block_len);
  tmp10 = amd_bytealign (append[ 9], append[10], block_len);
  tmp11 = amd_bytealign (append[10], append[11], block_len);
  tmp12 = amd_bytealign (append[11], append[12], block_len);
  tmp13 = amd_bytealign (append[12], append[13], block_len);
  tmp14 = amd_bytealign (append[13], append[14], block_len);
  tmp15 = amd_bytealign (append[14], append[15], block_len);
  tmp16 = amd_bytealign (append[15],          0, block_len);
  #endif

  u32 carry[16] = { 0 };

  switch (div)
  {
    case  0:  block[ 0] |= tmp00;
              block[ 1]  = tmp01;
              block[ 2]  = tmp02;
              block[ 3]  = tmp03;
              block[ 4]  = tmp04;
              block[ 5]  = tmp05;
              block[ 6]  = tmp06;
              block[ 7]  = tmp07;
              block[ 8]  = tmp08;
              block[ 9]  = tmp09;
              block[10]  = tmp10;
              block[11]  = tmp11;
              block[12]  = tmp12;
              block[13]  = tmp13;
              block[14]  = tmp14;
              block[15]  = tmp15;
              carry[ 0]  = tmp16;
              break;
    case  1:  block[ 1] |= tmp00;
              block[ 2]  = tmp01;
              block[ 3]  = tmp02;
              block[ 4]  = tmp03;
              block[ 5]  = tmp04;
              block[ 6]  = tmp05;
              block[ 7]  = tmp06;
              block[ 8]  = tmp07;
              block[ 9]  = tmp08;
              block[10]  = tmp09;
              block[11]  = tmp10;
              block[12]  = tmp11;
              block[13]  = tmp12;
              block[14]  = tmp13;
              block[15]  = tmp14;
              carry[ 0]  = tmp15;
              carry[ 1]  = tmp16;
              break;
    case  2:  block[ 2] |= tmp00;
              block[ 3]  = tmp01;
              block[ 4]  = tmp02;
              block[ 5]  = tmp03;
              block[ 6]  = tmp04;
              block[ 7]  = tmp05;
              block[ 8]  = tmp06;
              block[ 9]  = tmp07;
              block[10]  = tmp08;
              block[11]  = tmp09;
              block[12]  = tmp10;
              block[13]  = tmp11;
              block[14]  = tmp12;
              block[15]  = tmp13;
              carry[ 0]  = tmp14;
              carry[ 1]  = tmp15;
              carry[ 2]  = tmp16;
              break;
    case  3:  block[ 3] |= tmp00;
              block[ 4]  = tmp01;
              block[ 5]  = tmp02;
              block[ 6]  = tmp03;
              block[ 7]  = tmp04;
              block[ 8]  = tmp05;
              block[ 9]  = tmp06;
              block[10]  = tmp07;
              block[11]  = tmp08;
              block[12]  = tmp09;
              block[13]  = tmp10;
              block[14]  = tmp11;
              block[15]  = tmp12;
              carry[ 0]  = tmp13;
              carry[ 1]  = tmp14;
              carry[ 2]  = tmp15;
              carry[ 3]  = tmp16;
              break;
    case  4:  block[ 4] |= tmp00;
              block[ 5]  = tmp01;
              block[ 6]  = tmp02;
              block[ 7]  = tmp03;
              block[ 8]  = tmp04;
              block[ 9]  = tmp05;
              block[10]  = tmp06;
              block[11]  = tmp07;
              block[12]  = tmp08;
              block[13]  = tmp09;
              block[14]  = tmp10;
              block[15]  = tmp11;
              carry[ 0]  = tmp12;
              carry[ 1]  = tmp13;
              carry[ 2]  = tmp14;
              carry[ 3]  = tmp15;
              carry[ 4]  = tmp16;
              break;
    case  5:  block[ 5] |= tmp00;
              block[ 6]  = tmp01;
              block[ 7]  = tmp02;
              block[ 8]  = tmp03;
              block[ 9]  = tmp04;
              block[10]  = tmp05;
              block[11]  = tmp06;
              block[12]  = tmp07;
              block[13]  = tmp08;
              block[14]  = tmp09;
              block[15]  = tmp10;
              carry[ 0]  = tmp11;
              carry[ 1]  = tmp12;
              carry[ 2]  = tmp13;
              carry[ 3]  = tmp14;
              carry[ 4]  = tmp15;
              carry[ 5]  = tmp16;
              break;
    case  6:  block[ 6] |= tmp00;
              block[ 7]  = tmp01;
              block[ 8]  = tmp02;
              block[ 9]  = tmp03;
              block[10]  = tmp04;
              block[11]  = tmp05;
              block[12]  = tmp06;
              block[13]  = tmp07;
              block[14]  = tmp08;
              block[15]  = tmp09;
              carry[ 0]  = tmp10;
              carry[ 1]  = tmp11;
              carry[ 2]  = tmp12;
              carry[ 3]  = tmp13;
              carry[ 4]  = tmp14;
              carry[ 5]  = tmp15;
              carry[ 6]  = tmp16;
              break;
    case  7:  block[ 7] |= tmp00;
              block[ 8]  = tmp01;
              block[ 9]  = tmp02;
              block[10]  = tmp03;
              block[11]  = tmp04;
              block[12]  = tmp05;
              block[13]  = tmp06;
              block[14]  = tmp07;
              block[15]  = tmp08;
              carry[ 0]  = tmp09;
              carry[ 1]  = tmp10;
              carry[ 2]  = tmp11;
              carry[ 3]  = tmp12;
              carry[ 4]  = tmp13;
              carry[ 5]  = tmp14;
              carry[ 6]  = tmp15;
              carry[ 7]  = tmp16;
              break;
    case  8:  block[ 8] |= tmp00;
              block[ 9]  = tmp01;
              block[10]  = tmp02;
              block[11]  = tmp03;
              block[12]  = tmp04;
              block[13]  = tmp05;
              block[14]  = tmp06;
              block[15]  = tmp07;
              carry[ 0]  = tmp08;
              carry[ 1]  = tmp09;
              carry[ 2]  = tmp10;
              carry[ 3]  = tmp11;
              carry[ 4]  = tmp12;
              carry[ 5]  = tmp13;
              carry[ 6]  = tmp14;
              carry[ 7]  = tmp15;
              carry[ 8]  = tmp16;
              break;
    case  9:  block[ 9] |= tmp00;
              block[10]  = tmp01;
              block[11]  = tmp02;
              block[12]  = tmp03;
              block[13]  = tmp04;
              block[14]  = tmp05;
              block[15]  = tmp06;
              carry[ 0]  = tmp07;
              carry[ 1]  = tmp08;
              carry[ 2]  = tmp09;
              carry[ 3]  = tmp10;
              carry[ 4]  = tmp11;
              carry[ 5]  = tmp12;
              carry[ 6]  = tmp13;
              carry[ 7]  = tmp14;
              carry[ 8]  = tmp15;
              carry[ 9]  = tmp16;
              break;
    case 10:  block[10] |= tmp00;
              block[11]  = tmp01;
              block[12]  = tmp02;
              block[13]  = tmp03;
              block[14]  = tmp04;
              block[15]  = tmp05;
              carry[ 0]  = tmp06;
              carry[ 1]  = tmp07;
              carry[ 2]  = tmp08;
              carry[ 3]  = tmp09;
              carry[ 4]  = tmp10;
              carry[ 5]  = tmp11;
              carry[ 6]  = tmp12;
              carry[ 7]  = tmp13;
              carry[ 8]  = tmp14;
              carry[ 9]  = tmp15;
              carry[10]  = tmp16;
              break;
    case 11:  block[11] |= tmp00;
              block[12]  = tmp01;
              block[13]  = tmp02;
              block[14]  = tmp03;
              block[15]  = tmp04;
              carry[ 0]  = tmp05;
              carry[ 1]  = tmp06;
              carry[ 2]  = tmp07;
              carry[ 3]  = tmp08;
              carry[ 4]  = tmp09;
              carry[ 5]  = tmp10;
              carry[ 6]  = tmp11;
              carry[ 7]  = tmp12;
              carry[ 8]  = tmp13;
              carry[ 9]  = tmp14;
              carry[10]  = tmp15;
              carry[11]  = tmp16;
              break;
    case 12:  block[12] |= tmp00;
              block[13]  = tmp01;
              block[14]  = tmp02;
              block[15]  = tmp03;
              carry[ 0]  = tmp04;
              carry[ 1]  = tmp05;
              carry[ 2]  = tmp06;
              carry[ 3]  = tmp07;
              carry[ 4]  = tmp08;
              carry[ 5]  = tmp09;
              carry[ 6]  = tmp10;
              carry[ 7]  = tmp11;
              carry[ 8]  = tmp12;
              carry[ 9]  = tmp13;
              carry[10]  = tmp14;
              carry[11]  = tmp15;
              carry[12]  = tmp16;
              break;
    case 13:  block[13] |= tmp00;
              block[14]  = tmp01;
              block[15]  = tmp02;
              carry[ 0]  = tmp03;
              carry[ 1]  = tmp04;
              carry[ 2]  = tmp05;
              carry[ 3]  = tmp06;
              carry[ 4]  = tmp07;
              carry[ 5]  = tmp08;
              carry[ 6]  = tmp09;
              carry[ 7]  = tmp10;
              carry[ 8]  = tmp11;
              carry[ 9]  = tmp12;
              carry[10]  = tmp13;
              carry[11]  = tmp14;
              carry[12]  = tmp15;
              carry[13]  = tmp16;
              break;
    case 14:  block[14] |= tmp00;
              block[15]  = tmp01;
              carry[ 0]  = tmp02;
              carry[ 1]  = tmp03;
              carry[ 2]  = tmp04;
              carry[ 3]  = tmp05;
              carry[ 4]  = tmp06;
              carry[ 5]  = tmp07;
              carry[ 6]  = tmp08;
              carry[ 7]  = tmp09;
              carry[ 8]  = tmp10;
              carry[ 9]  = tmp11;
              carry[10]  = tmp12;
              carry[11]  = tmp13;
              carry[12]  = tmp14;
              carry[13]  = tmp15;
              carry[14]  = tmp16;
              break;
    case 15:  block[15] |= tmp00;
              carry[ 0]  = tmp01;
              carry[ 1]  = tmp02;
              carry[ 2]  = tmp03;
              carry[ 3]  = tmp04;
              carry[ 4]  = tmp05;
              carry[ 5]  = tmp06;
              carry[ 6]  = tmp07;
              carry[ 7]  = tmp08;
              carry[ 8]  = tmp09;
              carry[ 9]  = tmp10;
              carry[10]  = tmp11;
              carry[11]  = tmp12;
              carry[12]  = tmp13;
              carry[13]  = tmp14;
              carry[14]  = tmp15;
              carry[15]  = tmp16;
              break;
  }

  u32 new_len = block_len + append_len;

  if (new_len >= 64)
  {
    new_len -= 64;

    sha256_transform (block, digest);

    block[ 0] = carry[ 0];
    block[ 1] = carry[ 1];
    block[ 2] = carry[ 2];
    block[ 3] = carry[ 3];
    block[ 4] = carry[ 4];
    block[ 5] = carry[ 5];
    block[ 6] = carry[ 6];
    block[ 7] = carry[ 7];
    block[ 8] = carry[ 8];
    block[ 9] = carry[ 9];
    block[10] = carry[10];
    block[11] = carry[11];
    block[12] = carry[12];
    block[13] = carry[13];
    block[14] = carry[14];
    block[15] = carry[15];
  }

  return new_len;
}

__kernel void m11600_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global seven_zip_tmp_t *tmps, __global seven_zip_hook_t *seven_zip_hook, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * context save
   */

  tmps[gid].dgst[0] = SHA256M_A;
  tmps[gid].dgst[1] = SHA256M_B;
  tmps[gid].dgst[2] = SHA256M_C;
  tmps[gid].dgst[3] = SHA256M_D;
  tmps[gid].dgst[4] = SHA256M_E;
  tmps[gid].dgst[5] = SHA256M_F;
  tmps[gid].dgst[6] = SHA256M_G;
  tmps[gid].dgst[7] = SHA256M_H;

  tmps[gid].block[ 0] = 0;
  tmps[gid].block[ 1] = 0;
  tmps[gid].block[ 2] = 0;
  tmps[gid].block[ 3] = 0;
  tmps[gid].block[ 4] = 0;
  tmps[gid].block[ 5] = 0;
  tmps[gid].block[ 6] = 0;
  tmps[gid].block[ 7] = 0;
  tmps[gid].block[ 8] = 0;
  tmps[gid].block[ 9] = 0;
  tmps[gid].block[10] = 0;
  tmps[gid].block[11] = 0;
  tmps[gid].block[12] = 0;
  tmps[gid].block[13] = 0;
  tmps[gid].block[14] = 0;
  tmps[gid].block[15] = 0;

  tmps[gid].block_len = 0;
  tmps[gid].final_len = 0;
}

__kernel void m11600_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global seven_zip_tmp_t *tmps, __global seven_zip_hook_t *seven_zip_hook, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw[16] = { 0 };

  pw[0] = pws[gid].i[0];
  pw[1] = pws[gid].i[1];
  pw[2] = pws[gid].i[2];
  pw[3] = pws[gid].i[3];
  pw[4] = pws[gid].i[4];
  pw[5] = pws[gid].i[5];
  pw[6] = pws[gid].i[6];
  pw[7] = pws[gid].i[7];

  u32 pw_len = pws[gid].pw_len;

  make_utf16le (&pw[ 4], &pw[ 8], &pw[12]);
  make_utf16le (&pw[ 0], &pw[ 0], &pw[ 4]);

  pw_len *= 2;

  pw[ 0] = swap32 (pw[ 0]);
  pw[ 1] = swap32 (pw[ 1]);
  pw[ 2] = swap32 (pw[ 2]);
  pw[ 3] = swap32 (pw[ 3]);
  pw[ 4] = swap32 (pw[ 4]);
  pw[ 5] = swap32 (pw[ 5]);
  pw[ 6] = swap32 (pw[ 6]);
  pw[ 7] = swap32 (pw[ 7]);
  pw[ 8] = swap32 (pw[ 8]);
  pw[ 9] = swap32 (pw[ 9]);
  pw[10] = swap32 (pw[10]);
  pw[11] = swap32 (pw[11]);
  pw[12] = swap32 (pw[12]);
  pw[13] = swap32 (pw[13]);
  pw[14] = swap32 (pw[14]);
  pw[15] = swap32 (pw[15]);

  /**
   * context load
   */

  u32 dgst[8];

  dgst[0] = tmps[gid].dgst[0];
  dgst[1] = tmps[gid].dgst[1];
  dgst[2] = tmps[gid].dgst[2];
  dgst[3] = tmps[gid].dgst[3];
  dgst[4] = tmps[gid].dgst[4];
  dgst[5] = tmps[gid].dgst[5];
  dgst[6] = tmps[gid].dgst[6];
  dgst[7] = tmps[gid].dgst[7];

  u32 block[16];

  block[ 0] = tmps[gid].block[ 0];
  block[ 1] = tmps[gid].block[ 1];
  block[ 2] = tmps[gid].block[ 2];
  block[ 3] = tmps[gid].block[ 3];
  block[ 4] = tmps[gid].block[ 4];
  block[ 5] = tmps[gid].block[ 5];
  block[ 6] = tmps[gid].block[ 6];
  block[ 7] = tmps[gid].block[ 7];
  block[ 8] = tmps[gid].block[ 8];
  block[ 9] = tmps[gid].block[ 9];
  block[10] = tmps[gid].block[10];
  block[11] = tmps[gid].block[11];
  block[12] = tmps[gid].block[12];
  block[13] = tmps[gid].block[13];
  block[14] = tmps[gid].block[14];
  block[15] = tmps[gid].block[15];

  u32 block_len = tmps[gid].block_len;
  u32 final_len = tmps[gid].final_len;

  /**
   * base
   */

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    const u32 j_swap = swap32 (j);

    block_len = memcat64c_be (block, block_len,     pw, pw_len, dgst); final_len += pw_len;
    block_len = memcat8c_be  (block, block_len, j_swap,      8, dgst); final_len += 8;
  }

  /**
   * context save
   */

  tmps[gid].dgst[0] = dgst[0];
  tmps[gid].dgst[1] = dgst[1];
  tmps[gid].dgst[2] = dgst[2];
  tmps[gid].dgst[3] = dgst[3];
  tmps[gid].dgst[4] = dgst[4];
  tmps[gid].dgst[5] = dgst[5];
  tmps[gid].dgst[6] = dgst[6];
  tmps[gid].dgst[7] = dgst[7];

  tmps[gid].block[ 0] = block[ 0];
  tmps[gid].block[ 1] = block[ 1];
  tmps[gid].block[ 2] = block[ 2];
  tmps[gid].block[ 3] = block[ 3];
  tmps[gid].block[ 4] = block[ 4];
  tmps[gid].block[ 5] = block[ 5];
  tmps[gid].block[ 6] = block[ 6];
  tmps[gid].block[ 7] = block[ 7];
  tmps[gid].block[ 8] = block[ 8];
  tmps[gid].block[ 9] = block[ 9];
  tmps[gid].block[10] = block[10];
  tmps[gid].block[11] = block[11];
  tmps[gid].block[12] = block[12];
  tmps[gid].block[13] = block[13];
  tmps[gid].block[14] = block[14];
  tmps[gid].block[15] = block[15];

  tmps[gid].block_len = block_len;
  tmps[gid].final_len = final_len;
}

__kernel void m11600_hook23 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global seven_zip_tmp_t *tmps, __global seven_zip_hook_t *seven_zip_hook, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  if (gid >= gid_max) return;

  /**
   * context load
   */

  u32 dgst[8];

  dgst[0] = tmps[gid].dgst[0];
  dgst[1] = tmps[gid].dgst[1];
  dgst[2] = tmps[gid].dgst[2];
  dgst[3] = tmps[gid].dgst[3];
  dgst[4] = tmps[gid].dgst[4];
  dgst[5] = tmps[gid].dgst[5];
  dgst[6] = tmps[gid].dgst[6];
  dgst[7] = tmps[gid].dgst[7];

  u32 block_len = tmps[gid].block_len;
  u32 final_len = tmps[gid].final_len;

  // this optimization should work as long as we have an iteration 6 or higher

  u32 block[16];

  block[ 0] = 0x80000000;
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
  block[15] = final_len * 8;

  sha256_transform (block, dgst);

  seven_zip_hook[gid].ukey[0] = swap32 (dgst[0]);
  seven_zip_hook[gid].ukey[1] = swap32 (dgst[1]);
  seven_zip_hook[gid].ukey[2] = swap32 (dgst[2]);
  seven_zip_hook[gid].ukey[3] = swap32 (dgst[3]);
  seven_zip_hook[gid].ukey[4] = swap32 (dgst[4]);
  seven_zip_hook[gid].ukey[5] = swap32 (dgst[5]);
  seven_zip_hook[gid].ukey[6] = swap32 (dgst[6]);
  seven_zip_hook[gid].ukey[7] = swap32 (dgst[7]);
}

__kernel void m11600_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global seven_zip_tmp_t *tmps, __global seven_zip_hook_t *seven_zip_hook, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  if (seven_zip_hook[gid].hook_success == 1)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, 0);

    return;
  }
 }
