/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define _SHA256_

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

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

static void sha256_transform (const u32x w[16], u32x digest[8])
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];
  u32x e = digest[4];
  u32x f = digest[5];
  u32x g = digest[6];
  u32x h = digest[7];

  u32x w0_t = w[ 0];
  u32x w1_t = w[ 1];
  u32x w2_t = w[ 2];
  u32x w3_t = w[ 3];
  u32x w4_t = w[ 4];
  u32x w5_t = w[ 5];
  u32x w6_t = w[ 6];
  u32x w7_t = w[ 7];
  u32x w8_t = w[ 8];
  u32x w9_t = w[ 9];
  u32x wa_t = w[10];
  u32x wb_t = w[11];
  u32x wc_t = w[12];
  u32x wd_t = w[13];
  u32x we_t = w[14];
  u32x wf_t = w[15];

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

static void memcat64c_be (u32x block[16], const u32 offset, u32x carry[16])
{
  const u32 mod = offset & 3;
  const u32 div = offset / 4;

  u32x tmp00;
  u32x tmp01;
  u32x tmp02;
  u32x tmp03;
  u32x tmp04;
  u32x tmp05;
  u32x tmp06;
  u32x tmp07;
  u32x tmp08;
  u32x tmp09;
  u32x tmp10;
  u32x tmp11;
  u32x tmp12;
  u32x tmp13;
  u32x tmp14;
  u32x tmp15;
  u32x tmp16;

  #ifdef IS_NV
  const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;

  tmp00 = __byte_perm (carry[ 0],         0, selector);
  tmp01 = __byte_perm (carry[ 1], carry[ 0], selector);
  tmp02 = __byte_perm (carry[ 2], carry[ 1], selector);
  tmp03 = __byte_perm (carry[ 3], carry[ 2], selector);
  tmp04 = __byte_perm (carry[ 4], carry[ 3], selector);
  tmp05 = __byte_perm (carry[ 5], carry[ 4], selector);
  tmp06 = __byte_perm (carry[ 6], carry[ 5], selector);
  tmp07 = __byte_perm (carry[ 7], carry[ 6], selector);
  tmp08 = __byte_perm (carry[ 8], carry[ 7], selector);
  tmp09 = __byte_perm (carry[ 9], carry[ 8], selector);
  tmp10 = __byte_perm (carry[10], carry[ 9], selector);
  tmp11 = __byte_perm (carry[11], carry[10], selector);
  tmp12 = __byte_perm (carry[12], carry[11], selector);
  tmp13 = __byte_perm (carry[13], carry[12], selector);
  tmp14 = __byte_perm (carry[14], carry[13], selector);
  tmp15 = __byte_perm (carry[15], carry[14], selector);
  tmp16 = __byte_perm (        0, carry[15], selector);
  #endif

  #if defined IS_AMD || defined IS_GENERIC
  tmp00 = amd_bytealign (        0, carry[ 0], offset);
  tmp01 = amd_bytealign (carry[ 0], carry[ 1], offset);
  tmp02 = amd_bytealign (carry[ 1], carry[ 2], offset);
  tmp03 = amd_bytealign (carry[ 2], carry[ 3], offset);
  tmp04 = amd_bytealign (carry[ 3], carry[ 4], offset);
  tmp05 = amd_bytealign (carry[ 4], carry[ 5], offset);
  tmp06 = amd_bytealign (carry[ 5], carry[ 6], offset);
  tmp07 = amd_bytealign (carry[ 6], carry[ 7], offset);
  tmp08 = amd_bytealign (carry[ 7], carry[ 8], offset);
  tmp09 = amd_bytealign (carry[ 8], carry[ 9], offset);
  tmp10 = amd_bytealign (carry[ 9], carry[10], offset);
  tmp11 = amd_bytealign (carry[10], carry[11], offset);
  tmp12 = amd_bytealign (carry[11], carry[12], offset);
  tmp13 = amd_bytealign (carry[12], carry[13], offset);
  tmp14 = amd_bytealign (carry[13], carry[14], offset);
  tmp15 = amd_bytealign (carry[14], carry[15], offset);
  tmp16 = amd_bytealign (carry[15],         0, offset);
  #endif

  carry[ 0] = 0;
  carry[ 1] = 0;
  carry[ 2] = 0;
  carry[ 3] = 0;
  carry[ 4] = 0;
  carry[ 5] = 0;
  carry[ 6] = 0;
  carry[ 7] = 0;
  carry[ 8] = 0;
  carry[ 9] = 0;
  carry[10] = 0;
  carry[11] = 0;
  carry[12] = 0;
  carry[13] = 0;
  carry[14] = 0;
  carry[15] = 0;

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
}

static void m13800m (__local u32 *s_esalt, u32 w[16], const u32 pw_len, __global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __constant u32x * words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global win8phone_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x w_t[16];

    w_t[ 0] = w0;
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
    w_t[14] = w[14];
    w_t[15] = w[15];

    u32x carry[16];

    carry[ 0] = s_esalt[ 0];
    carry[ 1] = s_esalt[ 1];
    carry[ 2] = s_esalt[ 2];
    carry[ 3] = s_esalt[ 3];
    carry[ 4] = s_esalt[ 4];
    carry[ 5] = s_esalt[ 5];
    carry[ 6] = s_esalt[ 6];
    carry[ 7] = s_esalt[ 7];
    carry[ 8] = s_esalt[ 8];
    carry[ 9] = s_esalt[ 9];
    carry[10] = s_esalt[10];
    carry[11] = s_esalt[11];
    carry[12] = s_esalt[12];
    carry[13] = s_esalt[13];
    carry[14] = s_esalt[14];
    carry[15] = s_esalt[15];

    // we can always use pw_len here, since we add exactly the hash buffer size
    memcat64c_be (w_t, pw_len, carry);

    u32x digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (w_t, digest);

    w_t[ 0] = carry[ 0];
    w_t[ 1] = carry[ 1];
    w_t[ 2] = carry[ 2];
    w_t[ 3] = carry[ 3];
    w_t[ 4] = carry[ 4];
    w_t[ 5] = carry[ 5];
    w_t[ 6] = carry[ 6];
    w_t[ 7] = carry[ 7];
    w_t[ 8] = carry[ 8];
    w_t[ 9] = carry[ 9];
    w_t[10] = carry[10];
    w_t[11] = carry[11];
    w_t[12] = carry[12];
    w_t[13] = carry[13];
    w_t[14] = carry[14];
    w_t[15] = carry[15];

    carry[ 0] = s_esalt[16];
    carry[ 1] = s_esalt[17];
    carry[ 2] = s_esalt[18];
    carry[ 3] = s_esalt[19];
    carry[ 4] = s_esalt[20];
    carry[ 5] = s_esalt[21];
    carry[ 6] = s_esalt[22];
    carry[ 7] = s_esalt[23];
    carry[ 8] = s_esalt[24];
    carry[ 9] = s_esalt[25];
    carry[10] = s_esalt[26];
    carry[11] = s_esalt[27];
    carry[12] = s_esalt[28];
    carry[13] = s_esalt[29];
    carry[14] = s_esalt[30];
    carry[15] = s_esalt[31];

    // we can always use pw_len here, since we add exactly the hash buffer size
    memcat64c_be (w_t, pw_len, carry);

    sha256_transform (w_t, digest);

    w_t[ 0] = carry[ 0];
    w_t[ 1] = carry[ 1];
    w_t[ 2] = carry[ 2];
    w_t[ 3] = carry[ 3];
    w_t[ 4] = carry[ 4];
    w_t[ 5] = carry[ 5];
    w_t[ 6] = carry[ 6];
    w_t[ 7] = carry[ 7];
    w_t[ 8] = carry[ 8];
    w_t[ 9] = carry[ 9];
    w_t[10] = carry[10];
    w_t[11] = carry[11];
    w_t[12] = carry[12];
    w_t[13] = carry[13];
    w_t[14] = carry[14];
    w_t[15] = carry[15];

    // we can always use pw_len here, since we add exactly the hash buffer size
    append_0x80_4x4 (w_t + 0, w_t + 4, w_t + 8, w_t + 12, pw_len ^ 3);

    w_t[14] = 0;
    w_t[15] = (pw_len + 128) * 8;

    sha256_transform (w_t, digest);

    const u32x d = digest[DGST_R0];
    const u32x h = digest[DGST_R1];
    const u32x c = digest[DGST_R2];
    const u32x g = digest[DGST_R3];

    COMPARE_M_SIMD (d, h, c, g);
  }
}

static void m13800s (__local u32 *s_esalt, u32 w[16], const u32 pw_len, __global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __constant u32x * words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global win8phone_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x w_t[16];

    w_t[ 0] = w0;
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
    w_t[14] = w[14];
    w_t[15] = w[15];

    u32x carry[16];

    carry[ 0] = s_esalt[ 0];
    carry[ 1] = s_esalt[ 1];
    carry[ 2] = s_esalt[ 2];
    carry[ 3] = s_esalt[ 3];
    carry[ 4] = s_esalt[ 4];
    carry[ 5] = s_esalt[ 5];
    carry[ 6] = s_esalt[ 6];
    carry[ 7] = s_esalt[ 7];
    carry[ 8] = s_esalt[ 8];
    carry[ 9] = s_esalt[ 9];
    carry[10] = s_esalt[10];
    carry[11] = s_esalt[11];
    carry[12] = s_esalt[12];
    carry[13] = s_esalt[13];
    carry[14] = s_esalt[14];
    carry[15] = s_esalt[15];

    // we can always use pw_len here, since we add exactly the hash buffer size
    memcat64c_be (w_t, pw_len, carry);

    u32x digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform (w_t, digest);

    w_t[ 0] = carry[ 0];
    w_t[ 1] = carry[ 1];
    w_t[ 2] = carry[ 2];
    w_t[ 3] = carry[ 3];
    w_t[ 4] = carry[ 4];
    w_t[ 5] = carry[ 5];
    w_t[ 6] = carry[ 6];
    w_t[ 7] = carry[ 7];
    w_t[ 8] = carry[ 8];
    w_t[ 9] = carry[ 9];
    w_t[10] = carry[10];
    w_t[11] = carry[11];
    w_t[12] = carry[12];
    w_t[13] = carry[13];
    w_t[14] = carry[14];
    w_t[15] = carry[15];

    carry[ 0] = s_esalt[16];
    carry[ 1] = s_esalt[17];
    carry[ 2] = s_esalt[18];
    carry[ 3] = s_esalt[19];
    carry[ 4] = s_esalt[20];
    carry[ 5] = s_esalt[21];
    carry[ 6] = s_esalt[22];
    carry[ 7] = s_esalt[23];
    carry[ 8] = s_esalt[24];
    carry[ 9] = s_esalt[25];
    carry[10] = s_esalt[26];
    carry[11] = s_esalt[27];
    carry[12] = s_esalt[28];
    carry[13] = s_esalt[29];
    carry[14] = s_esalt[30];
    carry[15] = s_esalt[31];

    // we can always use pw_len here, since we add exactly the hash buffer size
    memcat64c_be (w_t, pw_len, carry);

    sha256_transform (w_t, digest);

    w_t[ 0] = carry[ 0];
    w_t[ 1] = carry[ 1];
    w_t[ 2] = carry[ 2];
    w_t[ 3] = carry[ 3];
    w_t[ 4] = carry[ 4];
    w_t[ 5] = carry[ 5];
    w_t[ 6] = carry[ 6];
    w_t[ 7] = carry[ 7];
    w_t[ 8] = carry[ 8];
    w_t[ 9] = carry[ 9];
    w_t[10] = carry[10];
    w_t[11] = carry[11];
    w_t[12] = carry[12];
    w_t[13] = carry[13];
    w_t[14] = carry[14];
    w_t[15] = carry[15];

    // we can always use pw_len here, since we add exactly the hash buffer size
    append_0x80_4x4 (w_t + 0, w_t + 4, w_t + 8, w_t + 12, pw_len ^ 3);

    w_t[14] = 0;
    w_t[15] = (pw_len + 128) * 8;

    sha256_transform (w_t, digest);

    const u32x d = digest[DGST_R0];
    const u32x h = digest[DGST_R1];
    const u32x c = digest[DGST_R2];
    const u32x g = digest[DGST_R3];

    COMPARE_S_SIMD (d, h, c, g);
  }
}

__kernel void m13800_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __constant u32x * words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global win8phone_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * shared
   */

  __local u32 s_esalt[32];

  for (u32 i = lid; i < 32; i += lsz)
  {
    s_esalt[i] = esalt_bufs[salt_pos].salt_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  m13800m (s_esalt, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m13800_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __constant u32x * words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global win8phone_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * shared
   */

  __local u32 s_esalt[32];

  for (u32 i = lid; i < 32; i += lsz)
  {
    s_esalt[i] = esalt_bufs[salt_pos].salt_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  m13800m (s_esalt, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m13800_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __constant u32x * words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global win8phone_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * shared
   */

  __local u32 s_esalt[32];

  for (u32 i = lid; i < 32; i += lsz)
  {
    s_esalt[i] = esalt_bufs[salt_pos].salt_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  m13800m (s_esalt, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m13800_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __constant u32x * words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global win8phone_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * shared
   */

  __local u32 s_esalt[32];

  for (u32 i = lid; i < 32; i += lsz)
  {
    s_esalt[i] = esalt_bufs[salt_pos].salt_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  m13800s (s_esalt, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m13800_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __constant u32x * words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global win8phone_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * shared
   */

  __local u32 s_esalt[32];

  for (u32 i = lid; i < 32; i += lsz)
  {
    s_esalt[i] = esalt_bufs[salt_pos].salt_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  m13800s (s_esalt, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}

__kernel void m13800_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __constant u32x * words_buf_r, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global win8phone_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * base
   */

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * shared
   */

  __local u32 s_esalt[32];

  for (u32 i = lid; i < 32; i += lsz)
  {
    s_esalt[i] = esalt_bufs[salt_pos].salt_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * main
   */

  m13800s (s_esalt, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset);
}
