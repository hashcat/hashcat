/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

#include "inc_cipher_serpent.cl"

#include "inc_luks_af.cl"
#include "inc_luks_essiv.cl"
#include "inc_luks_xts.cl"

#include "inc_luks_serpent.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define MAX_ENTROPY 7.0

__constant u64a k_sha512[80] =
{
  SHA512C00, SHA512C01, SHA512C02, SHA512C03,
  SHA512C04, SHA512C05, SHA512C06, SHA512C07,
  SHA512C08, SHA512C09, SHA512C0a, SHA512C0b,
  SHA512C0c, SHA512C0d, SHA512C0e, SHA512C0f,
  SHA512C10, SHA512C11, SHA512C12, SHA512C13,
  SHA512C14, SHA512C15, SHA512C16, SHA512C17,
  SHA512C18, SHA512C19, SHA512C1a, SHA512C1b,
  SHA512C1c, SHA512C1d, SHA512C1e, SHA512C1f,
  SHA512C20, SHA512C21, SHA512C22, SHA512C23,
  SHA512C24, SHA512C25, SHA512C26, SHA512C27,
  SHA512C28, SHA512C29, SHA512C2a, SHA512C2b,
  SHA512C2c, SHA512C2d, SHA512C2e, SHA512C2f,
  SHA512C30, SHA512C31, SHA512C32, SHA512C33,
  SHA512C34, SHA512C35, SHA512C36, SHA512C37,
  SHA512C38, SHA512C39, SHA512C3a, SHA512C3b,
  SHA512C3c, SHA512C3d, SHA512C3e, SHA512C3f,
  SHA512C40, SHA512C41, SHA512C42, SHA512C43,
  SHA512C44, SHA512C45, SHA512C46, SHA512C47,
  SHA512C48, SHA512C49, SHA512C4a, SHA512C4b,
  SHA512C4c, SHA512C4d, SHA512C4e, SHA512C4f,
};

void sha512_transform_S (const u64 w0[4], const u64 w1[4], const u64 w2[4], const u64 w3[4], u64 digest[8])
{
  u64 a = digest[0];
  u64 b = digest[1];
  u64 c = digest[2];
  u64 d = digest[3];
  u64 e = digest[4];
  u64 f = digest[5];
  u64 g = digest[6];
  u64 h = digest[7];

  u64 w0_t = w0[0];
  u64 w1_t = w0[1];
  u64 w2_t = w0[2];
  u64 w3_t = w0[3];
  u64 w4_t = w1[0];
  u64 w5_t = w1[1];
  u64 w6_t = w1[2];
  u64 w7_t = w1[3];
  u64 w8_t = w2[0];
  u64 w9_t = w2[1];
  u64 wa_t = w2[2];
  u64 wb_t = w2[3];
  u64 wc_t = w3[0];
  u64 wd_t = w3[1];
  u64 we_t = w3[2];
  u64 wf_t = w3[3];

  #define ROUND_EXPAND_S()                            \
  {                                                   \
    w0_t = SHA512_EXPAND_S (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND_S (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND_S (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND_S (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND_S (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND_S (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND_S (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND_S (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND_S (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND_S (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND_S (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND_S (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND_S (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND_S (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND_S (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND_S (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP_S(i)                                                                   \
  {                                                                                         \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP_S (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND_S (); ROUND_STEP_S (i);
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

void hmac_sha512_pad_S (u64 w0[4], u64 w1[4], u64 w2[4], u64 w3[4], u64 ipad[8], u64 opad[8])
{
  w0[0] = w0[0] ^ 0x3636363636363636;
  w0[1] = w0[1] ^ 0x3636363636363636;
  w0[2] = w0[2] ^ 0x3636363636363636;
  w0[3] = w0[3] ^ 0x3636363636363636;
  w1[0] = w1[0] ^ 0x3636363636363636;
  w1[1] = w1[1] ^ 0x3636363636363636;
  w1[2] = w1[2] ^ 0x3636363636363636;
  w1[3] = w1[3] ^ 0x3636363636363636;
  w2[0] = w2[0] ^ 0x3636363636363636;
  w2[1] = w2[1] ^ 0x3636363636363636;
  w2[2] = w2[2] ^ 0x3636363636363636;
  w2[3] = w2[3] ^ 0x3636363636363636;
  w3[0] = w3[0] ^ 0x3636363636363636;
  w3[1] = w3[1] ^ 0x3636363636363636;
  w3[2] = w3[2] ^ 0x3636363636363636;
  w3[3] = w3[3] ^ 0x3636363636363636;

  ipad[0] = SHA512M_A;
  ipad[1] = SHA512M_B;
  ipad[2] = SHA512M_C;
  ipad[3] = SHA512M_D;
  ipad[4] = SHA512M_E;
  ipad[5] = SHA512M_F;
  ipad[6] = SHA512M_G;
  ipad[7] = SHA512M_H;

  sha512_transform_S (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a6a6a6a6a;

  opad[0] = SHA512M_A;
  opad[1] = SHA512M_B;
  opad[2] = SHA512M_C;
  opad[3] = SHA512M_D;
  opad[4] = SHA512M_E;
  opad[5] = SHA512M_F;
  opad[6] = SHA512M_G;
  opad[7] = SHA512M_H;

  sha512_transform_S (w0, w1, w2, w3, opad);
}

void hmac_sha512_run_S (u64 w0[4], u64 w1[4], u64 w2[4], u64 w3[4], u64 ipad[8], u64 opad[8], u64 digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_S (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x8000000000000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_S (w0, w1, w2, w3, digest);
}

void sha512_transform_V (const u64x w0[4], const u64x w1[4], const u64x w2[4], const u64x w3[4], u64x digest[8])
{
  u64x a = digest[0];
  u64x b = digest[1];
  u64x c = digest[2];
  u64x d = digest[3];
  u64x e = digest[4];
  u64x f = digest[5];
  u64x g = digest[6];
  u64x h = digest[7];

  u64x w0_t = w0[0];
  u64x w1_t = w0[1];
  u64x w2_t = w0[2];
  u64x w3_t = w0[3];
  u64x w4_t = w1[0];
  u64x w5_t = w1[1];
  u64x w6_t = w1[2];
  u64x w7_t = w1[3];
  u64x w8_t = w2[0];
  u64x w9_t = w2[1];
  u64x wa_t = w2[2];
  u64x wb_t = w2[3];
  u64x wc_t = w3[0];
  u64x wd_t = w3[1];
  u64x we_t = w3[2];
  u64x wf_t = w3[3];

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
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

void hmac_sha512_run_V (u64x w0[4], u64x w1[4], u64x w2[4], u64x w3[4], u64x ipad[8], u64x opad[8], u64x digest[8])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_V (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x8000000000000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_V (w0, w1, w2, w3, digest);
}

__kernel void m14632_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global luks_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global luks_t *luks_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u64 w0[4];
  u64 w1[4];
  u64 w2[4];
  u64 w3[4];

  w0[0] = hl32_to_64_S (swap32_S (pws[gid].i[ 0]), swap32_S (pws[gid].i[ 1]));
  w0[1] = hl32_to_64_S (swap32_S (pws[gid].i[ 2]), swap32_S (pws[gid].i[ 3]));
  w0[2] = hl32_to_64_S (swap32_S (pws[gid].i[ 4]), swap32_S (pws[gid].i[ 5]));
  w0[3] = hl32_to_64_S (swap32_S (pws[gid].i[ 6]), swap32_S (pws[gid].i[ 7]));
  w1[0] = hl32_to_64_S (swap32_S (pws[gid].i[ 8]), swap32_S (pws[gid].i[ 9]));
  w1[1] = hl32_to_64_S (swap32_S (pws[gid].i[10]), swap32_S (pws[gid].i[11]));
  w1[2] = hl32_to_64_S (swap32_S (pws[gid].i[12]), swap32_S (pws[gid].i[13]));
  w1[3] = hl32_to_64_S (swap32_S (pws[gid].i[14]), swap32_S (pws[gid].i[15]));
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  /**
   * salt
   */

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  u64 salt_buf0[4];

  salt_buf0[0] = hl32_to_64_S (swap32_S (salt_bufs[salt_pos].salt_buf[0]), swap32_S (salt_bufs[salt_pos].salt_buf[1]));
  salt_buf0[1] = hl32_to_64_S (swap32_S (salt_bufs[salt_pos].salt_buf[2]), swap32_S (salt_bufs[salt_pos].salt_buf[3]));
  salt_buf0[2] = hl32_to_64_S (swap32_S (salt_bufs[salt_pos].salt_buf[4]), swap32_S (salt_bufs[salt_pos].salt_buf[5]));
  salt_buf0[3] = hl32_to_64_S (swap32_S (salt_bufs[salt_pos].salt_buf[6]), swap32_S (salt_bufs[salt_pos].salt_buf[7]));

  u32 key_size = luks_bufs[digests_offset].key_size;

  /**
   * pads
   */

  u64 ipad[8];
  u64 opad[8];

  hmac_sha512_pad_S (w0, w1, w2, w3, ipad, opad);

  tmps[gid].ipad64[0] = ipad[0];
  tmps[gid].ipad64[1] = ipad[1];
  tmps[gid].ipad64[2] = ipad[2];
  tmps[gid].ipad64[3] = ipad[3];
  tmps[gid].ipad64[4] = ipad[4];
  tmps[gid].ipad64[5] = ipad[5];
  tmps[gid].ipad64[6] = ipad[6];
  tmps[gid].ipad64[7] = ipad[7];

  tmps[gid].opad64[0] = opad[0];
  tmps[gid].opad64[1] = opad[1];
  tmps[gid].opad64[2] = opad[2];
  tmps[gid].opad64[3] = opad[3];
  tmps[gid].opad64[4] = opad[4];
  tmps[gid].opad64[5] = opad[5];
  tmps[gid].opad64[6] = opad[6];
  tmps[gid].opad64[7] = opad[7];

  for (u32 i = 0, j = 1; i < ((key_size / 8) / 4); i += 16, j += 1)
  {
    w0[0] = salt_buf0[0];
    w0[1] = salt_buf0[1];
    w0[2] = salt_buf0[2];
    w0[3] = salt_buf0[3];
    w1[0] = hl32_to_64_S (j, 0x80000000);
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
    w3[3] = (128 + salt_len + 4) * 8;

    u64 dgst[8];

    hmac_sha512_run_S (w0, w1, w2, w3, ipad, opad, dgst);

    tmps[gid].dgst64[i + 0] = dgst[0];
    tmps[gid].dgst64[i + 1] = dgst[1];
    tmps[gid].dgst64[i + 2] = dgst[2];
    tmps[gid].dgst64[i + 3] = dgst[3];
    tmps[gid].dgst64[i + 4] = dgst[4];
    tmps[gid].dgst64[i + 5] = dgst[5];
    tmps[gid].dgst64[i + 6] = dgst[6];
    tmps[gid].dgst64[i + 7] = dgst[7];

    tmps[gid].out64[i + 0] = dgst[0];
    tmps[gid].out64[i + 1] = dgst[1];
    tmps[gid].out64[i + 2] = dgst[2];
    tmps[gid].out64[i + 3] = dgst[3];
    tmps[gid].out64[i + 4] = dgst[4];
    tmps[gid].out64[i + 5] = dgst[5];
    tmps[gid].out64[i + 6] = dgst[6];
    tmps[gid].out64[i + 7] = dgst[7];
  }
}

__kernel void m14632_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global luks_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global luks_t *luks_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u64x ipad[8];
  u64x opad[8];

  ipad[0] = pack64v (tmps, ipad64, gid, 0);
  ipad[1] = pack64v (tmps, ipad64, gid, 1);
  ipad[2] = pack64v (tmps, ipad64, gid, 2);
  ipad[3] = pack64v (tmps, ipad64, gid, 3);
  ipad[4] = pack64v (tmps, ipad64, gid, 4);
  ipad[5] = pack64v (tmps, ipad64, gid, 5);
  ipad[6] = pack64v (tmps, ipad64, gid, 6);
  ipad[7] = pack64v (tmps, ipad64, gid, 7);

  opad[0] = pack64v (tmps, opad64, gid, 0);
  opad[1] = pack64v (tmps, opad64, gid, 1);
  opad[2] = pack64v (tmps, opad64, gid, 2);
  opad[3] = pack64v (tmps, opad64, gid, 3);
  opad[4] = pack64v (tmps, opad64, gid, 4);
  opad[5] = pack64v (tmps, opad64, gid, 5);
  opad[6] = pack64v (tmps, opad64, gid, 6);
  opad[7] = pack64v (tmps, opad64, gid, 7);

  u32 key_size = luks_bufs[digests_offset].key_size;

  for (u32 i = 0; i < ((key_size / 8) / 4); i += 16)
  {
    u64x dgst[8];
    u64x out[8];

    dgst[0] = pack64v (tmps, dgst64, gid, i + 0);
    dgst[1] = pack64v (tmps, dgst64, gid, i + 1);
    dgst[2] = pack64v (tmps, dgst64, gid, i + 2);
    dgst[3] = pack64v (tmps, dgst64, gid, i + 3);
    dgst[4] = pack64v (tmps, dgst64, gid, i + 4);
    dgst[5] = pack64v (tmps, dgst64, gid, i + 5);
    dgst[6] = pack64v (tmps, dgst64, gid, i + 6);
    dgst[7] = pack64v (tmps, dgst64, gid, i + 7);

    out[0] = pack64v (tmps, out64, gid, i + 0);
    out[1] = pack64v (tmps, out64, gid, i + 1);
    out[2] = pack64v (tmps, out64, gid, i + 2);
    out[3] = pack64v (tmps, out64, gid, i + 3);
    out[4] = pack64v (tmps, out64, gid, i + 4);
    out[5] = pack64v (tmps, out64, gid, i + 5);
    out[6] = pack64v (tmps, out64, gid, i + 6);
    out[7] = pack64v (tmps, out64, gid, i + 7);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u64x w0[4];
      u64x w1[4];
      u64x w2[4];
      u64x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x8000000000000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (128 + 64) * 8;

      hmac_sha512_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpackv (tmps, dgst64, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst64, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst64, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst64, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst64, gid, i + 4, dgst[4]);
    unpackv (tmps, dgst64, gid, i + 5, dgst[5]);
    unpackv (tmps, dgst64, gid, i + 6, dgst[6]);
    unpackv (tmps, dgst64, gid, i + 7, dgst[7]);

    unpackv (tmps, out64, gid, i + 0, out[0]);
    unpackv (tmps, out64, gid, i + 1, out[1]);
    unpackv (tmps, out64, gid, i + 2, out[2]);
    unpackv (tmps, out64, gid, i + 3, out[3]);
    unpackv (tmps, out64, gid, i + 4, out[4]);
    unpackv (tmps, out64, gid, i + 5, out[5]);
    unpackv (tmps, out64, gid, i + 6, out[6]);
    unpackv (tmps, out64, gid, i + 7, out[7]);
  }
}

__kernel void m14632_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global luks_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global luks_t *luks_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  // decrypt AF with first pbkdf2 result
  // merge AF to masterkey
  // decrypt first payload sector with masterkey

  u32 pt_buf[128];

  luks_af_sha512_then_serpent_decrypt (&luks_bufs[digests_offset], &tmps[gid], pt_buf);

  // check entropy

  const float entropy = get_entropy (pt_buf, 128);

  if (entropy < MAX_ENTROPY)
  {
    mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
  }
}
