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

#define SHA256_S0_S(x) (rotl32_S ((x), 25u) ^ rotl32_S ((x), 14u) ^ SHIFT_RIGHT_32 ((x),  3u))
#define SHA256_S1_S(x) (rotl32_S ((x), 15u) ^ rotl32_S ((x), 13u) ^ SHIFT_RIGHT_32 ((x), 10u))

#define SHA256_EXPAND_S(x,y,z,w) (SHA256_S1_S (x) + y + SHA256_S0_S (z) + w)

DECLSPEC void sha256_transform (u32x *digest, const u32x *w)
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

DECLSPEC void sha256_transform_z (u32x *digest)
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];
  u32x e = digest[4];
  u32x f = digest[5];
  u32x g = digest[6];
  u32x h = digest[7];

  #define ROUND_STEP_Z(i)                                                                 \
  {                                                                                       \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, 0, k_sha256[i +  0]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, 0, k_sha256[i +  1]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, 0, k_sha256[i +  2]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, 0, k_sha256[i +  3]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, 0, k_sha256[i +  4]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, 0, k_sha256[i +  5]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, 0, k_sha256[i +  6]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, 0, k_sha256[i +  7]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, 0, k_sha256[i +  8]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, 0, k_sha256[i +  9]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, 0, k_sha256[i + 10]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, 0, k_sha256[i + 11]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, 0, k_sha256[i + 12]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, 0, k_sha256[i + 13]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, 0, k_sha256[i + 14]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, 0, k_sha256[i + 15]); \
  }

  ROUND_STEP_Z (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
  {
    ROUND_STEP_Z (i);
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

DECLSPEC void sha256_transform_s (u32x *digest, __local u32 *w)
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];
  u32x e = digest[4];
  u32x f = digest[5];
  u32x g = digest[6];
  u32x h = digest[7];

  #define ROUND_STEP_S(i)                                                                      \
  {                                                                                            \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w[i +  0], k_sha256[i +  0]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w[i +  1], k_sha256[i +  1]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w[i +  2], k_sha256[i +  2]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w[i +  3], k_sha256[i +  3]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w[i +  4], k_sha256[i +  4]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w[i +  5], k_sha256[i +  5]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w[i +  6], k_sha256[i +  6]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w[i +  7], k_sha256[i +  7]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w[i +  8], k_sha256[i +  8]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w[i +  9], k_sha256[i +  9]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w[i + 10], k_sha256[i + 10]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w[i + 11], k_sha256[i + 11]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w[i + 12], k_sha256[i + 12]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w[i + 13], k_sha256[i + 13]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w[i + 14], k_sha256[i + 14]); \
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w[i + 15], k_sha256[i + 15]); \
  }

  ROUND_STEP_S (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
  {
    ROUND_STEP_S (i);
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

__kernel void m08000_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  const u32 salt_buf0 = swap32_S (salt_bufs[salt_pos].salt_buf[ 0]);
  const u32 salt_buf1 = swap32_S (salt_bufs[salt_pos].salt_buf[ 1]);
  const u32 salt_buf2 = swap32_S (salt_bufs[salt_pos].salt_buf[ 2]); // 0x80

  /**
   * precompute final msg blocks
   */

  __local u32 w_s1[64];
  __local u32 w_s2[64];

  for (MAYBE_VOLATILE u32 i = lid; i < 64; i += lsz)
  {
    w_s1[i] = 0;
    w_s2[i] = 0;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (lid == 0)
  {
    w_s1[15] =               0 | salt_buf0 >> 16;

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 16; i < 64; i++)
    {
      w_s1[i] = SHA256_EXPAND_S (w_s1[i - 2], w_s1[i - 7], w_s1[i - 15], w_s1[i - 16]);
    }

    w_s2[ 0] = salt_buf0 << 16 | salt_buf1 >> 16;
    w_s2[ 1] = salt_buf1 << 16 | salt_buf2 >> 16;
    w_s2[ 2] = salt_buf2 << 16 | 0;
    w_s2[15] = (510 + 8) * 8;

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 16; i < 64; i++)
    {
      w_s2[i] = SHA256_EXPAND_S (w_s2[i - 2], w_s2[i - 7], w_s2[i - 15], w_s2[i - 16]);
    }
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    /**
     * SHA256
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_utf16le (w0, w0_t, w1_t);
    make_utf16le (w1, w2_t, w3_t);

    u32x w_t[16];

    w_t[ 0] = swap32 (w0_t[0]);
    w_t[ 1] = swap32 (w0_t[1]);
    w_t[ 2] = swap32 (w0_t[2]);
    w_t[ 3] = swap32 (w0_t[3]);
    w_t[ 4] = swap32 (w1_t[0]);
    w_t[ 5] = swap32 (w1_t[1]);
    w_t[ 6] = swap32 (w1_t[2]);
    w_t[ 7] = swap32 (w1_t[3]);
    w_t[ 8] = swap32 (w2_t[0]);
    w_t[ 9] = swap32 (w2_t[1]);
    w_t[10] = swap32 (w2_t[2]);
    w_t[11] = swap32 (w2_t[3]);
    w_t[12] = swap32 (w3_t[0]);
    w_t[13] = swap32 (w3_t[1]);
    w_t[14] = swap32 (w3_t[2]);
    w_t[15] = swap32 (w3_t[3]);

    w_t[ 0] = w_t[ 0] >> 8;
    w_t[ 1] = w_t[ 1] >> 8;
    w_t[ 2] = w_t[ 2] >> 8;
    w_t[ 3] = w_t[ 3] >> 8;
    w_t[ 4] = w_t[ 4] >> 8;
    w_t[ 5] = w_t[ 5] >> 8;
    w_t[ 6] = w_t[ 6] >> 8;
    w_t[ 7] = w_t[ 7] >> 8;
    w_t[ 8] = w_t[ 8] >> 8;
    w_t[ 9] = w_t[ 9] >> 8;
    w_t[10] = w_t[10] >> 8;
    w_t[11] = w_t[11] >> 8;
    w_t[12] = w_t[12] >> 8;
    w_t[13] = w_t[13] >> 8;
    w_t[14] = w_t[14] >> 8;
    w_t[15] = w_t[15] >> 8;

    u32x digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform   (digest, w_t);   //   0 -  64
    sha256_transform_z (digest);        //  64 - 128
    sha256_transform_z (digest);        // 128 - 192
    sha256_transform_z (digest);        // 192 - 256
    sha256_transform_z (digest);        // 256 - 320
    sha256_transform_z (digest);        // 320 - 384
    sha256_transform_z (digest);        // 384 - 448
    sha256_transform_s (digest, w_s1);  // 448 - 512
    sha256_transform_s (digest, w_s2);  // 512 - 576

    COMPARE_M_SIMD (digest[3], digest[7], digest[2], digest[6]);
  }
}

__kernel void m08000_m08 (KERN_ATTR_BASIC ())
{
}

__kernel void m08000_m16 (KERN_ATTR_BASIC ())
{
}

__kernel void m08000_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * salt
   */

  const u32 salt_buf0 = swap32_S (salt_bufs[salt_pos].salt_buf[ 0]);
  const u32 salt_buf1 = swap32_S (salt_bufs[salt_pos].salt_buf[ 1]);
  const u32 salt_buf2 = swap32_S (salt_bufs[salt_pos].salt_buf[ 2]); // 0x80

  /**
   * precompute final msg blocks
   */

  __local u32 w_s1[64];
  __local u32 w_s2[64];

  for (MAYBE_VOLATILE u32 i = lid; i < 64; i += lsz)
  {
    w_s1[i] = 0;
    w_s2[i] = 0;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (lid == 0)
  {
    w_s1[15] =               0 | salt_buf0 >> 16;

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 16; i < 64; i++)
    {
      w_s1[i] = SHA256_EXPAND_S (w_s1[i - 2], w_s1[i - 7], w_s1[i - 15], w_s1[i - 16]);
    }

    w_s2[ 0] = salt_buf0 << 16 | salt_buf1 >> 16;
    w_s2[ 1] = salt_buf1 << 16 | salt_buf2 >> 16;
    w_s2[ 2] = salt_buf2 << 16 | 0;
    w_s2[15] = (510 + 8) * 8;

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 16; i < 64; i++)
    {
      w_s2[i] = SHA256_EXPAND_S (w_s2[i - 2], w_s2[i - 7], w_s2[i - 15], w_s2[i - 16]);
    }
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

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

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];

    /**
     * SHA256
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_utf16le (w0, w0_t, w1_t);
    make_utf16le (w1, w2_t, w3_t);

    u32x w_t[16];

    w_t[ 0] = swap32 (w0_t[0]);
    w_t[ 1] = swap32 (w0_t[1]);
    w_t[ 2] = swap32 (w0_t[2]);
    w_t[ 3] = swap32 (w0_t[3]);
    w_t[ 4] = swap32 (w1_t[0]);
    w_t[ 5] = swap32 (w1_t[1]);
    w_t[ 6] = swap32 (w1_t[2]);
    w_t[ 7] = swap32 (w1_t[3]);
    w_t[ 8] = swap32 (w2_t[0]);
    w_t[ 9] = swap32 (w2_t[1]);
    w_t[10] = swap32 (w2_t[2]);
    w_t[11] = swap32 (w2_t[3]);
    w_t[12] = swap32 (w3_t[0]);
    w_t[13] = swap32 (w3_t[1]);
    w_t[14] = swap32 (w3_t[2]);
    w_t[15] = swap32 (w3_t[3]);

    w_t[ 0] = w_t[ 0] >> 8;
    w_t[ 1] = w_t[ 1] >> 8;
    w_t[ 2] = w_t[ 2] >> 8;
    w_t[ 3] = w_t[ 3] >> 8;
    w_t[ 4] = w_t[ 4] >> 8;
    w_t[ 5] = w_t[ 5] >> 8;
    w_t[ 6] = w_t[ 6] >> 8;
    w_t[ 7] = w_t[ 7] >> 8;
    w_t[ 8] = w_t[ 8] >> 8;
    w_t[ 9] = w_t[ 9] >> 8;
    w_t[10] = w_t[10] >> 8;
    w_t[11] = w_t[11] >> 8;
    w_t[12] = w_t[12] >> 8;
    w_t[13] = w_t[13] >> 8;
    w_t[14] = w_t[14] >> 8;
    w_t[15] = w_t[15] >> 8;

    u32x digest[8];

    digest[0] = SHA256M_A;
    digest[1] = SHA256M_B;
    digest[2] = SHA256M_C;
    digest[3] = SHA256M_D;
    digest[4] = SHA256M_E;
    digest[5] = SHA256M_F;
    digest[6] = SHA256M_G;
    digest[7] = SHA256M_H;

    sha256_transform   (digest, w_t);   //   0 -  64
    sha256_transform_z (digest);        //  64 - 128
    sha256_transform_z (digest);        // 128 - 192
    sha256_transform_z (digest);        // 192 - 256
    sha256_transform_z (digest);        // 256 - 320
    sha256_transform_z (digest);        // 320 - 384
    sha256_transform_z (digest);        // 384 - 448
    sha256_transform_s (digest, w_s1);  // 448 - 512
    sha256_transform_s (digest, w_s2);  // 512 - 576

    COMPARE_S_SIMD (digest[3], digest[7], digest[2], digest[6]);
  }
}

__kernel void m08000_s08 (KERN_ATTR_BASIC ())
{
}

__kernel void m08000_s16 (KERN_ATTR_BASIC ())
{
}
