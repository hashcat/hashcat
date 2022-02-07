/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

DECLSPEC void sha256_transform_m (PRIVATE_AS u32x *digest, PRIVATE_AS const u32x *w)
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

  #if defined IS_CUDA
  ROUND_EXPAND (); ROUND_STEP (16);
  ROUND_EXPAND (); ROUND_STEP (32);
  ROUND_EXPAND (); ROUND_STEP (48);
  #else
  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }
  #endif

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

DECLSPEC void sha256_transform_z (PRIVATE_AS u32x *digest)
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

  #if defined IS_CUDA
  ROUND_STEP_Z (16);
  ROUND_STEP_Z (32);
  ROUND_STEP_Z (48);
  #else
  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
  {
    ROUND_STEP_Z (i);
  }
  #endif

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

DECLSPEC void sha256_transform_s (PRIVATE_AS u32x *digest, LOCAL_AS u32 *w)
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

KERNEL_FQ void m08000_m04 (KERN_ATTR_RULES ())
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

  const u32 salt_buf0 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 0]);
  const u32 salt_buf1 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 1]);
  const u32 salt_buf2 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 2]); // 0x80

  /**
   * precompute final msg blocks
   */

  LOCAL_VK u32 w_s1[64];
  LOCAL_VK u32 w_s2[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    w_s1[i] = 0;
    w_s2[i] = 0;
  }

  SYNC_THREADS ();

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

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_utf16le (w0, w0_t, w1_t);
    make_utf16le (w1, w2_t, w3_t);

    u32x w_t[16];

    w_t[ 0] = hc_swap32 (w0_t[0]);
    w_t[ 1] = hc_swap32 (w0_t[1]);
    w_t[ 2] = hc_swap32 (w0_t[2]);
    w_t[ 3] = hc_swap32 (w0_t[3]);
    w_t[ 4] = hc_swap32 (w1_t[0]);
    w_t[ 5] = hc_swap32 (w1_t[1]);
    w_t[ 6] = hc_swap32 (w1_t[2]);
    w_t[ 7] = hc_swap32 (w1_t[3]);
    w_t[ 8] = hc_swap32 (w2_t[0]);
    w_t[ 9] = hc_swap32 (w2_t[1]);
    w_t[10] = hc_swap32 (w2_t[2]);
    w_t[11] = hc_swap32 (w2_t[3]);
    w_t[12] = hc_swap32 (w3_t[0]);
    w_t[13] = hc_swap32 (w3_t[1]);
    w_t[14] = hc_swap32 (w3_t[2]);
    w_t[15] = hc_swap32 (w3_t[3]);

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

    sha256_transform_m   (digest, w_t);   //   0 -  64
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

KERNEL_FQ void m08000_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m08000_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m08000_s04 (KERN_ATTR_RULES ())
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

  const u32 salt_buf0 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 0]);
  const u32 salt_buf1 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 1]);
  const u32 salt_buf2 = hc_swap32_S (salt_bufs[SALT_POS_HOST].salt_buf[ 2]); // 0x80

  /**
   * precompute final msg blocks
   */

  LOCAL_VK u32 w_s1[64];
  LOCAL_VK u32 w_s2[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    w_s1[i] = 0;
    w_s2[i] = 0;
  }

  SYNC_THREADS ();

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

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_utf16le (w0, w0_t, w1_t);
    make_utf16le (w1, w2_t, w3_t);

    u32x w_t[16];

    w_t[ 0] = hc_swap32 (w0_t[0]);
    w_t[ 1] = hc_swap32 (w0_t[1]);
    w_t[ 2] = hc_swap32 (w0_t[2]);
    w_t[ 3] = hc_swap32 (w0_t[3]);
    w_t[ 4] = hc_swap32 (w1_t[0]);
    w_t[ 5] = hc_swap32 (w1_t[1]);
    w_t[ 6] = hc_swap32 (w1_t[2]);
    w_t[ 7] = hc_swap32 (w1_t[3]);
    w_t[ 8] = hc_swap32 (w2_t[0]);
    w_t[ 9] = hc_swap32 (w2_t[1]);
    w_t[10] = hc_swap32 (w2_t[2]);
    w_t[11] = hc_swap32 (w2_t[3]);
    w_t[12] = hc_swap32 (w3_t[0]);
    w_t[13] = hc_swap32 (w3_t[1]);
    w_t[14] = hc_swap32 (w3_t[2]);
    w_t[15] = hc_swap32 (w3_t[3]);

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

    sha256_transform_m   (digest, w_t);   //   0 -  64
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

KERNEL_FQ void m08000_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m08000_s16 (KERN_ATTR_RULES ())
{
}
