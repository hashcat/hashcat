/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"
#endif

DECLSPEC void sha512_transform_opt (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u64x *digest)
{
  u32x wend = 0x80000000;
  u32x wlen = 64*8;

  u64x w0_t = hl32_to_64 (w0[0], w0[1]);
  u64x w1_t = hl32_to_64 (w0[2], w0[3]);
  u64x w2_t = hl32_to_64 (w1[0], w1[1]);
  u64x w3_t = hl32_to_64 (w1[2], w1[3]);
  u64x w4_t = hl32_to_64 (w2[0], w2[1]);
  u64x w5_t = hl32_to_64 (w2[2], w2[3]);
  u64x w6_t = hl32_to_64 (w3[0], w3[1]);
  u64x w7_t = hl32_to_64 (w3[2], w3[3]);
  u64x w8_t = hl32_to_64 (wend, 0);
  u64x w9_t = 0;
  u64x wa_t = 0;
  u64x wb_t = 0;
  u64x wc_t = 0;
  u64x wd_t = 0;
  u64x we_t = 0;
  u64x wf_t = hl32_to_64 (0, wlen);

  u64x a = digest[0];
  u64x b = digest[1];
  u64x c = digest[2];
  u64x d = digest[3];
  u64x e = digest[4];
  u64x f = digest[5];
  u64x g = digest[6];
  u64x h = digest[7];

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

  #ifdef IS_CUDA
  ROUND_EXPAND (); ROUND_STEP (16);
  ROUND_EXPAND (); ROUND_STEP (32);
  ROUND_EXPAND (); ROUND_STEP (48);
  ROUND_EXPAND (); ROUND_STEP (64);
  #else
  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }
  #endif

  /* rev
  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
  */

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
  digest[5] = f;
  digest[6] = g;
  digest[7] = h;
}

KERNEL_FQ void m21000_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sha512
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];
    u32x w4_t[4];
    u32x w5_t[4];
    u32x w6_t[4];
    u32x w7_t[4];

    w0_t[0] = hc_swap32 (w0[0]);
    w0_t[1] = hc_swap32 (w0[1]);
    w0_t[2] = hc_swap32 (w0[2]);
    w0_t[3] = hc_swap32 (w0[3]);
    w1_t[0] = hc_swap32 (w1[0]);
    w1_t[1] = hc_swap32 (w1[1]);
    w1_t[2] = hc_swap32 (w1[2]);
    w1_t[3] = hc_swap32 (w1[3]);
    w2_t[0] = hc_swap32 (w2[0]);
    w2_t[1] = hc_swap32 (w2[1]);
    w2_t[2] = hc_swap32 (w2[2]);
    w2_t[3] = hc_swap32 (w2[3]);
    w3_t[0] = hc_swap32 (w3[0]);
    w3_t[1] = hc_swap32 (w3[1]);
    w3_t[2] = 0;
    w3_t[3] = 0;
    w4_t[0] = 0;
    w4_t[1] = 0;
    w4_t[2] = 0;
    w4_t[3] = 0;
    w5_t[0] = 0;
    w5_t[1] = 0;
    w5_t[2] = 0;
    w5_t[3] = 0;
    w6_t[0] = 0;
    w6_t[1] = 0;
    w6_t[2] = 0;
    w6_t[3] = 0;
    w7_t[0] = 0;
    w7_t[1] = 0;
    w7_t[2] = 0;
    w7_t[3] = out_len * 8;

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_vector (w0_t, w1_t, w2_t, w3_t, w4_t, w5_t, w6_t, w7_t, digest);

    w0_t[0] = h32_from_64 (digest[0]);
    w0_t[1] = l32_from_64 (digest[0]);
    w0_t[2] = h32_from_64 (digest[1]);
    w0_t[3] = l32_from_64 (digest[1]);
    w1_t[0] = h32_from_64 (digest[2]);
    w1_t[1] = l32_from_64 (digest[2]);
    w1_t[2] = h32_from_64 (digest[3]);
    w1_t[3] = l32_from_64 (digest[3]);
    w2_t[0] = h32_from_64 (digest[4]);
    w2_t[1] = l32_from_64 (digest[4]);
    w2_t[2] = h32_from_64 (digest[5]);
    w2_t[3] = l32_from_64 (digest[5]);
    w3_t[0] = h32_from_64 (digest[6]);
    w3_t[1] = l32_from_64 (digest[6]);
    w3_t[2] = h32_from_64 (digest[7]);
    w3_t[3] = l32_from_64 (digest[7]);

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_opt (w0_t, w1_t, w2_t, w3_t, digest);

    const u32x r0 = l32_from_64 (digest[7]);
    const u32x r1 = h32_from_64 (digest[7]);
    const u32x r2 = l32_from_64 (digest[3]);
    const u32x r3 = h32_from_64 (digest[3]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m21000_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21000_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21000_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

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

  const u32 pw_len = pws[gid].pw_len & 63;

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
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sha512
     */

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];
    u32x w4_t[4];
    u32x w5_t[4];
    u32x w6_t[4];
    u32x w7_t[4];

    w0_t[0] = hc_swap32 (w0[0]);
    w0_t[1] = hc_swap32 (w0[1]);
    w0_t[2] = hc_swap32 (w0[2]);
    w0_t[3] = hc_swap32 (w0[3]);
    w1_t[0] = hc_swap32 (w1[0]);
    w1_t[1] = hc_swap32 (w1[1]);
    w1_t[2] = hc_swap32 (w1[2]);
    w1_t[3] = hc_swap32 (w1[3]);
    w2_t[0] = hc_swap32 (w2[0]);
    w2_t[1] = hc_swap32 (w2[1]);
    w2_t[2] = hc_swap32 (w2[2]);
    w2_t[3] = hc_swap32 (w2[3]);
    w3_t[0] = hc_swap32 (w3[0]);
    w3_t[1] = hc_swap32 (w3[1]);
    w3_t[2] = 0;
    w3_t[3] = 0;
    w4_t[0] = 0;
    w4_t[1] = 0;
    w4_t[2] = 0;
    w4_t[3] = 0;
    w5_t[0] = 0;
    w5_t[1] = 0;
    w5_t[2] = 0;
    w5_t[3] = 0;
    w6_t[0] = 0;
    w6_t[1] = 0;
    w6_t[2] = 0;
    w6_t[3] = 0;
    w7_t[0] = 0;
    w7_t[1] = 0;
    w7_t[2] = 0;
    w7_t[3] = out_len * 8;

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_vector (w0_t, w1_t, w2_t, w3_t, w4_t, w5_t, w6_t, w7_t, digest);

    w0_t[0] = h32_from_64 (digest[0]);
    w0_t[1] = l32_from_64 (digest[0]);
    w0_t[2] = h32_from_64 (digest[1]);
    w0_t[3] = l32_from_64 (digest[1]);
    w1_t[0] = h32_from_64 (digest[2]);
    w1_t[1] = l32_from_64 (digest[2]);
    w1_t[2] = h32_from_64 (digest[3]);
    w1_t[3] = l32_from_64 (digest[3]);
    w2_t[0] = h32_from_64 (digest[4]);
    w2_t[1] = l32_from_64 (digest[4]);
    w2_t[2] = h32_from_64 (digest[5]);
    w2_t[3] = l32_from_64 (digest[5]);
    w3_t[0] = h32_from_64 (digest[6]);
    w3_t[1] = l32_from_64 (digest[6]);
    w3_t[2] = h32_from_64 (digest[7]);
    w3_t[3] = l32_from_64 (digest[7]);

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_opt (w0_t, w1_t, w2_t, w3_t, digest);

    const u32x r0 = l32_from_64 (digest[7]);
    const u32x r1 = h32_from_64 (digest[7]);
    const u32x r2 = l32_from_64 (digest[3]);
    const u32x r3 = h32_from_64 (digest[3]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m21000_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21000_s16 (KERN_ATTR_RULES ())
{
}
