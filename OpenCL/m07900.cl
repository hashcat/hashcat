/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_hash_sha512.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

void orig_sha512_transform (const u64 w[16], u64 dgst[8])
{
  u64 a = dgst[0];
  u64 b = dgst[1];
  u64 c = dgst[2];
  u64 d = dgst[3];
  u64 e = dgst[4];
  u64 f = dgst[5];
  u64 g = dgst[6];
  u64 h = dgst[7];

  u64 w0_t = w[ 0];
  u64 w1_t = w[ 1];
  u64 w2_t = w[ 2];
  u64 w3_t = w[ 3];
  u64 w4_t = w[ 4];
  u64 w5_t = w[ 5];
  u64 w6_t = w[ 6];
  u64 w7_t = w[ 7];
  u64 w8_t = w[ 8];
  u64 w9_t = w[ 9];
  u64 wa_t = w[10];
  u64 wb_t = w[11];
  u64 wc_t = w[12];
  u64 wd_t = w[13];
  u64 we_t = w[14];
  u64 wf_t = w[15];

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

  dgst[0] += a;
  dgst[1] += b;
  dgst[2] += c;
  dgst[3] += d;
  dgst[4] += e;
  dgst[5] += f;
  dgst[6] += g;
  dgst[7] += h;
}

__kernel void m07900_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global drupal7_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha512_ctx_t ctx;

  sha512_init (&ctx);

  sha512_update_global_swap (&ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  sha512_final (&ctx);

  tmps[gid].digest_buf[0] = ctx.h[0];
  tmps[gid].digest_buf[1] = ctx.h[1];
  tmps[gid].digest_buf[2] = ctx.h[2];
  tmps[gid].digest_buf[3] = ctx.h[3];
  tmps[gid].digest_buf[4] = ctx.h[4];
  tmps[gid].digest_buf[5] = ctx.h[5];
  tmps[gid].digest_buf[6] = ctx.h[6];
  tmps[gid].digest_buf[7] = ctx.h[7];
}

__kernel void m07900_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global drupal7_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  const u32 pw_lenv = ceil ((float) pw_len / 4);

  u32 w[64] = { 0 };

  for (int idx = 0; idx < pw_lenv; idx++)
  {
    w[idx] = pws[gid].i[idx];

    barrier (CLK_GLOBAL_MEM_FENCE);
  }

  for (int idx = 0; idx < pw_lenv; idx++)
  {
    w[idx] = swap32_S (w[idx]);
  }

  /**
   * load
   */

  u64 digest[8];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];
  digest[4] = tmps[gid].digest_buf[4];
  digest[5] = tmps[gid].digest_buf[5];
  digest[6] = tmps[gid].digest_buf[6];
  digest[7] = tmps[gid].digest_buf[7];

  /**
   * loop
   */

  sha512_ctx_t sha512_ctx;

  sha512_init (&sha512_ctx);

  sha512_ctx.w0[0] = h32_from_64_S (digest[0]);
  sha512_ctx.w0[1] = l32_from_64_S (digest[0]);
  sha512_ctx.w0[2] = h32_from_64_S (digest[1]);
  sha512_ctx.w0[3] = l32_from_64_S (digest[1]);
  sha512_ctx.w1[0] = h32_from_64_S (digest[2]);
  sha512_ctx.w1[1] = l32_from_64_S (digest[2]);
  sha512_ctx.w1[2] = h32_from_64_S (digest[3]);
  sha512_ctx.w1[3] = l32_from_64_S (digest[3]);
  sha512_ctx.w2[0] = h32_from_64_S (digest[4]);
  sha512_ctx.w2[1] = l32_from_64_S (digest[4]);
  sha512_ctx.w2[2] = h32_from_64_S (digest[5]);
  sha512_ctx.w2[3] = l32_from_64_S (digest[5]);
  sha512_ctx.w3[0] = h32_from_64_S (digest[6]);
  sha512_ctx.w3[1] = l32_from_64_S (digest[6]);
  sha512_ctx.w3[2] = h32_from_64_S (digest[7]);
  sha512_ctx.w3[3] = l32_from_64_S (digest[7]);

  sha512_ctx.len = 64;

  sha512_update (&sha512_ctx, w, pw_len);

  sha512_final (&sha512_ctx);

  digest[0] = sha512_ctx.h[0];
  digest[1] = sha512_ctx.h[1];
  digest[2] = sha512_ctx.h[2];
  digest[3] = sha512_ctx.h[3];
  digest[4] = sha512_ctx.h[4];
  digest[5] = sha512_ctx.h[5];
  digest[6] = sha512_ctx.h[6];
  digest[7] = sha512_ctx.h[7];

  if ((64 + pw_len + 1) >= 112)
  {
    for (u32 i = 1; i < loop_cnt; i++)
    {
      sha512_init (&sha512_ctx);

      sha512_ctx.w0[0] = h32_from_64_S (digest[0]);
      sha512_ctx.w0[1] = l32_from_64_S (digest[0]);
      sha512_ctx.w0[2] = h32_from_64_S (digest[1]);
      sha512_ctx.w0[3] = l32_from_64_S (digest[1]);
      sha512_ctx.w1[0] = h32_from_64_S (digest[2]);
      sha512_ctx.w1[1] = l32_from_64_S (digest[2]);
      sha512_ctx.w1[2] = h32_from_64_S (digest[3]);
      sha512_ctx.w1[3] = l32_from_64_S (digest[3]);
      sha512_ctx.w2[0] = h32_from_64_S (digest[4]);
      sha512_ctx.w2[1] = l32_from_64_S (digest[4]);
      sha512_ctx.w2[2] = h32_from_64_S (digest[5]);
      sha512_ctx.w2[3] = l32_from_64_S (digest[5]);
      sha512_ctx.w3[0] = h32_from_64_S (digest[6]);
      sha512_ctx.w3[1] = l32_from_64_S (digest[6]);
      sha512_ctx.w3[2] = h32_from_64_S (digest[7]);
      sha512_ctx.w3[3] = l32_from_64_S (digest[7]);

      sha512_ctx.len = 64;

      sha512_update (&sha512_ctx, w, pw_len);

      sha512_final (&sha512_ctx);

      digest[0] = sha512_ctx.h[0];
      digest[1] = sha512_ctx.h[1];
      digest[2] = sha512_ctx.h[2];
      digest[3] = sha512_ctx.h[3];
      digest[4] = sha512_ctx.h[4];
      digest[5] = sha512_ctx.h[5];
      digest[6] = sha512_ctx.h[6];
      digest[7] = sha512_ctx.h[7];
    }
  }
  else
  {
    for (u32 i = 1; i < loop_cnt; i++)
    {
      sha512_ctx.w0[0] = h32_from_64_S (digest[0]);
      sha512_ctx.w0[1] = l32_from_64_S (digest[0]);
      sha512_ctx.w0[2] = h32_from_64_S (digest[1]);
      sha512_ctx.w0[3] = l32_from_64_S (digest[1]);
      sha512_ctx.w1[0] = h32_from_64_S (digest[2]);
      sha512_ctx.w1[1] = l32_from_64_S (digest[2]);
      sha512_ctx.w1[2] = h32_from_64_S (digest[3]);
      sha512_ctx.w1[3] = l32_from_64_S (digest[3]);
      sha512_ctx.w2[0] = h32_from_64_S (digest[4]);
      sha512_ctx.w2[1] = l32_from_64_S (digest[4]);
      sha512_ctx.w2[2] = h32_from_64_S (digest[5]);
      sha512_ctx.w2[3] = l32_from_64_S (digest[5]);
      sha512_ctx.w3[0] = h32_from_64_S (digest[6]);
      sha512_ctx.w3[1] = l32_from_64_S (digest[6]);
      sha512_ctx.w3[2] = h32_from_64_S (digest[7]);
      sha512_ctx.w3[3] = l32_from_64_S (digest[7]);

      digest[0] = SHA512M_A;
      digest[1] = SHA512M_B;
      digest[2] = SHA512M_C;
      digest[3] = SHA512M_D;
      digest[4] = SHA512M_A;
      digest[5] = SHA512M_B;
      digest[6] = SHA512M_C;
      digest[7] = SHA512M_D;

      sha512_transform (sha512_ctx.w0, sha512_ctx.w1, sha512_ctx.w2, sha512_ctx.w3, sha512_ctx.w4, sha512_ctx.w5, sha512_ctx.w6, sha512_ctx.w7, digest);
    }
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
  tmps[gid].digest_buf[4] = digest[4];
  tmps[gid].digest_buf[5] = digest[5];
  tmps[gid].digest_buf[6] = digest[6];
  tmps[gid].digest_buf[7] = digest[7];
}

__kernel void m07900_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global drupal7_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = l32_from_64 (tmps[gid].digest_buf[0]);
  const u32 r1 = h32_from_64 (tmps[gid].digest_buf[0]);
  const u32 r2 = l32_from_64 (tmps[gid].digest_buf[1]);
  const u32 r3 = h32_from_64 (tmps[gid].digest_buf[1]);

  #define il_pos 0

  #include COMPARE_M
}
