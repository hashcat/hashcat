/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_hash_md5.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define md5crypt_magic 0x00243124u

DECLSPEC void md5_transform_transport (const u32 *w, u32 *digest)
{
  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  t0[0] = w[ 0];
  t0[1] = w[ 1];
  t0[2] = w[ 2];
  t0[3] = w[ 3];
  t1[0] = w[ 4];
  t1[1] = w[ 5];
  t1[2] = w[ 6];
  t1[3] = w[ 7];
  t2[0] = w[ 8];
  t2[1] = w[ 9];
  t2[2] = w[10];
  t2[3] = w[11];
  t3[0] = w[12];
  t3[1] = w[13];
  t3[2] = w[14];
  t3[3] = w[15];

  md5_transform (t0, t1, t2, t3, digest);
}

__kernel void m00500_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global md5crypt_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[salt_pos].salt_buf[idx];
  }

  /**
   * prepare
   */

  md5_ctx_t md5_ctx1;

  md5_init (&md5_ctx1);

  md5_update (&md5_ctx1, w, pw_len);

  md5_update (&md5_ctx1, s, salt_len);

  md5_update (&md5_ctx1, w, pw_len);

  md5_final (&md5_ctx1);

  u32 final[16] = { 0 };

  final[0] = md5_ctx1.h[0];
  final[1] = md5_ctx1.h[1];
  final[2] = md5_ctx1.h[2];
  final[3] = md5_ctx1.h[3];

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update (&md5_ctx, w, pw_len);

  u32 m[16] = { 0 };

  m[0] = md5crypt_magic;

  md5_update (&md5_ctx, m, 3);

  md5_update (&md5_ctx, s, salt_len);

  int pl;

  for (pl = pw_len; pl > 16; pl -= 16)
  {
    md5_update (&md5_ctx, final, 16);
  }

  truncate_block_4x4_le_S (final, pl);

  md5_update (&md5_ctx, final, pl);

  /* Then something really weird... */

  for (int i = pw_len; i != 0; i >>= 1)
  {
    u32 t[16] = { 0 };

    if (i & 1)
    {
      t[0] = 0;
    }
    else
    {
      t[0] = w[0] & 0xff;
    }

    md5_update (&md5_ctx, t, 1);
  }

  md5_final (&md5_ctx);

  tmps[gid].digest_buf[0] = md5_ctx.h[0];
  tmps[gid].digest_buf[1] = md5_ctx.h[1];
  tmps[gid].digest_buf[2] = md5_ctx.h[2];
  tmps[gid].digest_buf[3] = md5_ctx.h[3];
}

__kernel void m00500_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global md5crypt_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * init
   */

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };

  for (int i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = salt_bufs[salt_pos].salt_buf[idx];
  }

  /**
   * digest
   */

  u32 digest[4];

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  u32 wpc_len[8];

  wpc_len[0] = 16     +        0 +      0 + pw_len;
  wpc_len[1] = pw_len +        0 +      0 + 16;
  wpc_len[2] = 16     + salt_len +      0 + pw_len;
  wpc_len[3] = pw_len + salt_len +      0 + 16;
  wpc_len[4] = 16     +        0 + pw_len + pw_len;
  wpc_len[5] = pw_len +        0 + pw_len + 16;
  wpc_len[6] = 16     + salt_len + pw_len + pw_len;
  wpc_len[7] = pw_len + salt_len + pw_len + 16;

  // largest possible wpc_len[7] is not enough because of zero buffer loop

  u32 wpc[8][64 + 64 + 64 + 64];

  #define PUTCHAR_LE(a,p,c) ((u8 *)(a))[(p)] = (u8) (c)
  #define GETCHAR_LE(a,p)   ((u8 *)(a))[(p)]

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 8; i++)
  {
    u32 block_len = 0;

    if (i & 1)
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR_LE (wpc[i], block_len++, GETCHAR_LE (w, j));
      }
    }
    else
    {
      block_len += 16;
    }

    if (i & 2)
    {
      for (u32 j = 0; j < salt_len; j++)
      {
        PUTCHAR_LE (wpc[i], block_len++, GETCHAR_LE (s, j));
      }
    }

    if (i & 4)
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR_LE (wpc[i], block_len++, GETCHAR_LE (w, j));
      }
    }

    if (i & 1)
    {
      block_len += 16;
    }
    else
    {
      for (u32 j = 0; j < pw_len; j++)
      {
        PUTCHAR_LE (wpc[i], block_len++, GETCHAR_LE (w, j));
      }
    }
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 8; i++)
  {
    u32 *z = wpc[i] + ((wpc_len[i] / 64) * 16);

    truncate_block_16x4_le_S (z + 0, z + 4, z + 8, z + 12, wpc_len[i] & 63);
  }

  /**
   * loop
   */

  for (u32 i = 0, j = loop_pos; i < loop_cnt; i++, j++)
  {
    const u32 j1 = (j & 1) ? 1 : 0;
    const u32 j3 = (j % 3) ? 2 : 0;
    const u32 j7 = (j % 7) ? 4 : 0;

    const u32 pc = j1 + j3 + j7;

    if (j1)
    {
      #ifdef _unroll
      #pragma unroll
      #endif
      for (u32 k = 0, p = wpc_len[pc] - 16; k < 16; k++, p++)
      {
        PUTCHAR_LE (wpc[pc], p, GETCHAR_LE (digest, k));
      }
    }
    else
    {
      wpc[pc][0] = digest[0];
      wpc[pc][1] = digest[1];
      wpc[pc][2] = digest[2];
      wpc[pc][3] = digest[3];
    }

    md5_ctx_t md5_ctx;

    md5_init (&md5_ctx);

    md5_update (&md5_ctx, wpc[pc], wpc_len[pc]);

    md5_final (&md5_ctx);

    digest[0] = md5_ctx.h[0];
    digest[1] = md5_ctx.h[1];
    digest[2] = md5_ctx.h[2];
    digest[3] = md5_ctx.h[3];
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

__kernel void m00500_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global md5crypt_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 r0 = tmps[gid].digest_buf[DGST_R0];
  const u32 r1 = tmps[gid].digest_buf[DGST_R1];
  const u32 r2 = tmps[gid].digest_buf[DGST_R2];
  const u32 r3 = tmps[gid].digest_buf[DGST_R3];

  #define il_pos 0

  #include COMPARE_M
}
