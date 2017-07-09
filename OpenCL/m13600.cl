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
#include "inc_hash_sha1.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

void hmac_sha1_run_V (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[5], u32x opad[5], u32x digest[5])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

__kernel void m13600_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global pbkdf2_sha1_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const zip2_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];
  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];
  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];
  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init (&sha1_hmac_ctx, w0, w1, w2, w3);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, esalt_bufs[digests_offset].salt_buf, esalt_bufs[digests_offset].salt_len);

  const u32 mode = esalt_bufs[digests_offset].mode;

  u32 iter_start;
  u32 iter_stop;
  u32 count_start;

  switch (mode)
  {
    case 1: iter_start  = 0;
            iter_stop   = 2;
            count_start = 1;
            break;
    case 2: iter_start  = 1;
            iter_stop   = 3;
            count_start = 2;
            break;
    case 3: iter_start  = 1;
            iter_stop   = 4;
            count_start = 2;
            break;
  }

  for (u32 i = iter_start, j = count_start; i < iter_stop; i++, j++)
  {
    const u32 i5 = i * 5;

    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

    w0[0] = j;
    w0[1] = 0;
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
    w3[3] = 0;

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    tmps[gid].dgst[i5 + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i5 + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i5 + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i5 + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i5 + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i5 + 0] = tmps[gid].dgst[i5 + 0];
    tmps[gid].out[i5 + 1] = tmps[gid].dgst[i5 + 1];
    tmps[gid].out[i5 + 2] = tmps[gid].dgst[i5 + 2];
    tmps[gid].out[i5 + 3] = tmps[gid].dgst[i5 + 3];
    tmps[gid].out[i5 + 4] = tmps[gid].dgst[i5 + 4];
  }
}

__kernel void m13600_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global pbkdf2_sha1_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const zip2_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 ipad[5];

  ipad[0] = tmps[gid].ipad[0];
  ipad[1] = tmps[gid].ipad[1];
  ipad[2] = tmps[gid].ipad[2];
  ipad[3] = tmps[gid].ipad[3];
  ipad[4] = tmps[gid].ipad[4];

  u32 opad[5];

  opad[0] = tmps[gid].opad[0];
  opad[1] = tmps[gid].opad[1];
  opad[2] = tmps[gid].opad[2];
  opad[3] = tmps[gid].opad[3];
  opad[4] = tmps[gid].opad[4];

  const u32 mode = esalt_bufs[digests_offset].mode;

  u32 iter_start;
  u32 iter_stop;
  u32 count_start;

  switch (mode)
  {
    case 1: iter_start  = 0;
            iter_stop   = 2;
            count_start = 1;
            break;
    case 2: iter_start  = 1;
            iter_stop   = 3;
            count_start = 2;
            break;
    case 3: iter_start  = 1;
            iter_stop   = 4;
            count_start = 2;
            break;
  }

  for (u32 i = iter_start, j = count_start; i < iter_stop; i++, j++)
  {
    const u32 i5 = i * 5;

    u32 dgst[5];

    dgst[0] = tmps[gid].dgst[i5 + 0];
    dgst[1] = tmps[gid].dgst[i5 + 1];
    dgst[2] = tmps[gid].dgst[i5 + 2];
    dgst[3] = tmps[gid].dgst[i5 + 3];
    dgst[4] = tmps[gid].dgst[i5 + 4];

    u32 out[5];

    out[0] = tmps[gid].out[i5 + 0];
    out[1] = tmps[gid].out[i5 + 1];
    out[2] = tmps[gid].out[i5 + 2];
    out[3] = tmps[gid].out[i5 + 3];
    out[4] = tmps[gid].out[i5 + 4];

    for (u32 k = 0; k < loop_cnt; k++)
    {
      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    tmps[gid].dgst[i5 + 0] = dgst[0];
    tmps[gid].dgst[i5 + 1] = dgst[1];
    tmps[gid].dgst[i5 + 2] = dgst[2];
    tmps[gid].dgst[i5 + 3] = dgst[3];
    tmps[gid].dgst[i5 + 4] = dgst[4];

    tmps[gid].out[i5 + 0] = out[0];
    tmps[gid].out[i5 + 1] = out[1];
    tmps[gid].out[i5 + 2] = out[2];
    tmps[gid].out[i5 + 3] = out[3];
    tmps[gid].out[i5 + 4] = out[4];
  }
}

__kernel void m13600_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global pbkdf2_sha1_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const zip2_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32 lid = get_local_id (0);

  u32 key[8] = { 0 };

  const u32 mode = esalt_bufs[digests_offset].mode;

  u32 iter_start;
  u32 iter_stop;

  switch (mode)
  {
    case 1: iter_start = 4;
            iter_stop  = 8;
            break;
    case 2: iter_start = 6;
            iter_stop  = 12;
            break;
    case 3: iter_start = 8;
            iter_stop  = 16;
            break;
  }

  u32 i, j;
  for (i = iter_start, j = 0; i < iter_stop; i++, j++)
  {
    key[j] = tmps[gid].out[i];
  }

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = key[0];
  w0[1] = key[1];
  w0[2] = key[2];
  w0[3] = key[3];
  w1[0] = key[4];
  w1[1] = key[5];
  w1[2] = key[6];
  w1[3] = key[7];
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  u32 ipad[5];
  u32 opad[5];

  hmac_sha1_pad (w0, w1, w2, w3, ipad, opad);

  int data_len = esalt_bufs[digests_offset].data_len;

  int data_left;
  int data_off;

  for (data_left = data_len, data_off = 0; data_left >= 56; data_left -= 64, data_off += 16)
  {
    w0[0] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  0]);
    w0[1] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  1]);
    w0[2] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  2]);
    w0[3] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  3]);
    w1[0] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  4]);
    w1[1] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  5]);
    w1[2] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  6]);
    w1[3] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  7]);
    w2[0] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  8]);
    w2[1] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  9]);
    w2[2] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 10]);
    w2[3] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 11]);
    w3[0] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 12]);
    w3[1] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 13]);
    w3[2] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 14]);
    w3[3] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 15]);

    sha1_transform (w0, w1, w2, w3, ipad);
  }

  w0[0] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  0]);
  w0[1] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  1]);
  w0[2] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  2]);
  w0[3] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  3]);
  w1[0] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  4]);
  w1[1] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  5]);
  w1[2] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  6]);
  w1[3] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  7]);
  w2[0] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  8]);
  w2[1] = swap32 (esalt_bufs[digests_offset].data_buf[data_off +  9]);
  w2[2] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 10]);
  w2[3] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 11]);
  w3[0] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 12]);
  w3[1] = swap32 (esalt_bufs[digests_offset].data_buf[data_off + 13]);
  w3[2] = 0;
  w3[3] = (64 + data_len) * 8;

  u32 digest[5];

  hmac_sha1_run (w0, w1, w2, w3, ipad, opad, digest);

  const u32 r0 = swap32 (digest[0] & 0xffffffff);
  const u32 r1 = swap32 (digest[1] & 0xffffffff);
  const u32 r2 = swap32 (digest[2] & 0xffff0000);
  const u32 r3 = swap32 (digest[3] & 0x00000000);

  #define il_pos 0

  #include COMPARE_M
}
