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
#include "inc_hash_md5.cl"
#include "inc_hash_sha1.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

u8 hex_to_u8 (const u8 hex[2])
{
  u8 v = 0;

  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);

  return (v);
}

__kernel void m02501_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global wpapmk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const wpa_t *wpa_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 in[16];

  in[ 0] = pws[gid].i[ 0];
  in[ 1] = pws[gid].i[ 1];
  in[ 2] = pws[gid].i[ 2];
  in[ 3] = pws[gid].i[ 3];
  in[ 4] = pws[gid].i[ 4];
  in[ 5] = pws[gid].i[ 5];
  in[ 6] = pws[gid].i[ 6];
  in[ 7] = pws[gid].i[ 7];
  in[ 8] = pws[gid].i[ 8];
  in[ 9] = pws[gid].i[ 9];
  in[10] = pws[gid].i[10];
  in[11] = pws[gid].i[11];
  in[12] = pws[gid].i[12];
  in[13] = pws[gid].i[13];
  in[14] = pws[gid].i[14];
  in[15] = pws[gid].i[15];

  u8 *in_ptr = (u8 *) in;

  u32 out[8];

  u8 *out_ptr = (u8 *) out;

  for (int i = 0, j = 0; i < 32; i += 1, j += 2)
  {
    out_ptr[i] = hex_to_u8 (in_ptr + j);
  }

  tmps[gid].out[0] = swap32_S (out[0]);
  tmps[gid].out[1] = swap32_S (out[1]);
  tmps[gid].out[2] = swap32_S (out[2]);
  tmps[gid].out[3] = swap32_S (out[3]);
  tmps[gid].out[4] = swap32_S (out[4]);
  tmps[gid].out[5] = swap32_S (out[5]);
  tmps[gid].out[6] = swap32_S (out[6]);
  tmps[gid].out[7] = swap32_S (out[7]);
}

__kernel void m02501_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global wpapmk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const wpa_t *wpa_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;
}

__kernel void m02501_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const pw_t *combs_buf, __global const bf_t *bfs_buf, __global wpapmk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const wpa_t *wpa_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u64 gid_max)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 out[8];

  out[0] = tmps[gid].out[0];
  out[1] = tmps[gid].out[1];
  out[2] = tmps[gid].out[2];
  out[3] = tmps[gid].out[3];
  out[4] = tmps[gid].out[4];
  out[5] = tmps[gid].out[5];
  out[6] = tmps[gid].out[6];
  out[7] = tmps[gid].out[7];

  const u64 lid = get_local_id (0);

  const u32 digest_pos = loop_pos;

  const u32 digest_cur = digests_offset + digest_pos;

  __global const wpa_t *wpa = &wpa_bufs[digest_cur];

  u32 pke[32];

  pke[ 0] = wpa->pke[ 0];
  pke[ 1] = wpa->pke[ 1];
  pke[ 2] = wpa->pke[ 2];
  pke[ 3] = wpa->pke[ 3];
  pke[ 4] = wpa->pke[ 4];
  pke[ 5] = wpa->pke[ 5];
  pke[ 6] = wpa->pke[ 6];
  pke[ 7] = wpa->pke[ 7];
  pke[ 8] = wpa->pke[ 8];
  pke[ 9] = wpa->pke[ 9];
  pke[10] = wpa->pke[10];
  pke[11] = wpa->pke[11];
  pke[12] = wpa->pke[12];
  pke[13] = wpa->pke[13];
  pke[14] = wpa->pke[14];
  pke[15] = wpa->pke[15];
  pke[16] = wpa->pke[16];
  pke[17] = wpa->pke[17];
  pke[18] = wpa->pke[18];
  pke[19] = wpa->pke[19];
  pke[20] = wpa->pke[20];
  pke[21] = wpa->pke[21];
  pke[22] = wpa->pke[22];
  pke[23] = wpa->pke[23];
  pke[24] = wpa->pke[24];
  pke[25] = 0;
  pke[26] = 0;
  pke[27] = 0;
  pke[28] = 0;
  pke[29] = 0;
  pke[30] = 0;
  pke[31] = 0;

  u32 to;

  if (wpa->nonce_compare < 0)
  {
    to = pke[15] << 24
       | pke[16] >>  8;
  }
  else
  {
    to = pke[23] << 24
       | pke[24] >>  8;
  }

  const u32 nonce_error_corrections = wpa->nonce_error_corrections;

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    u32 t = to;

    t = swap32_S (t);

    t -= nonce_error_corrections / 2;
    t += nonce_error_correction;

    t = swap32_S (t);

    if (wpa->nonce_compare < 0)
    {
      pke[15] = (pke[15] & ~0x000000ff) | (t >> 24);
      pke[16] = (pke[16] & ~0xffffff00) | (t <<  8);
    }
    else
    {
      pke[23] = (pke[23] & ~0x000000ff) | (t >> 24);
      pke[24] = (pke[24] & ~0xffffff00) | (t <<  8);
    }

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = out[0];
    w0[1] = out[1];
    w0[2] = out[2];
    w0[3] = out[3];
    w1[0] = out[4];
    w1[1] = out[5];
    w1[2] = out[6];
    w1[3] = out[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_hmac_ctx_t ctx1;

    sha1_hmac_init_64 (&ctx1, w0, w1, w2, w3);

    sha1_hmac_update (&ctx1, pke, 100);

    sha1_hmac_final (&ctx1);

    u32 digest[4];

    digest[0] = ctx1.opad.h[0];
    digest[1] = ctx1.opad.h[1];
    digest[2] = ctx1.opad.h[2];
    digest[3] = ctx1.opad.h[3];

    if (wpa->keyver == 1)
    {
      u32 t0[4];
      u32 t1[4];
      u32 t2[4];
      u32 t3[4];

      t0[0] = swap32_S (digest[0]);
      t0[1] = swap32_S (digest[1]);
      t0[2] = swap32_S (digest[2]);
      t0[3] = swap32_S (digest[3]);
      t1[0] = 0;
      t1[1] = 0;
      t1[2] = 0;
      t1[3] = 0;
      t2[0] = 0;
      t2[1] = 0;
      t2[2] = 0;
      t2[3] = 0;
      t3[0] = 0;
      t3[1] = 0;
      t3[2] = 0;
      t3[3] = 0;

      md5_hmac_ctx_t ctx2;

      md5_hmac_init_64 (&ctx2, t0, t1, t2, t3);

      md5_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);

      md5_hmac_final (&ctx2);

      digest[0] = ctx2.opad.h[0];
      digest[1] = ctx2.opad.h[1];
      digest[2] = ctx2.opad.h[2];
      digest[3] = ctx2.opad.h[3];
    }
    else
    {
      u32 t0[4];
      u32 t1[4];
      u32 t2[4];
      u32 t3[4];

      t0[0] = digest[0];
      t0[1] = digest[1];
      t0[2] = digest[2];
      t0[3] = digest[3];
      t1[0] = 0;
      t1[1] = 0;
      t1[2] = 0;
      t1[3] = 0;
      t2[0] = 0;
      t2[1] = 0;
      t2[2] = 0;
      t2[3] = 0;
      t3[0] = 0;
      t3[1] = 0;
      t3[2] = 0;
      t3[3] = 0;

      sha1_hmac_ctx_t ctx2;

      sha1_hmac_init_64 (&ctx2, t0, t1, t2, t3);

      sha1_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);

      sha1_hmac_final (&ctx2);

      digest[0] = ctx2.opad.h[0];
      digest[1] = ctx2.opad.h[1];
      digest[2] = ctx2.opad.h[2];
      digest[3] = ctx2.opad.h[3];
    }

    /**
     * final compare
     */

    if ((digest[0] == wpa->keymic[0])
     && (digest[1] == wpa->keymic[1])
     && (digest[2] == wpa->keymic[2])
     && (digest[3] == wpa->keymic[3]))
    {
      if (atomic_inc (&hashes_shown[digest_cur]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, digest_cur, gid, 0);
      }
    }
  }

  // the same code again, but with BE order for the t++

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    u32 t = to;

    t -= nonce_error_corrections / 2;
    t += nonce_error_correction;

    if (t == to) continue; // we already had this checked in the LE loop

    if (wpa->nonce_compare < 0)
    {
      pke[15] = (pke[15] & ~0x000000ff) | (t >> 24);
      pke[16] = (pke[16] & ~0xffffff00) | (t <<  8);
    }
    else
    {
      pke[23] = (pke[23] & ~0x000000ff) | (t >> 24);
      pke[24] = (pke[24] & ~0xffffff00) | (t <<  8);
    }

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = out[0];
    w0[1] = out[1];
    w0[2] = out[2];
    w0[3] = out[3];
    w1[0] = out[4];
    w1[1] = out[5];
    w1[2] = out[6];
    w1[3] = out[7];
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha1_hmac_ctx_t ctx1;

    sha1_hmac_init_64 (&ctx1, w0, w1, w2, w3);

    sha1_hmac_update (&ctx1, pke, 100);

    sha1_hmac_final (&ctx1);

    u32 digest[4];

    digest[0] = ctx1.opad.h[0];
    digest[1] = ctx1.opad.h[1];
    digest[2] = ctx1.opad.h[2];
    digest[3] = ctx1.opad.h[3];

    if (wpa->keyver == 1)
    {
      u32 t0[4];
      u32 t1[4];
      u32 t2[4];
      u32 t3[4];

      t0[0] = swap32_S (digest[0]);
      t0[1] = swap32_S (digest[1]);
      t0[2] = swap32_S (digest[2]);
      t0[3] = swap32_S (digest[3]);
      t1[0] = 0;
      t1[1] = 0;
      t1[2] = 0;
      t1[3] = 0;
      t2[0] = 0;
      t2[1] = 0;
      t2[2] = 0;
      t2[3] = 0;
      t3[0] = 0;
      t3[1] = 0;
      t3[2] = 0;
      t3[3] = 0;

      md5_hmac_ctx_t ctx2;

      md5_hmac_init_64 (&ctx2, t0, t1, t2, t3);

      md5_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);

      md5_hmac_final (&ctx2);

      digest[0] = ctx2.opad.h[0];
      digest[1] = ctx2.opad.h[1];
      digest[2] = ctx2.opad.h[2];
      digest[3] = ctx2.opad.h[3];
    }
    else
    {
      u32 t0[4];
      u32 t1[4];
      u32 t2[4];
      u32 t3[4];

      t0[0] = digest[0];
      t0[1] = digest[1];
      t0[2] = digest[2];
      t0[3] = digest[3];
      t1[0] = 0;
      t1[1] = 0;
      t1[2] = 0;
      t1[3] = 0;
      t2[0] = 0;
      t2[1] = 0;
      t2[2] = 0;
      t2[3] = 0;
      t3[0] = 0;
      t3[1] = 0;
      t3[2] = 0;
      t3[3] = 0;

      sha1_hmac_ctx_t ctx2;

      sha1_hmac_init_64 (&ctx2, t0, t1, t2, t3);

      sha1_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);

      sha1_hmac_final (&ctx2);

      digest[0] = ctx2.opad.h[0];
      digest[1] = ctx2.opad.h[1];
      digest[2] = ctx2.opad.h[2];
      digest[3] = ctx2.opad.h[3];
    }

    /**
     * final compare
     */

    if ((digest[0] == wpa->keymic[0])
     && (digest[1] == wpa->keymic[1])
     && (digest[2] == wpa->keymic[2])
     && (digest[3] == wpa->keymic[3]))
    {
      if (atomic_inc (&hashes_shown[digest_cur]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, digest_cur, gid, 0);
      }
    }
  }
}
