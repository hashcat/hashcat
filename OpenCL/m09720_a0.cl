/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define _OLDOFFICE01_

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_simd.cl"

static void md5_transform (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[4])
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];

  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = w3[3];

  MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

  MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

  MD5_STEP (MD5_H , a, b, c, d, w5_t, MD5C20, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w8_t, MD5C21, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, wb_t, MD5C22, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, we_t, MD5C23, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w1_t, MD5C24, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w4_t, MD5C25, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w7_t, MD5C26, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, wa_t, MD5C27, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, wd_t, MD5C28, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w0_t, MD5C29, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w3_t, MD5C2a, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w6_t, MD5C2b, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w9_t, MD5C2c, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, wc_t, MD5C2d, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, wf_t, MD5C2e, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w2_t, MD5C2f, MD5S23);

  MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

static void gen336 (u32x digest_pre[4], u32 salt_buf[4], u32x digest[4])
{
  u32x digest_t0[2];
  u32x digest_t1[2];
  u32x digest_t2[2];
  u32x digest_t3[2];

  digest_t0[0] = digest_pre[0];
  digest_t0[1] = digest_pre[1] & 0xff;

  digest_t1[0] =                       digest_pre[0] <<  8;
  digest_t1[1] = digest_pre[0] >> 24 | digest_pre[1] <<  8;

  digest_t2[0] =                       digest_pre[0] << 16;
  digest_t2[1] = digest_pre[0] >> 16 | digest_pre[1] << 16;

  digest_t3[0] =                       digest_pre[0] << 24;
  digest_t3[1] = digest_pre[0] >>  8 | digest_pre[1] << 24;

  u32x salt_buf_t0[4];
  u32x salt_buf_t1[5];
  u32x salt_buf_t2[5];
  u32x salt_buf_t3[5];

  salt_buf_t0[0] = salt_buf[0];
  salt_buf_t0[1] = salt_buf[1];
  salt_buf_t0[2] = salt_buf[2];
  salt_buf_t0[3] = salt_buf[3];

  salt_buf_t1[0] =                     salt_buf[0] <<  8;
  salt_buf_t1[1] = salt_buf[0] >> 24 | salt_buf[1] <<  8;
  salt_buf_t1[2] = salt_buf[1] >> 24 | salt_buf[2] <<  8;
  salt_buf_t1[3] = salt_buf[2] >> 24 | salt_buf[3] <<  8;
  salt_buf_t1[4] = salt_buf[3] >> 24;

  salt_buf_t2[0] =                     salt_buf[0] << 16;
  salt_buf_t2[1] = salt_buf[0] >> 16 | salt_buf[1] << 16;
  salt_buf_t2[2] = salt_buf[1] >> 16 | salt_buf[2] << 16;
  salt_buf_t2[3] = salt_buf[2] >> 16 | salt_buf[3] << 16;
  salt_buf_t2[4] = salt_buf[3] >> 16;

  salt_buf_t3[0] =                     salt_buf[0] << 24;
  salt_buf_t3[1] = salt_buf[0] >>  8 | salt_buf[1] << 24;
  salt_buf_t3[2] = salt_buf[1] >>  8 | salt_buf[2] << 24;
  salt_buf_t3[3] = salt_buf[2] >>  8 | salt_buf[3] << 24;
  salt_buf_t3[4] = salt_buf[3] >>  8;

  u32x w0_t[4];
  u32x w1_t[4];
  u32x w2_t[4];
  u32x w3_t[4];

  // generate the 16 * 21 buffer

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..5
  w0_t[0]  = digest_t0[0];
  w0_t[1]  = digest_t0[1];

  // 5..21
  w0_t[1] |= salt_buf_t1[0];
  w0_t[2]  = salt_buf_t1[1];
  w0_t[3]  = salt_buf_t1[2];
  w1_t[0]  = salt_buf_t1[3];
  w1_t[1]  = salt_buf_t1[4];

  // 21..26
  w1_t[1] |= digest_t1[0];
  w1_t[2]  = digest_t1[1];

  // 26..42
  w1_t[2] |= salt_buf_t2[0];
  w1_t[3]  = salt_buf_t2[1];
  w2_t[0]  = salt_buf_t2[2];
  w2_t[1]  = salt_buf_t2[3];
  w2_t[2]  = salt_buf_t2[4];

  // 42..47
  w2_t[2] |= digest_t2[0];
  w2_t[3]  = digest_t2[1];

  // 47..63
  w2_t[3] |= salt_buf_t3[0];
  w3_t[0]  = salt_buf_t3[1];
  w3_t[1]  = salt_buf_t3[2];
  w3_t[2]  = salt_buf_t3[3];
  w3_t[3]  = salt_buf_t3[4];

  // 63..

  w3_t[3] |= digest_t3[0];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..4
  w0_t[0]  = digest_t3[1];

  // 4..20
  w0_t[1]  = salt_buf_t0[0];
  w0_t[2]  = salt_buf_t0[1];
  w0_t[3]  = salt_buf_t0[2];
  w1_t[0]  = salt_buf_t0[3];

  // 20..25
  w1_t[1]  = digest_t0[0];
  w1_t[2]  = digest_t0[1];

  // 25..41
  w1_t[2] |= salt_buf_t1[0];
  w1_t[3]  = salt_buf_t1[1];
  w2_t[0]  = salt_buf_t1[2];
  w2_t[1]  = salt_buf_t1[3];
  w2_t[2]  = salt_buf_t1[4];

  // 41..46
  w2_t[2] |= digest_t1[0];
  w2_t[3]  = digest_t1[1];

  // 46..62
  w2_t[3] |= salt_buf_t2[0];
  w3_t[0]  = salt_buf_t2[1];
  w3_t[1]  = salt_buf_t2[2];
  w3_t[2]  = salt_buf_t2[3];
  w3_t[3]  = salt_buf_t2[4];

  // 62..
  w3_t[3] |= digest_t2[0];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..3
  w0_t[0]  = digest_t2[1];

  // 3..19
  w0_t[0] |= salt_buf_t3[0];
  w0_t[1]  = salt_buf_t3[1];
  w0_t[2]  = salt_buf_t3[2];
  w0_t[3]  = salt_buf_t3[3];
  w1_t[0]  = salt_buf_t3[4];

  // 19..24
  w1_t[0] |= digest_t3[0];
  w1_t[1]  = digest_t3[1];

  // 24..40
  w1_t[2]  = salt_buf_t0[0];
  w1_t[3]  = salt_buf_t0[1];
  w2_t[0]  = salt_buf_t0[2];
  w2_t[1]  = salt_buf_t0[3];

  // 40..45
  w2_t[2]  = digest_t0[0];
  w2_t[3]  = digest_t0[1];

  // 45..61
  w2_t[3] |= salt_buf_t1[0];
  w3_t[0]  = salt_buf_t1[1];
  w3_t[1]  = salt_buf_t1[2];
  w3_t[2]  = salt_buf_t1[3];
  w3_t[3]  = salt_buf_t1[4];

  // 61..
  w3_t[3] |= digest_t1[0];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..2
  w0_t[0]  = digest_t1[1];

  // 2..18
  w0_t[0] |= salt_buf_t2[0];
  w0_t[1]  = salt_buf_t2[1];
  w0_t[2]  = salt_buf_t2[2];
  w0_t[3]  = salt_buf_t2[3];
  w1_t[0]  = salt_buf_t2[4];

  // 18..23
  w1_t[0] |= digest_t2[0];
  w1_t[1]  = digest_t2[1];

  // 23..39
  w1_t[1] |= salt_buf_t3[0];
  w1_t[2]  = salt_buf_t3[1];
  w1_t[3]  = salt_buf_t3[2];
  w2_t[0]  = salt_buf_t3[3];
  w2_t[1]  = salt_buf_t3[4];

  // 39..44
  w2_t[1] |= digest_t3[0];
  w2_t[2]  = digest_t3[1];

  // 44..60
  w2_t[3]  = salt_buf_t0[0];
  w3_t[0]  = salt_buf_t0[1];
  w3_t[1]  = salt_buf_t0[2];
  w3_t[2]  = salt_buf_t0[3];

  // 60..
  w3_t[3]  = digest_t0[0];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0] = 0;
  w0_t[1] = 0;
  w0_t[2] = 0;
  w0_t[3] = 0;
  w1_t[0] = 0;
  w1_t[1] = 0;
  w1_t[2] = 0;
  w1_t[3] = 0;
  w2_t[0] = 0;
  w2_t[1] = 0;
  w2_t[2] = 0;
  w2_t[3] = 0;
  w3_t[0] = 0;
  w3_t[1] = 0;
  w3_t[2] = 0;
  w3_t[3] = 0;

  // 0..1
  w0_t[0]  = digest_t0[1];

  // 1..17
  w0_t[0] |= salt_buf_t1[0];
  w0_t[1]  = salt_buf_t1[1];
  w0_t[2]  = salt_buf_t1[2];
  w0_t[3]  = salt_buf_t1[3];
  w1_t[0]  = salt_buf_t1[4];

  // 17..22
  w1_t[0] |= digest_t1[0];
  w1_t[1]  = digest_t1[1];

  // 22..38
  w1_t[1] |= salt_buf_t2[0];
  w1_t[2]  = salt_buf_t2[1];
  w1_t[3]  = salt_buf_t2[2];
  w2_t[0]  = salt_buf_t2[3];
  w2_t[1]  = salt_buf_t2[4];

  // 38..43
  w2_t[1] |= digest_t2[0];
  w2_t[2]  = digest_t2[1];

  // 43..59
  w2_t[2] |= salt_buf_t3[0];
  w2_t[3]  = salt_buf_t3[1];
  w3_t[0]  = salt_buf_t3[2];
  w3_t[1]  = salt_buf_t3[3];
  w3_t[2]  = salt_buf_t3[4];

  // 59..
  w3_t[2] |= digest_t3[0];
  w3_t[3]  = digest_t3[1];

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);

  w0_t[0]  = salt_buf_t0[0];
  w0_t[1]  = salt_buf_t0[1];
  w0_t[2]  = salt_buf_t0[2];
  w0_t[3]  = salt_buf_t0[3];
  w1_t[0]  = 0x80;
  w1_t[1]  = 0;
  w1_t[2]  = 0;
  w1_t[3]  = 0;
  w2_t[0]  = 0;
  w2_t[1]  = 0;
  w2_t[2]  = 0;
  w2_t[3]  = 0;
  w3_t[0]  = 0;
  w3_t[1]  = 0;
  w3_t[2]  = 21 * 16 * 8;
  w3_t[3]  = 0;

  md5_transform (w0_t, w1_t, w2_t, w3_t, digest);
}

__kernel void m09720_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global oldoffice01_t *oldoffice01_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

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

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * md5
     */

    make_unicode (w1, w2, w3);
    make_unicode (w0, w0, w1);

    w3[2] = out_len * 8 * 2;
    w3[3] = 0;

    u32x digest_pre[4];

    digest_pre[0] = MD5M_A;
    digest_pre[1] = MD5M_B;
    digest_pre[2] = MD5M_C;
    digest_pre[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest_pre);

    digest_pre[0] &= 0xffffffff;
    digest_pre[1] &= 0x000000ff;
    digest_pre[2] &= 0x00000000;
    digest_pre[3] &= 0x00000000;

    u32x digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    gen336 (digest_pre, salt_buf, digest);

    u32x a = digest[0];
    u32x b = digest[1] & 0xff;
    u32x c = 0;
    u32x d = 0;

    COMPARE_M_SIMD (a, b, c, d);
  }
}

__kernel void m09720_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global oldoffice01_t *oldoffice01_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m09720_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global oldoffice01_t *oldoffice01_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m09720_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global oldoffice01_t *oldoffice01_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

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

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

  u32 salt_buf[4];

  salt_buf[0] = salt_bufs[salt_pos].salt_buf[0];
  salt_buf[1] = salt_bufs[salt_pos].salt_buf[1];
  salt_buf[2] = salt_bufs[salt_pos].salt_buf[2];
  salt_buf[3] = salt_bufs[salt_pos].salt_buf[3];

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

    const u32x out_len = apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * md5
     */

    make_unicode (w1, w2, w3);
    make_unicode (w0, w0, w1);

    w3[2] = out_len * 8 * 2;
    w3[3] = 0;

    u32x digest_pre[4];

    digest_pre[0] = MD5M_A;
    digest_pre[1] = MD5M_B;
    digest_pre[2] = MD5M_C;
    digest_pre[3] = MD5M_D;

    md5_transform (w0, w1, w2, w3, digest_pre);

    digest_pre[0] &= 0xffffffff;
    digest_pre[1] &= 0x000000ff;
    digest_pre[2] &= 0x00000000;
    digest_pre[3] &= 0x00000000;

    u32x digest[4];

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    gen336 (digest_pre, salt_buf, digest);

    u32x a = digest[0];
    u32x b = digest[1] & 0xff;
    u32x c = 0;
    u32x d = 0;

    COMPARE_S_SIMD (a, b, c, d);
  }
}

__kernel void m09720_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global oldoffice01_t *oldoffice01_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m09720_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global oldoffice01_t *oldoffice01_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
