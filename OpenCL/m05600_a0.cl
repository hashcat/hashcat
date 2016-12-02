/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define _NETNTLMV2_

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_simd.cl"

static void md4_transform (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[4])
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

  MD4_STEP (MD4_Fo, a, b, c, d, w0_t, MD4C00, MD4S00);
  MD4_STEP (MD4_Fo, d, a, b, c, w1_t, MD4C00, MD4S01);
  MD4_STEP (MD4_Fo, c, d, a, b, w2_t, MD4C00, MD4S02);
  MD4_STEP (MD4_Fo, b, c, d, a, w3_t, MD4C00, MD4S03);
  MD4_STEP (MD4_Fo, a, b, c, d, w4_t, MD4C00, MD4S00);
  MD4_STEP (MD4_Fo, d, a, b, c, w5_t, MD4C00, MD4S01);
  MD4_STEP (MD4_Fo, c, d, a, b, w6_t, MD4C00, MD4S02);
  MD4_STEP (MD4_Fo, b, c, d, a, w7_t, MD4C00, MD4S03);
  MD4_STEP (MD4_Fo, a, b, c, d, w8_t, MD4C00, MD4S00);
  MD4_STEP (MD4_Fo, d, a, b, c, w9_t, MD4C00, MD4S01);
  MD4_STEP (MD4_Fo, c, d, a, b, wa_t, MD4C00, MD4S02);
  MD4_STEP (MD4_Fo, b, c, d, a, wb_t, MD4C00, MD4S03);
  MD4_STEP (MD4_Fo, a, b, c, d, wc_t, MD4C00, MD4S00);
  MD4_STEP (MD4_Fo, d, a, b, c, wd_t, MD4C00, MD4S01);
  MD4_STEP (MD4_Fo, c, d, a, b, we_t, MD4C00, MD4S02);
  MD4_STEP (MD4_Fo, b, c, d, a, wf_t, MD4C00, MD4S03);

  MD4_STEP (MD4_Go, a, b, c, d, w0_t, MD4C01, MD4S10);
  MD4_STEP (MD4_Go, d, a, b, c, w4_t, MD4C01, MD4S11);
  MD4_STEP (MD4_Go, c, d, a, b, w8_t, MD4C01, MD4S12);
  MD4_STEP (MD4_Go, b, c, d, a, wc_t, MD4C01, MD4S13);
  MD4_STEP (MD4_Go, a, b, c, d, w1_t, MD4C01, MD4S10);
  MD4_STEP (MD4_Go, d, a, b, c, w5_t, MD4C01, MD4S11);
  MD4_STEP (MD4_Go, c, d, a, b, w9_t, MD4C01, MD4S12);
  MD4_STEP (MD4_Go, b, c, d, a, wd_t, MD4C01, MD4S13);
  MD4_STEP (MD4_Go, a, b, c, d, w2_t, MD4C01, MD4S10);
  MD4_STEP (MD4_Go, d, a, b, c, w6_t, MD4C01, MD4S11);
  MD4_STEP (MD4_Go, c, d, a, b, wa_t, MD4C01, MD4S12);
  MD4_STEP (MD4_Go, b, c, d, a, we_t, MD4C01, MD4S13);
  MD4_STEP (MD4_Go, a, b, c, d, w3_t, MD4C01, MD4S10);
  MD4_STEP (MD4_Go, d, a, b, c, w7_t, MD4C01, MD4S11);
  MD4_STEP (MD4_Go, c, d, a, b, wb_t, MD4C01, MD4S12);
  MD4_STEP (MD4_Go, b, c, d, a, wf_t, MD4C01, MD4S13);

  MD4_STEP (MD4_H , a, b, c, d, w0_t, MD4C02, MD4S20);
  MD4_STEP (MD4_H , d, a, b, c, w8_t, MD4C02, MD4S21);
  MD4_STEP (MD4_H , c, d, a, b, w4_t, MD4C02, MD4S22);
  MD4_STEP (MD4_H , b, c, d, a, wc_t, MD4C02, MD4S23);
  MD4_STEP (MD4_H , a, b, c, d, w2_t, MD4C02, MD4S20);
  MD4_STEP (MD4_H , d, a, b, c, wa_t, MD4C02, MD4S21);
  MD4_STEP (MD4_H , c, d, a, b, w6_t, MD4C02, MD4S22);
  MD4_STEP (MD4_H , b, c, d, a, we_t, MD4C02, MD4S23);
  MD4_STEP (MD4_H , a, b, c, d, w1_t, MD4C02, MD4S20);
  MD4_STEP (MD4_H , d, a, b, c, w9_t, MD4C02, MD4S21);
  MD4_STEP (MD4_H , c, d, a, b, w5_t, MD4C02, MD4S22);
  MD4_STEP (MD4_H , b, c, d, a, wd_t, MD4C02, MD4S23);
  MD4_STEP (MD4_H , a, b, c, d, w3_t, MD4C02, MD4S20);
  MD4_STEP (MD4_H , d, a, b, c, wb_t, MD4C02, MD4S21);
  MD4_STEP (MD4_H , c, d, a, b, w7_t, MD4C02, MD4S22);
  MD4_STEP (MD4_H , b, c, d, a, wf_t, MD4C02, MD4S23);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

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

static void hmac_md5_pad (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[4], u32x opad[4])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = MD5M_A;
  ipad[1] = MD5M_B;
  ipad[2] = MD5M_C;
  ipad[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = MD5M_A;
  opad[1] = MD5M_B;
  opad[2] = MD5M_C;
  opad[3] = MD5M_D;

  md5_transform (w0, w1, w2, w3, opad);
}

static void hmac_md5_run (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[4], u32x opad[4], u32x digest[4])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];

  md5_transform (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];

  md5_transform (w0, w1, w2, w3, digest);
}

__kernel void m05600_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global netntlm_t *netntlm_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * salt
   */

  __local u32 s_userdomain_buf[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = netntlm_bufs[salt_pos].userdomain_buf[i];
  }

  __local u32 s_chall_buf[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = netntlm_bufs[salt_pos].chall_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  const u32 userdomain_len = netntlm_bufs[salt_pos].user_len
                           + netntlm_bufs[salt_pos].domain_len;

  const u32 chall_len = netntlm_bufs[salt_pos].srvchall_len
                      + netntlm_bufs[salt_pos].clichall_len;

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

  const u32 pw_len = pws[gid].pw_len;

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

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_unicode (w0, w0_t, w1_t);
    make_unicode (w1, w2_t, w3_t);

    w3_t[2] = out_len * 8 * 2;
    w3_t[3] = 0;

    u32x digest[4];

    digest[0] = MD4M_A;
    digest[1] = MD4M_B;
    digest[2] = MD4M_C;
    digest[3] = MD4M_D;

    md4_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
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

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    int left;
    int off;

    for (left = userdomain_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_userdomain_buf[off +  0];
      w0_t[1] = s_userdomain_buf[off +  1];
      w0_t[2] = s_userdomain_buf[off +  2];
      w0_t[3] = s_userdomain_buf[off +  3];
      w1_t[0] = s_userdomain_buf[off +  4];
      w1_t[1] = s_userdomain_buf[off +  5];
      w1_t[2] = s_userdomain_buf[off +  6];
      w1_t[3] = s_userdomain_buf[off +  7];
      w2_t[0] = s_userdomain_buf[off +  8];
      w2_t[1] = s_userdomain_buf[off +  9];
      w2_t[2] = s_userdomain_buf[off + 10];
      w2_t[3] = s_userdomain_buf[off + 11];
      w3_t[0] = s_userdomain_buf[off + 12];
      w3_t[1] = s_userdomain_buf[off + 13];
      w3_t[2] = s_userdomain_buf[off + 14];
      w3_t[3] = s_userdomain_buf[off + 15];

      md5_transform (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_userdomain_buf[off +  0];
    w0_t[1] = s_userdomain_buf[off +  1];
    w0_t[2] = s_userdomain_buf[off +  2];
    w0_t[3] = s_userdomain_buf[off +  3];
    w1_t[0] = s_userdomain_buf[off +  4];
    w1_t[1] = s_userdomain_buf[off +  5];
    w1_t[2] = s_userdomain_buf[off +  6];
    w1_t[3] = s_userdomain_buf[off +  7];
    w2_t[0] = s_userdomain_buf[off +  8];
    w2_t[1] = s_userdomain_buf[off +  9];
    w2_t[2] = s_userdomain_buf[off + 10];
    w2_t[3] = s_userdomain_buf[off + 11];
    w3_t[0] = s_userdomain_buf[off + 12];
    w3_t[1] = s_userdomain_buf[off + 13];
    w3_t[2] = (64 + userdomain_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
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

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    for (left = chall_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_chall_buf[off +  0];
      w0_t[1] = s_chall_buf[off +  1];
      w0_t[2] = s_chall_buf[off +  2];
      w0_t[3] = s_chall_buf[off +  3];
      w1_t[0] = s_chall_buf[off +  4];
      w1_t[1] = s_chall_buf[off +  5];
      w1_t[2] = s_chall_buf[off +  6];
      w1_t[3] = s_chall_buf[off +  7];
      w2_t[0] = s_chall_buf[off +  8];
      w2_t[1] = s_chall_buf[off +  9];
      w2_t[2] = s_chall_buf[off + 10];
      w2_t[3] = s_chall_buf[off + 11];
      w3_t[0] = s_chall_buf[off + 12];
      w3_t[1] = s_chall_buf[off + 13];
      w3_t[2] = s_chall_buf[off + 14];
      w3_t[3] = s_chall_buf[off + 15];

      md5_transform (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_chall_buf[off +  0];
    w0_t[1] = s_chall_buf[off +  1];
    w0_t[2] = s_chall_buf[off +  2];
    w0_t[3] = s_chall_buf[off +  3];
    w1_t[0] = s_chall_buf[off +  4];
    w1_t[1] = s_chall_buf[off +  5];
    w1_t[2] = s_chall_buf[off +  6];
    w1_t[3] = s_chall_buf[off +  7];
    w2_t[0] = s_chall_buf[off +  8];
    w2_t[1] = s_chall_buf[off +  9];
    w2_t[2] = s_chall_buf[off + 10];
    w2_t[3] = s_chall_buf[off + 11];
    w3_t[0] = s_chall_buf[off + 12];
    w3_t[1] = s_chall_buf[off + 13];
    w3_t[2] = (64 + chall_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    COMPARE_M_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

__kernel void m05600_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global netntlm_t *netntlm_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m05600_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global netntlm_t *netntlm_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m05600_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global netntlm_t *netntlm_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * salt
   */

  __local u32 s_userdomain_buf[64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_userdomain_buf[i] = netntlm_bufs[salt_pos].userdomain_buf[i];
  }

  __local u32 s_chall_buf[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_chall_buf[i] = netntlm_bufs[salt_pos].chall_buf[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  const u32 userdomain_len = netntlm_bufs[salt_pos].user_len
                           + netntlm_bufs[salt_pos].domain_len;

  const u32 chall_len = netntlm_bufs[salt_pos].srvchall_len
                      + netntlm_bufs[salt_pos].clichall_len;

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

  const u32 pw_len = pws[gid].pw_len;

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

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    make_unicode (w0, w0_t, w1_t);
    make_unicode (w1, w2_t, w3_t);

    w3_t[2] = out_len * 8 * 2;
    w3_t[3] = 0;

    u32x digest[4];

    digest[0] = MD4M_A;
    digest[1] = MD4M_B;
    digest[2] = MD4M_C;
    digest[3] = MD4M_D;

    md4_transform (w0_t, w1_t, w2_t, w3_t, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
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

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    u32x ipad[4];
    u32x opad[4];

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    int left;
    int off;

    for (left = userdomain_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_userdomain_buf[off +  0];
      w0_t[1] = s_userdomain_buf[off +  1];
      w0_t[2] = s_userdomain_buf[off +  2];
      w0_t[3] = s_userdomain_buf[off +  3];
      w1_t[0] = s_userdomain_buf[off +  4];
      w1_t[1] = s_userdomain_buf[off +  5];
      w1_t[2] = s_userdomain_buf[off +  6];
      w1_t[3] = s_userdomain_buf[off +  7];
      w2_t[0] = s_userdomain_buf[off +  8];
      w2_t[1] = s_userdomain_buf[off +  9];
      w2_t[2] = s_userdomain_buf[off + 10];
      w2_t[3] = s_userdomain_buf[off + 11];
      w3_t[0] = s_userdomain_buf[off + 12];
      w3_t[1] = s_userdomain_buf[off + 13];
      w3_t[2] = s_userdomain_buf[off + 14];
      w3_t[3] = s_userdomain_buf[off + 15];

      md5_transform (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_userdomain_buf[off +  0];
    w0_t[1] = s_userdomain_buf[off +  1];
    w0_t[2] = s_userdomain_buf[off +  2];
    w0_t[3] = s_userdomain_buf[off +  3];
    w1_t[0] = s_userdomain_buf[off +  4];
    w1_t[1] = s_userdomain_buf[off +  5];
    w1_t[2] = s_userdomain_buf[off +  6];
    w1_t[3] = s_userdomain_buf[off +  7];
    w2_t[0] = s_userdomain_buf[off +  8];
    w2_t[1] = s_userdomain_buf[off +  9];
    w2_t[2] = s_userdomain_buf[off + 10];
    w2_t[3] = s_userdomain_buf[off + 11];
    w3_t[0] = s_userdomain_buf[off + 12];
    w3_t[1] = s_userdomain_buf[off + 13];
    w3_t[2] = (64 + userdomain_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    w0_t[0] = digest[0];
    w0_t[1] = digest[1];
    w0_t[2] = digest[2];
    w0_t[3] = digest[3];
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

    digest[0] = MD5M_A;
    digest[1] = MD5M_B;
    digest[2] = MD5M_C;
    digest[3] = MD5M_D;

    hmac_md5_pad (w0_t, w1_t, w2_t, w3_t, ipad, opad);

    for (left = chall_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      w0_t[0] = s_chall_buf[off +  0];
      w0_t[1] = s_chall_buf[off +  1];
      w0_t[2] = s_chall_buf[off +  2];
      w0_t[3] = s_chall_buf[off +  3];
      w1_t[0] = s_chall_buf[off +  4];
      w1_t[1] = s_chall_buf[off +  5];
      w1_t[2] = s_chall_buf[off +  6];
      w1_t[3] = s_chall_buf[off +  7];
      w2_t[0] = s_chall_buf[off +  8];
      w2_t[1] = s_chall_buf[off +  9];
      w2_t[2] = s_chall_buf[off + 10];
      w2_t[3] = s_chall_buf[off + 11];
      w3_t[0] = s_chall_buf[off + 12];
      w3_t[1] = s_chall_buf[off + 13];
      w3_t[2] = s_chall_buf[off + 14];
      w3_t[3] = s_chall_buf[off + 15];

      md5_transform (w0_t, w1_t, w2_t, w3_t, ipad);
    }

    w0_t[0] = s_chall_buf[off +  0];
    w0_t[1] = s_chall_buf[off +  1];
    w0_t[2] = s_chall_buf[off +  2];
    w0_t[3] = s_chall_buf[off +  3];
    w1_t[0] = s_chall_buf[off +  4];
    w1_t[1] = s_chall_buf[off +  5];
    w1_t[2] = s_chall_buf[off +  6];
    w1_t[3] = s_chall_buf[off +  7];
    w2_t[0] = s_chall_buf[off +  8];
    w2_t[1] = s_chall_buf[off +  9];
    w2_t[2] = s_chall_buf[off + 10];
    w2_t[3] = s_chall_buf[off + 11];
    w3_t[0] = s_chall_buf[off + 12];
    w3_t[1] = s_chall_buf[off + 13];
    w3_t[2] = (64 + chall_len) * 8;
    w3_t[3] = 0;

    hmac_md5_run (w0_t, w1_t, w2_t, w3_t, ipad, opad, digest);

    COMPARE_S_SIMD (digest[0], digest[3], digest[2], digest[1]);
  }
}

__kernel void m05600_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global netntlm_t *netntlm_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m05600_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global netntlm_t *netntlm_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
