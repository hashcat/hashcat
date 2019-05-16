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
#include "inc_simd.cl"
#include "inc_hash_sha224.cl"
#endif

#define SHA224_STEP_REV(a,b,c,d,e,f,g)          \
{                                               \
  u32 t2 = SHA224_S2_S(b) + SHA224_F0o(b,c,d);  \
  u32 t1 = a - t2;                              \
  a = b;                                        \
  b = c;                                        \
  c = d;                                        \
  d = e - t1;                                   \
  e = f;                                        \
  f = g;                                        \
  g = 0;                                        \
}

KERNEL_FQ void m01300_m04 (KERN_ATTR_BASIC ())
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
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    /**
     * sha224
     */

    u32x w0_t = hc_swap32 (w0[0]);
    u32x w1_t = hc_swap32 (w0[1]);
    u32x w2_t = hc_swap32 (w0[2]);
    u32x w3_t = hc_swap32 (w0[3]);
    u32x w4_t = hc_swap32 (w1[0]);
    u32x w5_t = hc_swap32 (w1[1]);
    u32x w6_t = hc_swap32 (w1[2]);
    u32x w7_t = hc_swap32 (w1[3]);
    u32x w8_t = hc_swap32 (w2[0]);
    u32x w9_t = hc_swap32 (w2[1]);
    u32x wa_t = hc_swap32 (w2[2]);
    u32x wb_t = hc_swap32 (w2[3]);
    u32x wc_t = hc_swap32 (w3[0]);
    u32x wd_t = hc_swap32 (w3[1]);
    u32x we_t = 0;
    u32x wf_t = pw_len * 8;

    u32x a = SHA224M_A;
    u32x b = SHA224M_B;
    u32x c = SHA224M_C;
    u32x d = SHA224M_D;
    u32x e = SHA224M_E;
    u32x f = SHA224M_F;
    u32x g = SHA224M_G;
    u32x h = SHA224M_H;

    SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w0_t, SHA224C00);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w1_t, SHA224C01);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, w2_t, SHA224C02);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, w3_t, SHA224C03);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, w4_t, SHA224C04);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, w5_t, SHA224C05);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, w6_t, SHA224C06);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, w7_t, SHA224C07);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w8_t, SHA224C08);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w9_t, SHA224C09);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, wa_t, SHA224C0a);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, wb_t, SHA224C0b);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, wc_t, SHA224C0c);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, wd_t, SHA224C0d);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, we_t, SHA224C0e);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, wf_t, SHA224C0f);

    w0_t = SHA224_EXPAND (we_t, w9_t, w1_t, w0_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w0_t, SHA224C10);
    w1_t = SHA224_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w1_t, SHA224C11);
    w2_t = SHA224_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, w2_t, SHA224C12);
    w3_t = SHA224_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, w3_t, SHA224C13);
    w4_t = SHA224_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, w4_t, SHA224C14);
    w5_t = SHA224_EXPAND (w3_t, we_t, w6_t, w5_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, w5_t, SHA224C15);
    w6_t = SHA224_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, w6_t, SHA224C16);
    w7_t = SHA224_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, w7_t, SHA224C17);
    w8_t = SHA224_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w8_t, SHA224C18);
    w9_t = SHA224_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w9_t, SHA224C19);
    wa_t = SHA224_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, wa_t, SHA224C1a);
    wb_t = SHA224_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, wb_t, SHA224C1b);
    wc_t = SHA224_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, wc_t, SHA224C1c);
    wd_t = SHA224_EXPAND (wb_t, w6_t, we_t, wd_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, wd_t, SHA224C1d);
    we_t = SHA224_EXPAND (wc_t, w7_t, wf_t, we_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, we_t, SHA224C1e);
    wf_t = SHA224_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, wf_t, SHA224C1f);

    w0_t = SHA224_EXPAND (we_t, w9_t, w1_t, w0_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w0_t, SHA224C20);
    w1_t = SHA224_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w1_t, SHA224C21);
    w2_t = SHA224_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, w2_t, SHA224C22);
    w3_t = SHA224_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, w3_t, SHA224C23);
    w4_t = SHA224_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, w4_t, SHA224C24);
    w5_t = SHA224_EXPAND (w3_t, we_t, w6_t, w5_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, w5_t, SHA224C25);
    w6_t = SHA224_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, w6_t, SHA224C26);
    w7_t = SHA224_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, w7_t, SHA224C27);
    w8_t = SHA224_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w8_t, SHA224C28);
    w9_t = SHA224_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w9_t, SHA224C29);
    wa_t = SHA224_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, wa_t, SHA224C2a);
    wb_t = SHA224_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, wb_t, SHA224C2b);
    wc_t = SHA224_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, wc_t, SHA224C2c);
    wd_t = SHA224_EXPAND (wb_t, w6_t, we_t, wd_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, wd_t, SHA224C2d);
    we_t = SHA224_EXPAND (wc_t, w7_t, wf_t, we_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, we_t, SHA224C2e);
    wf_t = SHA224_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, wf_t, SHA224C2f);

    w0_t = SHA224_EXPAND (we_t, w9_t, w1_t, w0_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w0_t, SHA224C30);
    w1_t = SHA224_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w1_t, SHA224C31);
    w2_t = SHA224_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, w2_t, SHA224C32);
    w3_t = SHA224_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, w3_t, SHA224C33);
    w4_t = SHA224_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, w4_t, SHA224C34);
    w5_t = SHA224_EXPAND (w3_t, we_t, w6_t, w5_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, w5_t, SHA224C35);
    w6_t = SHA224_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, w6_t, SHA224C36);
    w7_t = SHA224_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, w7_t, SHA224C37);
    w8_t = SHA224_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w8_t, SHA224C38);
    w9_t = SHA224_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w9_t, SHA224C39);
    wa_t = SHA224_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, wa_t, SHA224C3a);
    wb_t = SHA224_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, wb_t, SHA224C3b);
    wc_t = SHA224_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, wc_t, SHA224C3c);
    wd_t = SHA224_EXPAND (wb_t, w6_t, we_t, wd_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, wd_t, SHA224C3d);
    we_t = SHA224_EXPAND (wc_t, w7_t, wf_t, we_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, we_t, SHA224C3e);
    wf_t = SHA224_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, wf_t, SHA224C3f);

    COMPARE_M_SIMD (d, f, c, g);
  }
}

KERNEL_FQ void m01300_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m01300_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m01300_s04 (KERN_ATTR_BASIC ())
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
   * reverse
   */

  u32 a_rev = digests_buf[digests_offset].digest_buf[0];
  u32 b_rev = digests_buf[digests_offset].digest_buf[1];
  u32 c_rev = digests_buf[digests_offset].digest_buf[2];
  u32 d_rev = digests_buf[digests_offset].digest_buf[3];
  u32 e_rev = digests_buf[digests_offset].digest_buf[4];
  u32 f_rev = digests_buf[digests_offset].digest_buf[5];
  u32 g_rev = digests_buf[digests_offset].digest_buf[6];

  SHA224_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev);
  SHA224_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev);
  SHA224_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev);

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
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    /**
     * sha224
     */

    u32x w0_t = hc_swap32 (w0[0]);
    u32x w1_t = hc_swap32 (w0[1]);
    u32x w2_t = hc_swap32 (w0[2]);
    u32x w3_t = hc_swap32 (w0[3]);
    u32x w4_t = hc_swap32 (w1[0]);
    u32x w5_t = hc_swap32 (w1[1]);
    u32x w6_t = hc_swap32 (w1[2]);
    u32x w7_t = hc_swap32 (w1[3]);
    u32x w8_t = hc_swap32 (w2[0]);
    u32x w9_t = hc_swap32 (w2[1]);
    u32x wa_t = hc_swap32 (w2[2]);
    u32x wb_t = hc_swap32 (w2[3]);
    u32x wc_t = hc_swap32 (w3[0]);
    u32x wd_t = hc_swap32 (w3[1]);
    u32x we_t = 0;
    u32x wf_t = pw_len * 8;

    u32x a = SHA224M_A;
    u32x b = SHA224M_B;
    u32x c = SHA224M_C;
    u32x d = SHA224M_D;
    u32x e = SHA224M_E;
    u32x f = SHA224M_F;
    u32x g = SHA224M_G;
    u32x h = SHA224M_H;

    SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w0_t, SHA224C00);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w1_t, SHA224C01);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, w2_t, SHA224C02);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, w3_t, SHA224C03);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, w4_t, SHA224C04);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, w5_t, SHA224C05);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, w6_t, SHA224C06);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, w7_t, SHA224C07);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w8_t, SHA224C08);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w9_t, SHA224C09);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, wa_t, SHA224C0a);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, wb_t, SHA224C0b);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, wc_t, SHA224C0c);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, wd_t, SHA224C0d);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, we_t, SHA224C0e);
    SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, wf_t, SHA224C0f);

    w0_t = SHA224_EXPAND (we_t, w9_t, w1_t, w0_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w0_t, SHA224C10);
    w1_t = SHA224_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w1_t, SHA224C11);
    w2_t = SHA224_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, w2_t, SHA224C12);
    w3_t = SHA224_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, w3_t, SHA224C13);
    w4_t = SHA224_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, w4_t, SHA224C14);
    w5_t = SHA224_EXPAND (w3_t, we_t, w6_t, w5_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, w5_t, SHA224C15);
    w6_t = SHA224_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, w6_t, SHA224C16);
    w7_t = SHA224_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, w7_t, SHA224C17);
    w8_t = SHA224_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w8_t, SHA224C18);
    w9_t = SHA224_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w9_t, SHA224C19);
    wa_t = SHA224_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, wa_t, SHA224C1a);
    wb_t = SHA224_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, wb_t, SHA224C1b);
    wc_t = SHA224_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, wc_t, SHA224C1c);
    wd_t = SHA224_EXPAND (wb_t, w6_t, we_t, wd_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, wd_t, SHA224C1d);
    we_t = SHA224_EXPAND (wc_t, w7_t, wf_t, we_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, we_t, SHA224C1e);
    wf_t = SHA224_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, wf_t, SHA224C1f);

    w0_t = SHA224_EXPAND (we_t, w9_t, w1_t, w0_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w0_t, SHA224C20);
    w1_t = SHA224_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w1_t, SHA224C21);
    w2_t = SHA224_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, w2_t, SHA224C22);
    w3_t = SHA224_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, w3_t, SHA224C23);
    w4_t = SHA224_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, w4_t, SHA224C24);
    w5_t = SHA224_EXPAND (w3_t, we_t, w6_t, w5_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, w5_t, SHA224C25);
    w6_t = SHA224_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, w6_t, SHA224C26);
    w7_t = SHA224_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, w7_t, SHA224C27);
    w8_t = SHA224_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w8_t, SHA224C28);
    w9_t = SHA224_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w9_t, SHA224C29);
    wa_t = SHA224_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, wa_t, SHA224C2a);
    wb_t = SHA224_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, wb_t, SHA224C2b);
    wc_t = SHA224_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, wc_t, SHA224C2c);
    wd_t = SHA224_EXPAND (wb_t, w6_t, we_t, wd_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, wd_t, SHA224C2d);
    we_t = SHA224_EXPAND (wc_t, w7_t, wf_t, we_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, we_t, SHA224C2e);
    wf_t = SHA224_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, wf_t, SHA224C2f);

    w0_t = SHA224_EXPAND (we_t, w9_t, w1_t, w0_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w0_t, SHA224C30);
    w1_t = SHA224_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w1_t, SHA224C31);
    w2_t = SHA224_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, w2_t, SHA224C32);
    w3_t = SHA224_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, w3_t, SHA224C33);
    w4_t = SHA224_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, w4_t, SHA224C34);
    w5_t = SHA224_EXPAND (w3_t, we_t, w6_t, w5_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, w5_t, SHA224C35);
    w6_t = SHA224_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, w6_t, SHA224C36);
    w7_t = SHA224_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, w7_t, SHA224C37);
    w8_t = SHA224_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, a, b, c, d, e, f, g, h, w8_t, SHA224C38);
    w9_t = SHA224_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, h, a, b, c, d, e, f, g, w9_t, SHA224C39);

    if (MATCHES_NONE_VS (g, d_rev)) continue;

    wa_t = SHA224_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, g, h, a, b, c, d, e, f, wa_t, SHA224C3a);
    wb_t = SHA224_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, f, g, h, a, b, c, d, e, wb_t, SHA224C3b);
    wc_t = SHA224_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, e, f, g, h, a, b, c, d, wc_t, SHA224C3c);
    wd_t = SHA224_EXPAND (wb_t, w6_t, we_t, wd_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, d, e, f, g, h, a, b, c, wd_t, SHA224C3d);
    we_t = SHA224_EXPAND (wc_t, w7_t, wf_t, we_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, c, d, e, f, g, h, a, b, we_t, SHA224C3e);
    wf_t = SHA224_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA224_STEP (SHA224_F0o, SHA224_F1o, b, c, d, e, f, g, h, a, wf_t, SHA224C3f);

    COMPARE_S_SIMD (d, f, c, g);
  }
}

KERNEL_FQ void m01300_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m01300_s16 (KERN_ATTR_BASIC ())
{
}
