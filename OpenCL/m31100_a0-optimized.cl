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
#include M2S(INCLUDE_PATH/inc_hash_sm3.cl)
#endif

KERNEL_FQ void m31100_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sm3
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
    u32x wf_t = out_len * 8;

    u32x a = SM3_IV_A;
    u32x b = SM3_IV_B;
    u32x c = SM3_IV_C;
    u32x d = SM3_IV_D;
    u32x e = SM3_IV_E;
    u32x f = SM3_IV_F;
    u32x g = SM3_IV_G;
    u32x h = SM3_IV_H;

    SM3_ROUND1(a, b, c, d, e, f, g, h, SM3_T00, w0_t, w0_t ^ w4_t);
    SM3_ROUND1(d, a, b, c, h, e, f, g, SM3_T01, w1_t, w1_t ^ w5_t);
    SM3_ROUND1(c, d, a, b, g, h, e, f, SM3_T02, w2_t, w2_t ^ w6_t);
    SM3_ROUND1(b, c, d, a, f, g, h, e, SM3_T03, w3_t, w3_t ^ w7_t);
    SM3_ROUND1(a, b, c, d, e, f, g, h, SM3_T04, w4_t, w4_t ^ w8_t);
    SM3_ROUND1(d, a, b, c, h, e, f, g, SM3_T05, w5_t, w5_t ^ w9_t);
    SM3_ROUND1(c, d, a, b, g, h, e, f, SM3_T06, w6_t, w6_t ^ wa_t);
    SM3_ROUND1(b, c, d, a, f, g, h, e, SM3_T07, w7_t, w7_t ^ wb_t);
    SM3_ROUND1(a, b, c, d, e, f, g, h, SM3_T08, w8_t, w8_t ^ wc_t);
    SM3_ROUND1(d, a, b, c, h, e, f, g, SM3_T09, w9_t, w9_t ^ wd_t);
    SM3_ROUND1(c, d, a, b, g, h, e, f, SM3_T10, wa_t, wa_t ^ we_t);
    SM3_ROUND1(b, c, d, a, f, g, h, e, SM3_T11, wb_t, wb_t ^ wf_t);
    w0_t = SM3_EXPAND(w0_t, w7_t, wd_t, w3_t, wa_t); SM3_ROUND1(a, b, c, d, e, f, g, h, SM3_T12, wc_t, wc_t ^ w0_t);
    w1_t = SM3_EXPAND(w1_t, w8_t, we_t, w4_t, wb_t); SM3_ROUND1(d, a, b, c, h, e, f, g, SM3_T13, wd_t, wd_t ^ w1_t);
    w2_t = SM3_EXPAND(w2_t, w9_t, wf_t, w5_t, wc_t); SM3_ROUND1(c, d, a, b, g, h, e, f, SM3_T14, we_t, we_t ^ w2_t);
    w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND1(b, c, d, a, f, g, h, e, SM3_T15, wf_t, wf_t ^ w3_t);

    w4_t = SM3_EXPAND(w4_t, wb_t, w1_t, w7_t, we_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T16, w0_t, w0_t ^ w4_t);
    w5_t = SM3_EXPAND(w5_t, wc_t, w2_t, w8_t, wf_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T17, w1_t, w1_t ^ w5_t);
    w6_t = SM3_EXPAND(w6_t, wd_t, w3_t, w9_t, w0_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T18, w2_t, w2_t ^ w6_t);
    w7_t = SM3_EXPAND(w7_t, we_t, w4_t, wa_t, w1_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T19, w3_t, w3_t ^ w7_t);
    w8_t = SM3_EXPAND(w8_t, wf_t, w5_t, wb_t, w2_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T20, w4_t, w4_t ^ w8_t);
    w9_t = SM3_EXPAND(w9_t, w0_t, w6_t, wc_t, w3_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T21, w5_t, w5_t ^ w9_t);
    wa_t = SM3_EXPAND(wa_t, w1_t, w7_t, wd_t, w4_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T22, w6_t, w6_t ^ wa_t);
    wb_t = SM3_EXPAND(wb_t, w2_t, w8_t, we_t, w5_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T23, w7_t, w7_t ^ wb_t);
    wc_t = SM3_EXPAND(wc_t, w3_t, w9_t, wf_t, w6_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T24, w8_t, w8_t ^ wc_t);
    wd_t = SM3_EXPAND(wd_t, w4_t, wa_t, w0_t, w7_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T25, w9_t, w9_t ^ wd_t);
    we_t = SM3_EXPAND(we_t, w5_t, wb_t, w1_t, w8_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T26, wa_t, wa_t ^ we_t);
    wf_t = SM3_EXPAND(wf_t, w6_t, wc_t, w2_t, w9_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T27, wb_t, wb_t ^ wf_t);
    w0_t = SM3_EXPAND(w0_t, w7_t, wd_t, w3_t, wa_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T28, wc_t, wc_t ^ w0_t);
    w1_t = SM3_EXPAND(w1_t, w8_t, we_t, w4_t, wb_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T29, wd_t, wd_t ^ w1_t);
    w2_t = SM3_EXPAND(w2_t, w9_t, wf_t, w5_t, wc_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T30, we_t, we_t ^ w2_t);
    w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T31, wf_t, wf_t ^ w3_t);

    w4_t = SM3_EXPAND(w4_t, wb_t, w1_t, w7_t, we_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T32, w0_t, w0_t ^ w4_t);
    w5_t = SM3_EXPAND(w5_t, wc_t, w2_t, w8_t, wf_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T33, w1_t, w1_t ^ w5_t);
    w6_t = SM3_EXPAND(w6_t, wd_t, w3_t, w9_t, w0_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T34, w2_t, w2_t ^ w6_t);
    w7_t = SM3_EXPAND(w7_t, we_t, w4_t, wa_t, w1_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T35, w3_t, w3_t ^ w7_t);
    w8_t = SM3_EXPAND(w8_t, wf_t, w5_t, wb_t, w2_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T36, w4_t, w4_t ^ w8_t);
    w9_t = SM3_EXPAND(w9_t, w0_t, w6_t, wc_t, w3_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T37, w5_t, w5_t ^ w9_t);
    wa_t = SM3_EXPAND(wa_t, w1_t, w7_t, wd_t, w4_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T38, w6_t, w6_t ^ wa_t);
    wb_t = SM3_EXPAND(wb_t, w2_t, w8_t, we_t, w5_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T39, w7_t, w7_t ^ wb_t);
    wc_t = SM3_EXPAND(wc_t, w3_t, w9_t, wf_t, w6_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T40, w8_t, w8_t ^ wc_t);
    wd_t = SM3_EXPAND(wd_t, w4_t, wa_t, w0_t, w7_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T41, w9_t, w9_t ^ wd_t);
    we_t = SM3_EXPAND(we_t, w5_t, wb_t, w1_t, w8_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T42, wa_t, wa_t ^ we_t);
    wf_t = SM3_EXPAND(wf_t, w6_t, wc_t, w2_t, w9_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T43, wb_t, wb_t ^ wf_t);
    w0_t = SM3_EXPAND(w0_t, w7_t, wd_t, w3_t, wa_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T44, wc_t, wc_t ^ w0_t);
    w1_t = SM3_EXPAND(w1_t, w8_t, we_t, w4_t, wb_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T45, wd_t, wd_t ^ w1_t);
    w2_t = SM3_EXPAND(w2_t, w9_t, wf_t, w5_t, wc_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T46, we_t, we_t ^ w2_t);
    w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T47, wf_t, wf_t ^ w3_t);

    w4_t = SM3_EXPAND(w4_t, wb_t, w1_t, w7_t, we_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T48, w0_t, w0_t ^ w4_t);
    w5_t = SM3_EXPAND(w5_t, wc_t, w2_t, w8_t, wf_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T49, w1_t, w1_t ^ w5_t);
    w6_t = SM3_EXPAND(w6_t, wd_t, w3_t, w9_t, w0_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T50, w2_t, w2_t ^ w6_t);
    w7_t = SM3_EXPAND(w7_t, we_t, w4_t, wa_t, w1_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T51, w3_t, w3_t ^ w7_t);
    w8_t = SM3_EXPAND(w8_t, wf_t, w5_t, wb_t, w2_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T52, w4_t, w4_t ^ w8_t);
    w9_t = SM3_EXPAND(w9_t, w0_t, w6_t, wc_t, w3_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T53, w5_t, w5_t ^ w9_t);
    wa_t = SM3_EXPAND(wa_t, w1_t, w7_t, wd_t, w4_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T54, w6_t, w6_t ^ wa_t);
    wb_t = SM3_EXPAND(wb_t, w2_t, w8_t, we_t, w5_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T55, w7_t, w7_t ^ wb_t);
    wc_t = SM3_EXPAND(wc_t, w3_t, w9_t, wf_t, w6_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T56, w8_t, w8_t ^ wc_t);
    wd_t = SM3_EXPAND(wd_t, w4_t, wa_t, w0_t, w7_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T57, w9_t, w9_t ^ wd_t);
    we_t = SM3_EXPAND(we_t, w5_t, wb_t, w1_t, w8_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T58, wa_t, wa_t ^ we_t);
    wf_t = SM3_EXPAND(wf_t, w6_t, wc_t, w2_t, w9_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T59, wb_t, wb_t ^ wf_t);
    w0_t = SM3_EXPAND(w0_t, w7_t, wd_t, w3_t, wa_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T60, wc_t, wc_t ^ w0_t);
    w1_t = SM3_EXPAND(w1_t, w8_t, we_t, w4_t, wb_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T61, wd_t, wd_t ^ w1_t);
    w2_t = SM3_EXPAND(w2_t, w9_t, wf_t, w5_t, wc_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T62, we_t, we_t ^ w2_t);
    //w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T63, wf_t, wf_t ^ w3_t);

    COMPARE_M_SIMD (d, h, b, f);
  }
}

KERNEL_FQ void m31100_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m31100_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m31100_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  const u32 d_rev = hc_rotr32_S (search[0], 9);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sm3
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
    u32x wf_t = out_len * 8;

    u32x a = SM3_IV_A;
    u32x b = SM3_IV_B;
    u32x c = SM3_IV_C;
    u32x d = SM3_IV_D;
    u32x e = SM3_IV_E;
    u32x f = SM3_IV_F;
    u32x g = SM3_IV_G;
    u32x h = SM3_IV_H;

    SM3_ROUND1(a, b, c, d, e, f, g, h, SM3_T00, w0_t, w0_t ^ w4_t);
    SM3_ROUND1(d, a, b, c, h, e, f, g, SM3_T01, w1_t, w1_t ^ w5_t);
    SM3_ROUND1(c, d, a, b, g, h, e, f, SM3_T02, w2_t, w2_t ^ w6_t);
    SM3_ROUND1(b, c, d, a, f, g, h, e, SM3_T03, w3_t, w3_t ^ w7_t);
    SM3_ROUND1(a, b, c, d, e, f, g, h, SM3_T04, w4_t, w4_t ^ w8_t);
    SM3_ROUND1(d, a, b, c, h, e, f, g, SM3_T05, w5_t, w5_t ^ w9_t);
    SM3_ROUND1(c, d, a, b, g, h, e, f, SM3_T06, w6_t, w6_t ^ wa_t);
    SM3_ROUND1(b, c, d, a, f, g, h, e, SM3_T07, w7_t, w7_t ^ wb_t);
    SM3_ROUND1(a, b, c, d, e, f, g, h, SM3_T08, w8_t, w8_t ^ wc_t);
    SM3_ROUND1(d, a, b, c, h, e, f, g, SM3_T09, w9_t, w9_t ^ wd_t);
    SM3_ROUND1(c, d, a, b, g, h, e, f, SM3_T10, wa_t, wa_t ^ we_t);
    SM3_ROUND1(b, c, d, a, f, g, h, e, SM3_T11, wb_t, wb_t ^ wf_t);
    w0_t = SM3_EXPAND(w0_t, w7_t, wd_t, w3_t, wa_t); SM3_ROUND1(a, b, c, d, e, f, g, h, SM3_T12, wc_t, wc_t ^ w0_t);
    w1_t = SM3_EXPAND(w1_t, w8_t, we_t, w4_t, wb_t); SM3_ROUND1(d, a, b, c, h, e, f, g, SM3_T13, wd_t, wd_t ^ w1_t);
    w2_t = SM3_EXPAND(w2_t, w9_t, wf_t, w5_t, wc_t); SM3_ROUND1(c, d, a, b, g, h, e, f, SM3_T14, we_t, we_t ^ w2_t);
    w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND1(b, c, d, a, f, g, h, e, SM3_T15, wf_t, wf_t ^ w3_t);

    w4_t = SM3_EXPAND(w4_t, wb_t, w1_t, w7_t, we_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T16, w0_t, w0_t ^ w4_t);
    w5_t = SM3_EXPAND(w5_t, wc_t, w2_t, w8_t, wf_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T17, w1_t, w1_t ^ w5_t);
    w6_t = SM3_EXPAND(w6_t, wd_t, w3_t, w9_t, w0_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T18, w2_t, w2_t ^ w6_t);
    w7_t = SM3_EXPAND(w7_t, we_t, w4_t, wa_t, w1_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T19, w3_t, w3_t ^ w7_t);
    w8_t = SM3_EXPAND(w8_t, wf_t, w5_t, wb_t, w2_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T20, w4_t, w4_t ^ w8_t);
    w9_t = SM3_EXPAND(w9_t, w0_t, w6_t, wc_t, w3_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T21, w5_t, w5_t ^ w9_t);
    wa_t = SM3_EXPAND(wa_t, w1_t, w7_t, wd_t, w4_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T22, w6_t, w6_t ^ wa_t);
    wb_t = SM3_EXPAND(wb_t, w2_t, w8_t, we_t, w5_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T23, w7_t, w7_t ^ wb_t);
    wc_t = SM3_EXPAND(wc_t, w3_t, w9_t, wf_t, w6_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T24, w8_t, w8_t ^ wc_t);
    wd_t = SM3_EXPAND(wd_t, w4_t, wa_t, w0_t, w7_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T25, w9_t, w9_t ^ wd_t);
    we_t = SM3_EXPAND(we_t, w5_t, wb_t, w1_t, w8_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T26, wa_t, wa_t ^ we_t);
    wf_t = SM3_EXPAND(wf_t, w6_t, wc_t, w2_t, w9_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T27, wb_t, wb_t ^ wf_t);
    w0_t = SM3_EXPAND(w0_t, w7_t, wd_t, w3_t, wa_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T28, wc_t, wc_t ^ w0_t);
    w1_t = SM3_EXPAND(w1_t, w8_t, we_t, w4_t, wb_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T29, wd_t, wd_t ^ w1_t);
    w2_t = SM3_EXPAND(w2_t, w9_t, wf_t, w5_t, wc_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T30, we_t, we_t ^ w2_t);
    w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T31, wf_t, wf_t ^ w3_t);

    w4_t = SM3_EXPAND(w4_t, wb_t, w1_t, w7_t, we_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T32, w0_t, w0_t ^ w4_t);
    w5_t = SM3_EXPAND(w5_t, wc_t, w2_t, w8_t, wf_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T33, w1_t, w1_t ^ w5_t);
    w6_t = SM3_EXPAND(w6_t, wd_t, w3_t, w9_t, w0_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T34, w2_t, w2_t ^ w6_t);
    w7_t = SM3_EXPAND(w7_t, we_t, w4_t, wa_t, w1_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T35, w3_t, w3_t ^ w7_t);
    w8_t = SM3_EXPAND(w8_t, wf_t, w5_t, wb_t, w2_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T36, w4_t, w4_t ^ w8_t);
    w9_t = SM3_EXPAND(w9_t, w0_t, w6_t, wc_t, w3_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T37, w5_t, w5_t ^ w9_t);
    wa_t = SM3_EXPAND(wa_t, w1_t, w7_t, wd_t, w4_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T38, w6_t, w6_t ^ wa_t);
    wb_t = SM3_EXPAND(wb_t, w2_t, w8_t, we_t, w5_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T39, w7_t, w7_t ^ wb_t);
    wc_t = SM3_EXPAND(wc_t, w3_t, w9_t, wf_t, w6_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T40, w8_t, w8_t ^ wc_t);
    wd_t = SM3_EXPAND(wd_t, w4_t, wa_t, w0_t, w7_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T41, w9_t, w9_t ^ wd_t);
    we_t = SM3_EXPAND(we_t, w5_t, wb_t, w1_t, w8_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T42, wa_t, wa_t ^ we_t);
    wf_t = SM3_EXPAND(wf_t, w6_t, wc_t, w2_t, w9_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T43, wb_t, wb_t ^ wf_t);
    w0_t = SM3_EXPAND(w0_t, w7_t, wd_t, w3_t, wa_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T44, wc_t, wc_t ^ w0_t);
    w1_t = SM3_EXPAND(w1_t, w8_t, we_t, w4_t, wb_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T45, wd_t, wd_t ^ w1_t);
    w2_t = SM3_EXPAND(w2_t, w9_t, wf_t, w5_t, wc_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T46, we_t, we_t ^ w2_t);
    w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T47, wf_t, wf_t ^ w3_t);

    w4_t = SM3_EXPAND(w4_t, wb_t, w1_t, w7_t, we_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T48, w0_t, w0_t ^ w4_t);
    w5_t = SM3_EXPAND(w5_t, wc_t, w2_t, w8_t, wf_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T49, w1_t, w1_t ^ w5_t);
    w6_t = SM3_EXPAND(w6_t, wd_t, w3_t, w9_t, w0_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T50, w2_t, w2_t ^ w6_t);
    w7_t = SM3_EXPAND(w7_t, we_t, w4_t, wa_t, w1_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T51, w3_t, w3_t ^ w7_t);
    w8_t = SM3_EXPAND(w8_t, wf_t, w5_t, wb_t, w2_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T52, w4_t, w4_t ^ w8_t);
    w9_t = SM3_EXPAND(w9_t, w0_t, w6_t, wc_t, w3_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T53, w5_t, w5_t ^ w9_t);
    wa_t = SM3_EXPAND(wa_t, w1_t, w7_t, wd_t, w4_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T54, w6_t, w6_t ^ wa_t);
    wb_t = SM3_EXPAND(wb_t, w2_t, w8_t, we_t, w5_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T55, w7_t, w7_t ^ wb_t);
    wc_t = SM3_EXPAND(wc_t, w3_t, w9_t, wf_t, w6_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T56, w8_t, w8_t ^ wc_t);
    wd_t = SM3_EXPAND(wd_t, w4_t, wa_t, w0_t, w7_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T57, w9_t, w9_t ^ wd_t);
    we_t = SM3_EXPAND(we_t, w5_t, wb_t, w1_t, w8_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T58, wa_t, wa_t ^ we_t);
    wf_t = SM3_EXPAND(wf_t, w6_t, wc_t, w2_t, w9_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T59, wb_t, wb_t ^ wf_t);
    w0_t = SM3_EXPAND(w0_t, w7_t, wd_t, w3_t, wa_t); SM3_ROUND2(a, b, c, d, e, f, g, h, SM3_T60, wc_t, wc_t ^ w0_t);

    if (MATCHES_NONE_VS (d, d_rev)) continue;

    w1_t = SM3_EXPAND(w1_t, w8_t, we_t, w4_t, wb_t); SM3_ROUND2(d, a, b, c, h, e, f, g, SM3_T61, wd_t, wd_t ^ w1_t);
    w2_t = SM3_EXPAND(w2_t, w9_t, wf_t, w5_t, wc_t); SM3_ROUND2(c, d, a, b, g, h, e, f, SM3_T62, we_t, we_t ^ w2_t);
    //w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T63, wf_t, wf_t ^ w3_t);

    COMPARE_S_SIMD (d, h, b, f);
  }
}

KERNEL_FQ void m31100_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m31100_s16 (KERN_ATTR_RULES ())
{
}
