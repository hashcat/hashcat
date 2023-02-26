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
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sm3.cl)
#endif

DECLSPEC void m31100m (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x w0_t = w0;
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

DECLSPEC void m31100s (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

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

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x w0_t = w0;
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

/* expansion phase optimization, for some reason slower than current implementation - probably compiler optimizer

DECLSPEC void m31100s (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  const u32 d_rev = hc_rotr32_S (search[0], 9);

  u32 pre_t[68];

  pre_t[ 0] = 0;
  pre_t[ 1] = w[ 1];
  pre_t[ 2] = w[ 2];
  pre_t[ 3] = w[ 3];
  pre_t[ 4] = w[ 4];
  pre_t[ 5] = w[ 5];
  pre_t[ 6] = w[ 6];
  pre_t[ 7] = w[ 7];
  pre_t[ 8] = w[ 8];
  pre_t[ 9] = w[ 9];
  pre_t[10] = w[10];
  pre_t[11] = w[11];
  pre_t[12] = w[12];
  pre_t[13] = w[13];
  pre_t[14] = w[14];
  pre_t[15] = w[15];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 68; i++)
  {
    pre_t[i] = SM3_EXPAND_S (pre_t[i - 16], pre_t[i - 9], pre_t[i - 3], pre_t[i - 13], pre_t[i - 6]);
  }

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x t[68];

    t[0] = w0;

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 1; i < 65; i++)
    {
      t[i] = pre_t[i];
    }

    const u32x fix16 = SM3_EXPAND (   w0,     0,     0,     0,     0);
    const u32x fix19 = SM3_EXPAND (    0,     0, fix16,     0,     0);
    const u32x fix22 = SM3_EXPAND (    0,     0, fix19,     0, fix16);
    const u32x fix25 = SM3_EXPAND (    0, fix16, fix22,     0, fix19);
    const u32x fix28 = SM3_EXPAND (    0, fix19, fix25,     0, fix22);
    const u32x fix29 = SM3_EXPAND (    0,     0,     0, fix16,     0);
    const u32x fix31 = SM3_EXPAND (    0, fix22, fix28,     0, fix25);
    const u32x fix32 = SM3_EXPAND (fix16,     0, fix29, fix19,     0);
    const u32x fix34 = SM3_EXPAND (    0, fix25, fix31,     0, fix28);
    const u32x fix35 = SM3_EXPAND (fix19,     0, fix32, fix22, fix29);
    const u32x fix37 = SM3_EXPAND (    0, fix28, fix34,     0, fix31);
    const u32x fix38 = SM3_EXPAND (fix22, fix29, fix35, fix25, fix32);
    const u32x fix40 = SM3_EXPAND (    0, fix31, fix37,     0, fix34);
    const u32x fix41 = SM3_EXPAND (fix25, fix32, fix38, fix28, fix35);
    const u32x fix42 = SM3_EXPAND (    0,     0,     0, fix29,     0);
    const u32x fix43 = SM3_EXPAND (    0, fix34, fix40,     0, fix37);
    const u32x fix44 = SM3_EXPAND (fix28, fix35, fix41, fix31, fix38);
    const u32x fix45 = SM3_EXPAND (fix29,     0, fix42, fix32,     0);
    const u32x fix46 = SM3_EXPAND (    0, fix37, fix43,     0, fix40);
    const u32x fix47 = SM3_EXPAND (fix31, fix38, fix44, fix34, fix41);
    const u32x fix48 = SM3_EXPAND (fix32,     0, fix45, fix35, fix42);
    const u32x fix49 = SM3_EXPAND (    0, fix40, fix46,     0, fix43);
    const u32x fix50 = SM3_EXPAND (fix34, fix41, fix47, fix37, fix44);
    const u32x fix51 = SM3_EXPAND (fix35, fix42, fix48, fix38, fix45);
    const u32x fix52 = SM3_EXPAND (    0, fix43, fix49,     0, fix46);
    const u32x fix53 = SM3_EXPAND (fix37, fix44, fix50, fix40, fix47);
    const u32x fix54 = SM3_EXPAND (fix38, fix45, fix51, fix41, fix48);
    const u32x fix55 = SM3_EXPAND (    0, fix46, fix52, fix42, fix49);
    const u32x fix56 = SM3_EXPAND (fix40, fix47, fix53, fix43, fix50);
    const u32x fix57 = SM3_EXPAND (fix41, fix48, fix54, fix44, fix51);
    const u32x fix58 = SM3_EXPAND (fix42, fix49, fix55, fix45, fix52);
    const u32x fix59 = SM3_EXPAND (fix43, fix50, fix56, fix46, fix53);
    const u32x fix60 = SM3_EXPAND (fix44, fix51, fix57, fix47, fix54);
    const u32x fix61 = SM3_EXPAND (fix45, fix52, fix58, fix48, fix55);
    const u32x fix62 = SM3_EXPAND (fix46, fix53, fix59, fix49, fix56);
    const u32x fix63 = SM3_EXPAND (fix47, fix54, fix60, fix50, fix57);
    const u32x fix64 = SM3_EXPAND (fix48, fix55, fix61, fix51, fix58);

    t[16] ^= fix16;
    t[19] ^= fix19;
    t[22] ^= fix22;
    t[25] ^= fix25;
    t[28] ^= fix28;
    t[29] ^= fix29;
    t[31] ^= fix31;
    t[32] ^= fix32;
    t[34] ^= fix34;
    t[35] ^= fix35;
    t[37] ^= fix37;
    t[38] ^= fix38;
    t[40] ^= fix40;
    t[41] ^= fix41;
    t[42] ^= fix42;
    t[43] ^= fix43;
    t[44] ^= fix44;
    t[45] ^= fix45;
    t[46] ^= fix46;
    t[47] ^= fix47;
    t[48] ^= fix48;
    t[49] ^= fix49;
    t[50] ^= fix50;
    t[51] ^= fix51;
    t[52] ^= fix52;
    t[53] ^= fix53;
    t[54] ^= fix54;
    t[55] ^= fix55;
    t[56] ^= fix56;
    t[57] ^= fix57;
    t[58] ^= fix58;
    t[59] ^= fix59;
    t[60] ^= fix60;
    t[61] ^= fix61;
    t[62] ^= fix62;
    t[63] ^= fix63;
    t[64] ^= fix64;

    u32x a = SM3_IV_A;
    u32x b = SM3_IV_B;
    u32x c = SM3_IV_C;
    u32x d = SM3_IV_D;
    u32x e = SM3_IV_E;
    u32x f = SM3_IV_F;
    u32x g = SM3_IV_G;
    u32x h = SM3_IV_H;

    SM3_ROUND1 (a, b, c, d, e, f, g, h, SM3_T00, t[ 0], t[ 0] ^ t[ 4]);
    SM3_ROUND1 (d, a, b, c, h, e, f, g, SM3_T01, t[ 1], t[ 1] ^ t[ 5]);
    SM3_ROUND1 (c, d, a, b, g, h, e, f, SM3_T02, t[ 2], t[ 2] ^ t[ 6]);
    SM3_ROUND1 (b, c, d, a, f, g, h, e, SM3_T03, t[ 3], t[ 3] ^ t[ 7]);
    SM3_ROUND1 (a, b, c, d, e, f, g, h, SM3_T04, t[ 4], t[ 4] ^ t[ 8]);
    SM3_ROUND1 (d, a, b, c, h, e, f, g, SM3_T05, t[ 5], t[ 5] ^ t[ 9]);
    SM3_ROUND1 (c, d, a, b, g, h, e, f, SM3_T06, t[ 6], t[ 6] ^ t[10]);
    SM3_ROUND1 (b, c, d, a, f, g, h, e, SM3_T07, t[ 7], t[ 7] ^ t[11]);
    SM3_ROUND1 (a, b, c, d, e, f, g, h, SM3_T08, t[ 8], t[ 8] ^ t[12]);
    SM3_ROUND1 (d, a, b, c, h, e, f, g, SM3_T09, t[ 9], t[ 9] ^ t[13]);
    SM3_ROUND1 (c, d, a, b, g, h, e, f, SM3_T10, t[10], t[10] ^ t[14]);
    SM3_ROUND1 (b, c, d, a, f, g, h, e, SM3_T11, t[11], t[11] ^ t[15]);
    SM3_ROUND1 (a, b, c, d, e, f, g, h, SM3_T12, t[12], t[12] ^ t[16]);
    SM3_ROUND1 (d, a, b, c, h, e, f, g, SM3_T13, t[13], t[13] ^ t[17]);
    SM3_ROUND1 (c, d, a, b, g, h, e, f, SM3_T14, t[14], t[14] ^ t[18]);
    SM3_ROUND1 (b, c, d, a, f, g, h, e, SM3_T15, t[15], t[15] ^ t[19]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T16, t[16], t[16] ^ t[20]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T17, t[17], t[17] ^ t[21]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T18, t[18], t[18] ^ t[22]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T19, t[19], t[19] ^ t[23]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T20, t[20], t[20] ^ t[24]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T21, t[21], t[21] ^ t[25]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T22, t[22], t[22] ^ t[26]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T23, t[23], t[23] ^ t[27]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T24, t[24], t[24] ^ t[28]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T25, t[25], t[25] ^ t[29]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T26, t[26], t[26] ^ t[30]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T27, t[27], t[27] ^ t[31]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T28, t[28], t[28] ^ t[32]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T29, t[29], t[29] ^ t[33]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T30, t[30], t[30] ^ t[34]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T31, t[31], t[31] ^ t[35]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T32, t[32], t[32] ^ t[36]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T33, t[33], t[33] ^ t[37]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T34, t[34], t[34] ^ t[38]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T35, t[35], t[35] ^ t[39]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T36, t[36], t[36] ^ t[40]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T37, t[37], t[37] ^ t[41]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T38, t[38], t[38] ^ t[42]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T39, t[39], t[39] ^ t[43]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T40, t[40], t[40] ^ t[44]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T41, t[41], t[41] ^ t[45]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T42, t[42], t[42] ^ t[46]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T43, t[43], t[43] ^ t[47]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T44, t[44], t[44] ^ t[48]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T45, t[45], t[45] ^ t[49]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T46, t[46], t[46] ^ t[50]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T47, t[47], t[47] ^ t[51]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T48, t[48], t[48] ^ t[52]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T49, t[49], t[49] ^ t[53]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T50, t[50], t[50] ^ t[54]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T51, t[51], t[51] ^ t[55]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T52, t[52], t[52] ^ t[56]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T53, t[53], t[53] ^ t[57]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T54, t[54], t[54] ^ t[58]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T55, t[55], t[55] ^ t[59]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T56, t[56], t[56] ^ t[60]);
    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T57, t[57], t[57] ^ t[61]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T58, t[58], t[58] ^ t[62]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T59, t[59], t[59] ^ t[63]);
    SM3_ROUND2 (a, b, c, d, e, f, g, h, SM3_T60, t[60], t[60] ^ t[64]);

    if (MATCHES_NONE_VS (d, d_rev)) continue;

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 65; i < 68; i++)
    {
      t[i] = pre_t[i];
    }

    const u32x fix65 = SM3_EXPAND (fix49, fix56, fix62, fix52, fix59);
    const u32x fix66 = SM3_EXPAND (fix50, fix57, fix63, fix53, fix60);
    const u32x fix67 = SM3_EXPAND (fix51, fix58, fix64, fix54, fix61);

    t[65] ^= fix65;
    t[66] ^= fix66;
    t[67] ^= fix67;

    SM3_ROUND2 (d, a, b, c, h, e, f, g, SM3_T61, t[61], t[61] ^ t[65]);
    SM3_ROUND2 (c, d, a, b, g, h, e, f, SM3_T62, t[62], t[62] ^ t[66]);
    SM3_ROUND2 (b, c, d, a, f, g, h, e, SM3_T63, t[63], t[63] ^ t[67]);

    COMPARE_S_SIMD (d, h, b, f);
  }
}
*/

KERNEL_FQ void m31100_m04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m31100m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31100_m08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m31100m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31100_m16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m31100m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31100_s04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m31100s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31100_s08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m31100s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31100_s16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m31100s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
