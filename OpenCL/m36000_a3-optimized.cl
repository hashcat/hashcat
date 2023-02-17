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

/**
 * useless for now
 *
#define SHA256_STEP_REV(a,b,c,d,e,f,g,h)        \
{                                               \
  u32 t2 = SHA256_S2_S(b) + SHA256_F0o(b,c,d);  \
  u32 t1 = a - t2;                              \
  a = b;                                        \
  b = c;                                        \
  c = d;                                        \
  d = e - t1;                                   \
  e = f;                                        \
  f = g;                                        \
  g = h;                                        \
  h = 0;                                        \
}
*/

DECLSPEC void m36000m (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
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

		/*
		u32x w0_t = hc_swap32 (w0);
    u32x w1_t = hc_swap32 (w[ 1]);
    u32x w2_t = hc_swap32 (w[ 2]);
    u32x w3_t = hc_swap32 (w[ 3]);
    u32x w4_t = hc_swap32 (w[ 4]);
    u32x w5_t = hc_swap32 (w[ 5]);
    u32x w6_t = hc_swap32 (w[ 6]);
    u32x w7_t = hc_swap32 (w[ 7]);
    u32x w8_t = hc_swap32 (w[ 8]);
    u32x w9_t = hc_swap32 (w[ 9]);
    u32x wa_t = hc_swap32 (w[10]);
    u32x wb_t = hc_swap32 (w[11]);
    u32x wc_t = hc_swap32 (w[12]);
    u32x wd_t = hc_swap32 (w[13]);
    u32x we_t = hc_swap32 (w[14]);
    u32x wf_t = hc_swap32 (w[15]);
		*/

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
    w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T63, wf_t, wf_t ^ w3_t);

    COMPARE_M_SIMD (a, b, c, d);
  }
}

DECLSPEC void m36000s (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
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

  /**
   * reverse
   */

	/**
	 * useless for now
	 *
  u32 a_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[0];
  u32 b_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[1];
  u32 c_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[2];
  u32 d_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[3];
  u32 e_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[4];
  u32 f_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[5];
  u32 g_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[6];
  u32 h_rev = digests_buf[DIGESTS_OFFSET_HOST].digest_buf[7];

  SHA256_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA256_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA256_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA256_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
	*/

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

		/*
		u32x w0_t = hc_swap32 (w0);
    u32x w1_t = hc_swap32 (w[ 1]);
    u32x w2_t = hc_swap32 (w[ 2]);
    u32x w3_t = hc_swap32 (w[ 3]);
    u32x w4_t = hc_swap32 (w[ 4]);
    u32x w5_t = hc_swap32 (w[ 5]);
    u32x w6_t = hc_swap32 (w[ 6]);
    u32x w7_t = hc_swap32 (w[ 7]);
    u32x w8_t = hc_swap32 (w[ 8]);
    u32x w9_t = hc_swap32 (w[ 9]);
    u32x wa_t = hc_swap32 (w[10]);
    u32x wb_t = hc_swap32 (w[11]);
    u32x wc_t = hc_swap32 (w[12]);
    u32x wd_t = hc_swap32 (w[13]);
    u32x we_t = hc_swap32 (w[14]);
    u32x wf_t = hc_swap32 (w[15]);
		*/

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
    w3_t = SM3_EXPAND(w3_t, wa_t, w0_t, w6_t, wd_t); SM3_ROUND2(b, c, d, a, f, g, h, e, SM3_T63, wf_t, wf_t ^ w3_t);

    COMPARE_S_SIMD (a, b, c, d);
  }
}

KERNEL_FQ void m36000_m04 (KERN_ATTR_VECTOR ())
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

  m36000m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m36000_m08 (KERN_ATTR_VECTOR ())
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

  m36000m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m36000_m16 (KERN_ATTR_VECTOR ())
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

  m36000m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m36000_s04 (KERN_ATTR_VECTOR ())
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

  m36000s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m36000_s08 (KERN_ATTR_VECTOR ())
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

  m36000s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m36000_s16 (KERN_ATTR_VECTOR ())
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

  m36000s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
