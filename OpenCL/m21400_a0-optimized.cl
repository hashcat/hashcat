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
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"
#endif

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

KERNEL_FQ void m21400_m04 (KERN_ATTR_RULES ())
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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sha256
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

    u32x a = SHA256M_A;
    u32x b = SHA256M_B;
    u32x c = SHA256M_C;
    u32x d = SHA256M_D;
    u32x e = SHA256M_E;
    u32x f = SHA256M_F;
    u32x g = SHA256M_G;
    u32x h = SHA256M_H;

    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C00);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C01);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C02);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C03);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C04);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C05);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C06);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C07);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C08);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C09);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C0a);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C0b);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C0c);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C0d);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C0e);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C0f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C10);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C11);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C12);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C13);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C14);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C15);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C16);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C17);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C18);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C19);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C1a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C1b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C1c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C1d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C1e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C1f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C20);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C21);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C22);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C23);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C24);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C25);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C26);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C27);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C28);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C29);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C2a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C2b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C2c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C2d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C2e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C2f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C30);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C31);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C32);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C33);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C34);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C35);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C36);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C37);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C38);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C39);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C3a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C3b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C3c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C3d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C3e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C3f);

    // 2nd round

    /**
     * sha256
     */

    w0_t = a + SHA256M_A;
    w1_t = b + SHA256M_B;
    w2_t = c + SHA256M_C;
    w3_t = d + SHA256M_D;
    w4_t = e + SHA256M_E;
    w5_t = f + SHA256M_F;
    w6_t = g + SHA256M_G;
    w7_t = h + SHA256M_H;
    w8_t = 0x80000000;
    w9_t = 0;
    wa_t = 0;
    wb_t = 0;
    wc_t = 0;
    wd_t = 0;
    we_t = 0;
    wf_t = 32 * 8;

    a = SHA256M_A;
    b = SHA256M_B;
    c = SHA256M_C;
    d = SHA256M_D;
    e = SHA256M_E;
    f = SHA256M_F;
    g = SHA256M_G;
    h = SHA256M_H;

    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C00);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C01);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C02);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C03);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C04);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C05);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C06);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C07);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C08);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C09);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C0a);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C0b);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C0c);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C0d);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C0e);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C0f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C10);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C11);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C12);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C13);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C14);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C15);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C16);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C17);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C18);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C19);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C1a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C1b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C1c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C1d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C1e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C1f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C20);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C21);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C22);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C23);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C24);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C25);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C26);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C27);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C28);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C29);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C2a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C2b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C2c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C2d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C2e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C2f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C30);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C31);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C32);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C33);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C34);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C35);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C36);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C37);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C38);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C39);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C3a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C3b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C3c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C3d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C3e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C3f);

    COMPARE_M_SIMD (d, h, c, g);
  }
}

KERNEL_FQ void m21400_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21400_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21400_s04 (KERN_ATTR_RULES ())
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

  const u32 pw_len = pws[gid].pw_len & 63;

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
  u32 h_rev = digests_buf[digests_offset].digest_buf[7];

  SHA256_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA256_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA256_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA256_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x80_2x4_VV (w0, w1, out_len);

    /**
     * sha256
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

    u32x a = SHA256M_A;
    u32x b = SHA256M_B;
    u32x c = SHA256M_C;
    u32x d = SHA256M_D;
    u32x e = SHA256M_E;
    u32x f = SHA256M_F;
    u32x g = SHA256M_G;
    u32x h = SHA256M_H;

    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C00);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C01);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C02);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C03);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C04);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C05);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C06);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C07);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C08);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C09);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C0a);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C0b);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C0c);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C0d);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C0e);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C0f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C10);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C11);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C12);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C13);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C14);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C15);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C16);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C17);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C18);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C19);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C1a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C1b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C1c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C1d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C1e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C1f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C20);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C21);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C22);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C23);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C24);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C25);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C26);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C27);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C28);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C29);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C2a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C2b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C2c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C2d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C2e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C2f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C30);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C31);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C32);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C33);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C34);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C35);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C36);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C37);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C38);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C39);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C3a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C3b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C3c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C3d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C3e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C3f);

    // start 2nd round

    /**
     * sha256
     */

    w0_t = a + SHA256M_A;
    w1_t = b + SHA256M_B;
    w2_t = c + SHA256M_C;
    w3_t = d + SHA256M_D;
    w4_t = e + SHA256M_E;
    w5_t = f + SHA256M_F;
    w6_t = g + SHA256M_G;
    w7_t = h + SHA256M_H;
    w8_t = 0x80000000;
    w9_t = 0;
    wa_t = 0;
    wb_t = 0;
    wc_t = 0;
    wd_t = 0;
    we_t = 0;
    wf_t = 32 * 8;

    a = SHA256M_A;
    b = SHA256M_B;
    c = SHA256M_C;
    d = SHA256M_D;
    e = SHA256M_E;
    f = SHA256M_F;
    g = SHA256M_G;
    h = SHA256M_H;

    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C00);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C01);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C02);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C03);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C04);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C05);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C06);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C07);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C08);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C09);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C0a);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C0b);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C0c);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C0d);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C0e);
    SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C0f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C10);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C11);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C12);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C13);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C14);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C15);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C16);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C17);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C18);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C19);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C1a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C1b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C1c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C1d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C1e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C1f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C20);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C21);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C22);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C23);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C24);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C25);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C26);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C27);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C28);
    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C29);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C2a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C2b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C2c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C2d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C2e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C2f);

    w0_t = SHA256_EXPAND (we_t, w9_t, w1_t, w0_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C30);
    w1_t = SHA256_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C31);
    w2_t = SHA256_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C32);
    w3_t = SHA256_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C33);
    w4_t = SHA256_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C34);
    w5_t = SHA256_EXPAND (w3_t, we_t, w6_t, w5_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C35);
    w6_t = SHA256_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C36);
    w7_t = SHA256_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C37);
    w8_t = SHA256_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C38);

    if (MATCHES_NONE_VS (h, d_rev)) continue;

    w9_t = SHA256_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C39);
    wa_t = SHA256_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C3a);
    wb_t = SHA256_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C3b);
    wc_t = SHA256_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C3c);
    wd_t = SHA256_EXPAND (wb_t, w6_t, we_t, wd_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C3d);
    we_t = SHA256_EXPAND (wc_t, w7_t, wf_t, we_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C3e);
    wf_t = SHA256_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C3f);

    COMPARE_S_SIMD (d, h, c, g);
  }
}

KERNEL_FQ void m21400_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m21400_s16 (KERN_ATTR_RULES ())
{
}
