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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#endif

#define SHA512_STEP_REV(a,b,c,d,e,f,g,h)           \
{                                                  \
  u64 t2 = SHA512_S0_S (b) + SHA512_F1o (b, c, d); \
  u64 t1 = a - t2;                                 \
  a = b;                                           \
  b = c;                                           \
  c = d;                                           \
  d = e - t1;                                      \
  e = f;                                           \
  f = g;                                           \
  g = h;                                           \
  h = 0;                                           \
}

DECLSPEC void sha512_transform_intern (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u64x *digest)
{
  u64x w0_t = hl32_to_64 (w0[0], w0[1]);
  u64x w1_t = hl32_to_64 (w0[2], w0[3]);
  u64x w2_t = hl32_to_64 (w1[0], w1[1]);
  u64x w3_t = hl32_to_64 (w1[2], w1[3]);
  u64x w4_t = hl32_to_64 (w2[0], w2[1]);
  u64x w5_t = hl32_to_64 (w2[2], w2[3]);
  u64x w6_t = hl32_to_64 (w3[0], w3[1]);
  u64x w7_t = 0;
  u64x w8_t = 0;
  u64x w9_t = 0;
  u64x wa_t = 0;
  u64x wb_t = 0;
  u64x wc_t = 0;
  u64x wd_t = 0;
  u64x we_t = 0;
  u64x wf_t = hl32_to_64 (w3[2], w3[3]);

  u64x a = digest[0];
  u64x b = digest[1];
  u64x c = digest[2];
  u64x d = digest[3];
  u64x e = digest[4];
  u64x f = digest[5];
  u64x g = digest[6];
  u64x h = digest[7];

                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C00);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C01);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C02);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C03);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C04);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C05);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C06);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C07);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C08);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C09);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C0a);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C0b);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C0c);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C0d);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C0e);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C0f);
  w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C10);
  w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C11);
  w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C12);
  w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C13);
  w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C14);
  w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C15);
  w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C16);
  w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C17);
  w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C18);
  w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C19);
  wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C1a);
  wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C1b);
  wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C1c);
  wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C1d);
  we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C1e);
  wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C1f);
  w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C20);
  w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C21);
  w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C22);
  w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C23);
  w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C24);
  w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C25);
  w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C26);
  w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C27);
  w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C28);
  w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C29);
  wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C2a);
  wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C2b);
  wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C2c);
  wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C2d);
  we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C2e);
  wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C2f);
  w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C30);
  w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C31);
  w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C32);
  w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C33);
  w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C34);
  w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C35);
  w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C36);
  w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C37);
  w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C38);
  w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C39);
  wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C3a);
  wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C3b);
  wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C3c);
  wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C3d);
  we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C3e);
  wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C3f);
  w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C40);
  w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C41);
  w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C42);
  w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C43);
  w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C44);
  w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C45);
  w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C46);
  w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C47);
  w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C48);
  w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C49);
  wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C4a);
  wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C4b);
  wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C4c);
  wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C4d);
  we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C4e);
  wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C4f);

  /* rev
  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
  */

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
  digest[5] = f;
  digest[6] = g;
  digest[7] = h;
}

DECLSPEC u32 sha512_transform_intern_rev (PRIVATE_AS const u32x *w0, PRIVATE_AS const u32x *w1, PRIVATE_AS const u32x *w2, PRIVATE_AS const u32x *w3, PRIVATE_AS u64x *digest, const u64 d_rev)
{
  u64x w0_t = hl32_to_64 (w0[0], w0[1]);
  u64x w1_t = hl32_to_64 (w0[2], w0[3]);
  u64x w2_t = hl32_to_64 (w1[0], w1[1]);
  u64x w3_t = hl32_to_64 (w1[2], w1[3]);
  u64x w4_t = hl32_to_64 (w2[0], w2[1]);
  u64x w5_t = hl32_to_64 (w2[2], w2[3]);
  u64x w6_t = hl32_to_64 (w3[0], w3[1]);
  u64x w7_t = 0;
  u64x w8_t = 0;
  u64x w9_t = 0;
  u64x wa_t = 0;
  u64x wb_t = 0;
  u64x wc_t = 0;
  u64x wd_t = 0;
  u64x we_t = 0;
  u64x wf_t = hl32_to_64 (w3[2], w3[3]);

  u64x a = digest[0];
  u64x b = digest[1];
  u64x c = digest[2];
  u64x d = digest[3];
  u64x e = digest[4];
  u64x f = digest[5];
  u64x g = digest[6];
  u64x h = digest[7];

                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C00);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C01);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C02);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C03);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C04);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C05);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C06);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C07);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C08);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C09);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C0a);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C0b);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C0c);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C0d);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C0e);
                                                 SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C0f);
  w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C10);
  w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C11);
  w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C12);
  w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C13);
  w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C14);
  w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C15);
  w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C16);
  w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C17);
  w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C18);
  w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C19);
  wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C1a);
  wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C1b);
  wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C1c);
  wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C1d);
  we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C1e);
  wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C1f);
  w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C20);
  w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C21);
  w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C22);
  w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C23);
  w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C24);
  w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C25);
  w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C26);
  w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C27);
  w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C28);
  w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C29);
  wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C2a);
  wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C2b);
  wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C2c);
  wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C2d);
  we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C2e);
  wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C2f);
  w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C30);
  w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C31);
  w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C32);
  w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C33);
  w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C34);
  w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C35);
  w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C36);
  w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C37);
  w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C38);
  w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C39);
  wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C3a);
  wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C3b);
  wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C3c);
  wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C3d);
  we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C3e);
  wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C3f);
  w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, SHA512C40);
  w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, SHA512C41);
  w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, SHA512C42);
  w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, SHA512C43);
  w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, SHA512C44);
  w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, SHA512C45);
  w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, SHA512C46);
  w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, SHA512C47);
  w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, SHA512C48);
  // each step shifts a into b into c into d, so d of the state four rounds back from the
  // digest is a of the state here, and a candidate missing it cannot match

  if (MATCHES_NONE_VS (h, d_rev)) return 1;
  w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, SHA512C49);
  wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, SHA512C4a);
  wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, SHA512C4b);
  wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, SHA512C4c);
  wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, SHA512C4d);
  we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, SHA512C4e);
  wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t); SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, SHA512C4f);

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
  digest[5] = f;
  digest[6] = g;
  digest[7] = h;

  return 0;
}

DECLSPEC void m01710m (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[SALT_POS_HOST].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[SALT_POS_HOST].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[SALT_POS_HOST].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[SALT_POS_HOST].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[SALT_POS_HOST].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[SALT_POS_HOST].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[SALT_POS_HOST].salt_buf[10];
  salt_buf2[3] = salt_bufs[SALT_POS_HOST].salt_buf[11];
  salt_buf3[0] = salt_bufs[SALT_POS_HOST].salt_buf[12];
  salt_buf3[1] = salt_bufs[SALT_POS_HOST].salt_buf[13];
  salt_buf3[2] = salt_bufs[SALT_POS_HOST].salt_buf[14];
  salt_buf3[3] = salt_bufs[SALT_POS_HOST].salt_buf[15];

  switch_buffer_by_offset_le_S (salt_buf0, salt_buf1, salt_buf2, salt_buf3, pw_len);

  w[ 0] |= hc_swap32_S (salt_buf0[0]);
  w[ 1] |= hc_swap32_S (salt_buf0[1]);
  w[ 2] |= hc_swap32_S (salt_buf0[2]);
  w[ 3] |= hc_swap32_S (salt_buf0[3]);
  w[ 4] |= hc_swap32_S (salt_buf1[0]);
  w[ 5] |= hc_swap32_S (salt_buf1[1]);
  w[ 6] |= hc_swap32_S (salt_buf1[2]);
  w[ 7] |= hc_swap32_S (salt_buf1[3]);
  w[ 8] |= hc_swap32_S (salt_buf2[0]);
  w[ 9] |= hc_swap32_S (salt_buf2[1]);
  w[10] |= hc_swap32_S (salt_buf2[2]);
  w[11] |= hc_swap32_S (salt_buf2[3]);
  w[12] |= hc_swap32_S (salt_buf3[0]);
  w[13] |= hc_swap32_S (salt_buf3[1]);
  w[14] |= hc_swap32_S (salt_buf3[2]);
  w[15] |= hc_swap32_S (salt_buf3[3]);

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  const u32 pw_salt_len = pw_len + salt_len;

  w[15] = pw_salt_len * 8;

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0;
    w0_t[1] = w[ 1];
    w0_t[2] = w[ 2];
    w0_t[3] = w[ 3];
    w1_t[0] = w[ 4];
    w1_t[1] = w[ 5];
    w1_t[2] = w[ 6];
    w1_t[3] = w[ 7];
    w2_t[0] = w[ 8];
    w2_t[1] = w[ 9];
    w2_t[2] = w[10];
    w2_t[3] = w[11];
    w3_t[0] = w[12];
    w3_t[1] = w[13];
    w3_t[2] = w[14];
    w3_t[3] = w[15];

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform_intern (w0_t, w1_t, w2_t, w3_t, digest);

    const u32x r0 = l32_from_64 (digest[7]);
    const u32x r1 = h32_from_64 (digest[7]);
    const u32x r2 = l32_from_64 (digest[3]);
    const u32x r3 = h32_from_64 (digest[3]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

DECLSPEC void m01710s (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
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

  u64 a_rev = hl32_to_64_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 1], digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 0]);
  u64 b_rev = hl32_to_64_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 3], digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 2]);
  u64 c_rev = hl32_to_64_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 5], digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 4]);
  u64 d_rev = hl32_to_64_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 7], digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 6]);
  u64 e_rev = hl32_to_64_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 9], digests_buf[DIGESTS_OFFSET_HOST].digest_buf[ 8]);
  u64 f_rev = hl32_to_64_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[11], digests_buf[DIGESTS_OFFSET_HOST].digest_buf[10]);
  u64 g_rev = hl32_to_64_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[13], digests_buf[DIGESTS_OFFSET_HOST].digest_buf[12]);
  u64 h_rev = hl32_to_64_S (digests_buf[DIGESTS_OFFSET_HOST].digest_buf[15], digests_buf[DIGESTS_OFFSET_HOST].digest_buf[14]);

  SHA512_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA512_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA512_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);
  SHA512_STEP_REV (a_rev, b_rev, c_rev, d_rev, e_rev, f_rev, g_rev, h_rev);

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = w0;
    w0_t[1] = w[ 1];
    w0_t[2] = w[ 2];
    w0_t[3] = w[ 3];
    w1_t[0] = w[ 4];
    w1_t[1] = w[ 5];
    w1_t[2] = w[ 6];
    w1_t[3] = w[ 7];
    w2_t[0] = w[ 8];
    w2_t[1] = w[ 9];
    w2_t[2] = w[10];
    w2_t[3] = w[11];
    w3_t[0] = w[12];
    w3_t[1] = w[13];
    w3_t[2] = w[14];
    w3_t[3] = w[15];

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    if (sha512_transform_intern_rev (w0_t, w1_t, w2_t, w3_t, digest, d_rev)) continue;

    const u32x r0 = l32_from_64 (digest[7]);
    const u32x r1 = h32_from_64 (digest[7]);
    const u32x r2 = l32_from_64 (digest[3]);
    const u32x r3 = h32_from_64 (digest[3]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m01710_m04 (KERN_ATTR_VECTOR ())
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

  m01710m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m01710_m08 (KERN_ATTR_VECTOR ())
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

  m01710m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m01710_m16 (KERN_ATTR_VECTOR ())
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

  m01710m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m01710_s04 (KERN_ATTR_VECTOR ())
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

  m01710s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m01710_s08 (KERN_ATTR_VECTOR ())
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

  m01710s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ KERNEL_FA void m01710_s16 (KERN_ATTR_VECTOR ())
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

  m01710s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
