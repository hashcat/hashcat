/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.h)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.h)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct scrtv2
{
  u32 ct_buf[64];
  int ct_len;

} scrtv2_t;

DECLSPEC void shift_buffer_by_offset (PRIVATE_AS u32 *w0, const u32 offset)
{
  const int offset_switch = offset / 4;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
  switch (offset_switch)
  {
    case 0:
      w0[3] = hc_bytealign_be_S (w0[2], w0[3], offset);
      w0[2] = hc_bytealign_be_S (w0[1], w0[2], offset);
      w0[1] = hc_bytealign_be_S (w0[0], w0[1], offset);
      w0[0] = hc_bytealign_be_S (    0, w0[0], offset);
      break;

    case 1:
      w0[3] = hc_bytealign_be_S (w0[1], w0[2], offset);
      w0[2] = hc_bytealign_be_S (w0[0], w0[1], offset);
      w0[1] = hc_bytealign_be_S (    0, w0[0], offset);
      w0[0] = 0;
      break;

    case 2:
      w0[3] = hc_bytealign_be_S (w0[0], w0[1], offset);
      w0[2] = hc_bytealign_be_S (    0, w0[0], offset);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w0[3] = hc_bytealign_be_S (    0, w0[0], offset);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    default:
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;
  }
  #endif

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

  #if defined IS_NV
  const int selector = (0x76543210 >> ((offset & 3) * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S(0x0706050403020100UL >> ((offset & 3) * 8));
  #endif

  switch (offset_switch)
  {
    case 0:
      w0[3] = hc_byte_perm_S (w0[3], w0[2], selector);
      w0[2] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[1] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[0] = hc_byte_perm_S (w0[0],     0, selector);
      break;

    case 1:
      w0[3] = hc_byte_perm_S (w0[2], w0[1], selector);
      w0[2] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[1] = hc_byte_perm_S (w0[0],     0, selector);
      w0[0] = 0;
      break;

    case 2:
      w0[3] = hc_byte_perm_S (w0[1], w0[0], selector);
      w0[2] = hc_byte_perm_S (w0[0],     0, selector);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w0[3] = hc_byte_perm_S (w0[0],     0, selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    default:
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;
  }
  #endif
}

DECLSPEC void aes256_scrt_format (PRIVATE_AS u32 *aes_ks, PRIVATE_AS u32 *pw, const u32 pw_len, PRIVATE_AS u32 *hash, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  AES256_set_encrypt_key (aes_ks, hash, s_te0, s_te1, s_te2, s_te3);

  shift_buffer_by_offset (hash, pw_len + 4);

  hash[0]  = hc_swap32_S (pw_len);
  hash[1] |= hc_swap32_S (pw[0]);
  hash[2] |= hc_swap32_S (pw[1]);
  hash[3] |= hc_swap32_S (pw[2]);

  AES256_encrypt (aes_ks, hash, out, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void aes256_scrt_format_VV (PRIVATE_AS u32 *aes_ks, PRIVATE_AS u32x *w, const u32 pw_len, PRIVATE_AS u32x *h, PRIVATE_AS u32x *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  #if VECT_SIZE == 1
  aes256_scrt_format (aes_ks, w, pw_len, h, out, s_te0, s_te1, s_te2, s_te3, s_te4);
  #endif

  #if VECT_SIZE >= 2
  u32 tmp_w[4];
  u32 tmp_h[8];
  u32 tmp_out[4];

  //s0

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s0;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s0;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s0 = tmp_out[i];

  //s1

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s1;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s1;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s1 = tmp_out[i];

  #endif

  #if VECT_SIZE >= 4

  //s2

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s2;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s2;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s2 = tmp_out[i];

  //s3

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s3;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s3;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s3 = tmp_out[i];

  #endif

  #if VECT_SIZE >= 8

  //s4

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s4;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s4;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s4 = tmp_out[i];

  //s5

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s5;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s5;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s5 = tmp_out[i];

  //s6

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s6;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s6;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s6 = tmp_out[i];

  //s7

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s7;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s7;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s7 = tmp_out[i];

  #endif

  #if VECT_SIZE >= 16

  //s8

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s8;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s8;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s8 = tmp_out[i];

  //s9

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].s9;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].s9;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].s9 = tmp_out[i];

  //sa

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sa;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sa;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sa = tmp_out[i];

  //sb

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sb;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sb;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sb = tmp_out[i];

  //sc

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sc;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sc;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sc = tmp_out[i];

  //sd

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sd;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sd;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sd = tmp_out[i];

  //se

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].se;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].se;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].se = tmp_out[i];

  //sf

  for (u32 i = 0; i < 4; i++) tmp_w[i] = w[i].sf;
  for (u32 i = 0; i < 8; i++) tmp_h[i] = h[i].sf;

  aes256_scrt_format (aes_ks, tmp_w, pw_len, tmp_h, tmp_out, s_te0, s_te1, s_te2, s_te3, s_te4);

  for (u32 i = 0; i < 4; i++) out[i].sf = tmp_out[i];

  #endif
}

DECLSPEC void m31400m (SHM_TYPE u32a *s_te0, SHM_TYPE u32a *s_te1, SHM_TYPE u32a *s_te2, SHM_TYPE u32a *s_te3, SHM_TYPE u32a *s_te4, PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR_ESALT (scrtv2_t))
{
  /**
   * modifiers are taken from args
   */

  /**
   * loop
   */

  u32 ks[60];

  u32x wt[4];

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    wt[0] = w0;
    wt[1] = w[1];
    wt[2] = w[2];
    wt[3] = w[3];

    u32x ww0[4];
    u32x ww1[4];
    u32x ww2[4];
    u32x ww3[4];

    ww0[0] = hc_swap32 (w0);
    ww0[1] = hc_swap32 (w[1]);
    ww0[2] = hc_swap32 (w[2]);
    ww0[3] = hc_swap32 (w[3]);
    ww1[0] = hc_swap32 (w[4]);
    ww1[1] = hc_swap32 (w[5]);
    ww1[2] = hc_swap32 (w[6]);
    ww1[3] = hc_swap32 (w[7]);
    ww2[0] = hc_swap32 (w[8]);
    ww2[1] = hc_swap32 (w[9]);
    ww2[2] = hc_swap32 (w[10]);
    ww2[3] = hc_swap32 (w[11]);
    ww3[0] = hc_swap32 (w[12]);
    ww3[1] = hc_swap32 (w[13]);
    ww3[2] = hc_swap32 (w[14]);
    ww3[3] = hc_swap32 (w[15]);

    const int off = pw_len & 63;

    append_0x80_4x4 (ww0, ww1, ww2, ww3, off ^ 3);

    ww3[2] = 0;
    ww3[3] = pw_len * 8;

    u32x w0_t = ww0[0];
    u32x w1_t = ww0[1];
    u32x w2_t = ww0[2];
    u32x w3_t = ww0[3];
    u32x w4_t = ww1[0];
    u32x w5_t = ww1[1];
    u32x w6_t = ww1[2];
    u32x w7_t = ww1[3];
    u32x w8_t = ww2[0];
    u32x w9_t = ww2[1];
    u32x wa_t = ww2[2];
    u32x wb_t = ww2[3];
    u32x wc_t = ww3[0];
    u32x wd_t = ww3[1];
    u32x we_t = ww3[2];
    u32x wf_t = ww3[3];

    // sha256

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

    u32x digest[8];

    digest[0] = a + make_u32x (SHA256M_A);
    digest[1] = b + make_u32x (SHA256M_B);
    digest[2] = c + make_u32x (SHA256M_C);
    digest[3] = d + make_u32x (SHA256M_D);
    digest[4] = e + make_u32x (SHA256M_E);
    digest[5] = f + make_u32x (SHA256M_F);
    digest[6] = g + make_u32x (SHA256M_G);
    digest[7] = h + make_u32x (SHA256M_H);

    u32x out[4] = { 0 };

    aes256_scrt_format_VV (ks, wt, pw_len, digest, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32x r0 = out[DGST_R0];
    const u32x r1 = out[DGST_R1];
    const u32x r2 = out[DGST_R2];
    const u32x r3 = out[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m31400_m04 (KERN_ATTR_VECTOR_ESALT (scrtv2_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

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

  m31400m (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31400_m08 (KERN_ATTR_VECTOR_ESALT (scrtv2_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

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

  m31400m (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31400_m16 (KERN_ATTR_VECTOR_ESALT (scrtv2_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

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

  m31400m (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

DECLSPEC void m31400s (SHM_TYPE u32a *s_te0, SHM_TYPE u32a *s_te1, SHM_TYPE u32a *s_te2, SHM_TYPE u32a *s_te3, SHM_TYPE u32a *s_te4, PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR_ESALT (scrtv2_t))
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
   * loop
   */

  u32 ks[60];

  u32x wt[4];

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    wt[0] = w0;
    wt[1] = w[1];
    wt[2] = w[2];
    wt[3] = w[3];

    u32x ww0[4];
    u32x ww1[4];
    u32x ww2[4];
    u32x ww3[4];

    ww0[0] = hc_swap32 (w0);
    ww0[1] = hc_swap32 (w[1]);
    ww0[2] = hc_swap32 (w[2]);
    ww0[3] = hc_swap32 (w[3]);
    ww1[0] = hc_swap32 (w[4]);
    ww1[1] = hc_swap32 (w[5]);
    ww1[2] = hc_swap32 (w[6]);
    ww1[3] = hc_swap32 (w[7]);
    ww2[0] = hc_swap32 (w[8]);
    ww2[1] = hc_swap32 (w[9]);
    ww2[2] = hc_swap32 (w[10]);
    ww2[3] = hc_swap32 (w[11]);
    ww3[0] = hc_swap32 (w[12]);
    ww3[1] = hc_swap32 (w[13]);
    ww3[2] = hc_swap32 (w[14]);
    ww3[3] = hc_swap32 (w[15]);

    const int off = pw_len & 63;

    append_0x80_4x4 (ww0, ww1, ww2, ww3, off ^ 3);

    ww3[2] = 0;
    ww3[3] = pw_len * 8;

    u32x w0_t = ww0[0];
    u32x w1_t = ww0[1];
    u32x w2_t = ww0[2];
    u32x w3_t = ww0[3];
    u32x w4_t = ww1[0];
    u32x w5_t = ww1[1];
    u32x w6_t = ww1[2];
    u32x w7_t = ww1[3];
    u32x w8_t = ww2[0];
    u32x w9_t = ww2[1];
    u32x wa_t = ww2[2];
    u32x wb_t = ww2[3];
    u32x wc_t = ww3[0];
    u32x wd_t = ww3[1];
    u32x we_t = ww3[2];
    u32x wf_t = ww3[3];

    // sha256

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

    u32x digest[8];

    digest[0] = a + make_u32x (SHA256M_A);
    digest[1] = b + make_u32x (SHA256M_B);
    digest[2] = c + make_u32x (SHA256M_C);
    digest[3] = d + make_u32x (SHA256M_D);
    digest[4] = e + make_u32x (SHA256M_E);
    digest[5] = f + make_u32x (SHA256M_F);
    digest[6] = g + make_u32x (SHA256M_G);
    digest[7] = h + make_u32x (SHA256M_H);

    u32x out[4] = { 0 };

    aes256_scrt_format_VV (ks, wt, pw_len, digest, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    const u32x r0 = out[DGST_R0];
    const u32x r1 = out[DGST_R1];
    const u32x r2 = out[DGST_R2];
    const u32x r3 = out[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m31400_s04 (KERN_ATTR_VECTOR_ESALT (scrtv2_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

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

  m31400s (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31400_s08 (KERN_ATTR_VECTOR_ESALT (scrtv2_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

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

  m31400s (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m31400_s16 (KERN_ATTR_VECTOR_ESALT (scrtv2_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

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

  m31400s (s_te0, s_te1, s_te2, s_te3, s_te4, w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
