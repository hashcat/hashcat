__constant u32a ESSIV_k_sha256[64] =
{
  SHA256C00, SHA256C01, SHA256C02, SHA256C03,
  SHA256C04, SHA256C05, SHA256C06, SHA256C07,
  SHA256C08, SHA256C09, SHA256C0a, SHA256C0b,
  SHA256C0c, SHA256C0d, SHA256C0e, SHA256C0f,
  SHA256C10, SHA256C11, SHA256C12, SHA256C13,
  SHA256C14, SHA256C15, SHA256C16, SHA256C17,
  SHA256C18, SHA256C19, SHA256C1a, SHA256C1b,
  SHA256C1c, SHA256C1d, SHA256C1e, SHA256C1f,
  SHA256C20, SHA256C21, SHA256C22, SHA256C23,
  SHA256C24, SHA256C25, SHA256C26, SHA256C27,
  SHA256C28, SHA256C29, SHA256C2a, SHA256C2b,
  SHA256C2c, SHA256C2d, SHA256C2e, SHA256C2f,
  SHA256C30, SHA256C31, SHA256C32, SHA256C33,
  SHA256C34, SHA256C35, SHA256C36, SHA256C37,
  SHA256C38, SHA256C39, SHA256C3a, SHA256C3b,
  SHA256C3c, SHA256C3d, SHA256C3e, SHA256C3f,
};

// basically a normal sha256_transform() but with a different name to avoid collisions with function nameing
DECLSPEC void ESSIV_sha256_transform_S (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];
  u32 e = digest[4];
  u32 f = digest[5];
  u32 g = digest[6];
  u32 h = digest[7];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  #define ESSIV_ROUND_EXPAND_S()                      \
  {                                                   \
    w0_t = SHA256_EXPAND_S (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA256_EXPAND_S (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA256_EXPAND_S (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA256_EXPAND_S (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA256_EXPAND_S (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA256_EXPAND_S (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA256_EXPAND_S (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA256_EXPAND_S (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA256_EXPAND_S (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA256_EXPAND_S (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA256_EXPAND_S (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA256_EXPAND_S (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA256_EXPAND_S (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA256_EXPAND_S (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA256_EXPAND_S (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA256_EXPAND_S (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ESSIV_ROUND_STEP_S(i)                                                                   \
  {                                                                                               \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, ESSIV_k_sha256[i +  0]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, ESSIV_k_sha256[i +  1]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, ESSIV_k_sha256[i +  2]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, ESSIV_k_sha256[i +  3]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, ESSIV_k_sha256[i +  4]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, ESSIV_k_sha256[i +  5]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, ESSIV_k_sha256[i +  6]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, ESSIV_k_sha256[i +  7]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, ESSIV_k_sha256[i +  8]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, ESSIV_k_sha256[i +  9]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, ESSIV_k_sha256[i + 10]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, ESSIV_k_sha256[i + 11]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, ESSIV_k_sha256[i + 12]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, ESSIV_k_sha256[i + 13]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, ESSIV_k_sha256[i + 14]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, ESSIV_k_sha256[i + 15]); \
  }

  ESSIV_ROUND_STEP_S (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
  {
    ESSIV_ROUND_EXPAND_S (); ESSIV_ROUND_STEP_S (i);
  }

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

DECLSPEC void ESSIV_sha256_init128 (u32 *key, u32 *essivhash)
{
  essivhash[0] = SHA256M_A;
  essivhash[1] = SHA256M_B;
  essivhash[2] = SHA256M_C;
  essivhash[3] = SHA256M_D;
  essivhash[4] = SHA256M_E;
  essivhash[5] = SHA256M_F;
  essivhash[6] = SHA256M_G;
  essivhash[7] = SHA256M_H;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = swap32_S (key[0]);
  w0[1] = swap32_S (key[1]);
  w0[2] = swap32_S (key[2]);
  w0[3] = swap32_S (key[3]);
  w1[0] = 0x80000000;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 16 * 8;

  ESSIV_sha256_transform_S (w0, w1, w2, w3, essivhash);

  essivhash[0] = swap32_S (essivhash[0]);
  essivhash[1] = swap32_S (essivhash[1]);
  essivhash[2] = swap32_S (essivhash[2]);
  essivhash[3] = swap32_S (essivhash[3]);
  essivhash[4] = swap32_S (essivhash[4]);
  essivhash[5] = swap32_S (essivhash[5]);
  essivhash[6] = swap32_S (essivhash[6]);
  essivhash[7] = swap32_S (essivhash[7]);
}

DECLSPEC void ESSIV_sha256_init256 (u32 *key, u32 *essivhash)
{
  essivhash[0] = SHA256M_A;
  essivhash[1] = SHA256M_B;
  essivhash[2] = SHA256M_C;
  essivhash[3] = SHA256M_D;
  essivhash[4] = SHA256M_E;
  essivhash[5] = SHA256M_F;
  essivhash[6] = SHA256M_G;
  essivhash[7] = SHA256M_H;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = swap32_S (key[0]);
  w0[1] = swap32_S (key[1]);
  w0[2] = swap32_S (key[2]);
  w0[3] = swap32_S (key[3]);
  w1[0] = swap32_S (key[4]);
  w1[1] = swap32_S (key[5]);
  w1[2] = swap32_S (key[6]);
  w1[3] = swap32_S (key[7]);
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 32 * 8;

  ESSIV_sha256_transform_S (w0, w1, w2, w3, essivhash);

  essivhash[0] = swap32_S (essivhash[0]);
  essivhash[1] = swap32_S (essivhash[1]);
  essivhash[2] = swap32_S (essivhash[2]);
  essivhash[3] = swap32_S (essivhash[3]);
  essivhash[4] = swap32_S (essivhash[4]);
  essivhash[5] = swap32_S (essivhash[5]);
  essivhash[6] = swap32_S (essivhash[6]);
  essivhash[7] = swap32_S (essivhash[7]);
}
