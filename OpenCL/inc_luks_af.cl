
// basically normal XXX_transform() but with a different name to avoid collisions with function nameing

__constant u32a AF_k_sha256[64] =
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

__constant u64a AF_k_sha512[80] =
{
  SHA512C00, SHA512C01, SHA512C02, SHA512C03,
  SHA512C04, SHA512C05, SHA512C06, SHA512C07,
  SHA512C08, SHA512C09, SHA512C0a, SHA512C0b,
  SHA512C0c, SHA512C0d, SHA512C0e, SHA512C0f,
  SHA512C10, SHA512C11, SHA512C12, SHA512C13,
  SHA512C14, SHA512C15, SHA512C16, SHA512C17,
  SHA512C18, SHA512C19, SHA512C1a, SHA512C1b,
  SHA512C1c, SHA512C1d, SHA512C1e, SHA512C1f,
  SHA512C20, SHA512C21, SHA512C22, SHA512C23,
  SHA512C24, SHA512C25, SHA512C26, SHA512C27,
  SHA512C28, SHA512C29, SHA512C2a, SHA512C2b,
  SHA512C2c, SHA512C2d, SHA512C2e, SHA512C2f,
  SHA512C30, SHA512C31, SHA512C32, SHA512C33,
  SHA512C34, SHA512C35, SHA512C36, SHA512C37,
  SHA512C38, SHA512C39, SHA512C3a, SHA512C3b,
  SHA512C3c, SHA512C3d, SHA512C3e, SHA512C3f,
  SHA512C40, SHA512C41, SHA512C42, SHA512C43,
  SHA512C44, SHA512C45, SHA512C46, SHA512C47,
  SHA512C48, SHA512C49, SHA512C4a, SHA512C4b,
  SHA512C4c, SHA512C4d, SHA512C4e, SHA512C4f,
};

DECLSPEC void AF_sha1_transform_S (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
{
  u32 A = digest[0];
  u32 B = digest[1];
  u32 C = digest[2];
  u32 D = digest[3];
  u32 E = digest[4];

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

  #undef K
  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, w0_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w1_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w2_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w3_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w4_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, w5_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w6_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w7_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w8_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w9_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, wa_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, wb_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, wc_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, wd_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, we_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

DECLSPEC void AF_sha256_transform_S (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
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

  #define SHA256_ROUND_EXPAND_S()                     \
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

  #define SHA256_ROUND_STEP_S(i)                                                               \
  {                                                                                            \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, AF_k_sha256[i +  0]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, AF_k_sha256[i +  1]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, AF_k_sha256[i +  2]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, AF_k_sha256[i +  3]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, AF_k_sha256[i +  4]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, AF_k_sha256[i +  5]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, AF_k_sha256[i +  6]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, AF_k_sha256[i +  7]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, AF_k_sha256[i +  8]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, AF_k_sha256[i +  9]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, AF_k_sha256[i + 10]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, AF_k_sha256[i + 11]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, AF_k_sha256[i + 12]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, AF_k_sha256[i + 13]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, AF_k_sha256[i + 14]); \
    SHA256_STEP_S (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, AF_k_sha256[i + 15]); \
  }

  SHA256_ROUND_STEP_S (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 64; i += 16)
  {
    SHA256_ROUND_EXPAND_S (); SHA256_ROUND_STEP_S (i);
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

DECLSPEC void AF_sha512_transform_S (const u64 *w0, const u64 *w1, const u64 *w2, const u64 *w3, u64 *digest)
{
  u64 a = digest[0];
  u64 b = digest[1];
  u64 c = digest[2];
  u64 d = digest[3];
  u64 e = digest[4];
  u64 f = digest[5];
  u64 g = digest[6];
  u64 h = digest[7];

  u64 w0_t = w0[0];
  u64 w1_t = w0[1];
  u64 w2_t = w0[2];
  u64 w3_t = w0[3];
  u64 w4_t = w1[0];
  u64 w5_t = w1[1];
  u64 w6_t = w1[2];
  u64 w7_t = w1[3];
  u64 w8_t = w2[0];
  u64 w9_t = w2[1];
  u64 wa_t = w2[2];
  u64 wb_t = w2[3];
  u64 wc_t = w3[0];
  u64 wd_t = w3[1];
  u64 we_t = w3[2];
  u64 wf_t = w3[3];

  #define SHA512_ROUND_EXPAND_S()                     \
  {                                                   \
    w0_t = SHA512_EXPAND_S (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND_S (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND_S (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND_S (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND_S (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND_S (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND_S (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND_S (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND_S (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND_S (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND_S (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND_S (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND_S (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND_S (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND_S (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND_S (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define SHA512_ROUND_STEP_S(i)                                                               \
  {                                                                                            \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, AF_k_sha512[i +  0]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, AF_k_sha512[i +  1]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, AF_k_sha512[i +  2]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, AF_k_sha512[i +  3]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, AF_k_sha512[i +  4]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, AF_k_sha512[i +  5]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, AF_k_sha512[i +  6]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, AF_k_sha512[i +  7]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, AF_k_sha512[i +  8]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, AF_k_sha512[i +  9]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, AF_k_sha512[i + 10]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, AF_k_sha512[i + 11]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, AF_k_sha512[i + 12]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, AF_k_sha512[i + 13]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, AF_k_sha512[i + 14]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, AF_k_sha512[i + 15]); \
  }

  SHA512_ROUND_STEP_S (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    SHA512_ROUND_EXPAND_S (); SHA512_ROUND_STEP_S (i);
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

DECLSPEC void AF_ripemd160_transform_S (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest)
{
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

  u32 a1 = digest[0];
  u32 b1 = digest[1];
  u32 c1 = digest[2];
  u32 d1 = digest[3];
  u32 e1 = digest[4];

  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, w0_t, RIPEMD160C00, RIPEMD160S00);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, w1_t, RIPEMD160C00, RIPEMD160S01);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, w2_t, RIPEMD160C00, RIPEMD160S02);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, w3_t, RIPEMD160C00, RIPEMD160S03);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, w4_t, RIPEMD160C00, RIPEMD160S04);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, w5_t, RIPEMD160C00, RIPEMD160S05);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, w6_t, RIPEMD160C00, RIPEMD160S06);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, w7_t, RIPEMD160C00, RIPEMD160S07);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, w8_t, RIPEMD160C00, RIPEMD160S08);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, w9_t, RIPEMD160C00, RIPEMD160S09);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, wa_t, RIPEMD160C00, RIPEMD160S0A);
  RIPEMD160_STEP_S (RIPEMD160_F , e1, a1, b1, c1, d1, wb_t, RIPEMD160C00, RIPEMD160S0B);
  RIPEMD160_STEP_S (RIPEMD160_F , d1, e1, a1, b1, c1, wc_t, RIPEMD160C00, RIPEMD160S0C);
  RIPEMD160_STEP_S (RIPEMD160_F , c1, d1, e1, a1, b1, wd_t, RIPEMD160C00, RIPEMD160S0D);
  RIPEMD160_STEP_S (RIPEMD160_F , b1, c1, d1, e1, a1, we_t, RIPEMD160C00, RIPEMD160S0E);
  RIPEMD160_STEP_S (RIPEMD160_F , a1, b1, c1, d1, e1, wf_t, RIPEMD160C00, RIPEMD160S0F);

  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w7_t, RIPEMD160C10, RIPEMD160S10);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, w4_t, RIPEMD160C10, RIPEMD160S11);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, wd_t, RIPEMD160C10, RIPEMD160S12);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, w1_t, RIPEMD160C10, RIPEMD160S13);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, wa_t, RIPEMD160C10, RIPEMD160S14);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w6_t, RIPEMD160C10, RIPEMD160S15);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, wf_t, RIPEMD160C10, RIPEMD160S16);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, w3_t, RIPEMD160C10, RIPEMD160S17);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, wc_t, RIPEMD160C10, RIPEMD160S18);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, w0_t, RIPEMD160C10, RIPEMD160S19);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w9_t, RIPEMD160C10, RIPEMD160S1A);
  RIPEMD160_STEP_S (RIPEMD160_Go, d1, e1, a1, b1, c1, w5_t, RIPEMD160C10, RIPEMD160S1B);
  RIPEMD160_STEP_S (RIPEMD160_Go, c1, d1, e1, a1, b1, w2_t, RIPEMD160C10, RIPEMD160S1C);
  RIPEMD160_STEP_S (RIPEMD160_Go, b1, c1, d1, e1, a1, we_t, RIPEMD160C10, RIPEMD160S1D);
  RIPEMD160_STEP_S (RIPEMD160_Go, a1, b1, c1, d1, e1, wb_t, RIPEMD160C10, RIPEMD160S1E);
  RIPEMD160_STEP_S (RIPEMD160_Go, e1, a1, b1, c1, d1, w8_t, RIPEMD160C10, RIPEMD160S1F);

  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, w3_t, RIPEMD160C20, RIPEMD160S20);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, wa_t, RIPEMD160C20, RIPEMD160S21);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, we_t, RIPEMD160C20, RIPEMD160S22);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, w4_t, RIPEMD160C20, RIPEMD160S23);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w9_t, RIPEMD160C20, RIPEMD160S24);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, wf_t, RIPEMD160C20, RIPEMD160S25);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, w8_t, RIPEMD160C20, RIPEMD160S26);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, w1_t, RIPEMD160C20, RIPEMD160S27);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, w2_t, RIPEMD160C20, RIPEMD160S28);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w7_t, RIPEMD160C20, RIPEMD160S29);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, w0_t, RIPEMD160C20, RIPEMD160S2A);
  RIPEMD160_STEP_S (RIPEMD160_H , c1, d1, e1, a1, b1, w6_t, RIPEMD160C20, RIPEMD160S2B);
  RIPEMD160_STEP_S (RIPEMD160_H , b1, c1, d1, e1, a1, wd_t, RIPEMD160C20, RIPEMD160S2C);
  RIPEMD160_STEP_S (RIPEMD160_H , a1, b1, c1, d1, e1, wb_t, RIPEMD160C20, RIPEMD160S2D);
  RIPEMD160_STEP_S (RIPEMD160_H , e1, a1, b1, c1, d1, w5_t, RIPEMD160C20, RIPEMD160S2E);
  RIPEMD160_STEP_S (RIPEMD160_H , d1, e1, a1, b1, c1, wc_t, RIPEMD160C20, RIPEMD160S2F);

  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w1_t, RIPEMD160C30, RIPEMD160S30);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, w9_t, RIPEMD160C30, RIPEMD160S31);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, wb_t, RIPEMD160C30, RIPEMD160S32);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, wa_t, RIPEMD160C30, RIPEMD160S33);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w0_t, RIPEMD160C30, RIPEMD160S34);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w8_t, RIPEMD160C30, RIPEMD160S35);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, wc_t, RIPEMD160C30, RIPEMD160S36);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, w4_t, RIPEMD160C30, RIPEMD160S37);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, wd_t, RIPEMD160C30, RIPEMD160S38);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w3_t, RIPEMD160C30, RIPEMD160S39);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w7_t, RIPEMD160C30, RIPEMD160S3A);
  RIPEMD160_STEP_S (RIPEMD160_Io, b1, c1, d1, e1, a1, wf_t, RIPEMD160C30, RIPEMD160S3B);
  RIPEMD160_STEP_S (RIPEMD160_Io, a1, b1, c1, d1, e1, we_t, RIPEMD160C30, RIPEMD160S3C);
  RIPEMD160_STEP_S (RIPEMD160_Io, e1, a1, b1, c1, d1, w5_t, RIPEMD160C30, RIPEMD160S3D);
  RIPEMD160_STEP_S (RIPEMD160_Io, d1, e1, a1, b1, c1, w6_t, RIPEMD160C30, RIPEMD160S3E);
  RIPEMD160_STEP_S (RIPEMD160_Io, c1, d1, e1, a1, b1, w2_t, RIPEMD160C30, RIPEMD160S3F);

  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, w4_t, RIPEMD160C40, RIPEMD160S40);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w0_t, RIPEMD160C40, RIPEMD160S41);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, w5_t, RIPEMD160C40, RIPEMD160S42);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, w9_t, RIPEMD160C40, RIPEMD160S43);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, w7_t, RIPEMD160C40, RIPEMD160S44);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, wc_t, RIPEMD160C40, RIPEMD160S45);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w2_t, RIPEMD160C40, RIPEMD160S46);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, wa_t, RIPEMD160C40, RIPEMD160S47);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, we_t, RIPEMD160C40, RIPEMD160S48);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, w1_t, RIPEMD160C40, RIPEMD160S49);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, w3_t, RIPEMD160C40, RIPEMD160S4A);
  RIPEMD160_STEP_S (RIPEMD160_J , a1, b1, c1, d1, e1, w8_t, RIPEMD160C40, RIPEMD160S4B);
  RIPEMD160_STEP_S (RIPEMD160_J , e1, a1, b1, c1, d1, wb_t, RIPEMD160C40, RIPEMD160S4C);
  RIPEMD160_STEP_S (RIPEMD160_J , d1, e1, a1, b1, c1, w6_t, RIPEMD160C40, RIPEMD160S4D);
  RIPEMD160_STEP_S (RIPEMD160_J , c1, d1, e1, a1, b1, wf_t, RIPEMD160C40, RIPEMD160S4E);
  RIPEMD160_STEP_S (RIPEMD160_J , b1, c1, d1, e1, a1, wd_t, RIPEMD160C40, RIPEMD160S4F);

  u32 a2 = digest[0];
  u32 b2 = digest[1];
  u32 c2 = digest[2];
  u32 d2 = digest[3];
  u32 e2 = digest[4];

  RIPEMD160_STEP_S_WORKAROUND_BUG (RIPEMD160_J , a2, b2, c2, d2, e2, w5_t, RIPEMD160C50, RIPEMD160S50);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, we_t, RIPEMD160C50, RIPEMD160S51);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w7_t, RIPEMD160C50, RIPEMD160S52);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, w0_t, RIPEMD160C50, RIPEMD160S53);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w9_t, RIPEMD160C50, RIPEMD160S54);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, w2_t, RIPEMD160C50, RIPEMD160S55);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, wb_t, RIPEMD160C50, RIPEMD160S56);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w4_t, RIPEMD160C50, RIPEMD160S57);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, wd_t, RIPEMD160C50, RIPEMD160S58);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w6_t, RIPEMD160C50, RIPEMD160S59);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, wf_t, RIPEMD160C50, RIPEMD160S5A);
  RIPEMD160_STEP_S (RIPEMD160_J , e2, a2, b2, c2, d2, w8_t, RIPEMD160C50, RIPEMD160S5B);
  RIPEMD160_STEP_S (RIPEMD160_J , d2, e2, a2, b2, c2, w1_t, RIPEMD160C50, RIPEMD160S5C);
  RIPEMD160_STEP_S (RIPEMD160_J , c2, d2, e2, a2, b2, wa_t, RIPEMD160C50, RIPEMD160S5D);
  RIPEMD160_STEP_S (RIPEMD160_J , b2, c2, d2, e2, a2, w3_t, RIPEMD160C50, RIPEMD160S5E);
  RIPEMD160_STEP_S (RIPEMD160_J , a2, b2, c2, d2, e2, wc_t, RIPEMD160C50, RIPEMD160S5F);

  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w6_t, RIPEMD160C60, RIPEMD160S60);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, wb_t, RIPEMD160C60, RIPEMD160S61);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, w3_t, RIPEMD160C60, RIPEMD160S62);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, w7_t, RIPEMD160C60, RIPEMD160S63);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, w0_t, RIPEMD160C60, RIPEMD160S64);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, wd_t, RIPEMD160C60, RIPEMD160S65);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, w5_t, RIPEMD160C60, RIPEMD160S66);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, wa_t, RIPEMD160C60, RIPEMD160S67);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, we_t, RIPEMD160C60, RIPEMD160S68);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, wf_t, RIPEMD160C60, RIPEMD160S69);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w8_t, RIPEMD160C60, RIPEMD160S6A);
  RIPEMD160_STEP_S (RIPEMD160_Io, d2, e2, a2, b2, c2, wc_t, RIPEMD160C60, RIPEMD160S6B);
  RIPEMD160_STEP_S (RIPEMD160_Io, c2, d2, e2, a2, b2, w4_t, RIPEMD160C60, RIPEMD160S6C);
  RIPEMD160_STEP_S (RIPEMD160_Io, b2, c2, d2, e2, a2, w9_t, RIPEMD160C60, RIPEMD160S6D);
  RIPEMD160_STEP_S (RIPEMD160_Io, a2, b2, c2, d2, e2, w1_t, RIPEMD160C60, RIPEMD160S6E);
  RIPEMD160_STEP_S (RIPEMD160_Io, e2, a2, b2, c2, d2, w2_t, RIPEMD160C60, RIPEMD160S6F);

  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, wf_t, RIPEMD160C70, RIPEMD160S70);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w5_t, RIPEMD160C70, RIPEMD160S71);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, w1_t, RIPEMD160C70, RIPEMD160S72);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, w3_t, RIPEMD160C70, RIPEMD160S73);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w7_t, RIPEMD160C70, RIPEMD160S74);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, we_t, RIPEMD160C70, RIPEMD160S75);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w6_t, RIPEMD160C70, RIPEMD160S76);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, w9_t, RIPEMD160C70, RIPEMD160S77);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, wb_t, RIPEMD160C70, RIPEMD160S78);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w8_t, RIPEMD160C70, RIPEMD160S79);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, wc_t, RIPEMD160C70, RIPEMD160S7A);
  RIPEMD160_STEP_S (RIPEMD160_H , c2, d2, e2, a2, b2, w2_t, RIPEMD160C70, RIPEMD160S7B);
  RIPEMD160_STEP_S (RIPEMD160_H , b2, c2, d2, e2, a2, wa_t, RIPEMD160C70, RIPEMD160S7C);
  RIPEMD160_STEP_S (RIPEMD160_H , a2, b2, c2, d2, e2, w0_t, RIPEMD160C70, RIPEMD160S7D);
  RIPEMD160_STEP_S (RIPEMD160_H , e2, a2, b2, c2, d2, w4_t, RIPEMD160C70, RIPEMD160S7E);
  RIPEMD160_STEP_S (RIPEMD160_H , d2, e2, a2, b2, c2, wd_t, RIPEMD160C70, RIPEMD160S7F);

  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, w8_t, RIPEMD160C80, RIPEMD160S80);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, w6_t, RIPEMD160C80, RIPEMD160S81);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w4_t, RIPEMD160C80, RIPEMD160S82);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w1_t, RIPEMD160C80, RIPEMD160S83);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, w3_t, RIPEMD160C80, RIPEMD160S84);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, wb_t, RIPEMD160C80, RIPEMD160S85);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, wf_t, RIPEMD160C80, RIPEMD160S86);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w0_t, RIPEMD160C80, RIPEMD160S87);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w5_t, RIPEMD160C80, RIPEMD160S88);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, wc_t, RIPEMD160C80, RIPEMD160S89);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, w2_t, RIPEMD160C80, RIPEMD160S8A);
  RIPEMD160_STEP_S (RIPEMD160_Go, b2, c2, d2, e2, a2, wd_t, RIPEMD160C80, RIPEMD160S8B);
  RIPEMD160_STEP_S (RIPEMD160_Go, a2, b2, c2, d2, e2, w9_t, RIPEMD160C80, RIPEMD160S8C);
  RIPEMD160_STEP_S (RIPEMD160_Go, e2, a2, b2, c2, d2, w7_t, RIPEMD160C80, RIPEMD160S8D);
  RIPEMD160_STEP_S (RIPEMD160_Go, d2, e2, a2, b2, c2, wa_t, RIPEMD160C80, RIPEMD160S8E);
  RIPEMD160_STEP_S (RIPEMD160_Go, c2, d2, e2, a2, b2, we_t, RIPEMD160C80, RIPEMD160S8F);

  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, wc_t, RIPEMD160C90, RIPEMD160S90);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, wf_t, RIPEMD160C90, RIPEMD160S91);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, wa_t, RIPEMD160C90, RIPEMD160S92);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w4_t, RIPEMD160C90, RIPEMD160S93);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w1_t, RIPEMD160C90, RIPEMD160S94);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, w5_t, RIPEMD160C90, RIPEMD160S95);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, w8_t, RIPEMD160C90, RIPEMD160S96);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, w7_t, RIPEMD160C90, RIPEMD160S97);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w6_t, RIPEMD160C90, RIPEMD160S98);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w2_t, RIPEMD160C90, RIPEMD160S99);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, wd_t, RIPEMD160C90, RIPEMD160S9A);
  RIPEMD160_STEP_S (RIPEMD160_F , a2, b2, c2, d2, e2, we_t, RIPEMD160C90, RIPEMD160S9B);
  RIPEMD160_STEP_S (RIPEMD160_F , e2, a2, b2, c2, d2, w0_t, RIPEMD160C90, RIPEMD160S9C);
  RIPEMD160_STEP_S (RIPEMD160_F , d2, e2, a2, b2, c2, w3_t, RIPEMD160C90, RIPEMD160S9D);
  RIPEMD160_STEP_S (RIPEMD160_F , c2, d2, e2, a2, b2, w9_t, RIPEMD160C90, RIPEMD160S9E);
  RIPEMD160_STEP_S (RIPEMD160_F , b2, c2, d2, e2, a2, wb_t, RIPEMD160C90, RIPEMD160S9F);

  const u32 a = digest[1] + c1 + d2;
  const u32 b = digest[2] + d1 + e2;
  const u32 c = digest[3] + e1 + a2;
  const u32 d = digest[4] + a1 + b2;
  const u32 e = digest[0] + b1 + c2;

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
}

// diffuse functions

DECLSPEC void AF_sha1_diffuse16 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 15

  w0[0] = 0;
  w0[1] = swap32_S (out[0]);
  w0[2] = swap32_S (out[1]);
  w0[3] = swap32_S (out[2]);
  w1[0] = swap32_S (out[3]);
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 20 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  AF_sha1_transform_S (w0, w1, w2, w3, digest);

  out[0] = swap32_S (digest[0]);
  out[1] = swap32_S (digest[1]);
  out[2] = swap32_S (digest[2]);
  out[3] = swap32_S (digest[3]);
}

DECLSPEC void AF_sha1_diffuse32 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 19

  w0[0] = 0;
  w0[1] = swap32_S (out[0]);
  w0[2] = swap32_S (out[1]);
  w0[3] = swap32_S (out[2]);
  w1[0] = swap32_S (out[3]);
  w1[1] = swap32_S (out[4]);
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 24 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  AF_sha1_transform_S (w0, w1, w2, w3, digest);

  out[0] = swap32_S (digest[0]);
  out[1] = swap32_S (digest[1]);
  out[2] = swap32_S (digest[2]);
  out[3] = swap32_S (digest[3]);
  out[4] = swap32_S (digest[4]);

  // 20 - 31

  w0[0] = 1;
  w0[1] = swap32_S (out[5]);
  w0[2] = swap32_S (out[6]);
  w0[3] = swap32_S (out[7]);
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

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  AF_sha1_transform_S (w0, w1, w2, w3, digest);

  out[5] = swap32_S (digest[0]);
  out[6] = swap32_S (digest[1]);
  out[7] = swap32_S (digest[2]);
}

DECLSPEC void AF_sha1_diffuse64 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 19

  w0[0] = 0;
  w0[1] = swap32_S (out[0]);
  w0[2] = swap32_S (out[1]);
  w0[3] = swap32_S (out[2]);
  w1[0] = swap32_S (out[3]);
  w1[1] = swap32_S (out[4]);
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 24 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  AF_sha1_transform_S (w0, w1, w2, w3, digest);

  out[0] = swap32_S (digest[0]);
  out[1] = swap32_S (digest[1]);
  out[2] = swap32_S (digest[2]);
  out[3] = swap32_S (digest[3]);
  out[4] = swap32_S (digest[4]);

  // 20 - 39

  w0[0] = 1;
  w0[1] = swap32_S (out[5]);
  w0[2] = swap32_S (out[6]);
  w0[3] = swap32_S (out[7]);
  w1[0] = swap32_S (out[8]);
  w1[1] = swap32_S (out[9]);
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 24 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  AF_sha1_transform_S (w0, w1, w2, w3, digest);

  out[5] = swap32_S (digest[0]);
  out[6] = swap32_S (digest[1]);
  out[7] = swap32_S (digest[2]);
  out[8] = swap32_S (digest[3]);
  out[9] = swap32_S (digest[4]);

  // 40 - 59

  w0[0] = 2;
  w0[1] = swap32_S (out[10]);
  w0[2] = swap32_S (out[11]);
  w0[3] = swap32_S (out[12]);
  w1[0] = swap32_S (out[13]);
  w1[1] = swap32_S (out[14]);
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 24 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  AF_sha1_transform_S (w0, w1, w2, w3, digest);

  out[10] = swap32_S (digest[0]);
  out[11] = swap32_S (digest[1]);
  out[12] = swap32_S (digest[2]);
  out[13] = swap32_S (digest[3]);
  out[14] = swap32_S (digest[4]);

  // 60 - 63

  w0[0] = 3;
  w0[1] = swap32_S (out[15]);
  w0[2] = 0x80000000;
  w0[3] = 0;
  w1[0] = 0;
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
  w3[3] = 8 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  AF_sha1_transform_S (w0, w1, w2, w3, digest);

  out[15] = swap32_S (digest[0]);
}

DECLSPEC void AF_sha256_diffuse16 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[8];

  // 0 - 15

  w0[0] = 0;
  w0[1] = swap32_S (out[0]);
  w0[2] = swap32_S (out[1]);
  w0[3] = swap32_S (out[2]);
  w1[0] = swap32_S (out[3]);
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 20 * 8;

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  AF_sha256_transform_S (w0, w1, w2, w3, digest);

  out[0] = swap32_S (digest[0]);
  out[1] = swap32_S (digest[1]);
  out[2] = swap32_S (digest[2]);
  out[3] = swap32_S (digest[3]);
}

DECLSPEC void AF_sha256_diffuse32 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[8];

  // 0 - 31

  w0[0] = 0;
  w0[1] = swap32_S (out[0]);
  w0[2] = swap32_S (out[1]);
  w0[3] = swap32_S (out[2]);
  w1[0] = swap32_S (out[3]);
  w1[1] = swap32_S (out[4]);
  w1[2] = swap32_S (out[5]);
  w1[3] = swap32_S (out[6]);
  w2[0] = swap32_S (out[7]);
  w2[1] = 0x80000000;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 36 * 8;

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  AF_sha256_transform_S (w0, w1, w2, w3, digest);

  out[0] = swap32_S (digest[0]);
  out[1] = swap32_S (digest[1]);
  out[2] = swap32_S (digest[2]);
  out[3] = swap32_S (digest[3]);
  out[4] = swap32_S (digest[4]);
  out[5] = swap32_S (digest[5]);
  out[6] = swap32_S (digest[6]);
  out[7] = swap32_S (digest[7]);
}

DECLSPEC void AF_sha256_diffuse64 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[8];

  // 0 - 31

  w0[0] = 0;
  w0[1] = swap32_S (out[0]);
  w0[2] = swap32_S (out[1]);
  w0[3] = swap32_S (out[2]);
  w1[0] = swap32_S (out[3]);
  w1[1] = swap32_S (out[4]);
  w1[2] = swap32_S (out[5]);
  w1[3] = swap32_S (out[6]);
  w2[0] = swap32_S (out[7]);
  w2[1] = 0x80000000;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 36 * 8;

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  AF_sha256_transform_S (w0, w1, w2, w3, digest);

  out[0] = swap32_S (digest[0]);
  out[1] = swap32_S (digest[1]);
  out[2] = swap32_S (digest[2]);
  out[3] = swap32_S (digest[3]);
  out[4] = swap32_S (digest[4]);
  out[5] = swap32_S (digest[5]);
  out[6] = swap32_S (digest[6]);
  out[7] = swap32_S (digest[7]);

  // 32 - 63

  w0[0] = 1;
  w0[1] = swap32_S (out[ 8]);
  w0[2] = swap32_S (out[ 9]);
  w0[3] = swap32_S (out[10]);
  w1[0] = swap32_S (out[11]);
  w1[1] = swap32_S (out[12]);
  w1[2] = swap32_S (out[13]);
  w1[3] = swap32_S (out[14]);
  w2[0] = swap32_S (out[15]);
  w2[1] = 0x80000000;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 36 * 8;

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  AF_sha256_transform_S (w0, w1, w2, w3, digest);

  out[ 8] = swap32_S (digest[0]);
  out[ 9] = swap32_S (digest[1]);
  out[10] = swap32_S (digest[2]);
  out[11] = swap32_S (digest[3]);
  out[12] = swap32_S (digest[4]);
  out[13] = swap32_S (digest[5]);
  out[14] = swap32_S (digest[6]);
  out[15] = swap32_S (digest[7]);
}

DECLSPEC void AF_sha512_diffuse16 (u32 *out)
{
  u64 w0[4];
  u64 w1[4];
  u64 w2[4];
  u64 w3[4];

  u64 digest[8];

  // 0 - 15

  w0[0] = hl32_to_64_S (                0, swap32_S (out[0]));
  w0[1] = hl32_to_64_S (swap32_S (out[1]), swap32_S (out[2]));
  w0[2] = hl32_to_64_S (swap32_S (out[3]),        0x80000000);
  w0[3] = 0;
  w1[0] = 0;
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
  w3[3] = 20 * 8;

  digest[0] = SHA512M_A;
  digest[1] = SHA512M_B;
  digest[2] = SHA512M_C;
  digest[3] = SHA512M_D;
  digest[4] = SHA512M_E;
  digest[5] = SHA512M_F;
  digest[6] = SHA512M_G;
  digest[7] = SHA512M_H;

  AF_sha512_transform_S (w0, w1, w2, w3, digest);

  out[0] = swap32_S (h32_from_64_S (digest[0]));
  out[1] = swap32_S (l32_from_64_S (digest[0]));
  out[2] = swap32_S (h32_from_64_S (digest[1]));
  out[3] = swap32_S (l32_from_64_S (digest[1]));
}

DECLSPEC void AF_sha512_diffuse32 (u32 *out)
{
  u64 w0[4];
  u64 w1[4];
  u64 w2[4];
  u64 w3[4];

  u64 digest[8];

  // 0 - 31

  w0[0] = hl32_to_64_S (                0, swap32_S (out[0]));
  w0[1] = hl32_to_64_S (swap32_S (out[1]), swap32_S (out[2]));
  w0[2] = hl32_to_64_S (swap32_S (out[3]), swap32_S (out[4]));
  w0[3] = hl32_to_64_S (swap32_S (out[5]), swap32_S (out[6]));
  w1[0] = hl32_to_64_S (swap32_S (out[7]),        0x80000000);
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
  w3[3] = 36 * 8;

  digest[0] = SHA512M_A;
  digest[1] = SHA512M_B;
  digest[2] = SHA512M_C;
  digest[3] = SHA512M_D;
  digest[4] = SHA512M_E;
  digest[5] = SHA512M_F;
  digest[6] = SHA512M_G;
  digest[7] = SHA512M_H;

  AF_sha512_transform_S (w0, w1, w2, w3, digest);

  out[0] = swap32_S (h32_from_64_S (digest[0]));
  out[1] = swap32_S (l32_from_64_S (digest[0]));
  out[2] = swap32_S (h32_from_64_S (digest[1]));
  out[3] = swap32_S (l32_from_64_S (digest[1]));
  out[4] = swap32_S (h32_from_64_S (digest[2]));
  out[5] = swap32_S (l32_from_64_S (digest[2]));
  out[6] = swap32_S (h32_from_64_S (digest[3]));
  out[7] = swap32_S (l32_from_64_S (digest[3]));
}

DECLSPEC void AF_sha512_diffuse64 (u32 *out)
{
  u64 w0[4];
  u64 w1[4];
  u64 w2[4];
  u64 w3[4];

  u64 digest[8];

  // 0 - 63

  w0[0] = hl32_to_64_S (                 0, swap32_S (out[ 0]));
  w0[1] = hl32_to_64_S (swap32_S (out[ 1]), swap32_S (out[ 2]));
  w0[2] = hl32_to_64_S (swap32_S (out[ 3]), swap32_S (out[ 4]));
  w0[3] = hl32_to_64_S (swap32_S (out[ 5]), swap32_S (out[ 6]));
  w1[0] = hl32_to_64_S (swap32_S (out[ 7]), swap32_S (out[ 8]));
  w1[1] = hl32_to_64_S (swap32_S (out[ 9]), swap32_S (out[10]));
  w1[2] = hl32_to_64_S (swap32_S (out[11]), swap32_S (out[12]));
  w1[3] = hl32_to_64_S (swap32_S (out[13]), swap32_S (out[14]));
  w2[0] = hl32_to_64_S (swap32_S (out[15]),         0x80000000);
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 68 * 8;

  digest[0] = SHA512M_A;
  digest[1] = SHA512M_B;
  digest[2] = SHA512M_C;
  digest[3] = SHA512M_D;
  digest[4] = SHA512M_E;
  digest[5] = SHA512M_F;
  digest[6] = SHA512M_G;
  digest[7] = SHA512M_H;

  AF_sha512_transform_S (w0, w1, w2, w3, digest);

  out[ 0] = swap32_S (h32_from_64_S (digest[0]));
  out[ 1] = swap32_S (l32_from_64_S (digest[0]));
  out[ 2] = swap32_S (h32_from_64_S (digest[1]));
  out[ 3] = swap32_S (l32_from_64_S (digest[1]));
  out[ 4] = swap32_S (h32_from_64_S (digest[2]));
  out[ 5] = swap32_S (l32_from_64_S (digest[2]));
  out[ 6] = swap32_S (h32_from_64_S (digest[3]));
  out[ 7] = swap32_S (l32_from_64_S (digest[3]));
  out[ 8] = swap32_S (h32_from_64_S (digest[4]));
  out[ 9] = swap32_S (l32_from_64_S (digest[4]));
  out[10] = swap32_S (h32_from_64_S (digest[5]));
  out[11] = swap32_S (l32_from_64_S (digest[5]));
  out[12] = swap32_S (h32_from_64_S (digest[6]));
  out[13] = swap32_S (l32_from_64_S (digest[6]));
  out[14] = swap32_S (h32_from_64_S (digest[7]));
  out[15] = swap32_S (l32_from_64_S (digest[7]));
}

DECLSPEC void AF_ripemd160_diffuse16 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 15

  w0[0] = 0 << 24;
  w0[1] = out[0];
  w0[2] = out[1];
  w0[3] = out[2];
  w1[0] = out[3];
  w1[1] = 0x80;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 20 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  AF_ripemd160_transform_S (w0, w1, w2, w3, digest);

  out[0] = digest[0];
  out[1] = digest[1];
  out[2] = digest[2];
  out[3] = digest[3];
}

DECLSPEC void AF_ripemd160_diffuse32 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 19

  w0[0] = 0 << 24;
  w0[1] = out[0];
  w0[2] = out[1];
  w0[3] = out[2];
  w1[0] = out[3];
  w1[1] = out[4];
  w1[2] = 0x80;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 24 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  AF_ripemd160_transform_S (w0, w1, w2, w3, digest);

  out[0] = digest[0];
  out[1] = digest[1];
  out[2] = digest[2];
  out[3] = digest[3];
  out[4] = digest[4];

  // 20 - 31

  w0[0] = 1 << 24;
  w0[1] = out[5];
  w0[2] = out[6];
  w0[3] = out[7];
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
  w3[2] = 16 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  AF_ripemd160_transform_S (w0, w1, w2, w3, digest);

  out[5] = digest[0];
  out[6] = digest[1];
  out[7] = digest[2];
}

DECLSPEC void AF_ripemd160_diffuse64 (u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 19

  w0[0] = 0 << 24;
  w0[1] = out[0];
  w0[2] = out[1];
  w0[3] = out[2];
  w1[0] = out[3];
  w1[1] = out[4];
  w1[2] = 0x80;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 24 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  AF_ripemd160_transform_S (w0, w1, w2, w3, digest);

  out[0] = digest[0];
  out[1] = digest[1];
  out[2] = digest[2];
  out[3] = digest[3];
  out[4] = digest[4];

  // 20 - 39

  w0[0] = 1 << 24;
  w0[1] = out[5];
  w0[2] = out[6];
  w0[3] = out[7];
  w1[0] = out[8];
  w1[1] = out[9];
  w1[2] = 0x80;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 24 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  AF_ripemd160_transform_S (w0, w1, w2, w3, digest);

  out[5] = digest[0];
  out[6] = digest[1];
  out[7] = digest[2];
  out[8] = digest[3];
  out[9] = digest[4];

  // 40 - 59

  w0[0] = 2 << 24;
  w0[1] = out[10];
  w0[2] = out[11];
  w0[3] = out[12];
  w1[0] = out[13];
  w1[1] = out[14];
  w1[2] = 0x80;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 24 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  AF_ripemd160_transform_S (w0, w1, w2, w3, digest);

  out[10] = digest[0];
  out[11] = digest[1];
  out[12] = digest[2];
  out[13] = digest[3];
  out[14] = digest[4];

  // 60 - 63

  w0[0] = 3 << 24;
  w0[1] = out[15];
  w0[2] = 0x80;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 8 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  AF_ripemd160_transform_S (w0, w1, w2, w3, digest);

  out[15] = digest[0];
}
