
// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf needs to be in algorithm native byte order (md5 = LE, sha1 = BE, etc)
// input buf needs to be 128 byte aligned when using sha512_update()

__constant u64a k_sha512[80] =
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

typedef struct sha512_ctx
{
  u64 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int len;

} sha512_ctx_t;

DECLSPEC void sha512_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, const u32 *w4, const u32 *w5, const u32 *w6, const u32 *w7, u64 *digest)
{
  u64 a = digest[0];
  u64 b = digest[1];
  u64 c = digest[2];
  u64 d = digest[3];
  u64 e = digest[4];
  u64 f = digest[5];
  u64 g = digest[6];
  u64 h = digest[7];

  u64 w0_t = hl32_to_64_S (w0[0], w0[1]);
  u64 w1_t = hl32_to_64_S (w0[2], w0[3]);
  u64 w2_t = hl32_to_64_S (w1[0], w1[1]);
  u64 w3_t = hl32_to_64_S (w1[2], w1[3]);
  u64 w4_t = hl32_to_64_S (w2[0], w2[1]);
  u64 w5_t = hl32_to_64_S (w2[2], w2[3]);
  u64 w6_t = hl32_to_64_S (w3[0], w3[1]);
  u64 w7_t = hl32_to_64_S (w3[2], w3[3]);
  u64 w8_t = hl32_to_64_S (w4[0], w4[1]);
  u64 w9_t = hl32_to_64_S (w4[2], w4[3]);
  u64 wa_t = hl32_to_64_S (w5[0], w5[1]);
  u64 wb_t = hl32_to_64_S (w5[2], w5[3]);
  u64 wc_t = hl32_to_64_S (w6[0], w6[1]);
  u64 wd_t = hl32_to_64_S (w6[2], w6[3]);
  u64 we_t = hl32_to_64_S (w7[0], w7[1]);
  u64 wf_t = hl32_to_64_S (w7[2], w7[3]);

  #define ROUND_EXPAND_S()                            \
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

  #define ROUND_STEP_S(i)                                                                   \
  {                                                                                         \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP_S (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP_S (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND_S (); ROUND_STEP_S (i);
  }

  #undef ROUND_EXPAND_S
  #undef ROUND_STEP_S

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

DECLSPEC void sha512_init (sha512_ctx_t *ctx)
{
  ctx->h[0] = SHA512M_A;
  ctx->h[1] = SHA512M_B;
  ctx->h[2] = SHA512M_C;
  ctx->h[3] = SHA512M_D;
  ctx->h[4] = SHA512M_E;
  ctx->h[5] = SHA512M_F;
  ctx->h[6] = SHA512M_G;
  ctx->h[7] = SHA512M_H;

  ctx->w0[0] = 0;
  ctx->w0[1] = 0;
  ctx->w0[2] = 0;
  ctx->w0[3] = 0;
  ctx->w1[0] = 0;
  ctx->w1[1] = 0;
  ctx->w1[2] = 0;
  ctx->w1[3] = 0;
  ctx->w2[0] = 0;
  ctx->w2[1] = 0;
  ctx->w2[2] = 0;
  ctx->w2[3] = 0;
  ctx->w3[0] = 0;
  ctx->w3[1] = 0;
  ctx->w3[2] = 0;
  ctx->w3[3] = 0;
  ctx->w4[0] = 0;
  ctx->w4[1] = 0;
  ctx->w4[2] = 0;
  ctx->w4[3] = 0;
  ctx->w5[0] = 0;
  ctx->w5[1] = 0;
  ctx->w5[2] = 0;
  ctx->w5[3] = 0;
  ctx->w6[0] = 0;
  ctx->w6[1] = 0;
  ctx->w6[2] = 0;
  ctx->w6[3] = 0;
  ctx->w7[0] = 0;
  ctx->w7[1] = 0;
  ctx->w7[2] = 0;
  ctx->w7[3] = 0;

  ctx->len = 0;
}

DECLSPEC void sha512_update_128 (sha512_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len)
{
  MAYBE_VOLATILE const int pos = ctx->len & 127;

  ctx->len += len;

  if ((pos + len) < 128)
  {
    switch_buffer_by_offset_8x4_be_S (w0, w1, w2, w3, w4, w5, w6, w7, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];
  }
  else
  {
    u32 c0[4] = { 0 };
    u32 c1[4] = { 0 };
    u32 c2[4] = { 0 };
    u32 c3[4] = { 0 };
    u32 c4[4] = { 0 };
    u32 c5[4] = { 0 };
    u32 c6[4] = { 0 };
    u32 c7[4] = { 0 };

    switch_buffer_by_offset_8x4_carry_be_S (w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3, c4, c5, c6, c7, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];

    sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
    ctx->w4[0] = c4[0];
    ctx->w4[1] = c4[1];
    ctx->w4[2] = c4[2];
    ctx->w4[3] = c4[3];
    ctx->w5[0] = c5[0];
    ctx->w5[1] = c5[1];
    ctx->w5[2] = c5[2];
    ctx->w5[3] = c5[3];
    ctx->w6[0] = c6[0];
    ctx->w6[1] = c6[1];
    ctx->w6[2] = c6[2];
    ctx->w6[3] = c6[3];
    ctx->w7[0] = c7[0];
    ctx->w7[1] = c7[1];
    ctx->w7[2] = c7[2];
    ctx->w7[3] = c7[3];
  }
}

DECLSPEC void sha512_update (sha512_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha512_update_swap (sha512_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);
    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);
    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);
    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = swap32_S (w3[2]);
    w3[3] = swap32_S (w3[3]);
    w4[0] = swap32_S (w4[0]);
    w4[1] = swap32_S (w4[1]);
    w4[2] = swap32_S (w4[2]);
    w4[3] = swap32_S (w4[3]);
    w5[0] = swap32_S (w5[0]);
    w5[1] = swap32_S (w5[1]);
    w5[2] = swap32_S (w5[2]);
    w5[3] = swap32_S (w5[3]);
    w6[0] = swap32_S (w6[0]);
    w6[1] = swap32_S (w6[1]);
    w6[2] = swap32_S (w6[2]);
    w6[3] = swap32_S (w6[3]);
    w7[0] = swap32_S (w7[0]);
    w7[1] = swap32_S (w7[1]);
    w7[2] = swap32_S (w7[2]);
    w7[3] = swap32_S (w7[3]);

    sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);
  w4[0] = swap32_S (w4[0]);
  w4[1] = swap32_S (w4[1]);
  w4[2] = swap32_S (w4[2]);
  w4[3] = swap32_S (w4[3]);
  w5[0] = swap32_S (w5[0]);
  w5[1] = swap32_S (w5[1]);
  w5[2] = swap32_S (w5[2]);
  w5[3] = swap32_S (w5[3]);
  w6[0] = swap32_S (w6[0]);
  w6[1] = swap32_S (w6[1]);
  w6[2] = swap32_S (w6[2]);
  w6[3] = swap32_S (w6[3]);
  w7[0] = swap32_S (w7[0]);
  w7[1] = swap32_S (w7[1]);
  w7[2] = swap32_S (w7[2]);
  w7[3] = swap32_S (w7[3]);

  sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha512_update_utf16le (sha512_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    make_utf16le_S (w3, w6, w7);
    make_utf16le_S (w2, w4, w5);
    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  make_utf16le_S (w3, w6, w7);
  make_utf16le_S (w2, w4, w5);
  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha512_update_utf16le_swap (sha512_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    make_utf16le_S (w3, w6, w7);
    make_utf16le_S (w2, w4, w5);
    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);
    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);
    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);
    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = swap32_S (w3[2]);
    w3[3] = swap32_S (w3[3]);
    w4[0] = swap32_S (w4[0]);
    w4[1] = swap32_S (w4[1]);
    w4[2] = swap32_S (w4[2]);
    w4[3] = swap32_S (w4[3]);
    w5[0] = swap32_S (w5[0]);
    w5[1] = swap32_S (w5[1]);
    w5[2] = swap32_S (w5[2]);
    w5[3] = swap32_S (w5[3]);
    w6[0] = swap32_S (w6[0]);
    w6[1] = swap32_S (w6[1]);
    w6[2] = swap32_S (w6[2]);
    w6[3] = swap32_S (w6[3]);
    w7[0] = swap32_S (w7[0]);
    w7[1] = swap32_S (w7[1]);
    w7[2] = swap32_S (w7[2]);
    w7[3] = swap32_S (w7[3]);

    sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  make_utf16le_S (w3, w6, w7);
  make_utf16le_S (w2, w4, w5);
  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);
  w4[0] = swap32_S (w4[0]);
  w4[1] = swap32_S (w4[1]);
  w4[2] = swap32_S (w4[2]);
  w4[3] = swap32_S (w4[3]);
  w5[0] = swap32_S (w5[0]);
  w5[1] = swap32_S (w5[1]);
  w5[2] = swap32_S (w5[2]);
  w5[3] = swap32_S (w5[3]);
  w6[0] = swap32_S (w6[0]);
  w6[1] = swap32_S (w6[1]);
  w6[2] = swap32_S (w6[2]);
  w6[3] = swap32_S (w6[3]);
  w7[0] = swap32_S (w7[0]);
  w7[1] = swap32_S (w7[1]);
  w7[2] = swap32_S (w7[2]);
  w7[3] = swap32_S (w7[3]);

  sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha512_update_global (sha512_ctx_t *ctx, const __global u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha512_update_global_swap (sha512_ctx_t *ctx, const __global u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);
    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);
    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);
    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = swap32_S (w3[2]);
    w3[3] = swap32_S (w3[3]);
    w4[0] = swap32_S (w4[0]);
    w4[1] = swap32_S (w4[1]);
    w4[2] = swap32_S (w4[2]);
    w4[3] = swap32_S (w4[3]);
    w5[0] = swap32_S (w5[0]);
    w5[1] = swap32_S (w5[1]);
    w5[2] = swap32_S (w5[2]);
    w5[3] = swap32_S (w5[3]);
    w6[0] = swap32_S (w6[0]);
    w6[1] = swap32_S (w6[1]);
    w6[2] = swap32_S (w6[2]);
    w6[3] = swap32_S (w6[3]);
    w7[0] = swap32_S (w7[0]);
    w7[1] = swap32_S (w7[1]);
    w7[2] = swap32_S (w7[2]);
    w7[3] = swap32_S (w7[3]);

    sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);
  w4[0] = swap32_S (w4[0]);
  w4[1] = swap32_S (w4[1]);
  w4[2] = swap32_S (w4[2]);
  w4[3] = swap32_S (w4[3]);
  w5[0] = swap32_S (w5[0]);
  w5[1] = swap32_S (w5[1]);
  w5[2] = swap32_S (w5[2]);
  w5[3] = swap32_S (w5[3]);
  w6[0] = swap32_S (w6[0]);
  w6[1] = swap32_S (w6[1]);
  w6[2] = swap32_S (w6[2]);
  w6[3] = swap32_S (w6[3]);
  w7[0] = swap32_S (w7[0]);
  w7[1] = swap32_S (w7[1]);
  w7[2] = swap32_S (w7[2]);
  w7[3] = swap32_S (w7[3]);

  sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha512_update_global_utf16le (sha512_ctx_t *ctx, const __global u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    make_utf16le_S (w3, w6, w7);
    make_utf16le_S (w2, w4, w5);
    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  make_utf16le_S (w3, w6, w7);
  make_utf16le_S (w2, w4, w5);
  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha512_update_global_utf16le_swap (sha512_ctx_t *ctx, const __global u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    make_utf16le_S (w3, w6, w7);
    make_utf16le_S (w2, w4, w5);
    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = swap32_S (w0[0]);
    w0[1] = swap32_S (w0[1]);
    w0[2] = swap32_S (w0[2]);
    w0[3] = swap32_S (w0[3]);
    w1[0] = swap32_S (w1[0]);
    w1[1] = swap32_S (w1[1]);
    w1[2] = swap32_S (w1[2]);
    w1[3] = swap32_S (w1[3]);
    w2[0] = swap32_S (w2[0]);
    w2[1] = swap32_S (w2[1]);
    w2[2] = swap32_S (w2[2]);
    w2[3] = swap32_S (w2[3]);
    w3[0] = swap32_S (w3[0]);
    w3[1] = swap32_S (w3[1]);
    w3[2] = swap32_S (w3[2]);
    w3[3] = swap32_S (w3[3]);
    w4[0] = swap32_S (w4[0]);
    w4[1] = swap32_S (w4[1]);
    w4[2] = swap32_S (w4[2]);
    w4[3] = swap32_S (w4[3]);
    w5[0] = swap32_S (w5[0]);
    w5[1] = swap32_S (w5[1]);
    w5[2] = swap32_S (w5[2]);
    w5[3] = swap32_S (w5[3]);
    w6[0] = swap32_S (w6[0]);
    w6[1] = swap32_S (w6[1]);
    w6[2] = swap32_S (w6[2]);
    w6[3] = swap32_S (w6[3]);
    w7[0] = swap32_S (w7[0]);
    w7[1] = swap32_S (w7[1]);
    w7[2] = swap32_S (w7[2]);
    w7[3] = swap32_S (w7[3]);

    sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  make_utf16le_S (w3, w6, w7);
  make_utf16le_S (w2, w4, w5);
  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);
  w3[2] = swap32_S (w3[2]);
  w3[3] = swap32_S (w3[3]);
  w4[0] = swap32_S (w4[0]);
  w4[1] = swap32_S (w4[1]);
  w4[2] = swap32_S (w4[2]);
  w4[3] = swap32_S (w4[3]);
  w5[0] = swap32_S (w5[0]);
  w5[1] = swap32_S (w5[1]);
  w5[2] = swap32_S (w5[2]);
  w5[3] = swap32_S (w5[3]);
  w6[0] = swap32_S (w6[0]);
  w6[1] = swap32_S (w6[1]);
  w6[2] = swap32_S (w6[2]);
  w6[3] = swap32_S (w6[3]);
  w7[0] = swap32_S (w7[0]);
  w7[1] = swap32_S (w7[1]);
  w7[2] = swap32_S (w7[2]);
  w7[3] = swap32_S (w7[3]);

  sha512_update_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha512_final (sha512_ctx_t *ctx)
{
  MAYBE_VOLATILE const int pos = ctx->len & 127;

  append_0x80_8x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, pos ^ 3);

  if (pos >= 112)
  {
    sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
    ctx->w4[0] = 0;
    ctx->w4[1] = 0;
    ctx->w4[2] = 0;
    ctx->w4[3] = 0;
    ctx->w5[0] = 0;
    ctx->w5[1] = 0;
    ctx->w5[2] = 0;
    ctx->w5[3] = 0;
    ctx->w6[0] = 0;
    ctx->w6[1] = 0;
    ctx->w6[2] = 0;
    ctx->w6[3] = 0;
    ctx->w7[0] = 0;
    ctx->w7[1] = 0;
    ctx->w7[2] = 0;
    ctx->w7[3] = 0;
  }

  ctx->w7[2] = 0;
  ctx->w7[3] = ctx->len * 8;

  sha512_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);
}

// sha512_hmac

typedef struct sha512_hmac_ctx
{
  sha512_ctx_t ipad;
  sha512_ctx_t opad;

} sha512_hmac_ctx_t;

DECLSPEC void sha512_hmac_init_128 (sha512_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, const u32 *w4, const u32 *w5, const u32 *w6, const u32 *w7)
{
  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];
  u32 t4[4];
  u32 t5[4];
  u32 t6[4];
  u32 t7[4];

  // ipad

  t0[0] = w0[0] ^ 0x36363636;
  t0[1] = w0[1] ^ 0x36363636;
  t0[2] = w0[2] ^ 0x36363636;
  t0[3] = w0[3] ^ 0x36363636;
  t1[0] = w1[0] ^ 0x36363636;
  t1[1] = w1[1] ^ 0x36363636;
  t1[2] = w1[2] ^ 0x36363636;
  t1[3] = w1[3] ^ 0x36363636;
  t2[0] = w2[0] ^ 0x36363636;
  t2[1] = w2[1] ^ 0x36363636;
  t2[2] = w2[2] ^ 0x36363636;
  t2[3] = w2[3] ^ 0x36363636;
  t3[0] = w3[0] ^ 0x36363636;
  t3[1] = w3[1] ^ 0x36363636;
  t3[2] = w3[2] ^ 0x36363636;
  t3[3] = w3[3] ^ 0x36363636;
  t4[0] = w4[0] ^ 0x36363636;
  t4[1] = w4[1] ^ 0x36363636;
  t4[2] = w4[2] ^ 0x36363636;
  t4[3] = w4[3] ^ 0x36363636;
  t5[0] = w5[0] ^ 0x36363636;
  t5[1] = w5[1] ^ 0x36363636;
  t5[2] = w5[2] ^ 0x36363636;
  t5[3] = w5[3] ^ 0x36363636;
  t6[0] = w6[0] ^ 0x36363636;
  t6[1] = w6[1] ^ 0x36363636;
  t6[2] = w6[2] ^ 0x36363636;
  t6[3] = w6[3] ^ 0x36363636;
  t7[0] = w7[0] ^ 0x36363636;
  t7[1] = w7[1] ^ 0x36363636;
  t7[2] = w7[2] ^ 0x36363636;
  t7[3] = w7[3] ^ 0x36363636;

  sha512_init (&ctx->ipad);

  sha512_update_128 (&ctx->ipad, t0, t1, t2, t3, t4, t5, t6, t7, 128);

  // opad

  t0[0] = w0[0] ^ 0x5c5c5c5c;
  t0[1] = w0[1] ^ 0x5c5c5c5c;
  t0[2] = w0[2] ^ 0x5c5c5c5c;
  t0[3] = w0[3] ^ 0x5c5c5c5c;
  t1[0] = w1[0] ^ 0x5c5c5c5c;
  t1[1] = w1[1] ^ 0x5c5c5c5c;
  t1[2] = w1[2] ^ 0x5c5c5c5c;
  t1[3] = w1[3] ^ 0x5c5c5c5c;
  t2[0] = w2[0] ^ 0x5c5c5c5c;
  t2[1] = w2[1] ^ 0x5c5c5c5c;
  t2[2] = w2[2] ^ 0x5c5c5c5c;
  t2[3] = w2[3] ^ 0x5c5c5c5c;
  t3[0] = w3[0] ^ 0x5c5c5c5c;
  t3[1] = w3[1] ^ 0x5c5c5c5c;
  t3[2] = w3[2] ^ 0x5c5c5c5c;
  t3[3] = w3[3] ^ 0x5c5c5c5c;
  t4[0] = w4[0] ^ 0x5c5c5c5c;
  t4[1] = w4[1] ^ 0x5c5c5c5c;
  t4[2] = w4[2] ^ 0x5c5c5c5c;
  t4[3] = w4[3] ^ 0x5c5c5c5c;
  t5[0] = w5[0] ^ 0x5c5c5c5c;
  t5[1] = w5[1] ^ 0x5c5c5c5c;
  t5[2] = w5[2] ^ 0x5c5c5c5c;
  t5[3] = w5[3] ^ 0x5c5c5c5c;
  t6[0] = w6[0] ^ 0x5c5c5c5c;
  t6[1] = w6[1] ^ 0x5c5c5c5c;
  t6[2] = w6[2] ^ 0x5c5c5c5c;
  t6[3] = w6[3] ^ 0x5c5c5c5c;
  t7[0] = w7[0] ^ 0x5c5c5c5c;
  t7[1] = w7[1] ^ 0x5c5c5c5c;
  t7[2] = w7[2] ^ 0x5c5c5c5c;
  t7[3] = w7[3] ^ 0x5c5c5c5c;

  sha512_init (&ctx->opad);

  sha512_update_128 (&ctx->opad, t0, t1, t2, t3, t4, t5, t6, t7, 128);
}

DECLSPEC void sha512_hmac_init (sha512_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  if (len > 128)
  {
    sha512_ctx_t tmp;

    sha512_init (&tmp);

    sha512_update (&tmp, w, len);

    sha512_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[0]);
    w0[1] = l32_from_64_S (tmp.h[0]);
    w0[2] = h32_from_64_S (tmp.h[1]);
    w0[3] = l32_from_64_S (tmp.h[1]);
    w1[0] = h32_from_64_S (tmp.h[2]);
    w1[1] = l32_from_64_S (tmp.h[2]);
    w1[2] = h32_from_64_S (tmp.h[3]);
    w1[3] = l32_from_64_S (tmp.h[3]);
    w2[0] = h32_from_64_S (tmp.h[4]);
    w2[1] = l32_from_64_S (tmp.h[4]);
    w2[2] = h32_from_64_S (tmp.h[5]);
    w2[3] = l32_from_64_S (tmp.h[5]);
    w3[0] = h32_from_64_S (tmp.h[6]);
    w3[1] = l32_from_64_S (tmp.h[6]);
    w3[2] = h32_from_64_S (tmp.h[7]);
    w3[3] = l32_from_64_S (tmp.h[7]);
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
    w4[0] = w[16];
    w4[1] = w[17];
    w4[2] = w[18];
    w4[3] = w[19];
    w5[0] = w[20];
    w5[1] = w[21];
    w5[2] = w[22];
    w5[3] = w[23];
    w6[0] = w[24];
    w6[1] = w[25];
    w6[2] = w[26];
    w6[3] = w[27];
    w7[0] = w[28];
    w7[1] = w[29];
    w7[2] = w[30];
    w7[3] = w[31];
  }

  sha512_hmac_init_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha512_hmac_init_swap (sha512_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  if (len > 128)
  {
    sha512_ctx_t tmp;

    sha512_init (&tmp);

    sha512_update_swap (&tmp, w, len);

    sha512_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[0]);
    w0[1] = l32_from_64_S (tmp.h[0]);
    w0[2] = h32_from_64_S (tmp.h[1]);
    w0[3] = l32_from_64_S (tmp.h[1]);
    w1[0] = h32_from_64_S (tmp.h[2]);
    w1[1] = l32_from_64_S (tmp.h[2]);
    w1[2] = h32_from_64_S (tmp.h[3]);
    w1[3] = l32_from_64_S (tmp.h[3]);
    w2[0] = h32_from_64_S (tmp.h[4]);
    w2[1] = l32_from_64_S (tmp.h[4]);
    w2[2] = h32_from_64_S (tmp.h[5]);
    w2[3] = l32_from_64_S (tmp.h[5]);
    w3[0] = h32_from_64_S (tmp.h[6]);
    w3[1] = l32_from_64_S (tmp.h[6]);
    w3[2] = h32_from_64_S (tmp.h[7]);
    w3[3] = l32_from_64_S (tmp.h[7]);
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;
  }
  else
  {
    w0[0] = swap32_S (w[ 0]);
    w0[1] = swap32_S (w[ 1]);
    w0[2] = swap32_S (w[ 2]);
    w0[3] = swap32_S (w[ 3]);
    w1[0] = swap32_S (w[ 4]);
    w1[1] = swap32_S (w[ 5]);
    w1[2] = swap32_S (w[ 6]);
    w1[3] = swap32_S (w[ 7]);
    w2[0] = swap32_S (w[ 8]);
    w2[1] = swap32_S (w[ 9]);
    w2[2] = swap32_S (w[10]);
    w2[3] = swap32_S (w[11]);
    w3[0] = swap32_S (w[12]);
    w3[1] = swap32_S (w[13]);
    w3[2] = swap32_S (w[14]);
    w3[3] = swap32_S (w[15]);
    w4[0] = swap32_S (w[16]);
    w4[1] = swap32_S (w[17]);
    w4[2] = swap32_S (w[18]);
    w4[3] = swap32_S (w[19]);
    w5[0] = swap32_S (w[20]);
    w5[1] = swap32_S (w[21]);
    w5[2] = swap32_S (w[22]);
    w5[3] = swap32_S (w[23]);
    w6[0] = swap32_S (w[24]);
    w6[1] = swap32_S (w[25]);
    w6[2] = swap32_S (w[26]);
    w6[3] = swap32_S (w[27]);
    w7[0] = swap32_S (w[28]);
    w7[1] = swap32_S (w[29]);
    w7[2] = swap32_S (w[30]);
    w7[3] = swap32_S (w[31]);
  }

  sha512_hmac_init_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha512_hmac_init_global (sha512_hmac_ctx_t *ctx, __global const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  if (len > 128)
  {
    sha512_ctx_t tmp;

    sha512_init (&tmp);

    sha512_update_global (&tmp, w, len);

    sha512_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[0]);
    w0[1] = l32_from_64_S (tmp.h[0]);
    w0[2] = h32_from_64_S (tmp.h[1]);
    w0[3] = l32_from_64_S (tmp.h[1]);
    w1[0] = h32_from_64_S (tmp.h[2]);
    w1[1] = l32_from_64_S (tmp.h[2]);
    w1[2] = h32_from_64_S (tmp.h[3]);
    w1[3] = l32_from_64_S (tmp.h[3]);
    w2[0] = h32_from_64_S (tmp.h[4]);
    w2[1] = l32_from_64_S (tmp.h[4]);
    w2[2] = h32_from_64_S (tmp.h[5]);
    w2[3] = l32_from_64_S (tmp.h[5]);
    w3[0] = h32_from_64_S (tmp.h[6]);
    w3[1] = l32_from_64_S (tmp.h[6]);
    w3[2] = h32_from_64_S (tmp.h[7]);
    w3[3] = l32_from_64_S (tmp.h[7]);
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
    w4[0] = w[16];
    w4[1] = w[17];
    w4[2] = w[18];
    w4[3] = w[19];
    w5[0] = w[20];
    w5[1] = w[21];
    w5[2] = w[22];
    w5[3] = w[23];
    w6[0] = w[24];
    w6[1] = w[25];
    w6[2] = w[26];
    w6[3] = w[27];
    w7[0] = w[28];
    w7[1] = w[29];
    w7[2] = w[30];
    w7[3] = w[31];
  }

  sha512_hmac_init_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha512_hmac_init_global_swap (sha512_hmac_ctx_t *ctx, __global const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  if (len > 128)
  {
    sha512_ctx_t tmp;

    sha512_init (&tmp);

    sha512_update_global_swap (&tmp, w, len);

    sha512_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[0]);
    w0[1] = l32_from_64_S (tmp.h[0]);
    w0[2] = h32_from_64_S (tmp.h[1]);
    w0[3] = l32_from_64_S (tmp.h[1]);
    w1[0] = h32_from_64_S (tmp.h[2]);
    w1[1] = l32_from_64_S (tmp.h[2]);
    w1[2] = h32_from_64_S (tmp.h[3]);
    w1[3] = l32_from_64_S (tmp.h[3]);
    w2[0] = h32_from_64_S (tmp.h[4]);
    w2[1] = l32_from_64_S (tmp.h[4]);
    w2[2] = h32_from_64_S (tmp.h[5]);
    w2[3] = l32_from_64_S (tmp.h[5]);
    w3[0] = h32_from_64_S (tmp.h[6]);
    w3[1] = l32_from_64_S (tmp.h[6]);
    w3[2] = h32_from_64_S (tmp.h[7]);
    w3[3] = l32_from_64_S (tmp.h[7]);
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;
  }
  else
  {
    w0[0] = swap32_S (w[ 0]);
    w0[1] = swap32_S (w[ 1]);
    w0[2] = swap32_S (w[ 2]);
    w0[3] = swap32_S (w[ 3]);
    w1[0] = swap32_S (w[ 4]);
    w1[1] = swap32_S (w[ 5]);
    w1[2] = swap32_S (w[ 6]);
    w1[3] = swap32_S (w[ 7]);
    w2[0] = swap32_S (w[ 8]);
    w2[1] = swap32_S (w[ 9]);
    w2[2] = swap32_S (w[10]);
    w2[3] = swap32_S (w[11]);
    w3[0] = swap32_S (w[12]);
    w3[1] = swap32_S (w[13]);
    w3[2] = swap32_S (w[14]);
    w3[3] = swap32_S (w[15]);
    w4[0] = swap32_S (w[16]);
    w4[1] = swap32_S (w[17]);
    w4[2] = swap32_S (w[18]);
    w4[3] = swap32_S (w[19]);
    w5[0] = swap32_S (w[20]);
    w5[1] = swap32_S (w[21]);
    w5[2] = swap32_S (w[22]);
    w5[3] = swap32_S (w[23]);
    w6[0] = swap32_S (w[24]);
    w6[1] = swap32_S (w[25]);
    w6[2] = swap32_S (w[26]);
    w6[3] = swap32_S (w[27]);
    w7[0] = swap32_S (w[28]);
    w7[1] = swap32_S (w[29]);
    w7[2] = swap32_S (w[30]);
    w7[3] = swap32_S (w[31]);
  }

  sha512_hmac_init_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha512_hmac_update_128 (sha512_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, u32 *w4, u32 *w5, u32 *w6, u32 *w7, const int len)
{
  sha512_update_128 (&ctx->ipad, w0, w1, w2, w3, w4, w5, w6, w7, len);
}

DECLSPEC void sha512_hmac_update (sha512_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  sha512_update (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_update_swap (sha512_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  sha512_update_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_update_utf16le (sha512_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  sha512_update_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_update_utf16le_swap (sha512_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  sha512_update_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_update_global (sha512_hmac_ctx_t *ctx, const __global u32 *w, const int len)
{
  sha512_update_global (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_update_global_swap (sha512_hmac_ctx_t *ctx, const __global u32 *w, const int len)
{
  sha512_update_global_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_update_global_utf16le (sha512_hmac_ctx_t *ctx, const __global u32 *w, const int len)
{
  sha512_update_global_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_update_global_utf16le_swap (sha512_hmac_ctx_t *ctx, const __global u32 *w, const int len)
{
  sha512_update_global_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_final (sha512_hmac_ctx_t *ctx)
{
  sha512_final (&ctx->ipad);

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];
  u32 t4[4];
  u32 t5[4];
  u32 t6[4];
  u32 t7[4];

  t0[0] = h32_from_64_S (ctx->ipad.h[0]);
  t0[1] = l32_from_64_S (ctx->ipad.h[0]);
  t0[2] = h32_from_64_S (ctx->ipad.h[1]);
  t0[3] = l32_from_64_S (ctx->ipad.h[1]);
  t1[0] = h32_from_64_S (ctx->ipad.h[2]);
  t1[1] = l32_from_64_S (ctx->ipad.h[2]);
  t1[2] = h32_from_64_S (ctx->ipad.h[3]);
  t1[3] = l32_from_64_S (ctx->ipad.h[3]);
  t2[0] = h32_from_64_S (ctx->ipad.h[4]);
  t2[1] = l32_from_64_S (ctx->ipad.h[4]);
  t2[2] = h32_from_64_S (ctx->ipad.h[5]);
  t2[3] = l32_from_64_S (ctx->ipad.h[5]);
  t3[0] = h32_from_64_S (ctx->ipad.h[6]);
  t3[1] = l32_from_64_S (ctx->ipad.h[6]);
  t3[2] = h32_from_64_S (ctx->ipad.h[7]);
  t3[3] = l32_from_64_S (ctx->ipad.h[7]);
  t4[0] = 0;
  t4[1] = 0;
  t4[2] = 0;
  t4[3] = 0;
  t5[0] = 0;
  t5[1] = 0;
  t5[2] = 0;
  t5[3] = 0;
  t6[0] = 0;
  t6[1] = 0;
  t6[2] = 0;
  t6[3] = 0;
  t7[0] = 0;
  t7[1] = 0;
  t7[2] = 0;
  t7[3] = 0;

  sha512_update_128 (&ctx->opad, t0, t1, t2, t3, t4, t5, t6, t7, 64);

  sha512_final (&ctx->opad);
}

// while input buf can be a vector datatype, the length of the different elements can not

typedef struct sha512_ctx_vector
{
  u64x h[8];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  int  len;

} sha512_ctx_vector_t;

DECLSPEC void sha512_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, const u32x *w4, const u32x *w5, const u32x *w6, const u32x *w7, u64x *digest)
{
  u64x a = digest[0];
  u64x b = digest[1];
  u64x c = digest[2];
  u64x d = digest[3];
  u64x e = digest[4];
  u64x f = digest[5];
  u64x g = digest[6];
  u64x h = digest[7];

  u64x w0_t = hl32_to_64 (w0[0], w0[1]);
  u64x w1_t = hl32_to_64 (w0[2], w0[3]);
  u64x w2_t = hl32_to_64 (w1[0], w1[1]);
  u64x w3_t = hl32_to_64 (w1[2], w1[3]);
  u64x w4_t = hl32_to_64 (w2[0], w2[1]);
  u64x w5_t = hl32_to_64 (w2[2], w2[3]);
  u64x w6_t = hl32_to_64 (w3[0], w3[1]);
  u64x w7_t = hl32_to_64 (w3[2], w3[3]);
  u64x w8_t = hl32_to_64 (w4[0], w4[1]);
  u64x w9_t = hl32_to_64 (w4[2], w4[3]);
  u64x wa_t = hl32_to_64 (w5[0], w5[1]);
  u64x wb_t = hl32_to_64 (w5[2], w5[3]);
  u64x wc_t = hl32_to_64 (w6[0], w6[1]);
  u64x wd_t = hl32_to_64 (w6[2], w6[3]);
  u64x we_t = hl32_to_64 (w7[0], w7[1]);
  u64x wf_t = hl32_to_64 (w7[2], w7[3]);

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }

  #undef ROUND_EXPAND
  #undef ROUND_STEP

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}

DECLSPEC void sha512_init_vector (sha512_ctx_vector_t *ctx)
{
  ctx->h[0] = SHA512M_A;
  ctx->h[1] = SHA512M_B;
  ctx->h[2] = SHA512M_C;
  ctx->h[3] = SHA512M_D;
  ctx->h[4] = SHA512M_E;
  ctx->h[5] = SHA512M_F;
  ctx->h[6] = SHA512M_G;
  ctx->h[7] = SHA512M_H;

  ctx->w0[0] = 0;
  ctx->w0[1] = 0;
  ctx->w0[2] = 0;
  ctx->w0[3] = 0;
  ctx->w1[0] = 0;
  ctx->w1[1] = 0;
  ctx->w1[2] = 0;
  ctx->w1[3] = 0;
  ctx->w2[0] = 0;
  ctx->w2[1] = 0;
  ctx->w2[2] = 0;
  ctx->w2[3] = 0;
  ctx->w3[0] = 0;
  ctx->w3[1] = 0;
  ctx->w3[2] = 0;
  ctx->w3[3] = 0;
  ctx->w4[0] = 0;
  ctx->w4[1] = 0;
  ctx->w4[2] = 0;
  ctx->w4[3] = 0;
  ctx->w5[0] = 0;
  ctx->w5[1] = 0;
  ctx->w5[2] = 0;
  ctx->w5[3] = 0;
  ctx->w6[0] = 0;
  ctx->w6[1] = 0;
  ctx->w6[2] = 0;
  ctx->w6[3] = 0;
  ctx->w7[0] = 0;
  ctx->w7[1] = 0;
  ctx->w7[2] = 0;
  ctx->w7[3] = 0;

  ctx->len = 0;
}

DECLSPEC void sha512_init_vector_from_scalar (sha512_ctx_vector_t *ctx, sha512_ctx_t *ctx0)
{
  ctx->h[0] = ctx0->h[0];
  ctx->h[1] = ctx0->h[1];
  ctx->h[2] = ctx0->h[2];
  ctx->h[3] = ctx0->h[3];
  ctx->h[4] = ctx0->h[4];
  ctx->h[5] = ctx0->h[5];
  ctx->h[6] = ctx0->h[6];
  ctx->h[7] = ctx0->h[7];

  ctx->w0[0] = ctx0->w0[0];
  ctx->w0[1] = ctx0->w0[1];
  ctx->w0[2] = ctx0->w0[2];
  ctx->w0[3] = ctx0->w0[3];
  ctx->w1[0] = ctx0->w1[0];
  ctx->w1[1] = ctx0->w1[1];
  ctx->w1[2] = ctx0->w1[2];
  ctx->w1[3] = ctx0->w1[3];
  ctx->w2[0] = ctx0->w2[0];
  ctx->w2[1] = ctx0->w2[1];
  ctx->w2[2] = ctx0->w2[2];
  ctx->w2[3] = ctx0->w2[3];
  ctx->w3[0] = ctx0->w3[0];
  ctx->w3[1] = ctx0->w3[1];
  ctx->w3[2] = ctx0->w3[2];
  ctx->w3[3] = ctx0->w3[3];
  ctx->w4[0] = ctx0->w4[0];
  ctx->w4[1] = ctx0->w4[1];
  ctx->w4[2] = ctx0->w4[2];
  ctx->w4[3] = ctx0->w4[3];
  ctx->w5[0] = ctx0->w5[0];
  ctx->w5[1] = ctx0->w5[1];
  ctx->w5[2] = ctx0->w5[2];
  ctx->w5[3] = ctx0->w5[3];
  ctx->w6[0] = ctx0->w6[0];
  ctx->w6[1] = ctx0->w6[1];
  ctx->w6[2] = ctx0->w6[2];
  ctx->w6[3] = ctx0->w6[3];
  ctx->w7[0] = ctx0->w7[0];
  ctx->w7[1] = ctx0->w7[1];
  ctx->w7[2] = ctx0->w7[2];
  ctx->w7[3] = ctx0->w7[3];

  ctx->len = ctx0->len;
}

DECLSPEC void sha512_update_vector_128 (sha512_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const int len)
{
  MAYBE_VOLATILE const int pos = ctx->len & 127;

  ctx->len += len;

  if ((pos + len) < 128)
  {
    switch_buffer_by_offset_8x4_be (w0, w1, w2, w3, w4, w5, w6, w7, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];
  }
  else
  {
    u32x c0[4] = { 0 };
    u32x c1[4] = { 0 };
    u32x c2[4] = { 0 };
    u32x c3[4] = { 0 };
    u32x c4[4] = { 0 };
    u32x c5[4] = { 0 };
    u32x c6[4] = { 0 };
    u32x c7[4] = { 0 };

    switch_buffer_by_offset_8x4_carry_be (w0, w1, w2, w3, w4, w5, w6, w7, c0, c1, c2, c3, c4, c5, c6, c7, pos);

    ctx->w0[0] |= w0[0];
    ctx->w0[1] |= w0[1];
    ctx->w0[2] |= w0[2];
    ctx->w0[3] |= w0[3];
    ctx->w1[0] |= w1[0];
    ctx->w1[1] |= w1[1];
    ctx->w1[2] |= w1[2];
    ctx->w1[3] |= w1[3];
    ctx->w2[0] |= w2[0];
    ctx->w2[1] |= w2[1];
    ctx->w2[2] |= w2[2];
    ctx->w2[3] |= w2[3];
    ctx->w3[0] |= w3[0];
    ctx->w3[1] |= w3[1];
    ctx->w3[2] |= w3[2];
    ctx->w3[3] |= w3[3];
    ctx->w4[0] |= w4[0];
    ctx->w4[1] |= w4[1];
    ctx->w4[2] |= w4[2];
    ctx->w4[3] |= w4[3];
    ctx->w5[0] |= w5[0];
    ctx->w5[1] |= w5[1];
    ctx->w5[2] |= w5[2];
    ctx->w5[3] |= w5[3];
    ctx->w6[0] |= w6[0];
    ctx->w6[1] |= w6[1];
    ctx->w6[2] |= w6[2];
    ctx->w6[3] |= w6[3];
    ctx->w7[0] |= w7[0];
    ctx->w7[1] |= w7[1];
    ctx->w7[2] |= w7[2];
    ctx->w7[3] |= w7[3];

    sha512_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = c0[0];
    ctx->w0[1] = c0[1];
    ctx->w0[2] = c0[2];
    ctx->w0[3] = c0[3];
    ctx->w1[0] = c1[0];
    ctx->w1[1] = c1[1];
    ctx->w1[2] = c1[2];
    ctx->w1[3] = c1[3];
    ctx->w2[0] = c2[0];
    ctx->w2[1] = c2[1];
    ctx->w2[2] = c2[2];
    ctx->w2[3] = c2[3];
    ctx->w3[0] = c3[0];
    ctx->w3[1] = c3[1];
    ctx->w3[2] = c3[2];
    ctx->w3[3] = c3[3];
    ctx->w4[0] = c4[0];
    ctx->w4[1] = c4[1];
    ctx->w4[2] = c4[2];
    ctx->w4[3] = c4[3];
    ctx->w5[0] = c5[0];
    ctx->w5[1] = c5[1];
    ctx->w5[2] = c5[2];
    ctx->w5[3] = c5[3];
    ctx->w6[0] = c6[0];
    ctx->w6[1] = c6[1];
    ctx->w6[2] = c6[2];
    ctx->w6[3] = c6[3];
    ctx->w7[0] = c7[0];
    ctx->w7[1] = c7[1];
    ctx->w7[2] = c7[2];
    ctx->w7[3] = c7[3];
  }
}

DECLSPEC void sha512_update_vector (sha512_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha512_update_vector_swap (sha512_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 128; pos1 += 128, pos4 += 32)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];
    w4[0] = w[pos4 + 16];
    w4[1] = w[pos4 + 17];
    w4[2] = w[pos4 + 18];
    w4[3] = w[pos4 + 19];
    w5[0] = w[pos4 + 20];
    w5[1] = w[pos4 + 21];
    w5[2] = w[pos4 + 22];
    w5[3] = w[pos4 + 23];
    w6[0] = w[pos4 + 24];
    w6[1] = w[pos4 + 25];
    w6[2] = w[pos4 + 26];
    w6[3] = w[pos4 + 27];
    w7[0] = w[pos4 + 28];
    w7[1] = w[pos4 + 29];
    w7[2] = w[pos4 + 30];
    w7[3] = w[pos4 + 31];

    w0[0] = swap32 (w0[0]);
    w0[1] = swap32 (w0[1]);
    w0[2] = swap32 (w0[2]);
    w0[3] = swap32 (w0[3]);
    w1[0] = swap32 (w1[0]);
    w1[1] = swap32 (w1[1]);
    w1[2] = swap32 (w1[2]);
    w1[3] = swap32 (w1[3]);
    w2[0] = swap32 (w2[0]);
    w2[1] = swap32 (w2[1]);
    w2[2] = swap32 (w2[2]);
    w2[3] = swap32 (w2[3]);
    w3[0] = swap32 (w3[0]);
    w3[1] = swap32 (w3[1]);
    w3[2] = swap32 (w3[2]);
    w3[3] = swap32 (w3[3]);
    w4[0] = swap32 (w4[0]);
    w4[1] = swap32 (w4[1]);
    w4[2] = swap32 (w4[2]);
    w4[3] = swap32 (w4[3]);
    w5[0] = swap32 (w5[0]);
    w5[1] = swap32 (w5[1]);
    w5[2] = swap32 (w5[2]);
    w5[3] = swap32 (w5[3]);
    w6[0] = swap32 (w6[0]);
    w6[1] = swap32 (w6[1]);
    w6[2] = swap32 (w6[2]);
    w6[3] = swap32 (w6[3]);
    w7[0] = swap32 (w7[0]);
    w7[1] = swap32 (w7[1]);
    w7[2] = swap32 (w7[2]);
    w7[3] = swap32 (w7[3]);

    sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 128);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];
  w4[0] = w[pos4 + 16];
  w4[1] = w[pos4 + 17];
  w4[2] = w[pos4 + 18];
  w4[3] = w[pos4 + 19];
  w5[0] = w[pos4 + 20];
  w5[1] = w[pos4 + 21];
  w5[2] = w[pos4 + 22];
  w5[3] = w[pos4 + 23];
  w6[0] = w[pos4 + 24];
  w6[1] = w[pos4 + 25];
  w6[2] = w[pos4 + 26];
  w6[3] = w[pos4 + 27];
  w7[0] = w[pos4 + 28];
  w7[1] = w[pos4 + 29];
  w7[2] = w[pos4 + 30];
  w7[3] = w[pos4 + 31];

  w0[0] = swap32 (w0[0]);
  w0[1] = swap32 (w0[1]);
  w0[2] = swap32 (w0[2]);
  w0[3] = swap32 (w0[3]);
  w1[0] = swap32 (w1[0]);
  w1[1] = swap32 (w1[1]);
  w1[2] = swap32 (w1[2]);
  w1[3] = swap32 (w1[3]);
  w2[0] = swap32 (w2[0]);
  w2[1] = swap32 (w2[1]);
  w2[2] = swap32 (w2[2]);
  w2[3] = swap32 (w2[3]);
  w3[0] = swap32 (w3[0]);
  w3[1] = swap32 (w3[1]);
  w3[2] = swap32 (w3[2]);
  w3[3] = swap32 (w3[3]);
  w4[0] = swap32 (w4[0]);
  w4[1] = swap32 (w4[1]);
  w4[2] = swap32 (w4[2]);
  w4[3] = swap32 (w4[3]);
  w5[0] = swap32 (w5[0]);
  w5[1] = swap32 (w5[1]);
  w5[2] = swap32 (w5[2]);
  w5[3] = swap32 (w5[3]);
  w6[0] = swap32 (w6[0]);
  w6[1] = swap32 (w6[1]);
  w6[2] = swap32 (w6[2]);
  w6[3] = swap32 (w6[3]);
  w7[0] = swap32 (w7[0]);
  w7[1] = swap32 (w7[1]);
  w7[2] = swap32 (w7[2]);
  w7[3] = swap32 (w7[3]);

  sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, len - pos1);
}

DECLSPEC void sha512_update_vector_utf16le (sha512_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    make_utf16le (w3, w6, w7);
    make_utf16le (w2, w4, w5);
    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  make_utf16le (w3, w6, w7);
  make_utf16le (w2, w4, w5);
  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha512_update_vector_utf16le_swap (sha512_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    make_utf16le (w3, w6, w7);
    make_utf16le (w2, w4, w5);
    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w0[0] = swap32 (w0[0]);
    w0[1] = swap32 (w0[1]);
    w0[2] = swap32 (w0[2]);
    w0[3] = swap32 (w0[3]);
    w1[0] = swap32 (w1[0]);
    w1[1] = swap32 (w1[1]);
    w1[2] = swap32 (w1[2]);
    w1[3] = swap32 (w1[3]);
    w2[0] = swap32 (w2[0]);
    w2[1] = swap32 (w2[1]);
    w2[2] = swap32 (w2[2]);
    w2[3] = swap32 (w2[3]);
    w3[0] = swap32 (w3[0]);
    w3[1] = swap32 (w3[1]);
    w3[2] = swap32 (w3[2]);
    w3[3] = swap32 (w3[3]);
    w4[0] = swap32 (w4[0]);
    w4[1] = swap32 (w4[1]);
    w4[2] = swap32 (w4[2]);
    w4[3] = swap32 (w4[3]);
    w5[0] = swap32 (w5[0]);
    w5[1] = swap32 (w5[1]);
    w5[2] = swap32 (w5[2]);
    w5[3] = swap32 (w5[3]);
    w6[0] = swap32 (w6[0]);
    w6[1] = swap32 (w6[1]);
    w6[2] = swap32 (w6[2]);
    w6[3] = swap32 (w6[3]);
    w7[0] = swap32 (w7[0]);
    w7[1] = swap32 (w7[1]);
    w7[2] = swap32 (w7[2]);
    w7[3] = swap32 (w7[3]);

    sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  make_utf16le (w3, w6, w7);
  make_utf16le (w2, w4, w5);
  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  w0[0] = swap32 (w0[0]);
  w0[1] = swap32 (w0[1]);
  w0[2] = swap32 (w0[2]);
  w0[3] = swap32 (w0[3]);
  w1[0] = swap32 (w1[0]);
  w1[1] = swap32 (w1[1]);
  w1[2] = swap32 (w1[2]);
  w1[3] = swap32 (w1[3]);
  w2[0] = swap32 (w2[0]);
  w2[1] = swap32 (w2[1]);
  w2[2] = swap32 (w2[2]);
  w2[3] = swap32 (w2[3]);
  w3[0] = swap32 (w3[0]);
  w3[1] = swap32 (w3[1]);
  w3[2] = swap32 (w3[2]);
  w3[3] = swap32 (w3[3]);
  w4[0] = swap32 (w4[0]);
  w4[1] = swap32 (w4[1]);
  w4[2] = swap32 (w4[2]);
  w4[3] = swap32 (w4[3]);
  w5[0] = swap32 (w5[0]);
  w5[1] = swap32 (w5[1]);
  w5[2] = swap32 (w5[2]);
  w5[3] = swap32 (w5[3]);
  w6[0] = swap32 (w6[0]);
  w6[1] = swap32 (w6[1]);
  w6[2] = swap32 (w6[2]);
  w6[3] = swap32 (w6[3]);
  w7[0] = swap32 (w7[0]);
  w7[1] = swap32 (w7[1]);
  w7[2] = swap32 (w7[2]);
  w7[3] = swap32 (w7[3]);

  sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha512_update_vector_utf16beN (sha512_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 64; pos1 += 64, pos4 += 16)
  {
    w0[0] = w[pos4 +  0];
    w0[1] = w[pos4 +  1];
    w0[2] = w[pos4 +  2];
    w0[3] = w[pos4 +  3];
    w1[0] = w[pos4 +  4];
    w1[1] = w[pos4 +  5];
    w1[2] = w[pos4 +  6];
    w1[3] = w[pos4 +  7];
    w2[0] = w[pos4 +  8];
    w2[1] = w[pos4 +  9];
    w2[2] = w[pos4 + 10];
    w2[3] = w[pos4 + 11];
    w3[0] = w[pos4 + 12];
    w3[1] = w[pos4 + 13];
    w3[2] = w[pos4 + 14];
    w3[3] = w[pos4 + 15];

    make_utf16beN (w3, w6, w7);
    make_utf16beN (w2, w4, w5);
    make_utf16beN (w1, w2, w3);
    make_utf16beN (w0, w0, w1);

    sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64 * 2);
  }

  w0[0] = w[pos4 +  0];
  w0[1] = w[pos4 +  1];
  w0[2] = w[pos4 +  2];
  w0[3] = w[pos4 +  3];
  w1[0] = w[pos4 +  4];
  w1[1] = w[pos4 +  5];
  w1[2] = w[pos4 +  6];
  w1[3] = w[pos4 +  7];
  w2[0] = w[pos4 +  8];
  w2[1] = w[pos4 +  9];
  w2[2] = w[pos4 + 10];
  w2[3] = w[pos4 + 11];
  w3[0] = w[pos4 + 12];
  w3[1] = w[pos4 + 13];
  w3[2] = w[pos4 + 14];
  w3[3] = w[pos4 + 15];

  make_utf16beN (w3, w6, w7);
  make_utf16beN (w2, w4, w5);
  make_utf16beN (w1, w2, w3);
  make_utf16beN (w0, w0, w1);

  sha512_update_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7, (len - pos1) * 2);
}

DECLSPEC void sha512_final_vector (sha512_ctx_vector_t *ctx)
{
  MAYBE_VOLATILE const int pos = ctx->len & 127;

  append_0x80_8x4 (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, pos ^ 3);

  if (pos >= 112)
  {
    sha512_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);

    ctx->w0[0] = 0;
    ctx->w0[1] = 0;
    ctx->w0[2] = 0;
    ctx->w0[3] = 0;
    ctx->w1[0] = 0;
    ctx->w1[1] = 0;
    ctx->w1[2] = 0;
    ctx->w1[3] = 0;
    ctx->w2[0] = 0;
    ctx->w2[1] = 0;
    ctx->w2[2] = 0;
    ctx->w2[3] = 0;
    ctx->w3[0] = 0;
    ctx->w3[1] = 0;
    ctx->w3[2] = 0;
    ctx->w3[3] = 0;
    ctx->w4[0] = 0;
    ctx->w4[1] = 0;
    ctx->w4[2] = 0;
    ctx->w4[3] = 0;
    ctx->w5[0] = 0;
    ctx->w5[1] = 0;
    ctx->w5[2] = 0;
    ctx->w5[3] = 0;
    ctx->w6[0] = 0;
    ctx->w6[1] = 0;
    ctx->w6[2] = 0;
    ctx->w6[3] = 0;
    ctx->w7[0] = 0;
    ctx->w7[1] = 0;
    ctx->w7[2] = 0;
    ctx->w7[3] = 0;
  }

  ctx->w7[2] = 0;
  ctx->w7[3] = ctx->len * 8;

  sha512_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->w4, ctx->w5, ctx->w6, ctx->w7, ctx->h);
}

// HMAC + Vector

typedef struct sha512_hmac_ctx_vector
{
  sha512_ctx_vector_t ipad;
  sha512_ctx_vector_t opad;

} sha512_hmac_ctx_vector_t;

DECLSPEC void sha512_hmac_init_vector_128 (sha512_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, const u32x *w4, const u32x *w5, const u32x *w6, const u32x *w7)
{
  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];
  u32x t4[4];
  u32x t5[4];
  u32x t6[4];
  u32x t7[4];

  // ipad

  t0[0] = w0[0] ^ 0x36363636;
  t0[1] = w0[1] ^ 0x36363636;
  t0[2] = w0[2] ^ 0x36363636;
  t0[3] = w0[3] ^ 0x36363636;
  t1[0] = w1[0] ^ 0x36363636;
  t1[1] = w1[1] ^ 0x36363636;
  t1[2] = w1[2] ^ 0x36363636;
  t1[3] = w1[3] ^ 0x36363636;
  t2[0] = w2[0] ^ 0x36363636;
  t2[1] = w2[1] ^ 0x36363636;
  t2[2] = w2[2] ^ 0x36363636;
  t2[3] = w2[3] ^ 0x36363636;
  t3[0] = w3[0] ^ 0x36363636;
  t3[1] = w3[1] ^ 0x36363636;
  t3[2] = w3[2] ^ 0x36363636;
  t3[3] = w3[3] ^ 0x36363636;
  t4[0] = w4[0] ^ 0x36363636;
  t4[1] = w4[1] ^ 0x36363636;
  t4[2] = w4[2] ^ 0x36363636;
  t4[3] = w4[3] ^ 0x36363636;
  t5[0] = w5[0] ^ 0x36363636;
  t5[1] = w5[1] ^ 0x36363636;
  t5[2] = w5[2] ^ 0x36363636;
  t5[3] = w5[3] ^ 0x36363636;
  t6[0] = w6[0] ^ 0x36363636;
  t6[1] = w6[1] ^ 0x36363636;
  t6[2] = w6[2] ^ 0x36363636;
  t6[3] = w6[3] ^ 0x36363636;
  t7[0] = w7[0] ^ 0x36363636;
  t7[1] = w7[1] ^ 0x36363636;
  t7[2] = w7[2] ^ 0x36363636;
  t7[3] = w7[3] ^ 0x36363636;

  sha512_init_vector (&ctx->ipad);

  sha512_update_vector_128 (&ctx->ipad, t0, t1, t2, t3, t4, t5, t6, t7, 128);

  // opad

  t0[0] = w0[0] ^ 0x5c5c5c5c;
  t0[1] = w0[1] ^ 0x5c5c5c5c;
  t0[2] = w0[2] ^ 0x5c5c5c5c;
  t0[3] = w0[3] ^ 0x5c5c5c5c;
  t1[0] = w1[0] ^ 0x5c5c5c5c;
  t1[1] = w1[1] ^ 0x5c5c5c5c;
  t1[2] = w1[2] ^ 0x5c5c5c5c;
  t1[3] = w1[3] ^ 0x5c5c5c5c;
  t2[0] = w2[0] ^ 0x5c5c5c5c;
  t2[1] = w2[1] ^ 0x5c5c5c5c;
  t2[2] = w2[2] ^ 0x5c5c5c5c;
  t2[3] = w2[3] ^ 0x5c5c5c5c;
  t3[0] = w3[0] ^ 0x5c5c5c5c;
  t3[1] = w3[1] ^ 0x5c5c5c5c;
  t3[2] = w3[2] ^ 0x5c5c5c5c;
  t3[3] = w3[3] ^ 0x5c5c5c5c;
  t4[0] = w4[0] ^ 0x5c5c5c5c;
  t4[1] = w4[1] ^ 0x5c5c5c5c;
  t4[2] = w4[2] ^ 0x5c5c5c5c;
  t4[3] = w4[3] ^ 0x5c5c5c5c;
  t5[0] = w5[0] ^ 0x5c5c5c5c;
  t5[1] = w5[1] ^ 0x5c5c5c5c;
  t5[2] = w5[2] ^ 0x5c5c5c5c;
  t5[3] = w5[3] ^ 0x5c5c5c5c;
  t6[0] = w6[0] ^ 0x5c5c5c5c;
  t6[1] = w6[1] ^ 0x5c5c5c5c;
  t6[2] = w6[2] ^ 0x5c5c5c5c;
  t6[3] = w6[3] ^ 0x5c5c5c5c;
  t7[0] = w7[0] ^ 0x5c5c5c5c;
  t7[1] = w7[1] ^ 0x5c5c5c5c;
  t7[2] = w7[2] ^ 0x5c5c5c5c;
  t7[3] = w7[3] ^ 0x5c5c5c5c;

  sha512_init_vector (&ctx->opad);

  sha512_update_vector_128 (&ctx->opad, t0, t1, t2, t3, t4, t5, t6, t7, 128);
}

DECLSPEC void sha512_hmac_init_vector (sha512_hmac_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];
  u32x w4[4];
  u32x w5[4];
  u32x w6[4];
  u32x w7[4];

  if (len > 128)
  {
    sha512_ctx_vector_t tmp;

    sha512_init_vector (&tmp);

    sha512_update_vector (&tmp, w, len);

    sha512_final_vector (&tmp);

    w0[0] = h32_from_64 (tmp.h[0]);
    w0[1] = l32_from_64 (tmp.h[0]);
    w0[2] = h32_from_64 (tmp.h[1]);
    w0[3] = l32_from_64 (tmp.h[1]);
    w1[0] = h32_from_64 (tmp.h[2]);
    w1[1] = l32_from_64 (tmp.h[2]);
    w1[2] = h32_from_64 (tmp.h[3]);
    w1[3] = l32_from_64 (tmp.h[3]);
    w2[0] = h32_from_64 (tmp.h[4]);
    w2[1] = l32_from_64 (tmp.h[4]);
    w2[2] = h32_from_64 (tmp.h[5]);
    w2[3] = l32_from_64 (tmp.h[5]);
    w3[0] = h32_from_64 (tmp.h[6]);
    w3[1] = l32_from_64 (tmp.h[6]);
    w3[2] = h32_from_64 (tmp.h[7]);
    w3[3] = l32_from_64 (tmp.h[7]);
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;
  }
  else
  {
    w0[0] = w[ 0];
    w0[1] = w[ 1];
    w0[2] = w[ 2];
    w0[3] = w[ 3];
    w1[0] = w[ 4];
    w1[1] = w[ 5];
    w1[2] = w[ 6];
    w1[3] = w[ 7];
    w2[0] = w[ 8];
    w2[1] = w[ 9];
    w2[2] = w[10];
    w2[3] = w[11];
    w3[0] = w[12];
    w3[1] = w[13];
    w3[2] = w[14];
    w3[3] = w[15];
    w4[0] = w[16];
    w4[1] = w[17];
    w4[2] = w[18];
    w4[3] = w[19];
    w5[0] = w[20];
    w5[1] = w[21];
    w5[2] = w[22];
    w5[3] = w[23];
    w6[0] = w[24];
    w6[1] = w[25];
    w6[2] = w[26];
    w6[3] = w[27];
    w7[0] = w[28];
    w7[1] = w[29];
    w7[2] = w[30];
    w7[3] = w[31];
  }

  sha512_hmac_init_vector_128 (ctx, w0, w1, w2, w3, w4, w5, w6, w7);
}

DECLSPEC void sha512_hmac_update_vector_128 (sha512_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, const int len)
{
  sha512_update_vector_128 (&ctx->ipad, w0, w1, w2, w3, w4, w5, w6, w7, len);
}

DECLSPEC void sha512_hmac_update_vector (sha512_hmac_ctx_vector_t *ctx, const u32x *w, const int len)
{
  sha512_update_vector (&ctx->ipad, w, len);
}

DECLSPEC void sha512_hmac_final_vector (sha512_hmac_ctx_vector_t *ctx)
{
  sha512_final_vector (&ctx->ipad);

  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];
  u32x t4[4];
  u32x t5[4];
  u32x t6[4];
  u32x t7[4];

  t0[0] = h32_from_64 (ctx->ipad.h[0]);
  t0[1] = l32_from_64 (ctx->ipad.h[0]);
  t0[2] = h32_from_64 (ctx->ipad.h[1]);
  t0[3] = l32_from_64 (ctx->ipad.h[1]);
  t1[0] = h32_from_64 (ctx->ipad.h[2]);
  t1[1] = l32_from_64 (ctx->ipad.h[2]);
  t1[2] = h32_from_64 (ctx->ipad.h[3]);
  t1[3] = l32_from_64 (ctx->ipad.h[3]);
  t2[0] = h32_from_64 (ctx->ipad.h[4]);
  t2[1] = l32_from_64 (ctx->ipad.h[4]);
  t2[2] = h32_from_64 (ctx->ipad.h[5]);
  t2[3] = l32_from_64 (ctx->ipad.h[5]);
  t3[0] = h32_from_64 (ctx->ipad.h[6]);
  t3[1] = l32_from_64 (ctx->ipad.h[6]);
  t3[2] = h32_from_64 (ctx->ipad.h[7]);
  t3[3] = l32_from_64 (ctx->ipad.h[7]);
  t4[0] = 0;
  t4[1] = 0;
  t4[2] = 0;
  t4[3] = 0;
  t5[0] = 0;
  t5[1] = 0;
  t5[2] = 0;
  t5[3] = 0;
  t6[0] = 0;
  t6[1] = 0;
  t6[2] = 0;
  t6[3] = 0;
  t7[0] = 0;
  t7[1] = 0;
  t7[2] = 0;
  t7[3] = 0;

  sha512_update_vector_128 (&ctx->opad, t0, t1, t2, t3, t4, t5, t6, t7, 64);

  sha512_final_vector (&ctx->opad);
}
