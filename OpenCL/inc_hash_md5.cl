
// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf need to be in algorithm native byte order (md5 = LE, sha1 = BE, etc)
// input len can not be > 64. if you need it longer, loop it while calling update functions multiple times

typedef struct md5_ctx
{
  u32x h[4];

  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int  len;

} md5_ctx_t;

void md5_transform (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[4])
{
  u32x a = digest[0];
  u32x b = digest[1];
  u32x c = digest[2];
  u32x d = digest[3];

  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = w3[3];

  MD5_STEP (MD5_Fo, a, b, c, d, w0_t, MD5C00, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w1_t, MD5C01, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w2_t, MD5C02, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w3_t, MD5C03, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w4_t, MD5C04, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w5_t, MD5C05, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, w6_t, MD5C06, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, w7_t, MD5C07, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, w8_t, MD5C08, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, w9_t, MD5C09, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, wa_t, MD5C0a, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, wb_t, MD5C0b, MD5S03);
  MD5_STEP (MD5_Fo, a, b, c, d, wc_t, MD5C0c, MD5S00);
  MD5_STEP (MD5_Fo, d, a, b, c, wd_t, MD5C0d, MD5S01);
  MD5_STEP (MD5_Fo, c, d, a, b, we_t, MD5C0e, MD5S02);
  MD5_STEP (MD5_Fo, b, c, d, a, wf_t, MD5C0f, MD5S03);

  MD5_STEP (MD5_Go, a, b, c, d, w1_t, MD5C10, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w6_t, MD5C11, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, wb_t, MD5C12, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w0_t, MD5C13, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w5_t, MD5C14, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, wa_t, MD5C15, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, wf_t, MD5C16, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w4_t, MD5C17, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, w9_t, MD5C18, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, we_t, MD5C19, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w3_t, MD5C1a, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, w8_t, MD5C1b, MD5S13);
  MD5_STEP (MD5_Go, a, b, c, d, wd_t, MD5C1c, MD5S10);
  MD5_STEP (MD5_Go, d, a, b, c, w2_t, MD5C1d, MD5S11);
  MD5_STEP (MD5_Go, c, d, a, b, w7_t, MD5C1e, MD5S12);
  MD5_STEP (MD5_Go, b, c, d, a, wc_t, MD5C1f, MD5S13);

  MD5_STEP (MD5_H , a, b, c, d, w5_t, MD5C20, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w8_t, MD5C21, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, wb_t, MD5C22, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, we_t, MD5C23, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w1_t, MD5C24, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w4_t, MD5C25, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w7_t, MD5C26, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, wa_t, MD5C27, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, wd_t, MD5C28, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, w0_t, MD5C29, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, w3_t, MD5C2a, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w6_t, MD5C2b, MD5S23);
  MD5_STEP (MD5_H , a, b, c, d, w9_t, MD5C2c, MD5S20);
  MD5_STEP (MD5_H , d, a, b, c, wc_t, MD5C2d, MD5S21);
  MD5_STEP (MD5_H , c, d, a, b, wf_t, MD5C2e, MD5S22);
  MD5_STEP (MD5_H , b, c, d, a, w2_t, MD5C2f, MD5S23);

  MD5_STEP (MD5_I , a, b, c, d, w0_t, MD5C30, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w7_t, MD5C31, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, we_t, MD5C32, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w5_t, MD5C33, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, wc_t, MD5C34, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, w3_t, MD5C35, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, wa_t, MD5C36, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w1_t, MD5C37, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w8_t, MD5C38, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, wf_t, MD5C39, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w6_t, MD5C3a, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, wd_t, MD5C3b, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, w4_t, MD5C3c, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, wb_t, MD5C3d, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, w2_t, MD5C3e, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, w9_t, MD5C3f, MD5S33);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

void md5_init (md5_ctx_t *md5_ctx)
{
  md5_ctx->h[0] = MD5M_A;
  md5_ctx->h[1] = MD5M_B;
  md5_ctx->h[2] = MD5M_C;
  md5_ctx->h[3] = MD5M_D;

  md5_ctx->w0[0] = 0;
  md5_ctx->w0[1] = 0;
  md5_ctx->w0[2] = 0;
  md5_ctx->w0[3] = 0;
  md5_ctx->w1[0] = 0;
  md5_ctx->w1[1] = 0;
  md5_ctx->w1[2] = 0;
  md5_ctx->w1[3] = 0;
  md5_ctx->w2[0] = 0;
  md5_ctx->w2[1] = 0;
  md5_ctx->w2[2] = 0;
  md5_ctx->w2[3] = 0;
  md5_ctx->w3[0] = 0;
  md5_ctx->w3[1] = 0;
  md5_ctx->w3[2] = 0;
  md5_ctx->w3[3] = 0;

  md5_ctx->len = 0;
}

void md5_update_64 (md5_ctx_t *md5_ctx, u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const int len)
{
  const int pos = md5_ctx->len & 0x3f;

  md5_ctx->len += len;

  if ((pos + len) < 64)
  {
    switch_buffer_by_offset_le (w0, w1, w2, w3, pos);

    md5_ctx->w0[0] |= w0[0];
    md5_ctx->w0[1] |= w0[1];
    md5_ctx->w0[2] |= w0[2];
    md5_ctx->w0[3] |= w0[3];
    md5_ctx->w1[0] |= w1[0];
    md5_ctx->w1[1] |= w1[1];
    md5_ctx->w1[2] |= w1[2];
    md5_ctx->w1[3] |= w1[3];
    md5_ctx->w2[0] |= w2[0];
    md5_ctx->w2[1] |= w2[1];
    md5_ctx->w2[2] |= w2[2];
    md5_ctx->w2[3] |= w2[3];
    md5_ctx->w3[0] |= w3[0];
    md5_ctx->w3[1] |= w3[1];
    md5_ctx->w3[2] |= w3[2];
    md5_ctx->w3[3] |= w3[3];
  }
  else
  {
    u32x c0[4] = { 0 };
    u32x c1[4] = { 0 };
    u32x c2[4] = { 0 };
    u32x c3[4] = { 0 };

    switch_buffer_by_offset_carry_le (w0, w1, w2, w3, c0, c1, c2, c3, pos);

    md5_ctx->w0[0] |= w0[0];
    md5_ctx->w0[1] |= w0[1];
    md5_ctx->w0[2] |= w0[2];
    md5_ctx->w0[3] |= w0[3];
    md5_ctx->w1[0] |= w1[0];
    md5_ctx->w1[1] |= w1[1];
    md5_ctx->w1[2] |= w1[2];
    md5_ctx->w1[3] |= w1[3];
    md5_ctx->w2[0] |= w2[0];
    md5_ctx->w2[1] |= w2[1];
    md5_ctx->w2[2] |= w2[2];
    md5_ctx->w2[3] |= w2[3];
    md5_ctx->w3[0] |= w3[0];
    md5_ctx->w3[1] |= w3[1];
    md5_ctx->w3[2] |= w3[2];
    md5_ctx->w3[3] |= w3[3];

    md5_transform (md5_ctx->w0, md5_ctx->w1, md5_ctx->w2, md5_ctx->w3, md5_ctx->h);

    md5_ctx->w0[0] = c0[0];
    md5_ctx->w0[1] = c0[1];
    md5_ctx->w0[2] = c0[2];
    md5_ctx->w0[3] = c0[3];
    md5_ctx->w1[0] = c1[0];
    md5_ctx->w1[1] = c1[1];
    md5_ctx->w1[2] = c1[2];
    md5_ctx->w1[3] = c1[3];
    md5_ctx->w2[0] = c2[0];
    md5_ctx->w2[1] = c2[1];
    md5_ctx->w2[2] = c2[2];
    md5_ctx->w2[3] = c2[3];
    md5_ctx->w3[0] = c3[0];
    md5_ctx->w3[1] = c3[1];
    md5_ctx->w3[2] = c3[2];
    md5_ctx->w3[3] = c3[3];
  }
}

void md5_update (md5_ctx_t *md5_ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int i;
  int j;

  for (i = 0, j = 0; i < len - 64; i += 64, j += 16)
  {
    w0[0] = w[i +  0];
    w0[1] = w[i +  1];
    w0[2] = w[i +  2];
    w0[3] = w[i +  3];
    w1[0] = w[i +  4];
    w1[1] = w[i +  5];
    w1[2] = w[i +  6];
    w1[3] = w[i +  7];
    w2[0] = w[i +  8];
    w2[1] = w[i +  9];
    w2[2] = w[i + 10];
    w2[3] = w[i + 11];
    w3[0] = w[i + 12];
    w3[1] = w[i + 13];
    w3[2] = w[i + 14];
    w3[3] = w[i + 15];

    md5_update_64 (md5_ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = w[i +  0];
  w0[1] = w[i +  1];
  w0[2] = w[i +  2];
  w0[3] = w[i +  3];
  w1[0] = w[i +  4];
  w1[1] = w[i +  5];
  w1[2] = w[i +  6];
  w1[3] = w[i +  7];
  w2[0] = w[i +  8];
  w2[1] = w[i +  9];
  w2[2] = w[i + 10];
  w2[3] = w[i + 11];
  w3[0] = w[i + 12];
  w3[1] = w[i + 13];
  w3[2] = w[i + 14];
  w3[3] = w[i + 15];

  md5_update_64 (md5_ctx, w0, w1, w2, w3, len & 0x3f);
}

void md5_final (md5_ctx_t *md5_ctx)
{
  int pos = md5_ctx->len & 0x3f;

  append_0x80_4x4 (md5_ctx->w0, md5_ctx->w1, md5_ctx->w2, md5_ctx->w3, pos);

  if (pos >= 56)
  {
    md5_transform (md5_ctx->w0, md5_ctx->w1, md5_ctx->w2, md5_ctx->w3, md5_ctx->h);

    md5_ctx->w0[0] = 0;
    md5_ctx->w0[1] = 0;
    md5_ctx->w0[2] = 0;
    md5_ctx->w0[3] = 0;
    md5_ctx->w1[0] = 0;
    md5_ctx->w1[1] = 0;
    md5_ctx->w1[2] = 0;
    md5_ctx->w1[3] = 0;
    md5_ctx->w2[0] = 0;
    md5_ctx->w2[1] = 0;
    md5_ctx->w2[2] = 0;
    md5_ctx->w2[3] = 0;
    md5_ctx->w3[0] = 0;
    md5_ctx->w3[1] = 0;
    md5_ctx->w3[2] = 0;
    md5_ctx->w3[3] = 0;
  }

  md5_ctx->w3[2] = md5_ctx->len * 8;

  md5_transform (md5_ctx->w0, md5_ctx->w1, md5_ctx->w2, md5_ctx->w3, md5_ctx->h);
}
