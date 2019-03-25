/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_hash_whirlpool.h"

// important notes on this:
// input buf unused bytes needs to be set to zero
// input buf needs to be in algorithm native byte order (md5 = LE, sha256 = BE, etc)
// input buf needs to be 64 byte aligned when using whirlpool_update()

DECLSPEC void whirlpool_transform (const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, u32 *digest, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32 Kh[8];
  u32 Kl[8];

  Kh[0] = digest[ 0];
  Kl[0] = digest[ 1];
  Kh[1] = digest[ 2];
  Kl[1] = digest[ 3];
  Kh[2] = digest[ 4];
  Kl[2] = digest[ 5];
  Kh[3] = digest[ 6];
  Kl[3] = digest[ 7];
  Kh[4] = digest[ 8];
  Kl[4] = digest[ 9];
  Kh[5] = digest[10];
  Kl[5] = digest[11];
  Kh[6] = digest[12];
  Kl[6] = digest[13];
  Kh[7] = digest[14];
  Kl[7] = digest[15];

  u32 stateh[8];
  u32 statel[8];

  stateh[0] = w0[0] ^ Kh[0];
  statel[0] = w0[1] ^ Kl[0];
  stateh[1] = w0[2] ^ Kh[1];
  statel[1] = w0[3] ^ Kl[1];
  stateh[2] = w1[0] ^ Kh[2];
  statel[2] = w1[1] ^ Kl[2];
  stateh[3] = w1[2] ^ Kh[3];
  statel[3] = w1[3] ^ Kl[3];
  stateh[4] = w2[0] ^ Kh[4];
  statel[4] = w2[1] ^ Kl[4];
  stateh[5] = w2[2] ^ Kh[5];
  statel[5] = w2[3] ^ Kl[5];
  stateh[6] = w3[0] ^ Kh[6];
  statel[6] = w3[1] ^ Kl[6];
  stateh[7] = w3[2] ^ Kh[7];
  statel[7] = w3[3] ^ Kl[7];

  u32 r;

  for (r = 1; r <= R; r++)
  {
    u32 Lh[8];
    u32 Ll[8];

    u32 i;

    #ifdef _unroll
    #pragma unroll
    #endif
    for (i = 0; i < 8; i++)
    {
      const u32 Lp0 = Kh[(i + 8) & 7] >> 24;
      const u32 Lp1 = Kh[(i + 7) & 7] >> 16;
      const u32 Lp2 = Kh[(i + 6) & 7] >>  8;
      const u32 Lp3 = Kh[(i + 5) & 7] >>  0;
      const u32 Lp4 = Kl[(i + 4) & 7] >> 24;
      const u32 Lp5 = Kl[(i + 3) & 7] >> 16;
      const u32 Lp6 = Kl[(i + 2) & 7] >>  8;
      const u32 Lp7 = Kl[(i + 1) & 7] >>  0;

      Lh[i] = BOX_S (s_Ch, 0, Lp0 & 0xff)
            ^ BOX_S (s_Ch, 1, Lp1 & 0xff)
            ^ BOX_S (s_Ch, 2, Lp2 & 0xff)
            ^ BOX_S (s_Ch, 3, Lp3 & 0xff)
            ^ BOX_S (s_Ch, 4, Lp4 & 0xff)
            ^ BOX_S (s_Ch, 5, Lp5 & 0xff)
            ^ BOX_S (s_Ch, 6, Lp6 & 0xff)
            ^ BOX_S (s_Ch, 7, Lp7 & 0xff);

      Ll[i] = BOX_S (s_Cl, 0, Lp0 & 0xff)
            ^ BOX_S (s_Cl, 1, Lp1 & 0xff)
            ^ BOX_S (s_Cl, 2, Lp2 & 0xff)
            ^ BOX_S (s_Cl, 3, Lp3 & 0xff)
            ^ BOX_S (s_Cl, 4, Lp4 & 0xff)
            ^ BOX_S (s_Cl, 5, Lp5 & 0xff)
            ^ BOX_S (s_Cl, 6, Lp6 & 0xff)
            ^ BOX_S (s_Cl, 7, Lp7 & 0xff);
    }

    Kh[0] = Lh[0] ^ rch[r];
    Kl[0] = Ll[0] ^ rcl[r];
    Kh[1] = Lh[1];
    Kl[1] = Ll[1];
    Kh[2] = Lh[2];
    Kl[2] = Ll[2];
    Kh[3] = Lh[3];
    Kl[3] = Ll[3];
    Kh[4] = Lh[4];
    Kl[4] = Ll[4];
    Kh[5] = Lh[5];
    Kl[5] = Ll[5];
    Kh[6] = Lh[6];
    Kl[6] = Ll[6];
    Kh[7] = Lh[7];
    Kl[7] = Ll[7];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (i = 0; i < 8; i++)
    {
      const u32 Lp0 = stateh[(i + 8) & 7] >> 24;
      const u32 Lp1 = stateh[(i + 7) & 7] >> 16;
      const u32 Lp2 = stateh[(i + 6) & 7] >>  8;
      const u32 Lp3 = stateh[(i + 5) & 7] >>  0;
      const u32 Lp4 = statel[(i + 4) & 7] >> 24;
      const u32 Lp5 = statel[(i + 3) & 7] >> 16;
      const u32 Lp6 = statel[(i + 2) & 7] >>  8;
      const u32 Lp7 = statel[(i + 1) & 7] >>  0;

      Lh[i] = BOX_S (s_Ch, 0, Lp0 & 0xff)
            ^ BOX_S (s_Ch, 1, Lp1 & 0xff)
            ^ BOX_S (s_Ch, 2, Lp2 & 0xff)
            ^ BOX_S (s_Ch, 3, Lp3 & 0xff)
            ^ BOX_S (s_Ch, 4, Lp4 & 0xff)
            ^ BOX_S (s_Ch, 5, Lp5 & 0xff)
            ^ BOX_S (s_Ch, 6, Lp6 & 0xff)
            ^ BOX_S (s_Ch, 7, Lp7 & 0xff);

      Ll[i] = BOX_S (s_Cl, 0, Lp0 & 0xff)
            ^ BOX_S (s_Cl, 1, Lp1 & 0xff)
            ^ BOX_S (s_Cl, 2, Lp2 & 0xff)
            ^ BOX_S (s_Cl, 3, Lp3 & 0xff)
            ^ BOX_S (s_Cl, 4, Lp4 & 0xff)
            ^ BOX_S (s_Cl, 5, Lp5 & 0xff)
            ^ BOX_S (s_Cl, 6, Lp6 & 0xff)
            ^ BOX_S (s_Cl, 7, Lp7 & 0xff);
    }

    stateh[0] = Lh[0] ^ Kh[0];
    statel[0] = Ll[0] ^ Kl[0];
    stateh[1] = Lh[1] ^ Kh[1];
    statel[1] = Ll[1] ^ Kl[1];
    stateh[2] = Lh[2] ^ Kh[2];
    statel[2] = Ll[2] ^ Kl[2];
    stateh[3] = Lh[3] ^ Kh[3];
    statel[3] = Ll[3] ^ Kl[3];
    stateh[4] = Lh[4] ^ Kh[4];
    statel[4] = Ll[4] ^ Kl[4];
    stateh[5] = Lh[5] ^ Kh[5];
    statel[5] = Ll[5] ^ Kl[5];
    stateh[6] = Lh[6] ^ Kh[6];
    statel[6] = Ll[6] ^ Kl[6];
    stateh[7] = Lh[7] ^ Kh[7];
    statel[7] = Ll[7] ^ Kl[7];
  }

  digest[ 0] ^= stateh[0] ^ w0[0];
  digest[ 1] ^= statel[0] ^ w0[1];
  digest[ 2] ^= stateh[1] ^ w0[2];
  digest[ 3] ^= statel[1] ^ w0[3];
  digest[ 4] ^= stateh[2] ^ w1[0];
  digest[ 5] ^= statel[2] ^ w1[1];
  digest[ 6] ^= stateh[3] ^ w1[2];
  digest[ 7] ^= statel[3] ^ w1[3];
  digest[ 8] ^= stateh[4] ^ w2[0];
  digest[ 9] ^= statel[4] ^ w2[1];
  digest[10] ^= stateh[5] ^ w2[2];
  digest[11] ^= statel[5] ^ w2[3];
  digest[12] ^= stateh[6] ^ w3[0];
  digest[13] ^= statel[6] ^ w3[1];
  digest[14] ^= stateh[7] ^ w3[2];
  digest[15] ^= statel[7] ^ w3[3];
}

DECLSPEC void whirlpool_init (whirlpool_ctx_t *ctx, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  ctx->h[ 0] = 0;
  ctx->h[ 1] = 0;
  ctx->h[ 2] = 0;
  ctx->h[ 3] = 0;
  ctx->h[ 4] = 0;
  ctx->h[ 5] = 0;
  ctx->h[ 6] = 0;
  ctx->h[ 7] = 0;
  ctx->h[ 8] = 0;
  ctx->h[ 9] = 0;
  ctx->h[10] = 0;
  ctx->h[11] = 0;
  ctx->h[12] = 0;
  ctx->h[13] = 0;
  ctx->h[14] = 0;
  ctx->h[15] = 0;

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

  ctx->len = 0;

  ctx->s_Ch = s_Ch;
  ctx->s_Cl = s_Cl;
}

DECLSPEC void whirlpool_update_64 (whirlpool_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len)
{
  const int pos = ctx->len & 63;

  ctx->len += len;

  if ((pos + len) < 64)
  {
    switch_buffer_by_offset_be_S (w0, w1, w2, w3, pos);

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
  }
  else
  {
    u32 c0[4] = { 0 };
    u32 c1[4] = { 0 };
    u32 c2[4] = { 0 };
    u32 c3[4] = { 0 };

    switch_buffer_by_offset_carry_be_S (w0, w1, w2, w3, c0, c1, c2, c3, pos);

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

    whirlpool_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h, ctx->s_Ch, ctx->s_Cl);

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
  }
}

DECLSPEC void whirlpool_update (whirlpool_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

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

    whirlpool_update_64 (ctx, w0, w1, w2, w3, 64);
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

  whirlpool_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void whirlpool_update_swap (whirlpool_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

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

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);

    whirlpool_update_64 (ctx, w0, w1, w2, w3, 64);
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

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  whirlpool_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void whirlpool_update_utf16le (whirlpool_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    whirlpool_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  whirlpool_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void whirlpool_update_utf16le_swap (whirlpool_ctx_t *ctx, const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);

    whirlpool_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  whirlpool_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void whirlpool_update_global (whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

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

    whirlpool_update_64 (ctx, w0, w1, w2, w3, 64);
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

  whirlpool_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void whirlpool_update_global_swap (whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

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

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);

    whirlpool_update_64 (ctx, w0, w1, w2, w3, 64);
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

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  whirlpool_update_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void whirlpool_update_global_utf16le (whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    whirlpool_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  whirlpool_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void whirlpool_update_global_utf16le_swap (whirlpool_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le_S (w1, w2, w3);
    make_utf16le_S (w0, w0, w1);

    w0[0] = hc_swap32_S (w0[0]);
    w0[1] = hc_swap32_S (w0[1]);
    w0[2] = hc_swap32_S (w0[2]);
    w0[3] = hc_swap32_S (w0[3]);
    w1[0] = hc_swap32_S (w1[0]);
    w1[1] = hc_swap32_S (w1[1]);
    w1[2] = hc_swap32_S (w1[2]);
    w1[3] = hc_swap32_S (w1[3]);
    w2[0] = hc_swap32_S (w2[0]);
    w2[1] = hc_swap32_S (w2[1]);
    w2[2] = hc_swap32_S (w2[2]);
    w2[3] = hc_swap32_S (w2[3]);
    w3[0] = hc_swap32_S (w3[0]);
    w3[1] = hc_swap32_S (w3[1]);
    w3[2] = hc_swap32_S (w3[2]);
    w3[3] = hc_swap32_S (w3[3]);

    whirlpool_update_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le_S (w1, w2, w3);
  make_utf16le_S (w0, w0, w1);

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  whirlpool_update_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void whirlpool_final (whirlpool_ctx_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x80_4x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

  if (pos >= 32)
  {
    whirlpool_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h, ctx->s_Ch, ctx->s_Cl);

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
  }

  ctx->w3[2] = 0;
  ctx->w3[3] = ctx->len * 8;

  whirlpool_transform (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h, ctx->s_Ch, ctx->s_Cl);
}

// whirlpool_hmac

DECLSPEC void whirlpool_hmac_init_64 (whirlpool_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

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

  whirlpool_init (&ctx->ipad, s_Ch, s_Cl);

  whirlpool_update_64 (&ctx->ipad, t0, t1, t2, t3, 64);

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

  whirlpool_init (&ctx->opad, s_Ch, s_Cl);

  whirlpool_update_64 (&ctx->opad, t0, t1, t2, t3, 64);
}

DECLSPEC void whirlpool_hmac_init (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    whirlpool_ctx_t tmp;

    whirlpool_init (&tmp, s_Ch, s_Cl);

    whirlpool_update (&tmp, w, len);

    whirlpool_final (&tmp);

    w0[0] = tmp.h[ 0];
    w0[1] = tmp.h[ 1];
    w0[2] = tmp.h[ 2];
    w0[3] = tmp.h[ 3];
    w1[0] = tmp.h[ 4];
    w1[1] = tmp.h[ 5];
    w1[2] = tmp.h[ 6];
    w1[3] = tmp.h[ 7];
    w2[0] = tmp.h[ 8];
    w2[1] = tmp.h[ 9];
    w2[2] = tmp.h[10];
    w2[3] = tmp.h[11];
    w3[0] = tmp.h[12];
    w3[1] = tmp.h[13];
    w3[2] = tmp.h[14];
    w3[3] = tmp.h[15];
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
  }

  whirlpool_hmac_init_64 (ctx, w0, w1, w2, w3, s_Ch, s_Cl);
}

DECLSPEC void whirlpool_hmac_init_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    whirlpool_ctx_t tmp;

    whirlpool_init (&tmp, s_Ch, s_Cl);

    whirlpool_update_swap (&tmp, w, len);

    whirlpool_final (&tmp);

    w0[0] = tmp.h[ 0];
    w0[1] = tmp.h[ 1];
    w0[2] = tmp.h[ 2];
    w0[3] = tmp.h[ 3];
    w1[0] = tmp.h[ 4];
    w1[1] = tmp.h[ 5];
    w1[2] = tmp.h[ 6];
    w1[3] = tmp.h[ 7];
    w2[0] = tmp.h[ 8];
    w2[1] = tmp.h[ 9];
    w2[2] = tmp.h[10];
    w2[3] = tmp.h[11];
    w3[0] = tmp.h[12];
    w3[1] = tmp.h[13];
    w3[2] = tmp.h[14];
    w3[3] = tmp.h[15];
  }
  else
  {
    w0[0] = hc_swap32_S (w[ 0]);
    w0[1] = hc_swap32_S (w[ 1]);
    w0[2] = hc_swap32_S (w[ 2]);
    w0[3] = hc_swap32_S (w[ 3]);
    w1[0] = hc_swap32_S (w[ 4]);
    w1[1] = hc_swap32_S (w[ 5]);
    w1[2] = hc_swap32_S (w[ 6]);
    w1[3] = hc_swap32_S (w[ 7]);
    w2[0] = hc_swap32_S (w[ 8]);
    w2[1] = hc_swap32_S (w[ 9]);
    w2[2] = hc_swap32_S (w[10]);
    w2[3] = hc_swap32_S (w[11]);
    w3[0] = hc_swap32_S (w[12]);
    w3[1] = hc_swap32_S (w[13]);
    w3[2] = hc_swap32_S (w[14]);
    w3[3] = hc_swap32_S (w[15]);
  }

  whirlpool_hmac_init_64 (ctx, w0, w1, w2, w3, s_Ch, s_Cl);
}

DECLSPEC void whirlpool_hmac_init_global (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    whirlpool_ctx_t tmp;

    whirlpool_init (&tmp, s_Ch, s_Cl);

    whirlpool_update_global (&tmp, w, len);

    whirlpool_final (&tmp);

    w0[0] = tmp.h[ 0];
    w0[1] = tmp.h[ 1];
    w0[2] = tmp.h[ 2];
    w0[3] = tmp.h[ 3];
    w1[0] = tmp.h[ 4];
    w1[1] = tmp.h[ 5];
    w1[2] = tmp.h[ 6];
    w1[3] = tmp.h[ 7];
    w2[0] = tmp.h[ 8];
    w2[1] = tmp.h[ 9];
    w2[2] = tmp.h[10];
    w2[3] = tmp.h[11];
    w3[0] = tmp.h[12];
    w3[1] = tmp.h[13];
    w3[2] = tmp.h[14];
    w3[3] = tmp.h[15];
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
  }

  whirlpool_hmac_init_64 (ctx, w0, w1, w2, w3, s_Ch, s_Cl);
}

DECLSPEC void whirlpool_hmac_init_global_swap (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    whirlpool_ctx_t tmp;

    whirlpool_init (&tmp, s_Ch, s_Cl);

    whirlpool_update_global_swap (&tmp, w, len);

    whirlpool_final (&tmp);

    w0[0] = tmp.h[ 0];
    w0[1] = tmp.h[ 1];
    w0[2] = tmp.h[ 2];
    w0[3] = tmp.h[ 3];
    w1[0] = tmp.h[ 4];
    w1[1] = tmp.h[ 5];
    w1[2] = tmp.h[ 6];
    w1[3] = tmp.h[ 7];
    w2[0] = tmp.h[ 8];
    w2[1] = tmp.h[ 9];
    w2[2] = tmp.h[10];
    w2[3] = tmp.h[11];
    w3[0] = tmp.h[12];
    w3[1] = tmp.h[13];
    w3[2] = tmp.h[14];
    w3[3] = tmp.h[15];
  }
  else
  {
    w0[0] = hc_swap32_S (w[ 0]);
    w0[1] = hc_swap32_S (w[ 1]);
    w0[2] = hc_swap32_S (w[ 2]);
    w0[3] = hc_swap32_S (w[ 3]);
    w1[0] = hc_swap32_S (w[ 4]);
    w1[1] = hc_swap32_S (w[ 5]);
    w1[2] = hc_swap32_S (w[ 6]);
    w1[3] = hc_swap32_S (w[ 7]);
    w2[0] = hc_swap32_S (w[ 8]);
    w2[1] = hc_swap32_S (w[ 9]);
    w2[2] = hc_swap32_S (w[10]);
    w2[3] = hc_swap32_S (w[11]);
    w3[0] = hc_swap32_S (w[12]);
    w3[1] = hc_swap32_S (w[13]);
    w3[2] = hc_swap32_S (w[14]);
    w3[3] = hc_swap32_S (w[15]);
  }

  whirlpool_hmac_init_64 (ctx, w0, w1, w2, w3, s_Ch, s_Cl);
}

DECLSPEC void whirlpool_hmac_update_64 (whirlpool_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len)
{
  whirlpool_update_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void whirlpool_hmac_update (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  whirlpool_update (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_update_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  whirlpool_update_swap (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_update_utf16le (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  whirlpool_update_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_update_utf16le_swap (whirlpool_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  whirlpool_update_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_update_global (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  whirlpool_update_global (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_update_global_swap (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  whirlpool_update_global_swap (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_update_global_utf16le (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  whirlpool_update_global_utf16le (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_update_global_utf16le_swap (whirlpool_hmac_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  whirlpool_update_global_utf16le_swap (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_final (whirlpool_hmac_ctx_t *ctx)
{
  whirlpool_final (&ctx->ipad);

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  t0[0] = ctx->ipad.h[ 0];
  t0[1] = ctx->ipad.h[ 1];
  t0[2] = ctx->ipad.h[ 2];
  t0[3] = ctx->ipad.h[ 3];
  t1[0] = ctx->ipad.h[ 4];
  t1[1] = ctx->ipad.h[ 5];
  t1[2] = ctx->ipad.h[ 6];
  t1[3] = ctx->ipad.h[ 7];
  t2[0] = ctx->ipad.h[ 8];
  t2[1] = ctx->ipad.h[ 9];
  t2[2] = ctx->ipad.h[10];
  t2[3] = ctx->ipad.h[11];
  t3[0] = ctx->ipad.h[12];
  t3[1] = ctx->ipad.h[13];
  t3[2] = ctx->ipad.h[14];
  t3[3] = ctx->ipad.h[15];

  whirlpool_update_64 (&ctx->opad, t0, t1, t2, t3, 64);

  whirlpool_final (&ctx->opad);
}

// while input buf can be a vector datatype, the length of the different elements can not

DECLSPEC void whirlpool_transform_vector (const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, u32x *digest, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32x Kh[8];
  u32x Kl[8];

  Kh[0] = digest[ 0];
  Kl[0] = digest[ 1];
  Kh[1] = digest[ 2];
  Kl[1] = digest[ 3];
  Kh[2] = digest[ 4];
  Kl[2] = digest[ 5];
  Kh[3] = digest[ 6];
  Kl[3] = digest[ 7];
  Kh[4] = digest[ 8];
  Kl[4] = digest[ 9];
  Kh[5] = digest[10];
  Kl[5] = digest[11];
  Kh[6] = digest[12];
  Kl[6] = digest[13];
  Kh[7] = digest[14];
  Kl[7] = digest[15];

  u32x stateh[8];
  u32x statel[8];

  stateh[0] = w0[0] ^ Kh[0];
  statel[0] = w0[1] ^ Kl[0];
  stateh[1] = w0[2] ^ Kh[1];
  statel[1] = w0[3] ^ Kl[1];
  stateh[2] = w1[0] ^ Kh[2];
  statel[2] = w1[1] ^ Kl[2];
  stateh[3] = w1[2] ^ Kh[3];
  statel[3] = w1[3] ^ Kl[3];
  stateh[4] = w2[0] ^ Kh[4];
  statel[4] = w2[1] ^ Kl[4];
  stateh[5] = w2[2] ^ Kh[5];
  statel[5] = w2[3] ^ Kl[5];
  stateh[6] = w3[0] ^ Kh[6];
  statel[6] = w3[1] ^ Kl[6];
  stateh[7] = w3[2] ^ Kh[7];
  statel[7] = w3[3] ^ Kl[7];

  u32 r;

  for (r = 1; r <= R; r++)
  {
    u32x Lh[8];
    u32x Ll[8];

    u32 i;

    #ifdef _unroll
    #pragma unroll
    #endif
    for (i = 0; i < 8; i++)
    {
      const u32x Lp0 = Kh[(i + 8) & 7] >> 24;
      const u32x Lp1 = Kh[(i + 7) & 7] >> 16;
      const u32x Lp2 = Kh[(i + 6) & 7] >>  8;
      const u32x Lp3 = Kh[(i + 5) & 7] >>  0;
      const u32x Lp4 = Kl[(i + 4) & 7] >> 24;
      const u32x Lp5 = Kl[(i + 3) & 7] >> 16;
      const u32x Lp6 = Kl[(i + 2) & 7] >>  8;
      const u32x Lp7 = Kl[(i + 1) & 7] >>  0;

      Lh[i] = BOX (s_Ch, 0, Lp0 & 0xff)
            ^ BOX (s_Ch, 1, Lp1 & 0xff)
            ^ BOX (s_Ch, 2, Lp2 & 0xff)
            ^ BOX (s_Ch, 3, Lp3 & 0xff)
            ^ BOX (s_Ch, 4, Lp4 & 0xff)
            ^ BOX (s_Ch, 5, Lp5 & 0xff)
            ^ BOX (s_Ch, 6, Lp6 & 0xff)
            ^ BOX (s_Ch, 7, Lp7 & 0xff);

      Ll[i] = BOX (s_Cl, 0, Lp0 & 0xff)
            ^ BOX (s_Cl, 1, Lp1 & 0xff)
            ^ BOX (s_Cl, 2, Lp2 & 0xff)
            ^ BOX (s_Cl, 3, Lp3 & 0xff)
            ^ BOX (s_Cl, 4, Lp4 & 0xff)
            ^ BOX (s_Cl, 5, Lp5 & 0xff)
            ^ BOX (s_Cl, 6, Lp6 & 0xff)
            ^ BOX (s_Cl, 7, Lp7 & 0xff);
    }

    Kh[0] = Lh[0] ^ rch[r];
    Kl[0] = Ll[0] ^ rcl[r];
    Kh[1] = Lh[1];
    Kl[1] = Ll[1];
    Kh[2] = Lh[2];
    Kl[2] = Ll[2];
    Kh[3] = Lh[3];
    Kl[3] = Ll[3];
    Kh[4] = Lh[4];
    Kl[4] = Ll[4];
    Kh[5] = Lh[5];
    Kl[5] = Ll[5];
    Kh[6] = Lh[6];
    Kl[6] = Ll[6];
    Kh[7] = Lh[7];
    Kl[7] = Ll[7];

    #ifdef _unroll
    #pragma unroll
    #endif
    for (i = 0; i < 8; i++)
    {
      const u32x Lp0 = stateh[(i + 8) & 7] >> 24;
      const u32x Lp1 = stateh[(i + 7) & 7] >> 16;
      const u32x Lp2 = stateh[(i + 6) & 7] >>  8;
      const u32x Lp3 = stateh[(i + 5) & 7] >>  0;
      const u32x Lp4 = statel[(i + 4) & 7] >> 24;
      const u32x Lp5 = statel[(i + 3) & 7] >> 16;
      const u32x Lp6 = statel[(i + 2) & 7] >>  8;
      const u32x Lp7 = statel[(i + 1) & 7] >>  0;

      Lh[i] = BOX (s_Ch, 0, Lp0 & 0xff)
            ^ BOX (s_Ch, 1, Lp1 & 0xff)
            ^ BOX (s_Ch, 2, Lp2 & 0xff)
            ^ BOX (s_Ch, 3, Lp3 & 0xff)
            ^ BOX (s_Ch, 4, Lp4 & 0xff)
            ^ BOX (s_Ch, 5, Lp5 & 0xff)
            ^ BOX (s_Ch, 6, Lp6 & 0xff)
            ^ BOX (s_Ch, 7, Lp7 & 0xff);

      Ll[i] = BOX (s_Cl, 0, Lp0 & 0xff)
            ^ BOX (s_Cl, 1, Lp1 & 0xff)
            ^ BOX (s_Cl, 2, Lp2 & 0xff)
            ^ BOX (s_Cl, 3, Lp3 & 0xff)
            ^ BOX (s_Cl, 4, Lp4 & 0xff)
            ^ BOX (s_Cl, 5, Lp5 & 0xff)
            ^ BOX (s_Cl, 6, Lp6 & 0xff)
            ^ BOX (s_Cl, 7, Lp7 & 0xff);
    }

    stateh[0] = Lh[0] ^ Kh[0];
    statel[0] = Ll[0] ^ Kl[0];
    stateh[1] = Lh[1] ^ Kh[1];
    statel[1] = Ll[1] ^ Kl[1];
    stateh[2] = Lh[2] ^ Kh[2];
    statel[2] = Ll[2] ^ Kl[2];
    stateh[3] = Lh[3] ^ Kh[3];
    statel[3] = Ll[3] ^ Kl[3];
    stateh[4] = Lh[4] ^ Kh[4];
    statel[4] = Ll[4] ^ Kl[4];
    stateh[5] = Lh[5] ^ Kh[5];
    statel[5] = Ll[5] ^ Kl[5];
    stateh[6] = Lh[6] ^ Kh[6];
    statel[6] = Ll[6] ^ Kl[6];
    stateh[7] = Lh[7] ^ Kh[7];
    statel[7] = Ll[7] ^ Kl[7];
  }

  digest[ 0] ^= stateh[0] ^ w0[0];
  digest[ 1] ^= statel[0] ^ w0[1];
  digest[ 2] ^= stateh[1] ^ w0[2];
  digest[ 3] ^= statel[1] ^ w0[3];
  digest[ 4] ^= stateh[2] ^ w1[0];
  digest[ 5] ^= statel[2] ^ w1[1];
  digest[ 6] ^= stateh[3] ^ w1[2];
  digest[ 7] ^= statel[3] ^ w1[3];
  digest[ 8] ^= stateh[4] ^ w2[0];
  digest[ 9] ^= statel[4] ^ w2[1];
  digest[10] ^= stateh[5] ^ w2[2];
  digest[11] ^= statel[5] ^ w2[3];
  digest[12] ^= stateh[6] ^ w3[0];
  digest[13] ^= statel[6] ^ w3[1];
  digest[14] ^= stateh[7] ^ w3[2];
  digest[15] ^= statel[7] ^ w3[3];
}

DECLSPEC void whirlpool_init_vector (whirlpool_ctx_vector_t *ctx, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  ctx->h[ 0] = 0;
  ctx->h[ 1] = 0;
  ctx->h[ 2] = 0;
  ctx->h[ 3] = 0;
  ctx->h[ 4] = 0;
  ctx->h[ 5] = 0;
  ctx->h[ 6] = 0;
  ctx->h[ 7] = 0;
  ctx->h[ 8] = 0;
  ctx->h[ 9] = 0;
  ctx->h[10] = 0;
  ctx->h[11] = 0;
  ctx->h[12] = 0;
  ctx->h[13] = 0;
  ctx->h[14] = 0;
  ctx->h[15] = 0;

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

  ctx->len = 0;

  ctx->s_Ch = s_Ch;
  ctx->s_Cl = s_Cl;
}

DECLSPEC void whirlpool_init_vector_from_scalar (whirlpool_ctx_vector_t *ctx, whirlpool_ctx_t *ctx0)
{
  ctx->h[ 0] = ctx0->h[ 0];
  ctx->h[ 1] = ctx0->h[ 1];
  ctx->h[ 2] = ctx0->h[ 2];
  ctx->h[ 3] = ctx0->h[ 3];
  ctx->h[ 4] = ctx0->h[ 4];
  ctx->h[ 5] = ctx0->h[ 5];
  ctx->h[ 6] = ctx0->h[ 6];
  ctx->h[ 7] = ctx0->h[ 7];
  ctx->h[ 8] = ctx0->h[ 8];
  ctx->h[ 9] = ctx0->h[ 9];
  ctx->h[10] = ctx0->h[10];
  ctx->h[11] = ctx0->h[11];
  ctx->h[12] = ctx0->h[12];
  ctx->h[13] = ctx0->h[13];
  ctx->h[14] = ctx0->h[14];
  ctx->h[15] = ctx0->h[15];

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

  ctx->len = ctx0->len;

  ctx->s_Ch = ctx0->s_Ch;
  ctx->s_Cl = ctx0->s_Cl;
}

DECLSPEC void whirlpool_update_vector_64 (whirlpool_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len)
{
  const int pos = ctx->len & 63;

  ctx->len += len;

  if ((pos + len) < 64)
  {
    switch_buffer_by_offset_be (w0, w1, w2, w3, pos);

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
  }
  else
  {
    u32x c0[4] = { 0 };
    u32x c1[4] = { 0 };
    u32x c2[4] = { 0 };
    u32x c3[4] = { 0 };

    switch_buffer_by_offset_carry_be (w0, w1, w2, w3, c0, c1, c2, c3, pos);

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

    whirlpool_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h, ctx->s_Ch, ctx->s_Cl);

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
  }
}

DECLSPEC void whirlpool_update_vector (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

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

    whirlpool_update_vector_64 (ctx, w0, w1, w2, w3, 64);
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

  whirlpool_update_vector_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void whirlpool_update_vector_swap (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

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

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = hc_swap32 (w3[2]);
    w3[3] = hc_swap32 (w3[3]);

    whirlpool_update_vector_64 (ctx, w0, w1, w2, w3, 64);
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

  w0[0] = hc_swap32 (w0[0]);
  w0[1] = hc_swap32 (w0[1]);
  w0[2] = hc_swap32 (w0[2]);
  w0[3] = hc_swap32 (w0[3]);
  w1[0] = hc_swap32 (w1[0]);
  w1[1] = hc_swap32 (w1[1]);
  w1[2] = hc_swap32 (w1[2]);
  w1[3] = hc_swap32 (w1[3]);
  w2[0] = hc_swap32 (w2[0]);
  w2[1] = hc_swap32 (w2[1]);
  w2[2] = hc_swap32 (w2[2]);
  w2[3] = hc_swap32 (w2[3]);
  w3[0] = hc_swap32 (w3[0]);
  w3[1] = hc_swap32 (w3[1]);
  w3[2] = hc_swap32 (w3[2]);
  w3[3] = hc_swap32 (w3[3]);

  whirlpool_update_vector_64 (ctx, w0, w1, w2, w3, len - pos1);
}

DECLSPEC void whirlpool_update_vector_utf16le (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    whirlpool_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  whirlpool_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void whirlpool_update_vector_utf16le_swap (whirlpool_ctx_vector_t *ctx, const u32x *w, const int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int pos1;
  int pos4;

  for (pos1 = 0, pos4 = 0; pos1 < len - 32; pos1 += 32, pos4 += 8)
  {
    w0[0] = w[pos4 + 0];
    w0[1] = w[pos4 + 1];
    w0[2] = w[pos4 + 2];
    w0[3] = w[pos4 + 3];
    w1[0] = w[pos4 + 4];
    w1[1] = w[pos4 + 5];
    w1[2] = w[pos4 + 6];
    w1[3] = w[pos4 + 7];

    make_utf16le (w1, w2, w3);
    make_utf16le (w0, w0, w1);

    w0[0] = hc_swap32 (w0[0]);
    w0[1] = hc_swap32 (w0[1]);
    w0[2] = hc_swap32 (w0[2]);
    w0[3] = hc_swap32 (w0[3]);
    w1[0] = hc_swap32 (w1[0]);
    w1[1] = hc_swap32 (w1[1]);
    w1[2] = hc_swap32 (w1[2]);
    w1[3] = hc_swap32 (w1[3]);
    w2[0] = hc_swap32 (w2[0]);
    w2[1] = hc_swap32 (w2[1]);
    w2[2] = hc_swap32 (w2[2]);
    w2[3] = hc_swap32 (w2[3]);
    w3[0] = hc_swap32 (w3[0]);
    w3[1] = hc_swap32 (w3[1]);
    w3[2] = hc_swap32 (w3[2]);
    w3[3] = hc_swap32 (w3[3]);

    whirlpool_update_vector_64 (ctx, w0, w1, w2, w3, 32 * 2);
  }

  w0[0] = w[pos4 + 0];
  w0[1] = w[pos4 + 1];
  w0[2] = w[pos4 + 2];
  w0[3] = w[pos4 + 3];
  w1[0] = w[pos4 + 4];
  w1[1] = w[pos4 + 5];
  w1[2] = w[pos4 + 6];
  w1[3] = w[pos4 + 7];

  make_utf16le (w1, w2, w3);
  make_utf16le (w0, w0, w1);

  w0[0] = hc_swap32 (w0[0]);
  w0[1] = hc_swap32 (w0[1]);
  w0[2] = hc_swap32 (w0[2]);
  w0[3] = hc_swap32 (w0[3]);
  w1[0] = hc_swap32 (w1[0]);
  w1[1] = hc_swap32 (w1[1]);
  w1[2] = hc_swap32 (w1[2]);
  w1[3] = hc_swap32 (w1[3]);
  w2[0] = hc_swap32 (w2[0]);
  w2[1] = hc_swap32 (w2[1]);
  w2[2] = hc_swap32 (w2[2]);
  w2[3] = hc_swap32 (w2[3]);
  w3[0] = hc_swap32 (w3[0]);
  w3[1] = hc_swap32 (w3[1]);
  w3[2] = hc_swap32 (w3[2]);
  w3[3] = hc_swap32 (w3[3]);

  whirlpool_update_vector_64 (ctx, w0, w1, w2, w3, (len - pos1) * 2);
}

DECLSPEC void whirlpool_final_vector (whirlpool_ctx_vector_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x80_4x4 (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

  if (pos >= 32)
  {
    whirlpool_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h, ctx->s_Ch, ctx->s_Cl);

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
  }

  ctx->w3[2] = 0;
  ctx->w3[3] = ctx->len * 8;

  whirlpool_transform_vector (ctx->w0, ctx->w1, ctx->w2, ctx->w3, ctx->h, ctx->s_Ch, ctx->s_Cl);
}

// HMAC + Vector

DECLSPEC void whirlpool_hmac_init_vector_64 (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];

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

  whirlpool_init_vector (&ctx->ipad, s_Ch, s_Cl);

  whirlpool_update_vector_64 (&ctx->ipad, t0, t1, t2, t3, 64);

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

  whirlpool_init_vector (&ctx->opad, s_Ch, s_Cl);

  whirlpool_update_vector_64 (&ctx->opad, t0, t1, t2, t3, 64);
}

DECLSPEC void whirlpool_hmac_init_vector (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  if (len > 64)
  {
    whirlpool_ctx_vector_t tmp;

    whirlpool_init_vector (&tmp, s_Ch, s_Cl);

    whirlpool_update_vector (&tmp, w, len);

    whirlpool_final_vector (&tmp);

    w0[0] = tmp.h[ 0];
    w0[1] = tmp.h[ 1];
    w0[2] = tmp.h[ 2];
    w0[3] = tmp.h[ 3];
    w1[0] = tmp.h[ 4];
    w1[1] = tmp.h[ 5];
    w1[2] = tmp.h[ 6];
    w1[3] = tmp.h[ 7];
    w2[0] = tmp.h[ 8];
    w2[1] = tmp.h[ 9];
    w2[2] = tmp.h[10];
    w2[3] = tmp.h[11];
    w3[0] = tmp.h[12];
    w3[1] = tmp.h[13];
    w3[2] = tmp.h[14];
    w3[3] = tmp.h[15];
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
  }

  whirlpool_hmac_init_vector_64 (ctx, w0, w1, w2, w3, s_Ch, s_Cl);
}

DECLSPEC void whirlpool_hmac_update_vector_64 (whirlpool_hmac_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len)
{
  whirlpool_update_vector_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void whirlpool_hmac_update_vector (whirlpool_hmac_ctx_vector_t *ctx, const u32x *w, const int len)
{
  whirlpool_update_vector (&ctx->ipad, w, len);
}

DECLSPEC void whirlpool_hmac_final_vector (whirlpool_hmac_ctx_vector_t *ctx)
{
  whirlpool_final_vector (&ctx->ipad);

  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];

  t0[0] = ctx->ipad.h[ 0];
  t0[1] = ctx->ipad.h[ 1];
  t0[2] = ctx->ipad.h[ 2];
  t0[3] = ctx->ipad.h[ 3];
  t1[0] = ctx->ipad.h[ 4];
  t1[1] = ctx->ipad.h[ 5];
  t1[2] = ctx->ipad.h[ 6];
  t1[3] = ctx->ipad.h[ 7];
  t2[0] = ctx->ipad.h[ 8];
  t2[1] = ctx->ipad.h[ 9];
  t2[2] = ctx->ipad.h[10];
  t2[3] = ctx->ipad.h[11];
  t3[0] = ctx->ipad.h[12];
  t3[1] = ctx->ipad.h[13];
  t3[2] = ctx->ipad.h[14];
  t3[3] = ctx->ipad.h[15];

  whirlpool_update_vector_64 (&ctx->opad, t0, t1, t2, t3, 64);

  whirlpool_final_vector (&ctx->opad);
}

#undef R
#undef BOX
#undef BOX_S
