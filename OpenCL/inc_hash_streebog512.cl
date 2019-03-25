/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_hash_streebog512.h"

DECLSPEC void streebog512_init (streebog512_ctx_t *ctx, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  ctx->h[0] = 0;
  ctx->h[1] = 0;
  ctx->h[2] = 0;
  ctx->h[3] = 0;
  ctx->h[4] = 0;
  ctx->h[5] = 0;
  ctx->h[6] = 0;
  ctx->h[7] = 0;

  ctx->s[0] = 0;
  ctx->s[1] = 0;
  ctx->s[2] = 0;
  ctx->s[3] = 0;
  ctx->s[4] = 0;
  ctx->s[5] = 0;
  ctx->s[6] = 0;
  ctx->s[7] = 0;

  ctx->n[0] = 0;
  ctx->n[1] = 0;
  ctx->n[2] = 0;
  ctx->n[3] = 0;
  ctx->n[4] = 0;
  ctx->n[5] = 0;
  ctx->n[6] = 0;
  ctx->n[7] = 0;

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

  ctx->s_sbob_sl64 = s_sbob_sl64;
}

DECLSPEC void streebog512_add (u64 *x, const u64 *y)
{
  u64 carry = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 7; i >=0; i--)
  {
    const u64 left  = hc_swap64_S (x[i]);
    const u64 right = hc_swap64_S (y[i]);
    const u64 sum   = left + right + carry;

    carry = (sum < left) ? (u64) 1 : (u64) 0;

    x[i] = hc_swap64_S (sum);
  }
}

DECLSPEC void streebog512_g (u64 *h, const u64 *n, const u64 *m, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  u64 k[8];
  u64 s[8];
  u64 t[8];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    t[i] = h[i] ^ n[i];
  }

  for (int i = 0; i < 8; i++)
  {
    k[i] = SBOG_LPSti64;
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    s[i] = m[i];
  }

  for (int r = 0; r < 12; r++)
  {
    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      t[i] = s[i] ^ k[i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      s[i] = SBOG_LPSti64;
    }

    for (int i = 0; i < 8; i++)
    {
      t[i] = k[i] ^ sbob_rc64[r][i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      k[i] = SBOG_LPSti64;
    }
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    h[i] ^= s[i] ^ k[i] ^ m[i];
  }
}

DECLSPEC void streebog512_transform (streebog512_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3)
{
  u64 m[8];

  m[0] = hl32_to_64_S (w3[2], w3[3]);
  m[1] = hl32_to_64_S (w3[0], w3[1]);
  m[2] = hl32_to_64_S (w2[2], w2[3]);
  m[3] = hl32_to_64_S (w2[0], w2[1]);
  m[4] = hl32_to_64_S (w1[2], w1[3]);
  m[5] = hl32_to_64_S (w1[0], w1[1]);
  m[6] = hl32_to_64_S (w0[2], w0[3]);
  m[7] = hl32_to_64_S (w0[0], w0[1]);

  streebog512_g (ctx->h, ctx->n, m, ctx->s_sbob_sl64);

  u64 counterbuf[8] = { 0 };
  counterbuf[7] = 0x0002000000000000;
  streebog512_add (ctx->n, counterbuf);

  streebog512_add (ctx->s, m);
}

DECLSPEC void streebog512_update_64 (streebog512_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len)
{
  const int pos = ctx->len;

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

    ctx->len += len;
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

    streebog512_transform (ctx, ctx->w0, ctx->w1, ctx->w2, ctx->w3);

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

    ctx->len = (pos + len) & 63;
  }
}

DECLSPEC void streebog512_update (streebog512_ctx_t *ctx, const u32 *w, int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int off = 0;

  while (len > 63)
  {
    w0[0] = w[off +  0];
    w0[1] = w[off +  1];
    w0[2] = w[off +  2];
    w0[3] = w[off +  3];
    w1[0] = w[off +  4];
    w1[1] = w[off +  5];
    w1[2] = w[off +  6];
    w1[3] = w[off +  7];
    w2[0] = w[off +  8];
    w2[1] = w[off +  9];
    w2[2] = w[off + 10];
    w2[3] = w[off + 11];
    w3[0] = w[off + 12];
    w3[1] = w[off + 13];
    w3[2] = w[off + 14];
    w3[3] = w[off + 15];

    off += 16;
    len -= 64;

    streebog512_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  if (len > 0)
  {
    w0[0] = w[off +  0];
    w0[1] = w[off +  1];
    w0[2] = w[off +  2];
    w0[3] = w[off +  3];
    w1[0] = w[off +  4];
    w1[1] = w[off +  5];
    w1[2] = w[off +  6];
    w1[3] = w[off +  7];
    w2[0] = w[off +  8];
    w2[1] = w[off +  9];
    w2[2] = w[off + 10];
    w2[3] = w[off + 11];
    w3[0] = w[off + 12];
    w3[1] = w[off + 13];
    w3[2] = w[off + 14];
    w3[3] = w[off + 15];

    streebog512_update_64 (ctx, w0, w1, w2, w3, len);
  }
}

DECLSPEC void streebog512_update_swap (streebog512_ctx_t *ctx, const u32 *w, int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int off = 0;

  while (len > 63)
  {
    w0[0] = hc_swap32_S (w[off +  0]);
    w0[1] = hc_swap32_S (w[off +  1]);
    w0[2] = hc_swap32_S (w[off +  2]);
    w0[3] = hc_swap32_S (w[off +  3]);
    w1[0] = hc_swap32_S (w[off +  4]);
    w1[1] = hc_swap32_S (w[off +  5]);
    w1[2] = hc_swap32_S (w[off +  6]);
    w1[3] = hc_swap32_S (w[off +  7]);
    w2[0] = hc_swap32_S (w[off +  8]);
    w2[1] = hc_swap32_S (w[off +  9]);
    w2[2] = hc_swap32_S (w[off + 10]);
    w2[3] = hc_swap32_S (w[off + 11]);
    w3[0] = hc_swap32_S (w[off + 12]);
    w3[1] = hc_swap32_S (w[off + 13]);
    w3[2] = hc_swap32_S (w[off + 14]);
    w3[3] = hc_swap32_S (w[off + 15]);

    off += 16;
    len -= 64;

    streebog512_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  if (len > 0)
  {
    w0[0] = hc_swap32_S (w[off +  0]);
    w0[1] = hc_swap32_S (w[off +  1]);
    w0[2] = hc_swap32_S (w[off +  2]);
    w0[3] = hc_swap32_S (w[off +  3]);
    w1[0] = hc_swap32_S (w[off +  4]);
    w1[1] = hc_swap32_S (w[off +  5]);
    w1[2] = hc_swap32_S (w[off +  6]);
    w1[3] = hc_swap32_S (w[off +  7]);
    w2[0] = hc_swap32_S (w[off +  8]);
    w2[1] = hc_swap32_S (w[off +  9]);
    w2[2] = hc_swap32_S (w[off + 10]);
    w2[3] = hc_swap32_S (w[off + 11]);
    w3[0] = hc_swap32_S (w[off + 12]);
    w3[1] = hc_swap32_S (w[off + 13]);
    w3[2] = hc_swap32_S (w[off + 14]);
    w3[3] = hc_swap32_S (w[off + 15]);

    streebog512_update_64 (ctx, w0, w1, w2, w3, len);
  }
}

DECLSPEC void streebog512_update_global_swap (streebog512_ctx_t *ctx, const GLOBAL_AS u32 *w, int len)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int off = 0;

  while (len > 63)
  {
    w0[0] = hc_swap32_S (w[off +  0]);
    w0[1] = hc_swap32_S (w[off +  1]);
    w0[2] = hc_swap32_S (w[off +  2]);
    w0[3] = hc_swap32_S (w[off +  3]);
    w1[0] = hc_swap32_S (w[off +  4]);
    w1[1] = hc_swap32_S (w[off +  5]);
    w1[2] = hc_swap32_S (w[off +  6]);
    w1[3] = hc_swap32_S (w[off +  7]);
    w2[0] = hc_swap32_S (w[off +  8]);
    w2[1] = hc_swap32_S (w[off +  9]);
    w2[2] = hc_swap32_S (w[off + 10]);
    w2[3] = hc_swap32_S (w[off + 11]);
    w3[0] = hc_swap32_S (w[off + 12]);
    w3[1] = hc_swap32_S (w[off + 13]);
    w3[2] = hc_swap32_S (w[off + 14]);
    w3[3] = hc_swap32_S (w[off + 15]);

    off += 16;
    len -= 64;

    streebog512_update_64 (ctx, w0, w1, w2, w3, 64);
  }

  if (len > 0)
  {
    w0[0] = hc_swap32_S (w[off +  0]);
    w0[1] = hc_swap32_S (w[off +  1]);
    w0[2] = hc_swap32_S (w[off +  2]);
    w0[3] = hc_swap32_S (w[off +  3]);
    w1[0] = hc_swap32_S (w[off +  4]);
    w1[1] = hc_swap32_S (w[off +  5]);
    w1[2] = hc_swap32_S (w[off +  6]);
    w1[3] = hc_swap32_S (w[off +  7]);
    w2[0] = hc_swap32_S (w[off +  8]);
    w2[1] = hc_swap32_S (w[off +  9]);
    w2[2] = hc_swap32_S (w[off + 10]);
    w2[3] = hc_swap32_S (w[off + 11]);
    w3[0] = hc_swap32_S (w[off + 12]);
    w3[1] = hc_swap32_S (w[off + 13]);
    w3[2] = hc_swap32_S (w[off + 14]);
    w3[3] = hc_swap32_S (w[off + 15]);

    streebog512_update_64 (ctx, w0, w1, w2, w3, len);
  }
}

DECLSPEC void streebog512_final (streebog512_ctx_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x01_4x4_S (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

  u64 m[8];

  m[0] = hl32_to_64_S (ctx->w3[2], ctx->w3[3]);
  m[1] = hl32_to_64_S (ctx->w3[0], ctx->w3[1]);
  m[2] = hl32_to_64_S (ctx->w2[2], ctx->w2[3]);
  m[3] = hl32_to_64_S (ctx->w2[0], ctx->w2[1]);
  m[4] = hl32_to_64_S (ctx->w1[2], ctx->w1[3]);
  m[5] = hl32_to_64_S (ctx->w1[0], ctx->w1[1]);
  m[6] = hl32_to_64_S (ctx->w0[2], ctx->w0[3]);
  m[7] = hl32_to_64_S (ctx->w0[0], ctx->w0[1]);

  streebog512_g (ctx->h, ctx->n, m, ctx->s_sbob_sl64);

  u64 sizebuf[8] = { 0 };
  sizebuf[7] = hc_swap64_S ((u64) (ctx->len << 3));

  streebog512_add (ctx->n, sizebuf);

  streebog512_add (ctx->s, m);

  const u64 nullbuf[8] = { 0 };

  streebog512_g (ctx->h, nullbuf, ctx->n, ctx->s_sbob_sl64);

  streebog512_g (ctx->h, nullbuf, ctx->s, ctx->s_sbob_sl64);
}

DECLSPEC void streebog512_hmac_init_64 (streebog512_hmac_ctx_t *ctx, const u32 *w0, const u32 *w1, const u32 *w2, const u32 *w3, SHM_TYPE u64a (*s_sbob_sl64)[256])
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

  streebog512_init (&ctx->ipad, s_sbob_sl64);

  streebog512_update_64 (&ctx->ipad, t0, t1, t2, t3, 64);

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

  streebog512_init (&ctx->opad, s_sbob_sl64);

  streebog512_update_64 (&ctx->opad, t0, t1, t2, t3, 64);
}

DECLSPEC void streebog512_hmac_init (streebog512_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    streebog512_ctx_t tmp;

    streebog512_init (&tmp, s_sbob_sl64);

    streebog512_update (&tmp, w, len);

    streebog512_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[7]);
    w0[1] = l32_from_64_S (tmp.h[7]);
    w0[2] = h32_from_64_S (tmp.h[6]);
    w0[3] = l32_from_64_S (tmp.h[6]);
    w1[0] = h32_from_64_S (tmp.h[5]);
    w1[1] = l32_from_64_S (tmp.h[5]);
    w1[2] = h32_from_64_S (tmp.h[4]);
    w1[3] = l32_from_64_S (tmp.h[4]);
    w2[0] = h32_from_64_S (tmp.h[3]);
    w2[1] = l32_from_64_S (tmp.h[3]);
    w2[2] = h32_from_64_S (tmp.h[2]);
    w2[3] = l32_from_64_S (tmp.h[2]);
    w3[0] = h32_from_64_S (tmp.h[1]);
    w3[1] = l32_from_64_S (tmp.h[1]);
    w3[2] = h32_from_64_S (tmp.h[0]);
    w3[3] = l32_from_64_S (tmp.h[0]);
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

  streebog512_hmac_init_64 (ctx, w0, w1, w2, w3, s_sbob_sl64);
}

DECLSPEC void streebog512_hmac_init_swap (streebog512_hmac_ctx_t *ctx, const u32 *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  if (len > 64)
  {
    streebog512_ctx_t tmp;

    streebog512_init (&tmp, s_sbob_sl64);

    streebog512_update_swap (&tmp, w, len);

    streebog512_final (&tmp);

    w0[0] = h32_from_64_S (tmp.h[7]);
    w0[1] = l32_from_64_S (tmp.h[7]);
    w0[2] = h32_from_64_S (tmp.h[6]);
    w0[3] = l32_from_64_S (tmp.h[6]);
    w1[0] = h32_from_64_S (tmp.h[5]);
    w1[1] = l32_from_64_S (tmp.h[5]);
    w1[2] = h32_from_64_S (tmp.h[4]);
    w1[3] = l32_from_64_S (tmp.h[4]);
    w2[0] = h32_from_64_S (tmp.h[3]);
    w2[1] = l32_from_64_S (tmp.h[3]);
    w2[2] = h32_from_64_S (tmp.h[2]);
    w2[3] = l32_from_64_S (tmp.h[2]);
    w3[0] = h32_from_64_S (tmp.h[1]);
    w3[1] = l32_from_64_S (tmp.h[1]);
    w3[2] = h32_from_64_S (tmp.h[0]);
    w3[3] = l32_from_64_S (tmp.h[0]);
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

  streebog512_hmac_init_64 (ctx, w0, w1, w2, w3, s_sbob_sl64);
}

DECLSPEC void streebog512_hmac_update_64 (streebog512_hmac_ctx_t *ctx, u32 *w0, u32 *w1, u32 *w2, u32 *w3, const int len)
{
  streebog512_update_64 (&ctx->ipad, w0, w1, w2, w3, len);
}

DECLSPEC void streebog512_hmac_update (streebog512_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  streebog512_update (&ctx->ipad, w, len);
}

DECLSPEC void streebog512_hmac_update_swap (streebog512_hmac_ctx_t *ctx, const u32 *w, const int len)
{
  streebog512_update_swap (&ctx->ipad, w, len);
}

DECLSPEC void streebog512_hmac_update_global_swap (streebog512_hmac_ctx_t *ctx, const GLOBAL_AS u32 *w, const int len)
{
  streebog512_update_global_swap (&ctx->ipad, w, len);
}

DECLSPEC void streebog512_hmac_final (streebog512_hmac_ctx_t *ctx)
{
  streebog512_final (&ctx->ipad);

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];

  t0[0] = h32_from_64_S (ctx->ipad.h[7]);
  t0[1] = l32_from_64_S (ctx->ipad.h[7]);
  t0[2] = h32_from_64_S (ctx->ipad.h[6]);
  t0[3] = l32_from_64_S (ctx->ipad.h[6]);
  t1[0] = h32_from_64_S (ctx->ipad.h[5]);
  t1[1] = l32_from_64_S (ctx->ipad.h[5]);
  t1[2] = h32_from_64_S (ctx->ipad.h[4]);
  t1[3] = l32_from_64_S (ctx->ipad.h[4]);
  t2[0] = h32_from_64_S (ctx->ipad.h[3]);
  t2[1] = l32_from_64_S (ctx->ipad.h[3]);
  t2[2] = h32_from_64_S (ctx->ipad.h[2]);
  t2[3] = l32_from_64_S (ctx->ipad.h[2]);
  t3[0] = h32_from_64_S (ctx->ipad.h[1]);
  t3[1] = l32_from_64_S (ctx->ipad.h[1]);
  t3[2] = h32_from_64_S (ctx->ipad.h[0]);
  t3[3] = l32_from_64_S (ctx->ipad.h[0]);

  streebog512_update_64 (&ctx->opad, t0, t1, t2, t3, 64);

  streebog512_final (&ctx->opad);
}

DECLSPEC void streebog512_init_vector (streebog512_ctx_vector_t *ctx, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  ctx->h[0] = 0;
  ctx->h[1] = 0;
  ctx->h[2] = 0;
  ctx->h[3] = 0;
  ctx->h[4] = 0;
  ctx->h[5] = 0;
  ctx->h[6] = 0;
  ctx->h[7] = 0;

  ctx->s[0] = 0;
  ctx->s[1] = 0;
  ctx->s[2] = 0;
  ctx->s[3] = 0;
  ctx->s[4] = 0;
  ctx->s[5] = 0;
  ctx->s[6] = 0;
  ctx->s[7] = 0;

  ctx->n[0] = 0;
  ctx->n[1] = 0;
  ctx->n[2] = 0;
  ctx->n[3] = 0;
  ctx->n[4] = 0;
  ctx->n[5] = 0;
  ctx->n[6] = 0;
  ctx->n[7] = 0;

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

  ctx->s_sbob_sl64 = s_sbob_sl64;
}

DECLSPEC void streebog512_add_vector (u64x *x, const u64x *y)
{
  u64x carry = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 7; i >=0; i--)
  {
    const u64x left  = hc_swap64 (x[i]);
    const u64x right = hc_swap64 (y[i]);
    const u64x sum   = left + right + carry;

    carry = (sum < left) ? (u64x) 1 : (u64x) 0;

    x[i] = hc_swap64 (sum);
  }
}

DECLSPEC void streebog512_g_vector (u64x *h, const u64x *n, const u64x *m, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  u64x k[8];
  u64x s[8];
  u64x t[8];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    t[i] = h[i] ^ n[i];
  }

  for (int i = 0; i < 8; i++)
  {
    k[i] = SBOG_LPSti64;
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    s[i] = m[i];
  }

  for (int r = 0; r < 12; r++)
  {
    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      t[i] = s[i] ^ k[i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      s[i] = SBOG_LPSti64;
    }

    for (int i = 0; i < 8; i++)
    {
      t[i] = k[i] ^ sbob_rc64[r][i];
    }

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int i = 0; i < 8; i++)
    {
      k[i] = SBOG_LPSti64;
    }
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 8; i++)
  {
    h[i] ^= s[i] ^ k[i] ^ m[i];
  }
}

DECLSPEC void streebog512_transform_vector (streebog512_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3)
{
  u64x m[8];

  m[0] = hl32_to_64 (w3[2], w3[3]);
  m[1] = hl32_to_64 (w3[0], w3[1]);
  m[2] = hl32_to_64 (w2[2], w2[3]);
  m[3] = hl32_to_64 (w2[0], w2[1]);
  m[4] = hl32_to_64 (w1[2], w1[3]);
  m[5] = hl32_to_64 (w1[0], w1[1]);
  m[6] = hl32_to_64 (w0[2], w0[3]);
  m[7] = hl32_to_64 (w0[0], w0[1]);

  streebog512_g_vector (ctx->h, ctx->n, m, ctx->s_sbob_sl64);

  u64x counterbuf[8] = { 0 };
  counterbuf[7] = 0x0002000000000000;
  streebog512_add_vector (ctx->n, counterbuf);

  streebog512_add_vector (ctx->s, m);
}

DECLSPEC void streebog512_update_vector_64 (streebog512_ctx_vector_t *ctx, u32x *w0, u32x *w1, u32x *w2, u32x *w3, const int len)
{
  const int pos = ctx->len;

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

    ctx->len += len;
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

    streebog512_transform_vector (ctx, ctx->w0, ctx->w1, ctx->w2, ctx->w3);

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

    ctx->len = (pos + len) & 63;
  }
}

DECLSPEC void streebog512_update_vector (streebog512_ctx_vector_t *ctx, const u32x *w, int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int off = 0;

  while (len > 63)
  {
    w0[0] = w[off +  0];
    w0[1] = w[off +  1];
    w0[2] = w[off +  2];
    w0[3] = w[off +  3];
    w1[0] = w[off +  4];
    w1[1] = w[off +  5];
    w1[2] = w[off +  6];
    w1[3] = w[off +  7];
    w2[0] = w[off +  8];
    w2[1] = w[off +  9];
    w2[2] = w[off + 10];
    w2[3] = w[off + 11];
    w3[0] = w[off + 12];
    w3[1] = w[off + 13];
    w3[2] = w[off + 14];
    w3[3] = w[off + 15];

    off += 16;
    len -= 64;

    streebog512_update_vector_64 (ctx, w0, w1, w2, w3, 64);
  }

  if (len > 0)
  {
    w0[0] = w[off +  0];
    w0[1] = w[off +  1];
    w0[2] = w[off +  2];
    w0[3] = w[off +  3];
    w1[0] = w[off +  4];
    w1[1] = w[off +  5];
    w1[2] = w[off +  6];
    w1[3] = w[off +  7];
    w2[0] = w[off +  8];
    w2[1] = w[off +  9];
    w2[2] = w[off + 10];
    w2[3] = w[off + 11];
    w3[0] = w[off + 12];
    w3[1] = w[off + 13];
    w3[2] = w[off + 14];
    w3[3] = w[off + 15];

    streebog512_update_vector_64 (ctx, w0, w1, w2, w3, len);
  }
}

DECLSPEC void streebog512_update_vector_swap (streebog512_ctx_vector_t *ctx, const u32x *w, int len)
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  int off = 0;

  while (len > 63)
  {
    w0[0] = hc_swap32 (w[off +  0]);
    w0[1] = hc_swap32 (w[off +  1]);
    w0[2] = hc_swap32 (w[off +  2]);
    w0[3] = hc_swap32 (w[off +  3]);
    w1[0] = hc_swap32 (w[off +  4]);
    w1[1] = hc_swap32 (w[off +  5]);
    w1[2] = hc_swap32 (w[off +  6]);
    w1[3] = hc_swap32 (w[off +  7]);
    w2[0] = hc_swap32 (w[off +  8]);
    w2[1] = hc_swap32 (w[off +  9]);
    w2[2] = hc_swap32 (w[off + 10]);
    w2[3] = hc_swap32 (w[off + 11]);
    w3[0] = hc_swap32 (w[off + 12]);
    w3[1] = hc_swap32 (w[off + 13]);
    w3[2] = hc_swap32 (w[off + 14]);
    w3[3] = hc_swap32 (w[off + 15]);

    off += 16;
    len -= 64;

    streebog512_update_vector_64 (ctx, w0, w1, w2, w3, 64);
  }

  if (len > 0)
  {
    w0[0] = hc_swap32 (w[off +  0]);
    w0[1] = hc_swap32 (w[off +  1]);
    w0[2] = hc_swap32 (w[off +  2]);
    w0[3] = hc_swap32 (w[off +  3]);
    w1[0] = hc_swap32 (w[off +  4]);
    w1[1] = hc_swap32 (w[off +  5]);
    w1[2] = hc_swap32 (w[off +  6]);
    w1[3] = hc_swap32 (w[off +  7]);
    w2[0] = hc_swap32 (w[off +  8]);
    w2[1] = hc_swap32 (w[off +  9]);
    w2[2] = hc_swap32 (w[off + 10]);
    w2[3] = hc_swap32 (w[off + 11]);
    w3[0] = hc_swap32 (w[off + 12]);
    w3[1] = hc_swap32 (w[off + 13]);
    w3[2] = hc_swap32 (w[off + 14]);
    w3[3] = hc_swap32 (w[off + 15]);

    streebog512_update_vector_64 (ctx, w0, w1, w2, w3, len);
  }
}

DECLSPEC void streebog512_final_vector (streebog512_ctx_vector_t *ctx)
{
  const int pos = ctx->len & 63;

  append_0x01_4x4_VV (ctx->w0, ctx->w1, ctx->w2, ctx->w3, pos ^ 3);

  u64x m[8];

  m[0] = hl32_to_64 (ctx->w3[2], ctx->w3[3]);
  m[1] = hl32_to_64 (ctx->w3[0], ctx->w3[1]);
  m[2] = hl32_to_64 (ctx->w2[2], ctx->w2[3]);
  m[3] = hl32_to_64 (ctx->w2[0], ctx->w2[1]);
  m[4] = hl32_to_64 (ctx->w1[2], ctx->w1[3]);
  m[5] = hl32_to_64 (ctx->w1[0], ctx->w1[1]);
  m[6] = hl32_to_64 (ctx->w0[2], ctx->w0[3]);
  m[7] = hl32_to_64 (ctx->w0[0], ctx->w0[1]);

  streebog512_g_vector (ctx->h, ctx->n, m, ctx->s_sbob_sl64);

  u64x sizebuf[8] = { 0 };
  sizebuf[7] = hc_swap64 ((u64x) (ctx->len << 3));

  streebog512_add_vector (ctx->n, sizebuf);

  streebog512_add_vector (ctx->s, m);

  const u64x nullbuf[8] = { 0 };

  streebog512_g_vector (ctx->h, nullbuf, ctx->n, ctx->s_sbob_sl64);

  streebog512_g_vector (ctx->h, nullbuf, ctx->s, ctx->s_sbob_sl64);
}

DECLSPEC void streebog512_hmac_init_vector_64 (streebog512_hmac_ctx_vector_t *ctx, const u32x *w0, const u32x *w1, const u32x *w2, const u32x *w3, SHM_TYPE u64a (*s_sbob_sl64)[256])
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

  streebog512_init_vector (&ctx->ipad, s_sbob_sl64);

  streebog512_update_vector_64 (&ctx->ipad, t0, t1, t2, t3, 64);

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

  streebog512_init_vector (&ctx->opad, s_sbob_sl64);

  streebog512_update_vector_64 (&ctx->opad, t0, t1, t2, t3, 64);
}

DECLSPEC void streebog512_hmac_init_vector (streebog512_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  if (len > 64)
  {
    streebog512_ctx_vector_t tmp;

    streebog512_init_vector (&tmp, s_sbob_sl64);

    streebog512_update_vector (&tmp, w, len);

    streebog512_final_vector (&tmp);

    w0[0] = h32_from_64 (tmp.h[7]);
    w0[1] = l32_from_64 (tmp.h[7]);
    w0[2] = h32_from_64 (tmp.h[6]);
    w0[3] = l32_from_64 (tmp.h[6]);
    w1[0] = h32_from_64 (tmp.h[5]);
    w1[1] = l32_from_64 (tmp.h[5]);
    w1[2] = h32_from_64 (tmp.h[4]);
    w1[3] = l32_from_64 (tmp.h[4]);
    w2[0] = h32_from_64 (tmp.h[3]);
    w2[1] = l32_from_64 (tmp.h[3]);
    w2[2] = h32_from_64 (tmp.h[2]);
    w2[3] = l32_from_64 (tmp.h[2]);
    w3[0] = h32_from_64 (tmp.h[1]);
    w3[1] = l32_from_64 (tmp.h[1]);
    w3[2] = h32_from_64 (tmp.h[0]);
    w3[3] = l32_from_64 (tmp.h[0]);
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

  streebog512_hmac_init_vector_64 (ctx, w0, w1, w2, w3, s_sbob_sl64);
}

DECLSPEC void streebog512_hmac_init_vector_swap (streebog512_hmac_ctx_vector_t *ctx, const u32x *w, const int len, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  u32x w0[4];
  u32x w1[4];
  u32x w2[4];
  u32x w3[4];

  if (len > 64)
  {
    streebog512_ctx_vector_t tmp;

    streebog512_init_vector (&tmp, s_sbob_sl64);

    streebog512_update_vector_swap (&tmp, w, len);

    streebog512_final_vector (&tmp);

    w0[0] = h32_from_64 (tmp.h[7]);
    w0[1] = l32_from_64 (tmp.h[7]);
    w0[2] = h32_from_64 (tmp.h[6]);
    w0[3] = l32_from_64 (tmp.h[6]);
    w1[0] = h32_from_64 (tmp.h[5]);
    w1[1] = l32_from_64 (tmp.h[5]);
    w1[2] = h32_from_64 (tmp.h[4]);
    w1[3] = l32_from_64 (tmp.h[4]);
    w2[0] = h32_from_64 (tmp.h[3]);
    w2[1] = l32_from_64 (tmp.h[3]);
    w2[2] = h32_from_64 (tmp.h[2]);
    w2[3] = l32_from_64 (tmp.h[2]);
    w3[0] = h32_from_64 (tmp.h[1]);
    w3[1] = l32_from_64 (tmp.h[1]);
    w3[2] = h32_from_64 (tmp.h[0]);
    w3[3] = l32_from_64 (tmp.h[0]);
  }
  else
  {
    w0[0] = hc_swap32 (w[ 0]);
    w0[1] = hc_swap32 (w[ 1]);
    w0[2] = hc_swap32 (w[ 2]);
    w0[3] = hc_swap32 (w[ 3]);
    w1[0] = hc_swap32 (w[ 4]);
    w1[1] = hc_swap32 (w[ 5]);
    w1[2] = hc_swap32 (w[ 6]);
    w1[3] = hc_swap32 (w[ 7]);
    w2[0] = hc_swap32 (w[ 8]);
    w2[1] = hc_swap32 (w[ 9]);
    w2[2] = hc_swap32 (w[10]);
    w2[3] = hc_swap32 (w[11]);
    w3[0] = hc_swap32 (w[12]);
    w3[1] = hc_swap32 (w[13]);
    w3[2] = hc_swap32 (w[14]);
    w3[3] = hc_swap32 (w[15]);
  }

  streebog512_hmac_init_vector_64 (ctx, w0, w1, w2, w3, s_sbob_sl64);
}

DECLSPEC void streebog512_hmac_update_vector (streebog512_hmac_ctx_vector_t *ctx, const u32x *w, const int len)
{
  streebog512_update_vector (&ctx->ipad, w, len);
}

DECLSPEC void streebog512_hmac_update_vector_swap (streebog512_hmac_ctx_vector_t *ctx, const u32x *w, const int len)
{
  streebog512_update_vector_swap (&ctx->ipad, w, len);
}

DECLSPEC void streebog512_hmac_final_vector (streebog512_hmac_ctx_vector_t *ctx)
{
  streebog512_final_vector (&ctx->ipad);

  u32x t0[4];
  u32x t1[4];
  u32x t2[4];
  u32x t3[4];

  t0[0] = h32_from_64 (ctx->ipad.h[7]);
  t0[1] = l32_from_64 (ctx->ipad.h[7]);
  t0[2] = h32_from_64 (ctx->ipad.h[6]);
  t0[3] = l32_from_64 (ctx->ipad.h[6]);
  t1[0] = h32_from_64 (ctx->ipad.h[5]);
  t1[1] = l32_from_64 (ctx->ipad.h[5]);
  t1[2] = h32_from_64 (ctx->ipad.h[4]);
  t1[3] = l32_from_64 (ctx->ipad.h[4]);
  t2[0] = h32_from_64 (ctx->ipad.h[3]);
  t2[1] = l32_from_64 (ctx->ipad.h[3]);
  t2[2] = h32_from_64 (ctx->ipad.h[2]);
  t2[3] = l32_from_64 (ctx->ipad.h[2]);
  t3[0] = h32_from_64 (ctx->ipad.h[1]);
  t3[1] = l32_from_64 (ctx->ipad.h[1]);
  t3[2] = h32_from_64 (ctx->ipad.h[0]);
  t3[3] = l32_from_64 (ctx->ipad.h[0]);

  streebog512_update_vector_64 (&ctx->opad, t0, t1, t2, t3, 64);

  streebog512_final_vector (&ctx->opad);
}
