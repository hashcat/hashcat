/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha0.h"

// SHA-0 is SHA-1 without the rotate in its message schedule, so it runs on SHA-1's step macros. The
// block holds bytes in little endian words, as the other absorbing families keep it, and the
// transform swaps them to the big endian words SHA-1 reads.

DECLSPEC void sha0_transform (PRIVATE_AS u32 *dgst, PRIVATE_AS const u32 *w)
{
  u32 w0_t = hc_swap32_S (w[ 0]);
  u32 w1_t = hc_swap32_S (w[ 1]);
  u32 w2_t = hc_swap32_S (w[ 2]);
  u32 w3_t = hc_swap32_S (w[ 3]);
  u32 w4_t = hc_swap32_S (w[ 4]);
  u32 w5_t = hc_swap32_S (w[ 5]);
  u32 w6_t = hc_swap32_S (w[ 6]);
  u32 w7_t = hc_swap32_S (w[ 7]);
  u32 w8_t = hc_swap32_S (w[ 8]);
  u32 w9_t = hc_swap32_S (w[ 9]);
  u32 wa_t = hc_swap32_S (w[10]);
  u32 wb_t = hc_swap32_S (w[11]);
  u32 wc_t = hc_swap32_S (w[12]);
  u32 wd_t = hc_swap32_S (w[13]);
  u32 we_t = hc_swap32_S (w[14]);
  u32 wf_t = hc_swap32_S (w[15]);

  u32 a = dgst[0];
  u32 b = dgst[1];
  u32 c = dgst[2];
  u32 d = dgst[3];
  u32 e = dgst[4];

  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w0_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w1_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w2_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w3_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w4_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, w5_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w6_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w7_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w8_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w9_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, wa_t);
  SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, wb_t);
  SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, wc_t);
  SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, wd_t);
  SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, we_t);
  SHA1_STEP_S (SHA1_F0o, a, b, c, d, e, wf_t);
  w0_t = wd_t ^ w8_t ^ w2_t ^ w0_t; SHA1_STEP_S (SHA1_F0o, e, a, b, c, d, w0_t);
  w1_t = we_t ^ w9_t ^ w3_t ^ w1_t; SHA1_STEP_S (SHA1_F0o, d, e, a, b, c, w1_t);
  w2_t = wf_t ^ wa_t ^ w4_t ^ w2_t; SHA1_STEP_S (SHA1_F0o, c, d, e, a, b, w2_t);
  w3_t = w0_t ^ wb_t ^ w5_t ^ w3_t; SHA1_STEP_S (SHA1_F0o, b, c, d, e, a, w3_t);

  #undef K

  #define K SHA1C01

  w4_t = w1_t ^ wc_t ^ w6_t ^ w4_t; SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w4_t);
  w5_t = w2_t ^ wd_t ^ w7_t ^ w5_t; SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w5_t);
  w6_t = w3_t ^ we_t ^ w8_t ^ w6_t; SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w6_t);
  w7_t = w4_t ^ wf_t ^ w9_t ^ w7_t; SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w7_t);
  w8_t = w5_t ^ w0_t ^ wa_t ^ w8_t; SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w8_t);
  w9_t = w6_t ^ w1_t ^ wb_t ^ w9_t; SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w9_t);
  wa_t = w7_t ^ w2_t ^ wc_t ^ wa_t; SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wa_t);
  wb_t = w8_t ^ w3_t ^ wd_t ^ wb_t; SHA1_STEP_S (SHA1_F1, d, e, a, b, c, wb_t);
  wc_t = w9_t ^ w4_t ^ we_t ^ wc_t; SHA1_STEP_S (SHA1_F1, c, d, e, a, b, wc_t);
  wd_t = wa_t ^ w5_t ^ wf_t ^ wd_t; SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wd_t);
  we_t = wb_t ^ w6_t ^ w0_t ^ we_t; SHA1_STEP_S (SHA1_F1, a, b, c, d, e, we_t);
  wf_t = wc_t ^ w7_t ^ w1_t ^ wf_t; SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wf_t);
  w0_t = wd_t ^ w8_t ^ w2_t ^ w0_t; SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w0_t);
  w1_t = we_t ^ w9_t ^ w3_t ^ w1_t; SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w1_t);
  w2_t = wf_t ^ wa_t ^ w4_t ^ w2_t; SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w2_t);
  w3_t = w0_t ^ wb_t ^ w5_t ^ w3_t; SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w3_t);
  w4_t = w1_t ^ wc_t ^ w6_t ^ w4_t; SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w4_t);
  w5_t = w2_t ^ wd_t ^ w7_t ^ w5_t; SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w5_t);
  w6_t = w3_t ^ we_t ^ w8_t ^ w6_t; SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w6_t);
  w7_t = w4_t ^ wf_t ^ w9_t ^ w7_t; SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w7_t);

  #undef K

  #define K SHA1C02

  w8_t = w5_t ^ w0_t ^ wa_t ^ w8_t; SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w8_t);
  w9_t = w6_t ^ w1_t ^ wb_t ^ w9_t; SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w9_t);
  wa_t = w7_t ^ w2_t ^ wc_t ^ wa_t; SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, wa_t);
  wb_t = w8_t ^ w3_t ^ wd_t ^ wb_t; SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, wb_t);
  wc_t = w9_t ^ w4_t ^ we_t ^ wc_t; SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, wc_t);
  wd_t = wa_t ^ w5_t ^ wf_t ^ wd_t; SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, wd_t);
  we_t = wb_t ^ w6_t ^ w0_t ^ we_t; SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, we_t);
  wf_t = wc_t ^ w7_t ^ w1_t ^ wf_t; SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, wf_t);
  w0_t = wd_t ^ w8_t ^ w2_t ^ w0_t; SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w0_t);
  w1_t = we_t ^ w9_t ^ w3_t ^ w1_t; SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w1_t);
  w2_t = wf_t ^ wa_t ^ w4_t ^ w2_t; SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w2_t);
  w3_t = w0_t ^ wb_t ^ w5_t ^ w3_t; SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w3_t);
  w4_t = w1_t ^ wc_t ^ w6_t ^ w4_t; SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w4_t);
  w5_t = w2_t ^ wd_t ^ w7_t ^ w5_t; SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, w5_t);
  w6_t = w3_t ^ we_t ^ w8_t ^ w6_t; SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, w6_t);
  w7_t = w4_t ^ wf_t ^ w9_t ^ w7_t; SHA1_STEP_S (SHA1_F2o, a, b, c, d, e, w7_t);
  w8_t = w5_t ^ w0_t ^ wa_t ^ w8_t; SHA1_STEP_S (SHA1_F2o, e, a, b, c, d, w8_t);
  w9_t = w6_t ^ w1_t ^ wb_t ^ w9_t; SHA1_STEP_S (SHA1_F2o, d, e, a, b, c, w9_t);
  wa_t = w7_t ^ w2_t ^ wc_t ^ wa_t; SHA1_STEP_S (SHA1_F2o, c, d, e, a, b, wa_t);
  wb_t = w8_t ^ w3_t ^ wd_t ^ wb_t; SHA1_STEP_S (SHA1_F2o, b, c, d, e, a, wb_t);

  #undef K

  #define K SHA1C03

  wc_t = w9_t ^ w4_t ^ we_t ^ wc_t; SHA1_STEP_S (SHA1_F1, a, b, c, d, e, wc_t);
  wd_t = wa_t ^ w5_t ^ wf_t ^ wd_t; SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wd_t);
  we_t = wb_t ^ w6_t ^ w0_t ^ we_t; SHA1_STEP_S (SHA1_F1, d, e, a, b, c, we_t);
  wf_t = wc_t ^ w7_t ^ w1_t ^ wf_t; SHA1_STEP_S (SHA1_F1, c, d, e, a, b, wf_t);
  w0_t = wd_t ^ w8_t ^ w2_t ^ w0_t; SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w0_t);
  w1_t = we_t ^ w9_t ^ w3_t ^ w1_t; SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w1_t);
  w2_t = wf_t ^ wa_t ^ w4_t ^ w2_t; SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w2_t);
  w3_t = w0_t ^ wb_t ^ w5_t ^ w3_t; SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w3_t);
  w4_t = w1_t ^ wc_t ^ w6_t ^ w4_t; SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w4_t);
  w5_t = w2_t ^ wd_t ^ w7_t ^ w5_t; SHA1_STEP_S (SHA1_F1, b, c, d, e, a, w5_t);
  w6_t = w3_t ^ we_t ^ w8_t ^ w6_t; SHA1_STEP_S (SHA1_F1, a, b, c, d, e, w6_t);
  w7_t = w4_t ^ wf_t ^ w9_t ^ w7_t; SHA1_STEP_S (SHA1_F1, e, a, b, c, d, w7_t);
  w8_t = w5_t ^ w0_t ^ wa_t ^ w8_t; SHA1_STEP_S (SHA1_F1, d, e, a, b, c, w8_t);
  w9_t = w6_t ^ w1_t ^ wb_t ^ w9_t; SHA1_STEP_S (SHA1_F1, c, d, e, a, b, w9_t);
  wa_t = w7_t ^ w2_t ^ wc_t ^ wa_t; SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wa_t);
  wb_t = w8_t ^ w3_t ^ wd_t ^ wb_t; SHA1_STEP_S (SHA1_F1, a, b, c, d, e, wb_t);
  wc_t = w9_t ^ w4_t ^ we_t ^ wc_t; SHA1_STEP_S (SHA1_F1, e, a, b, c, d, wc_t);
  wd_t = wa_t ^ w5_t ^ wf_t ^ wd_t; SHA1_STEP_S (SHA1_F1, d, e, a, b, c, wd_t);
  we_t = wb_t ^ w6_t ^ w0_t ^ we_t; SHA1_STEP_S (SHA1_F1, c, d, e, a, b, we_t);
  wf_t = wc_t ^ w7_t ^ w1_t ^ wf_t; SHA1_STEP_S (SHA1_F1, b, c, d, e, a, wf_t);

  #undef K

  dgst[0] += a;
  dgst[1] += b;
  dgst[2] += c;
  dgst[3] += d;
  dgst[4] += e;
}

DECLSPEC void sha0_init (PRIVATE_AS sha0_ctx_t *ctx)
{
  ctx->h[0] = SHA1M_A;
  ctx->h[1] = SHA1M_B;
  ctx->h[2] = SHA1M_C;
  ctx->h[3] = SHA1M_D;
  ctx->h[4] = SHA1M_E;

  for (int i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void sha0_block (PRIVATE_AS sha0_ctx_t *ctx)
{
  sha0_transform (ctx->h, ctx->w);

  for (int i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void sha0_absorb (PRIVATE_AS sha0_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    sha0_block (ctx);

    if (n > fit)
    {
      ctx->w[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void sha0_update (PRIVATE_AS sha0_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    sha0_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void sha0_absorb_utf16le (PRIVATE_AS sha0_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  sha0_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) sha0_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void sha0_update_utf16le (PRIVATE_AS sha0_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (hc_enc_scan (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      sha0_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    sha0_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void sha0_update_global (PRIVATE_AS sha0_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    sha0_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void sha0_update_global_utf16le (PRIVATE_AS sha0_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (hc_enc_scan_global (w, len))
  {
    hc_enc_t hc_enc;

    hc_enc_init (&hc_enc);

    while (hc_enc_has_next (&hc_enc, len))
    {
      u32 enc_buf[16] = { 0 };

      const int enc_len = hc_enc_next_global (&hc_enc, w, len, 256, enc_buf, sizeof (enc_buf));

      if (enc_len == -1)
      {
        ctx->len = -1;

        return;
      }

      sha0_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    sha0_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding consists of the 0x80 byte, zeros up to byte 56 and the message length in bits, in big
// endian order, as SHA-1 pads. The block stores bytes in little endian words, so the length words
// are swapped. A context with invalid UTF-8 input produces a digest with every bit flipped, so that
// no candidate matches it by chance.

DECLSPEC void sha0_final (PRIVATE_AS sha0_ctx_t *ctx)
{
  const u32 len = (u32) ctx->len;

  sha0_absorb (ctx, 0x80, 1);

  if (ctx->pos > 56) sha0_block (ctx);

  ctx->w[14] = hc_swap32_S (len >> 29);
  ctx->w[15] = hc_swap32_S (len << 3);

  sha0_block (ctx);

  if (ctx->len < 0)
  {
    for (int i = 0; i < 5; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void sha0_transform_vector (PRIVATE_AS u32x *dgst, PRIVATE_AS const u32x *w)
{
  u32x w0_t = hc_swap32 (w[ 0]);
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

  u32x a = dgst[0];
  u32x b = dgst[1];
  u32x c = dgst[2];
  u32x d = dgst[3];
  u32x e = dgst[4];

  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w0_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w1_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w2_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w3_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w4_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, w5_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, w6_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, w7_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, w8_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, w9_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, wa_t);
  SHA1_STEP (SHA1_F0o, e, a, b, c, d, wb_t);
  SHA1_STEP (SHA1_F0o, d, e, a, b, c, wc_t);
  SHA1_STEP (SHA1_F0o, c, d, e, a, b, wd_t);
  SHA1_STEP (SHA1_F0o, b, c, d, e, a, we_t);
  SHA1_STEP (SHA1_F0o, a, b, c, d, e, wf_t);
  w0_t = wd_t ^ w8_t ^ w2_t ^ w0_t; SHA1_STEP (SHA1_F0o, e, a, b, c, d, w0_t);
  w1_t = we_t ^ w9_t ^ w3_t ^ w1_t; SHA1_STEP (SHA1_F0o, d, e, a, b, c, w1_t);
  w2_t = wf_t ^ wa_t ^ w4_t ^ w2_t; SHA1_STEP (SHA1_F0o, c, d, e, a, b, w2_t);
  w3_t = w0_t ^ wb_t ^ w5_t ^ w3_t; SHA1_STEP (SHA1_F0o, b, c, d, e, a, w3_t);

  #undef K

  #define K SHA1C01

  w4_t = w1_t ^ wc_t ^ w6_t ^ w4_t; SHA1_STEP (SHA1_F1, a, b, c, d, e, w4_t);
  w5_t = w2_t ^ wd_t ^ w7_t ^ w5_t; SHA1_STEP (SHA1_F1, e, a, b, c, d, w5_t);
  w6_t = w3_t ^ we_t ^ w8_t ^ w6_t; SHA1_STEP (SHA1_F1, d, e, a, b, c, w6_t);
  w7_t = w4_t ^ wf_t ^ w9_t ^ w7_t; SHA1_STEP (SHA1_F1, c, d, e, a, b, w7_t);
  w8_t = w5_t ^ w0_t ^ wa_t ^ w8_t; SHA1_STEP (SHA1_F1, b, c, d, e, a, w8_t);
  w9_t = w6_t ^ w1_t ^ wb_t ^ w9_t; SHA1_STEP (SHA1_F1, a, b, c, d, e, w9_t);
  wa_t = w7_t ^ w2_t ^ wc_t ^ wa_t; SHA1_STEP (SHA1_F1, e, a, b, c, d, wa_t);
  wb_t = w8_t ^ w3_t ^ wd_t ^ wb_t; SHA1_STEP (SHA1_F1, d, e, a, b, c, wb_t);
  wc_t = w9_t ^ w4_t ^ we_t ^ wc_t; SHA1_STEP (SHA1_F1, c, d, e, a, b, wc_t);
  wd_t = wa_t ^ w5_t ^ wf_t ^ wd_t; SHA1_STEP (SHA1_F1, b, c, d, e, a, wd_t);
  we_t = wb_t ^ w6_t ^ w0_t ^ we_t; SHA1_STEP (SHA1_F1, a, b, c, d, e, we_t);
  wf_t = wc_t ^ w7_t ^ w1_t ^ wf_t; SHA1_STEP (SHA1_F1, e, a, b, c, d, wf_t);
  w0_t = wd_t ^ w8_t ^ w2_t ^ w0_t; SHA1_STEP (SHA1_F1, d, e, a, b, c, w0_t);
  w1_t = we_t ^ w9_t ^ w3_t ^ w1_t; SHA1_STEP (SHA1_F1, c, d, e, a, b, w1_t);
  w2_t = wf_t ^ wa_t ^ w4_t ^ w2_t; SHA1_STEP (SHA1_F1, b, c, d, e, a, w2_t);
  w3_t = w0_t ^ wb_t ^ w5_t ^ w3_t; SHA1_STEP (SHA1_F1, a, b, c, d, e, w3_t);
  w4_t = w1_t ^ wc_t ^ w6_t ^ w4_t; SHA1_STEP (SHA1_F1, e, a, b, c, d, w4_t);
  w5_t = w2_t ^ wd_t ^ w7_t ^ w5_t; SHA1_STEP (SHA1_F1, d, e, a, b, c, w5_t);
  w6_t = w3_t ^ we_t ^ w8_t ^ w6_t; SHA1_STEP (SHA1_F1, c, d, e, a, b, w6_t);
  w7_t = w4_t ^ wf_t ^ w9_t ^ w7_t; SHA1_STEP (SHA1_F1, b, c, d, e, a, w7_t);

  #undef K

  #define K SHA1C02

  w8_t = w5_t ^ w0_t ^ wa_t ^ w8_t; SHA1_STEP (SHA1_F2o, a, b, c, d, e, w8_t);
  w9_t = w6_t ^ w1_t ^ wb_t ^ w9_t; SHA1_STEP (SHA1_F2o, e, a, b, c, d, w9_t);
  wa_t = w7_t ^ w2_t ^ wc_t ^ wa_t; SHA1_STEP (SHA1_F2o, d, e, a, b, c, wa_t);
  wb_t = w8_t ^ w3_t ^ wd_t ^ wb_t; SHA1_STEP (SHA1_F2o, c, d, e, a, b, wb_t);
  wc_t = w9_t ^ w4_t ^ we_t ^ wc_t; SHA1_STEP (SHA1_F2o, b, c, d, e, a, wc_t);
  wd_t = wa_t ^ w5_t ^ wf_t ^ wd_t; SHA1_STEP (SHA1_F2o, a, b, c, d, e, wd_t);
  we_t = wb_t ^ w6_t ^ w0_t ^ we_t; SHA1_STEP (SHA1_F2o, e, a, b, c, d, we_t);
  wf_t = wc_t ^ w7_t ^ w1_t ^ wf_t; SHA1_STEP (SHA1_F2o, d, e, a, b, c, wf_t);
  w0_t = wd_t ^ w8_t ^ w2_t ^ w0_t; SHA1_STEP (SHA1_F2o, c, d, e, a, b, w0_t);
  w1_t = we_t ^ w9_t ^ w3_t ^ w1_t; SHA1_STEP (SHA1_F2o, b, c, d, e, a, w1_t);
  w2_t = wf_t ^ wa_t ^ w4_t ^ w2_t; SHA1_STEP (SHA1_F2o, a, b, c, d, e, w2_t);
  w3_t = w0_t ^ wb_t ^ w5_t ^ w3_t; SHA1_STEP (SHA1_F2o, e, a, b, c, d, w3_t);
  w4_t = w1_t ^ wc_t ^ w6_t ^ w4_t; SHA1_STEP (SHA1_F2o, d, e, a, b, c, w4_t);
  w5_t = w2_t ^ wd_t ^ w7_t ^ w5_t; SHA1_STEP (SHA1_F2o, c, d, e, a, b, w5_t);
  w6_t = w3_t ^ we_t ^ w8_t ^ w6_t; SHA1_STEP (SHA1_F2o, b, c, d, e, a, w6_t);
  w7_t = w4_t ^ wf_t ^ w9_t ^ w7_t; SHA1_STEP (SHA1_F2o, a, b, c, d, e, w7_t);
  w8_t = w5_t ^ w0_t ^ wa_t ^ w8_t; SHA1_STEP (SHA1_F2o, e, a, b, c, d, w8_t);
  w9_t = w6_t ^ w1_t ^ wb_t ^ w9_t; SHA1_STEP (SHA1_F2o, d, e, a, b, c, w9_t);
  wa_t = w7_t ^ w2_t ^ wc_t ^ wa_t; SHA1_STEP (SHA1_F2o, c, d, e, a, b, wa_t);
  wb_t = w8_t ^ w3_t ^ wd_t ^ wb_t; SHA1_STEP (SHA1_F2o, b, c, d, e, a, wb_t);

  #undef K

  #define K SHA1C03

  wc_t = w9_t ^ w4_t ^ we_t ^ wc_t; SHA1_STEP (SHA1_F1, a, b, c, d, e, wc_t);
  wd_t = wa_t ^ w5_t ^ wf_t ^ wd_t; SHA1_STEP (SHA1_F1, e, a, b, c, d, wd_t);
  we_t = wb_t ^ w6_t ^ w0_t ^ we_t; SHA1_STEP (SHA1_F1, d, e, a, b, c, we_t);
  wf_t = wc_t ^ w7_t ^ w1_t ^ wf_t; SHA1_STEP (SHA1_F1, c, d, e, a, b, wf_t);
  w0_t = wd_t ^ w8_t ^ w2_t ^ w0_t; SHA1_STEP (SHA1_F1, b, c, d, e, a, w0_t);
  w1_t = we_t ^ w9_t ^ w3_t ^ w1_t; SHA1_STEP (SHA1_F1, a, b, c, d, e, w1_t);
  w2_t = wf_t ^ wa_t ^ w4_t ^ w2_t; SHA1_STEP (SHA1_F1, e, a, b, c, d, w2_t);
  w3_t = w0_t ^ wb_t ^ w5_t ^ w3_t; SHA1_STEP (SHA1_F1, d, e, a, b, c, w3_t);
  w4_t = w1_t ^ wc_t ^ w6_t ^ w4_t; SHA1_STEP (SHA1_F1, c, d, e, a, b, w4_t);
  w5_t = w2_t ^ wd_t ^ w7_t ^ w5_t; SHA1_STEP (SHA1_F1, b, c, d, e, a, w5_t);
  w6_t = w3_t ^ we_t ^ w8_t ^ w6_t; SHA1_STEP (SHA1_F1, a, b, c, d, e, w6_t);
  w7_t = w4_t ^ wf_t ^ w9_t ^ w7_t; SHA1_STEP (SHA1_F1, e, a, b, c, d, w7_t);
  w8_t = w5_t ^ w0_t ^ wa_t ^ w8_t; SHA1_STEP (SHA1_F1, d, e, a, b, c, w8_t);
  w9_t = w6_t ^ w1_t ^ wb_t ^ w9_t; SHA1_STEP (SHA1_F1, c, d, e, a, b, w9_t);
  wa_t = w7_t ^ w2_t ^ wc_t ^ wa_t; SHA1_STEP (SHA1_F1, b, c, d, e, a, wa_t);
  wb_t = w8_t ^ w3_t ^ wd_t ^ wb_t; SHA1_STEP (SHA1_F1, a, b, c, d, e, wb_t);
  wc_t = w9_t ^ w4_t ^ we_t ^ wc_t; SHA1_STEP (SHA1_F1, e, a, b, c, d, wc_t);
  wd_t = wa_t ^ w5_t ^ wf_t ^ wd_t; SHA1_STEP (SHA1_F1, d, e, a, b, c, wd_t);
  we_t = wb_t ^ w6_t ^ w0_t ^ we_t; SHA1_STEP (SHA1_F1, c, d, e, a, b, we_t);
  wf_t = wc_t ^ w7_t ^ w1_t ^ wf_t; SHA1_STEP (SHA1_F1, b, c, d, e, a, wf_t);

  #undef K

  dgst[0] += a;
  dgst[1] += b;
  dgst[2] += c;
  dgst[3] += d;
  dgst[4] += e;
}

DECLSPEC void sha0_init_vector (PRIVATE_AS sha0_ctx_vector_t *ctx)
{
  ctx->h[0] = SHA1M_A;
  ctx->h[1] = SHA1M_B;
  ctx->h[2] = SHA1M_C;
  ctx->h[3] = SHA1M_D;
  ctx->h[4] = SHA1M_E;

  for (int i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void sha0_block_vector (PRIVATE_AS sha0_ctx_vector_t *ctx)
{
  sha0_transform_vector (ctx->h, ctx->w);

  for (int i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void sha0_absorb_vector (PRIVATE_AS sha0_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    sha0_block_vector (ctx);

    if (n > fit)
    {
      ctx->w[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void sha0_update_vector (PRIVATE_AS sha0_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    sha0_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void sha0_update_vector_utf16le (PRIVATE_AS sha0_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    sha0_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) sha0_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void sha0_final_vector (PRIVATE_AS sha0_ctx_vector_t *ctx)
{
  const u32 len = (u32) ctx->len;

  sha0_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 56) sha0_block_vector (ctx);

  ctx->w[14] = hc_swap32_S (len >> 29);
  ctx->w[15] = hc_swap32_S (len << 3);

  sha0_block_vector (ctx);
}
