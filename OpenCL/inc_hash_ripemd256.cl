/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_ripemd256.h"

// The 4 boolean functions of RIPEMD in the order of the left line's rounds

#define RIPEMD256_F1(x,y,z) ((x) ^ (y) ^ (z))
#define RIPEMD256_F2(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define RIPEMD256_F3(x,y,z) (((x) | ~(y)) ^ (z))
#define RIPEMD256_F4(x,y,z) ((y) ^ ((z) & ((x) ^ (y))))

// One step with the registers named for their positions in this step:
// a = rotl (a + f (b, c, d) + x + k, s)

#define RIPEMD256_STEP_S(F,a,b,c,d,x,k,s)                                 \
{                                                                     \
  (a) = hc_rotl32_S ((a) + F ((b), (c), (d)) + (x) + (k), (s));       \
}

#define RIPEMD256_STEP(F,a,b,c,d,x,k,s)                                   \
{                                                                     \
  (a) = hc_rotl32 ((a) + F ((b), (c), (d)) + (x) + (k), (s));         \
}

DECLSPEC void ripemd256_transform (PRIVATE_AS u32 *dgst, PRIVATE_AS const u32 *w)
{
  u32 a = dgst[0];
  u32 b = dgst[1];
  u32 c = dgst[2];
  u32 d = dgst[3];
  u32 e = dgst[4];
  u32 f = dgst[5];
  u32 g = dgst[6];
  u32 h = dgst[7];

  // round 1

  RIPEMD256_STEP_S (RIPEMD256_F1, a, b, c, d, w[ 0], 0x00000000, 11);
  RIPEMD256_STEP_S (RIPEMD256_F4, e, f, g, h, w[ 5], 0x50a28be6,  8);
  RIPEMD256_STEP_S (RIPEMD256_F1, d, a, b, c, w[ 1], 0x00000000, 14);
  RIPEMD256_STEP_S (RIPEMD256_F4, h, e, f, g, w[14], 0x50a28be6,  9);
  RIPEMD256_STEP_S (RIPEMD256_F1, c, d, a, b, w[ 2], 0x00000000, 15);
  RIPEMD256_STEP_S (RIPEMD256_F4, g, h, e, f, w[ 7], 0x50a28be6,  9);
  RIPEMD256_STEP_S (RIPEMD256_F1, b, c, d, a, w[ 3], 0x00000000, 12);
  RIPEMD256_STEP_S (RIPEMD256_F4, f, g, h, e, w[ 0], 0x50a28be6, 11);
  RIPEMD256_STEP_S (RIPEMD256_F1, a, b, c, d, w[ 4], 0x00000000,  5);
  RIPEMD256_STEP_S (RIPEMD256_F4, e, f, g, h, w[ 9], 0x50a28be6, 13);
  RIPEMD256_STEP_S (RIPEMD256_F1, d, a, b, c, w[ 5], 0x00000000,  8);
  RIPEMD256_STEP_S (RIPEMD256_F4, h, e, f, g, w[ 2], 0x50a28be6, 15);
  RIPEMD256_STEP_S (RIPEMD256_F1, c, d, a, b, w[ 6], 0x00000000,  7);
  RIPEMD256_STEP_S (RIPEMD256_F4, g, h, e, f, w[11], 0x50a28be6, 15);
  RIPEMD256_STEP_S (RIPEMD256_F1, b, c, d, a, w[ 7], 0x00000000,  9);
  RIPEMD256_STEP_S (RIPEMD256_F4, f, g, h, e, w[ 4], 0x50a28be6,  5);
  RIPEMD256_STEP_S (RIPEMD256_F1, a, b, c, d, w[ 8], 0x00000000, 11);
  RIPEMD256_STEP_S (RIPEMD256_F4, e, f, g, h, w[13], 0x50a28be6,  7);
  RIPEMD256_STEP_S (RIPEMD256_F1, d, a, b, c, w[ 9], 0x00000000, 13);
  RIPEMD256_STEP_S (RIPEMD256_F4, h, e, f, g, w[ 6], 0x50a28be6,  7);
  RIPEMD256_STEP_S (RIPEMD256_F1, c, d, a, b, w[10], 0x00000000, 14);
  RIPEMD256_STEP_S (RIPEMD256_F4, g, h, e, f, w[15], 0x50a28be6,  8);
  RIPEMD256_STEP_S (RIPEMD256_F1, b, c, d, a, w[11], 0x00000000, 15);
  RIPEMD256_STEP_S (RIPEMD256_F4, f, g, h, e, w[ 8], 0x50a28be6, 11);
  RIPEMD256_STEP_S (RIPEMD256_F1, a, b, c, d, w[12], 0x00000000,  6);
  RIPEMD256_STEP_S (RIPEMD256_F4, e, f, g, h, w[ 1], 0x50a28be6, 14);
  RIPEMD256_STEP_S (RIPEMD256_F1, d, a, b, c, w[13], 0x00000000,  7);
  RIPEMD256_STEP_S (RIPEMD256_F4, h, e, f, g, w[10], 0x50a28be6, 14);
  RIPEMD256_STEP_S (RIPEMD256_F1, c, d, a, b, w[14], 0x00000000,  9);
  RIPEMD256_STEP_S (RIPEMD256_F4, g, h, e, f, w[ 3], 0x50a28be6, 12);
  RIPEMD256_STEP_S (RIPEMD256_F1, b, c, d, a, w[15], 0x00000000,  8);
  RIPEMD256_STEP_S (RIPEMD256_F4, f, g, h, e, w[12], 0x50a28be6,  6);

  { const u32 t = a; a = e; e = t; }

  // round 2

  RIPEMD256_STEP_S (RIPEMD256_F2, a, b, c, d, w[ 7], 0x5a827999,  7);
  RIPEMD256_STEP_S (RIPEMD256_F3, e, f, g, h, w[ 6], 0x5c4dd124,  9);
  RIPEMD256_STEP_S (RIPEMD256_F2, d, a, b, c, w[ 4], 0x5a827999,  6);
  RIPEMD256_STEP_S (RIPEMD256_F3, h, e, f, g, w[11], 0x5c4dd124, 13);
  RIPEMD256_STEP_S (RIPEMD256_F2, c, d, a, b, w[13], 0x5a827999,  8);
  RIPEMD256_STEP_S (RIPEMD256_F3, g, h, e, f, w[ 3], 0x5c4dd124, 15);
  RIPEMD256_STEP_S (RIPEMD256_F2, b, c, d, a, w[ 1], 0x5a827999, 13);
  RIPEMD256_STEP_S (RIPEMD256_F3, f, g, h, e, w[ 7], 0x5c4dd124,  7);
  RIPEMD256_STEP_S (RIPEMD256_F2, a, b, c, d, w[10], 0x5a827999, 11);
  RIPEMD256_STEP_S (RIPEMD256_F3, e, f, g, h, w[ 0], 0x5c4dd124, 12);
  RIPEMD256_STEP_S (RIPEMD256_F2, d, a, b, c, w[ 6], 0x5a827999,  9);
  RIPEMD256_STEP_S (RIPEMD256_F3, h, e, f, g, w[13], 0x5c4dd124,  8);
  RIPEMD256_STEP_S (RIPEMD256_F2, c, d, a, b, w[15], 0x5a827999,  7);
  RIPEMD256_STEP_S (RIPEMD256_F3, g, h, e, f, w[ 5], 0x5c4dd124,  9);
  RIPEMD256_STEP_S (RIPEMD256_F2, b, c, d, a, w[ 3], 0x5a827999, 15);
  RIPEMD256_STEP_S (RIPEMD256_F3, f, g, h, e, w[10], 0x5c4dd124, 11);
  RIPEMD256_STEP_S (RIPEMD256_F2, a, b, c, d, w[12], 0x5a827999,  7);
  RIPEMD256_STEP_S (RIPEMD256_F3, e, f, g, h, w[14], 0x5c4dd124,  7);
  RIPEMD256_STEP_S (RIPEMD256_F2, d, a, b, c, w[ 0], 0x5a827999, 12);
  RIPEMD256_STEP_S (RIPEMD256_F3, h, e, f, g, w[15], 0x5c4dd124,  7);
  RIPEMD256_STEP_S (RIPEMD256_F2, c, d, a, b, w[ 9], 0x5a827999, 15);
  RIPEMD256_STEP_S (RIPEMD256_F3, g, h, e, f, w[ 8], 0x5c4dd124, 12);
  RIPEMD256_STEP_S (RIPEMD256_F2, b, c, d, a, w[ 5], 0x5a827999,  9);
  RIPEMD256_STEP_S (RIPEMD256_F3, f, g, h, e, w[12], 0x5c4dd124,  7);
  RIPEMD256_STEP_S (RIPEMD256_F2, a, b, c, d, w[ 2], 0x5a827999, 11);
  RIPEMD256_STEP_S (RIPEMD256_F3, e, f, g, h, w[ 4], 0x5c4dd124,  6);
  RIPEMD256_STEP_S (RIPEMD256_F2, d, a, b, c, w[14], 0x5a827999,  7);
  RIPEMD256_STEP_S (RIPEMD256_F3, h, e, f, g, w[ 9], 0x5c4dd124, 15);
  RIPEMD256_STEP_S (RIPEMD256_F2, c, d, a, b, w[11], 0x5a827999, 13);
  RIPEMD256_STEP_S (RIPEMD256_F3, g, h, e, f, w[ 1], 0x5c4dd124, 13);
  RIPEMD256_STEP_S (RIPEMD256_F2, b, c, d, a, w[ 8], 0x5a827999, 12);
  RIPEMD256_STEP_S (RIPEMD256_F3, f, g, h, e, w[ 2], 0x5c4dd124, 11);

  { const u32 t = b; b = f; f = t; }

  // round 3

  RIPEMD256_STEP_S (RIPEMD256_F3, a, b, c, d, w[ 3], 0x6ed9eba1, 11);
  RIPEMD256_STEP_S (RIPEMD256_F2, e, f, g, h, w[15], 0x6d703ef3,  9);
  RIPEMD256_STEP_S (RIPEMD256_F3, d, a, b, c, w[10], 0x6ed9eba1, 13);
  RIPEMD256_STEP_S (RIPEMD256_F2, h, e, f, g, w[ 5], 0x6d703ef3,  7);
  RIPEMD256_STEP_S (RIPEMD256_F3, c, d, a, b, w[14], 0x6ed9eba1,  6);
  RIPEMD256_STEP_S (RIPEMD256_F2, g, h, e, f, w[ 1], 0x6d703ef3, 15);
  RIPEMD256_STEP_S (RIPEMD256_F3, b, c, d, a, w[ 4], 0x6ed9eba1,  7);
  RIPEMD256_STEP_S (RIPEMD256_F2, f, g, h, e, w[ 3], 0x6d703ef3, 11);
  RIPEMD256_STEP_S (RIPEMD256_F3, a, b, c, d, w[ 9], 0x6ed9eba1, 14);
  RIPEMD256_STEP_S (RIPEMD256_F2, e, f, g, h, w[ 7], 0x6d703ef3,  8);
  RIPEMD256_STEP_S (RIPEMD256_F3, d, a, b, c, w[15], 0x6ed9eba1,  9);
  RIPEMD256_STEP_S (RIPEMD256_F2, h, e, f, g, w[14], 0x6d703ef3,  6);
  RIPEMD256_STEP_S (RIPEMD256_F3, c, d, a, b, w[ 8], 0x6ed9eba1, 13);
  RIPEMD256_STEP_S (RIPEMD256_F2, g, h, e, f, w[ 6], 0x6d703ef3,  6);
  RIPEMD256_STEP_S (RIPEMD256_F3, b, c, d, a, w[ 1], 0x6ed9eba1, 15);
  RIPEMD256_STEP_S (RIPEMD256_F2, f, g, h, e, w[ 9], 0x6d703ef3, 14);
  RIPEMD256_STEP_S (RIPEMD256_F3, a, b, c, d, w[ 2], 0x6ed9eba1, 14);
  RIPEMD256_STEP_S (RIPEMD256_F2, e, f, g, h, w[11], 0x6d703ef3, 12);
  RIPEMD256_STEP_S (RIPEMD256_F3, d, a, b, c, w[ 7], 0x6ed9eba1,  8);
  RIPEMD256_STEP_S (RIPEMD256_F2, h, e, f, g, w[ 8], 0x6d703ef3, 13);
  RIPEMD256_STEP_S (RIPEMD256_F3, c, d, a, b, w[ 0], 0x6ed9eba1, 13);
  RIPEMD256_STEP_S (RIPEMD256_F2, g, h, e, f, w[12], 0x6d703ef3,  5);
  RIPEMD256_STEP_S (RIPEMD256_F3, b, c, d, a, w[ 6], 0x6ed9eba1,  6);
  RIPEMD256_STEP_S (RIPEMD256_F2, f, g, h, e, w[ 2], 0x6d703ef3, 14);
  RIPEMD256_STEP_S (RIPEMD256_F3, a, b, c, d, w[13], 0x6ed9eba1,  5);
  RIPEMD256_STEP_S (RIPEMD256_F2, e, f, g, h, w[10], 0x6d703ef3, 13);
  RIPEMD256_STEP_S (RIPEMD256_F3, d, a, b, c, w[11], 0x6ed9eba1, 12);
  RIPEMD256_STEP_S (RIPEMD256_F2, h, e, f, g, w[ 0], 0x6d703ef3, 13);
  RIPEMD256_STEP_S (RIPEMD256_F3, c, d, a, b, w[ 5], 0x6ed9eba1,  7);
  RIPEMD256_STEP_S (RIPEMD256_F2, g, h, e, f, w[ 4], 0x6d703ef3,  7);
  RIPEMD256_STEP_S (RIPEMD256_F3, b, c, d, a, w[12], 0x6ed9eba1,  5);
  RIPEMD256_STEP_S (RIPEMD256_F2, f, g, h, e, w[13], 0x6d703ef3,  5);

  { const u32 t = c; c = g; g = t; }

  // round 4

  RIPEMD256_STEP_S (RIPEMD256_F4, a, b, c, d, w[ 1], 0x8f1bbcdc, 11);
  RIPEMD256_STEP_S (RIPEMD256_F1, e, f, g, h, w[ 8], 0x00000000, 15);
  RIPEMD256_STEP_S (RIPEMD256_F4, d, a, b, c, w[ 9], 0x8f1bbcdc, 12);
  RIPEMD256_STEP_S (RIPEMD256_F1, h, e, f, g, w[ 6], 0x00000000,  5);
  RIPEMD256_STEP_S (RIPEMD256_F4, c, d, a, b, w[11], 0x8f1bbcdc, 14);
  RIPEMD256_STEP_S (RIPEMD256_F1, g, h, e, f, w[ 4], 0x00000000,  8);
  RIPEMD256_STEP_S (RIPEMD256_F4, b, c, d, a, w[10], 0x8f1bbcdc, 15);
  RIPEMD256_STEP_S (RIPEMD256_F1, f, g, h, e, w[ 1], 0x00000000, 11);
  RIPEMD256_STEP_S (RIPEMD256_F4, a, b, c, d, w[ 0], 0x8f1bbcdc, 14);
  RIPEMD256_STEP_S (RIPEMD256_F1, e, f, g, h, w[ 3], 0x00000000, 14);
  RIPEMD256_STEP_S (RIPEMD256_F4, d, a, b, c, w[ 8], 0x8f1bbcdc, 15);
  RIPEMD256_STEP_S (RIPEMD256_F1, h, e, f, g, w[11], 0x00000000, 14);
  RIPEMD256_STEP_S (RIPEMD256_F4, c, d, a, b, w[12], 0x8f1bbcdc,  9);
  RIPEMD256_STEP_S (RIPEMD256_F1, g, h, e, f, w[15], 0x00000000,  6);
  RIPEMD256_STEP_S (RIPEMD256_F4, b, c, d, a, w[ 4], 0x8f1bbcdc,  8);
  RIPEMD256_STEP_S (RIPEMD256_F1, f, g, h, e, w[ 0], 0x00000000, 14);
  RIPEMD256_STEP_S (RIPEMD256_F4, a, b, c, d, w[13], 0x8f1bbcdc,  9);
  RIPEMD256_STEP_S (RIPEMD256_F1, e, f, g, h, w[ 5], 0x00000000,  6);
  RIPEMD256_STEP_S (RIPEMD256_F4, d, a, b, c, w[ 3], 0x8f1bbcdc, 14);
  RIPEMD256_STEP_S (RIPEMD256_F1, h, e, f, g, w[12], 0x00000000,  9);
  RIPEMD256_STEP_S (RIPEMD256_F4, c, d, a, b, w[ 7], 0x8f1bbcdc,  5);
  RIPEMD256_STEP_S (RIPEMD256_F1, g, h, e, f, w[ 2], 0x00000000, 12);
  RIPEMD256_STEP_S (RIPEMD256_F4, b, c, d, a, w[15], 0x8f1bbcdc,  6);
  RIPEMD256_STEP_S (RIPEMD256_F1, f, g, h, e, w[13], 0x00000000,  9);
  RIPEMD256_STEP_S (RIPEMD256_F4, a, b, c, d, w[14], 0x8f1bbcdc,  8);
  RIPEMD256_STEP_S (RIPEMD256_F1, e, f, g, h, w[ 9], 0x00000000, 12);
  RIPEMD256_STEP_S (RIPEMD256_F4, d, a, b, c, w[ 5], 0x8f1bbcdc,  6);
  RIPEMD256_STEP_S (RIPEMD256_F1, h, e, f, g, w[ 7], 0x00000000,  5);
  RIPEMD256_STEP_S (RIPEMD256_F4, c, d, a, b, w[ 6], 0x8f1bbcdc,  5);
  RIPEMD256_STEP_S (RIPEMD256_F1, g, h, e, f, w[10], 0x00000000, 15);
  RIPEMD256_STEP_S (RIPEMD256_F4, b, c, d, a, w[ 2], 0x8f1bbcdc, 12);
  RIPEMD256_STEP_S (RIPEMD256_F1, f, g, h, e, w[14], 0x00000000,  8);

  { const u32 t = d; d = h; h = t; }

  dgst[0] += a;
  dgst[1] += b;
  dgst[2] += c;
  dgst[3] += d;
  dgst[4] += e;
  dgst[5] += f;
  dgst[6] += g;
  dgst[7] += h;
}

DECLSPEC void ripemd256_init (PRIVATE_AS ripemd256_ctx_t *ctx)
{
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0x76543210;
  ctx->h[5] = 0xfedcba98;
  ctx->h[6] = 0x89abcdef;
  ctx->h[7] = 0x01234567;

  for (int i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void ripemd256_block (PRIVATE_AS ripemd256_ctx_t *ctx)
{
  ripemd256_transform (ctx->h, ctx->w);

  for (int i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void ripemd256_absorb (PRIVATE_AS ripemd256_ctx_t *ctx, const u32 v, const int n)
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
    ripemd256_block (ctx);

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

DECLSPEC void ripemd256_update (PRIVATE_AS ripemd256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    ripemd256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void ripemd256_absorb_utf16le (PRIVATE_AS ripemd256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  ripemd256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) ripemd256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void ripemd256_update_utf16le (PRIVATE_AS ripemd256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      ripemd256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    ripemd256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void ripemd256_update_global (PRIVATE_AS ripemd256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    ripemd256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void ripemd256_update_global_utf16le (PRIVATE_AS ripemd256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      ripemd256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    ripemd256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding consists of the 0x80 byte, zeros up to byte 56 and the message length in bits, in
// little endian order, as MD4 pads. A context with invalid UTF-8 input produces a digest with every
// bit flipped, so that no candidate matches it by chance.

DECLSPEC void ripemd256_final (PRIVATE_AS ripemd256_ctx_t *ctx)
{
  const u32 len = (u32) ctx->len;

  ripemd256_absorb (ctx, 0x80, 1);

  if (ctx->pos > 56) ripemd256_block (ctx);

  ctx->w[14] = len << 3;
  ctx->w[15] = len >> 29;

  ripemd256_block (ctx);

  if (ctx->len < 0)
  {
    for (int i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void ripemd256_transform_vector (PRIVATE_AS u32x *dgst, PRIVATE_AS const u32x *w)
{
  u32x a = dgst[0];
  u32x b = dgst[1];
  u32x c = dgst[2];
  u32x d = dgst[3];
  u32x e = dgst[4];
  u32x f = dgst[5];
  u32x g = dgst[6];
  u32x h = dgst[7];

  // round 1

  RIPEMD256_STEP (RIPEMD256_F1, a, b, c, d, w[ 0], 0x00000000, 11);
  RIPEMD256_STEP (RIPEMD256_F4, e, f, g, h, w[ 5], 0x50a28be6,  8);
  RIPEMD256_STEP (RIPEMD256_F1, d, a, b, c, w[ 1], 0x00000000, 14);
  RIPEMD256_STEP (RIPEMD256_F4, h, e, f, g, w[14], 0x50a28be6,  9);
  RIPEMD256_STEP (RIPEMD256_F1, c, d, a, b, w[ 2], 0x00000000, 15);
  RIPEMD256_STEP (RIPEMD256_F4, g, h, e, f, w[ 7], 0x50a28be6,  9);
  RIPEMD256_STEP (RIPEMD256_F1, b, c, d, a, w[ 3], 0x00000000, 12);
  RIPEMD256_STEP (RIPEMD256_F4, f, g, h, e, w[ 0], 0x50a28be6, 11);
  RIPEMD256_STEP (RIPEMD256_F1, a, b, c, d, w[ 4], 0x00000000,  5);
  RIPEMD256_STEP (RIPEMD256_F4, e, f, g, h, w[ 9], 0x50a28be6, 13);
  RIPEMD256_STEP (RIPEMD256_F1, d, a, b, c, w[ 5], 0x00000000,  8);
  RIPEMD256_STEP (RIPEMD256_F4, h, e, f, g, w[ 2], 0x50a28be6, 15);
  RIPEMD256_STEP (RIPEMD256_F1, c, d, a, b, w[ 6], 0x00000000,  7);
  RIPEMD256_STEP (RIPEMD256_F4, g, h, e, f, w[11], 0x50a28be6, 15);
  RIPEMD256_STEP (RIPEMD256_F1, b, c, d, a, w[ 7], 0x00000000,  9);
  RIPEMD256_STEP (RIPEMD256_F4, f, g, h, e, w[ 4], 0x50a28be6,  5);
  RIPEMD256_STEP (RIPEMD256_F1, a, b, c, d, w[ 8], 0x00000000, 11);
  RIPEMD256_STEP (RIPEMD256_F4, e, f, g, h, w[13], 0x50a28be6,  7);
  RIPEMD256_STEP (RIPEMD256_F1, d, a, b, c, w[ 9], 0x00000000, 13);
  RIPEMD256_STEP (RIPEMD256_F4, h, e, f, g, w[ 6], 0x50a28be6,  7);
  RIPEMD256_STEP (RIPEMD256_F1, c, d, a, b, w[10], 0x00000000, 14);
  RIPEMD256_STEP (RIPEMD256_F4, g, h, e, f, w[15], 0x50a28be6,  8);
  RIPEMD256_STEP (RIPEMD256_F1, b, c, d, a, w[11], 0x00000000, 15);
  RIPEMD256_STEP (RIPEMD256_F4, f, g, h, e, w[ 8], 0x50a28be6, 11);
  RIPEMD256_STEP (RIPEMD256_F1, a, b, c, d, w[12], 0x00000000,  6);
  RIPEMD256_STEP (RIPEMD256_F4, e, f, g, h, w[ 1], 0x50a28be6, 14);
  RIPEMD256_STEP (RIPEMD256_F1, d, a, b, c, w[13], 0x00000000,  7);
  RIPEMD256_STEP (RIPEMD256_F4, h, e, f, g, w[10], 0x50a28be6, 14);
  RIPEMD256_STEP (RIPEMD256_F1, c, d, a, b, w[14], 0x00000000,  9);
  RIPEMD256_STEP (RIPEMD256_F4, g, h, e, f, w[ 3], 0x50a28be6, 12);
  RIPEMD256_STEP (RIPEMD256_F1, b, c, d, a, w[15], 0x00000000,  8);
  RIPEMD256_STEP (RIPEMD256_F4, f, g, h, e, w[12], 0x50a28be6,  6);

  { const u32x t = a; a = e; e = t; }

  // round 2

  RIPEMD256_STEP (RIPEMD256_F2, a, b, c, d, w[ 7], 0x5a827999,  7);
  RIPEMD256_STEP (RIPEMD256_F3, e, f, g, h, w[ 6], 0x5c4dd124,  9);
  RIPEMD256_STEP (RIPEMD256_F2, d, a, b, c, w[ 4], 0x5a827999,  6);
  RIPEMD256_STEP (RIPEMD256_F3, h, e, f, g, w[11], 0x5c4dd124, 13);
  RIPEMD256_STEP (RIPEMD256_F2, c, d, a, b, w[13], 0x5a827999,  8);
  RIPEMD256_STEP (RIPEMD256_F3, g, h, e, f, w[ 3], 0x5c4dd124, 15);
  RIPEMD256_STEP (RIPEMD256_F2, b, c, d, a, w[ 1], 0x5a827999, 13);
  RIPEMD256_STEP (RIPEMD256_F3, f, g, h, e, w[ 7], 0x5c4dd124,  7);
  RIPEMD256_STEP (RIPEMD256_F2, a, b, c, d, w[10], 0x5a827999, 11);
  RIPEMD256_STEP (RIPEMD256_F3, e, f, g, h, w[ 0], 0x5c4dd124, 12);
  RIPEMD256_STEP (RIPEMD256_F2, d, a, b, c, w[ 6], 0x5a827999,  9);
  RIPEMD256_STEP (RIPEMD256_F3, h, e, f, g, w[13], 0x5c4dd124,  8);
  RIPEMD256_STEP (RIPEMD256_F2, c, d, a, b, w[15], 0x5a827999,  7);
  RIPEMD256_STEP (RIPEMD256_F3, g, h, e, f, w[ 5], 0x5c4dd124,  9);
  RIPEMD256_STEP (RIPEMD256_F2, b, c, d, a, w[ 3], 0x5a827999, 15);
  RIPEMD256_STEP (RIPEMD256_F3, f, g, h, e, w[10], 0x5c4dd124, 11);
  RIPEMD256_STEP (RIPEMD256_F2, a, b, c, d, w[12], 0x5a827999,  7);
  RIPEMD256_STEP (RIPEMD256_F3, e, f, g, h, w[14], 0x5c4dd124,  7);
  RIPEMD256_STEP (RIPEMD256_F2, d, a, b, c, w[ 0], 0x5a827999, 12);
  RIPEMD256_STEP (RIPEMD256_F3, h, e, f, g, w[15], 0x5c4dd124,  7);
  RIPEMD256_STEP (RIPEMD256_F2, c, d, a, b, w[ 9], 0x5a827999, 15);
  RIPEMD256_STEP (RIPEMD256_F3, g, h, e, f, w[ 8], 0x5c4dd124, 12);
  RIPEMD256_STEP (RIPEMD256_F2, b, c, d, a, w[ 5], 0x5a827999,  9);
  RIPEMD256_STEP (RIPEMD256_F3, f, g, h, e, w[12], 0x5c4dd124,  7);
  RIPEMD256_STEP (RIPEMD256_F2, a, b, c, d, w[ 2], 0x5a827999, 11);
  RIPEMD256_STEP (RIPEMD256_F3, e, f, g, h, w[ 4], 0x5c4dd124,  6);
  RIPEMD256_STEP (RIPEMD256_F2, d, a, b, c, w[14], 0x5a827999,  7);
  RIPEMD256_STEP (RIPEMD256_F3, h, e, f, g, w[ 9], 0x5c4dd124, 15);
  RIPEMD256_STEP (RIPEMD256_F2, c, d, a, b, w[11], 0x5a827999, 13);
  RIPEMD256_STEP (RIPEMD256_F3, g, h, e, f, w[ 1], 0x5c4dd124, 13);
  RIPEMD256_STEP (RIPEMD256_F2, b, c, d, a, w[ 8], 0x5a827999, 12);
  RIPEMD256_STEP (RIPEMD256_F3, f, g, h, e, w[ 2], 0x5c4dd124, 11);

  { const u32x t = b; b = f; f = t; }

  // round 3

  RIPEMD256_STEP (RIPEMD256_F3, a, b, c, d, w[ 3], 0x6ed9eba1, 11);
  RIPEMD256_STEP (RIPEMD256_F2, e, f, g, h, w[15], 0x6d703ef3,  9);
  RIPEMD256_STEP (RIPEMD256_F3, d, a, b, c, w[10], 0x6ed9eba1, 13);
  RIPEMD256_STEP (RIPEMD256_F2, h, e, f, g, w[ 5], 0x6d703ef3,  7);
  RIPEMD256_STEP (RIPEMD256_F3, c, d, a, b, w[14], 0x6ed9eba1,  6);
  RIPEMD256_STEP (RIPEMD256_F2, g, h, e, f, w[ 1], 0x6d703ef3, 15);
  RIPEMD256_STEP (RIPEMD256_F3, b, c, d, a, w[ 4], 0x6ed9eba1,  7);
  RIPEMD256_STEP (RIPEMD256_F2, f, g, h, e, w[ 3], 0x6d703ef3, 11);
  RIPEMD256_STEP (RIPEMD256_F3, a, b, c, d, w[ 9], 0x6ed9eba1, 14);
  RIPEMD256_STEP (RIPEMD256_F2, e, f, g, h, w[ 7], 0x6d703ef3,  8);
  RIPEMD256_STEP (RIPEMD256_F3, d, a, b, c, w[15], 0x6ed9eba1,  9);
  RIPEMD256_STEP (RIPEMD256_F2, h, e, f, g, w[14], 0x6d703ef3,  6);
  RIPEMD256_STEP (RIPEMD256_F3, c, d, a, b, w[ 8], 0x6ed9eba1, 13);
  RIPEMD256_STEP (RIPEMD256_F2, g, h, e, f, w[ 6], 0x6d703ef3,  6);
  RIPEMD256_STEP (RIPEMD256_F3, b, c, d, a, w[ 1], 0x6ed9eba1, 15);
  RIPEMD256_STEP (RIPEMD256_F2, f, g, h, e, w[ 9], 0x6d703ef3, 14);
  RIPEMD256_STEP (RIPEMD256_F3, a, b, c, d, w[ 2], 0x6ed9eba1, 14);
  RIPEMD256_STEP (RIPEMD256_F2, e, f, g, h, w[11], 0x6d703ef3, 12);
  RIPEMD256_STEP (RIPEMD256_F3, d, a, b, c, w[ 7], 0x6ed9eba1,  8);
  RIPEMD256_STEP (RIPEMD256_F2, h, e, f, g, w[ 8], 0x6d703ef3, 13);
  RIPEMD256_STEP (RIPEMD256_F3, c, d, a, b, w[ 0], 0x6ed9eba1, 13);
  RIPEMD256_STEP (RIPEMD256_F2, g, h, e, f, w[12], 0x6d703ef3,  5);
  RIPEMD256_STEP (RIPEMD256_F3, b, c, d, a, w[ 6], 0x6ed9eba1,  6);
  RIPEMD256_STEP (RIPEMD256_F2, f, g, h, e, w[ 2], 0x6d703ef3, 14);
  RIPEMD256_STEP (RIPEMD256_F3, a, b, c, d, w[13], 0x6ed9eba1,  5);
  RIPEMD256_STEP (RIPEMD256_F2, e, f, g, h, w[10], 0x6d703ef3, 13);
  RIPEMD256_STEP (RIPEMD256_F3, d, a, b, c, w[11], 0x6ed9eba1, 12);
  RIPEMD256_STEP (RIPEMD256_F2, h, e, f, g, w[ 0], 0x6d703ef3, 13);
  RIPEMD256_STEP (RIPEMD256_F3, c, d, a, b, w[ 5], 0x6ed9eba1,  7);
  RIPEMD256_STEP (RIPEMD256_F2, g, h, e, f, w[ 4], 0x6d703ef3,  7);
  RIPEMD256_STEP (RIPEMD256_F3, b, c, d, a, w[12], 0x6ed9eba1,  5);
  RIPEMD256_STEP (RIPEMD256_F2, f, g, h, e, w[13], 0x6d703ef3,  5);

  { const u32x t = c; c = g; g = t; }

  // round 4

  RIPEMD256_STEP (RIPEMD256_F4, a, b, c, d, w[ 1], 0x8f1bbcdc, 11);
  RIPEMD256_STEP (RIPEMD256_F1, e, f, g, h, w[ 8], 0x00000000, 15);
  RIPEMD256_STEP (RIPEMD256_F4, d, a, b, c, w[ 9], 0x8f1bbcdc, 12);
  RIPEMD256_STEP (RIPEMD256_F1, h, e, f, g, w[ 6], 0x00000000,  5);
  RIPEMD256_STEP (RIPEMD256_F4, c, d, a, b, w[11], 0x8f1bbcdc, 14);
  RIPEMD256_STEP (RIPEMD256_F1, g, h, e, f, w[ 4], 0x00000000,  8);
  RIPEMD256_STEP (RIPEMD256_F4, b, c, d, a, w[10], 0x8f1bbcdc, 15);
  RIPEMD256_STEP (RIPEMD256_F1, f, g, h, e, w[ 1], 0x00000000, 11);
  RIPEMD256_STEP (RIPEMD256_F4, a, b, c, d, w[ 0], 0x8f1bbcdc, 14);
  RIPEMD256_STEP (RIPEMD256_F1, e, f, g, h, w[ 3], 0x00000000, 14);
  RIPEMD256_STEP (RIPEMD256_F4, d, a, b, c, w[ 8], 0x8f1bbcdc, 15);
  RIPEMD256_STEP (RIPEMD256_F1, h, e, f, g, w[11], 0x00000000, 14);
  RIPEMD256_STEP (RIPEMD256_F4, c, d, a, b, w[12], 0x8f1bbcdc,  9);
  RIPEMD256_STEP (RIPEMD256_F1, g, h, e, f, w[15], 0x00000000,  6);
  RIPEMD256_STEP (RIPEMD256_F4, b, c, d, a, w[ 4], 0x8f1bbcdc,  8);
  RIPEMD256_STEP (RIPEMD256_F1, f, g, h, e, w[ 0], 0x00000000, 14);
  RIPEMD256_STEP (RIPEMD256_F4, a, b, c, d, w[13], 0x8f1bbcdc,  9);
  RIPEMD256_STEP (RIPEMD256_F1, e, f, g, h, w[ 5], 0x00000000,  6);
  RIPEMD256_STEP (RIPEMD256_F4, d, a, b, c, w[ 3], 0x8f1bbcdc, 14);
  RIPEMD256_STEP (RIPEMD256_F1, h, e, f, g, w[12], 0x00000000,  9);
  RIPEMD256_STEP (RIPEMD256_F4, c, d, a, b, w[ 7], 0x8f1bbcdc,  5);
  RIPEMD256_STEP (RIPEMD256_F1, g, h, e, f, w[ 2], 0x00000000, 12);
  RIPEMD256_STEP (RIPEMD256_F4, b, c, d, a, w[15], 0x8f1bbcdc,  6);
  RIPEMD256_STEP (RIPEMD256_F1, f, g, h, e, w[13], 0x00000000,  9);
  RIPEMD256_STEP (RIPEMD256_F4, a, b, c, d, w[14], 0x8f1bbcdc,  8);
  RIPEMD256_STEP (RIPEMD256_F1, e, f, g, h, w[ 9], 0x00000000, 12);
  RIPEMD256_STEP (RIPEMD256_F4, d, a, b, c, w[ 5], 0x8f1bbcdc,  6);
  RIPEMD256_STEP (RIPEMD256_F1, h, e, f, g, w[ 7], 0x00000000,  5);
  RIPEMD256_STEP (RIPEMD256_F4, c, d, a, b, w[ 6], 0x8f1bbcdc,  5);
  RIPEMD256_STEP (RIPEMD256_F1, g, h, e, f, w[10], 0x00000000, 15);
  RIPEMD256_STEP (RIPEMD256_F4, b, c, d, a, w[ 2], 0x8f1bbcdc, 12);
  RIPEMD256_STEP (RIPEMD256_F1, f, g, h, e, w[14], 0x00000000,  8);

  { const u32x t = d; d = h; h = t; }

  dgst[0] += a;
  dgst[1] += b;
  dgst[2] += c;
  dgst[3] += d;
  dgst[4] += e;
  dgst[5] += f;
  dgst[6] += g;
  dgst[7] += h;
}

DECLSPEC void ripemd256_init_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx)
{
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0x76543210;
  ctx->h[5] = 0xfedcba98;
  ctx->h[6] = 0x89abcdef;
  ctx->h[7] = 0x01234567;

  for (int i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void ripemd256_block_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx)
{
  ripemd256_transform_vector (ctx->h, ctx->w);

  for (int i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void ripemd256_absorb_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx, const u32x v, const int n)
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
    ripemd256_block_vector (ctx);

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

DECLSPEC void ripemd256_update_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    ripemd256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void ripemd256_update_vector_utf16le (PRIVATE_AS ripemd256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    ripemd256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) ripemd256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void ripemd256_final_vector (PRIVATE_AS ripemd256_ctx_vector_t *ctx)
{
  const u32 len = (u32) ctx->len;

  ripemd256_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 56) ripemd256_block_vector (ctx);

  ctx->w[14] = len << 3;
  ctx->w[15] = len >> 29;

  ripemd256_block_vector (ctx);
}
