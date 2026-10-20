/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_ripemd.h"

// The 3 boolean functions of RIPEMD, as in MD4: selection, majority and parity

#define RIPEMD_F(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define RIPEMD_G(x,y,z) (((x) & (y)) | (((x) | (y)) & (z)))
#define RIPEMD_H(x,y,z) ((x) ^ (y) ^ (z))

// One step with the registers named for their positions in this step:
// a = rotl (a + f (b, c, d) + x + k, s)

#define RIPEMD_STEP_S(F,a,b,c,d,x,k,s)                                          \
{                                                                               \
  (a) = hc_rotl32_S ((a) + F ((b), (c), (d)) + (x) + (k), (s));                 \
}

#define RIPEMD_STEP(F,a,b,c,d,x,k,s)                                            \
{                                                                               \
  (a) = hc_rotl32 ((a) + F ((b), (c), (d)) + (x) + (k), (s));                   \
}

// The 48 steps of one line. Both lines read the message words in the same order with the same
// rotations and differ only in the constant of each round, K1 to K3.

#define RIPEMD_LINE(STEP,a,b,c,d,w,K1,K2,K3)                                    \
{                                                                               \
  STEP (RIPEMD_F, a, b, c, d, w[ 0], K1, 11);                                   \
  STEP (RIPEMD_F, d, a, b, c, w[ 1], K1, 14);                                   \
  STEP (RIPEMD_F, c, d, a, b, w[ 2], K1, 15);                                   \
  STEP (RIPEMD_F, b, c, d, a, w[ 3], K1, 12);                                   \
  STEP (RIPEMD_F, a, b, c, d, w[ 4], K1,  5);                                   \
  STEP (RIPEMD_F, d, a, b, c, w[ 5], K1,  8);                                   \
  STEP (RIPEMD_F, c, d, a, b, w[ 6], K1,  7);                                   \
  STEP (RIPEMD_F, b, c, d, a, w[ 7], K1,  9);                                   \
  STEP (RIPEMD_F, a, b, c, d, w[ 8], K1, 11);                                   \
  STEP (RIPEMD_F, d, a, b, c, w[ 9], K1, 13);                                   \
  STEP (RIPEMD_F, c, d, a, b, w[10], K1, 14);                                   \
  STEP (RIPEMD_F, b, c, d, a, w[11], K1, 15);                                   \
  STEP (RIPEMD_F, a, b, c, d, w[12], K1,  6);                                   \
  STEP (RIPEMD_F, d, a, b, c, w[13], K1,  7);                                   \
  STEP (RIPEMD_F, c, d, a, b, w[14], K1,  9);                                   \
  STEP (RIPEMD_F, b, c, d, a, w[15], K1,  8);                                   \
                                                                                \
  STEP (RIPEMD_G, a, b, c, d, w[ 7], K2,  7);                                   \
  STEP (RIPEMD_G, d, a, b, c, w[ 4], K2,  6);                                   \
  STEP (RIPEMD_G, c, d, a, b, w[13], K2,  8);                                   \
  STEP (RIPEMD_G, b, c, d, a, w[ 1], K2, 13);                                   \
  STEP (RIPEMD_G, a, b, c, d, w[10], K2, 11);                                   \
  STEP (RIPEMD_G, d, a, b, c, w[ 6], K2,  9);                                   \
  STEP (RIPEMD_G, c, d, a, b, w[15], K2,  7);                                   \
  STEP (RIPEMD_G, b, c, d, a, w[ 3], K2, 15);                                   \
  STEP (RIPEMD_G, a, b, c, d, w[12], K2,  7);                                   \
  STEP (RIPEMD_G, d, a, b, c, w[ 0], K2, 12);                                   \
  STEP (RIPEMD_G, c, d, a, b, w[ 9], K2, 15);                                   \
  STEP (RIPEMD_G, b, c, d, a, w[ 5], K2,  9);                                   \
  STEP (RIPEMD_G, a, b, c, d, w[14], K2,  7);                                   \
  STEP (RIPEMD_G, d, a, b, c, w[ 2], K2, 11);                                   \
  STEP (RIPEMD_G, c, d, a, b, w[11], K2, 13);                                   \
  STEP (RIPEMD_G, b, c, d, a, w[ 8], K2, 12);                                   \
                                                                                \
  STEP (RIPEMD_H, a, b, c, d, w[ 3], K3, 11);                                   \
  STEP (RIPEMD_H, d, a, b, c, w[10], K3, 13);                                   \
  STEP (RIPEMD_H, c, d, a, b, w[ 2], K3, 14);                                   \
  STEP (RIPEMD_H, b, c, d, a, w[ 4], K3,  7);                                   \
  STEP (RIPEMD_H, a, b, c, d, w[ 9], K3, 14);                                   \
  STEP (RIPEMD_H, d, a, b, c, w[15], K3,  9);                                   \
  STEP (RIPEMD_H, c, d, a, b, w[ 8], K3, 13);                                   \
  STEP (RIPEMD_H, b, c, d, a, w[ 1], K3, 15);                                   \
  STEP (RIPEMD_H, a, b, c, d, w[14], K3,  6);                                   \
  STEP (RIPEMD_H, d, a, b, c, w[ 7], K3,  8);                                   \
  STEP (RIPEMD_H, c, d, a, b, w[ 0], K3, 13);                                   \
  STEP (RIPEMD_H, b, c, d, a, w[ 6], K3,  6);                                   \
  STEP (RIPEMD_H, a, b, c, d, w[11], K3, 12);                                   \
  STEP (RIPEMD_H, d, a, b, c, w[13], K3,  5);                                   \
  STEP (RIPEMD_H, c, d, a, b, w[ 5], K3,  7);                                   \
  STEP (RIPEMD_H, b, c, d, a, w[12], K3,  5);                                   \
}

DECLSPEC void ripemd_transform (PRIVATE_AS u32 *dgst, PRIVATE_AS const u32 *w)
{
  u32 a = dgst[0];
  u32 b = dgst[1];
  u32 c = dgst[2];
  u32 d = dgst[3];
  u32 e = dgst[0];
  u32 f = dgst[1];
  u32 g = dgst[2];
  u32 h = dgst[3];

  RIPEMD_LINE (RIPEMD_STEP_S, a, b, c, d, w, 0x00000000, 0x5a827999, 0x6ed9eba1);
  RIPEMD_LINE (RIPEMD_STEP_S, e, f, g, h, w, 0x50a28be6, 0x00000000, 0x5c4dd124);

  const u32 t = dgst[1] + c + h;

  dgst[1] = dgst[2] + d + e;
  dgst[2] = dgst[3] + a + f;
  dgst[3] = dgst[0] + b + g;
  dgst[0] = t;
}

DECLSPEC void ripemd_init (PRIVATE_AS ripemd_ctx_t *ctx)
{
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void ripemd_block (PRIVATE_AS ripemd_ctx_t *ctx)
{
  ripemd_transform (ctx->h, ctx->w);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void ripemd_absorb (PRIVATE_AS ripemd_ctx_t *ctx, const u32 v, const int n)
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
    ripemd_block (ctx);

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

DECLSPEC void ripemd_update (PRIVATE_AS ripemd_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    ripemd_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void ripemd_absorb_utf16le (PRIVATE_AS ripemd_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  ripemd_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) ripemd_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void ripemd_update_utf16le (PRIVATE_AS ripemd_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      ripemd_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    ripemd_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void ripemd_update_global (PRIVATE_AS ripemd_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    ripemd_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void ripemd_update_global_utf16le (PRIVATE_AS ripemd_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      ripemd_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    ripemd_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding consists of the 0x80 byte, zeros up to byte 56 and the message length in bits, in
// little endian order, as MD4 pads. A context with invalid UTF-8 input produces a digest with every
// bit flipped, so that no candidate matches it by chance.

DECLSPEC void ripemd_final (PRIVATE_AS ripemd_ctx_t *ctx)
{
  const u32 len = (u32) ctx->len;

  ripemd_absorb (ctx, 0x80, 1);

  if (ctx->pos > 56) ripemd_block (ctx);

  ctx->w[14] = len << 3;
  ctx->w[15] = len >> 29;

  ripemd_block (ctx);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 4; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void ripemd_transform_vector (PRIVATE_AS u32x *dgst, PRIVATE_AS const u32x *w)
{
  u32x a = dgst[0];
  u32x b = dgst[1];
  u32x c = dgst[2];
  u32x d = dgst[3];
  u32x e = dgst[0];
  u32x f = dgst[1];
  u32x g = dgst[2];
  u32x h = dgst[3];

  RIPEMD_LINE (RIPEMD_STEP, a, b, c, d, w, 0x00000000, 0x5a827999, 0x6ed9eba1);
  RIPEMD_LINE (RIPEMD_STEP, e, f, g, h, w, 0x50a28be6, 0x00000000, 0x5c4dd124);

  const u32x t = dgst[1] + c + h;

  dgst[1] = dgst[2] + d + e;
  dgst[2] = dgst[3] + a + f;
  dgst[3] = dgst[0] + b + g;
  dgst[0] = t;
}

DECLSPEC void ripemd_init_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx)
{
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void ripemd_block_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx)
{
  ripemd_transform_vector (ctx->h, ctx->w);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void ripemd_absorb_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx, const u32x v, const int n)
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
    ripemd_block_vector (ctx);

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

DECLSPEC void ripemd_update_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    ripemd_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void ripemd_update_vector_utf16le (PRIVATE_AS ripemd_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    ripemd_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) ripemd_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void ripemd_final_vector (PRIVATE_AS ripemd_ctx_vector_t *ctx)
{
  const u32 len = (u32) ctx->len;

  ripemd_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 56) ripemd_block_vector (ctx);

  ctx->w[14] = len << 3;
  ctx->w[15] = len >> 29;

  ripemd_block_vector (ctx);
}
