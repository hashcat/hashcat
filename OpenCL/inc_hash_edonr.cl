/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_edonr.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off.

// The quasigroup operation Z = X * Y on 8 words each, the same for both sizes apart from the
// constants CA and CB and the rotations A1 to A7 and B1 to B7. Every input word is read before
// the first output word is written, so Z may be X or Y.

#define EDONR_Q(T,ROTL,CA,CB,A1,A2,A3,A4,A5,A6,A7,B1,B2,B3,B4,B5,B6,B7,X0,X1,X2,X3,X4,X5,X6,X7,Y0,Y1,Y2,Y3,Y4,Y5,Y6,Y7,Z0,Z1,Z2,Z3,Z4,Z5,Z6,Z7) \
{                                                                               \
  const T s0 = (X0) + (X4);                                                     \
  const T s1 = (X1) + (X7);                                                     \
  const T s2 = (X2) + (X3);                                                     \
  const T s3 = (X5) + (X6);                                                     \
  const T s4 = s0 + s1;                                                         \
  const T s5 = s2 + s3;                                                         \
                                                                                \
  const T a0 = (CA) + s4 + (X2);                                                \
  const T a1 = ROTL (s4 + (X3), A1);                                            \
  const T a2 = ROTL (s4 + (X6), A2);                                            \
  const T a3 = ROTL (s5 + (X7), A3);                                            \
  const T a4 = ROTL (s5 + (X1), A4);                                            \
  const T a5 = ROTL (s0 + s2 + (X5), A5);                                       \
  const T a6 = ROTL (s1 + s3 + (X0), A6);                                       \
  const T a7 = ROTL (s5 + (X4), A7);                                            \
                                                                                \
  const T c0 = a0 ^ a4;                                                         \
  const T c1 = a1 ^ a7;                                                         \
  const T c2 = a2 ^ a3;                                                         \
  const T c3 = a5 ^ a6;                                                         \
                                                                                \
  const T e0 = a3 ^ c3;                                                         \
  const T e1 = a2 ^ c3;                                                         \
  const T e2 = c2 ^ a5;                                                         \
  const T e3 = c0 ^ a1;                                                         \
  const T e4 = c0 ^ a7;                                                         \
  const T e5 = c1 ^ a6;                                                         \
  const T e6 = c2 ^ a4;                                                         \
  const T e7 = a0 ^ c1;                                                         \
                                                                                \
  const T r0 = (Y0) + (Y1);                                                     \
  const T r1 = (Y2) + (Y5);                                                     \
  const T r2 = (Y3) + (Y4);                                                     \
  const T r3 = (Y6) + (Y7);                                                     \
  const T r4 = r0 + r1;                                                         \
  const T r5 = r2 + r3;                                                         \
  const T r6 = r0 + r2;                                                         \
  const T r7 = r1 + r3;                                                         \
                                                                                \
  const T b0 = (CB) + r4 + (Y7);                                                \
  const T b1 = ROTL (r6 + (Y6), B1);                                            \
  const T b2 = ROTL (r4 + (Y3), B2);                                            \
  const T b3 = ROTL (r5 + (Y2), B3);                                            \
  const T b4 = ROTL (r6 + (Y5), B4);                                            \
  const T b5 = ROTL (r7 + (Y4), B5);                                            \
  const T b6 = ROTL (r7 + (Y1), B6);                                            \
  const T b7 = ROTL (r5 + (Y0), B7);                                            \
                                                                                \
  const T d0 = b0 ^ b1;                                                         \
  const T d1 = b2 ^ b5;                                                         \
  const T d2 = b3 ^ b4;                                                         \
  const T d3 = b6 ^ b7;                                                         \
                                                                                \
  Z0 = e3 + (d0 ^ b5);                                                          \
  Z1 = e4 + (b2 ^ d3);                                                          \
  Z2 = e5 + (d0 ^ b3);                                                          \
  Z3 = e6 + (b0 ^ d2);                                                          \
  Z4 = e7 + (b1 ^ d1);                                                          \
  Z5 = e0 + (d2 ^ b6);                                                          \
  Z6 = e1 + (d1 ^ b7);                                                          \
  Z7 = e2 + (b4 ^ d3);                                                          \
}

#define EDONR256_Q(T,ROTL,X0,X1,X2,X3,X4,X5,X6,X7,Y0,Y1,Y2,Y3,Y4,Y5,Y6,Y7,Z0,Z1,Z2,Z3,Z4,Z5,Z6,Z7) \
  EDONR_Q (T, ROTL, 0xaaaaaaaa, 0x55555555, 5, 11, 13, 17, 19, 29, 31, 3, 7, 11, 17, 19, 23, 29, \
           X0, X1, X2, X3, X4, X5, X6, X7, Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7)

#define EDONR512_Q(T,ROTL,X0,X1,X2,X3,X4,X5,X6,X7,Y0,Y1,Y2,Y3,Y4,Y5,Y6,Y7,Z0,Z1,Z2,Z3,Z4,Z5,Z6,Z7) \
  EDONR_Q (T, ROTL, 0xaaaaaaaaaaaaaaaa, 0x5555555555555555, 5, 19, 29, 31, 41, 57, 61, 3, 17, 23, 31, 37, 45, 59, \
           X0, X1, X2, X3, X4, X5, X6, X7, Y0, Y1, Y2, Y3, Y4, Y5, Y6, Y7, Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7)

// One block: 4 rows of 2 quasigroup operations on the block M and the chaining state H, of 16 words
// each. P holds the 2 halves of the intermediate row.

#define EDONR_TRANSFORM(Q,T,ROTL,H,M)                                           \
{                                                                               \
  T p[16];                                                                      \
                                                                                \
  Q (T, ROTL, M[15], M[14], M[13], M[12], M[11], M[10], M[ 9], M[ 8],           \
              M[ 0], M[ 1], M[ 2], M[ 3], M[ 4], M[ 5], M[ 6], M[ 7],           \
              p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7]);          \
  Q (T, ROTL, p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],           \
              M[ 8], M[ 9], M[10], M[11], M[12], M[13], M[14], M[15],           \
              p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15]);          \
                                                                                \
  Q (T, ROTL, H[ 8], H[ 9], H[10], H[11], H[12], H[13], H[14], H[15],           \
              p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],           \
              p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7]);          \
  Q (T, ROTL, p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],           \
              p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15],           \
              p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15]);          \
                                                                                \
  Q (T, ROTL, p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],           \
              H[ 0], H[ 1], H[ 2], H[ 3], H[ 4], H[ 5], H[ 6], H[ 7],           \
              p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7]);          \
  Q (T, ROTL, p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15],           \
              p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],           \
              p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15]);          \
                                                                                \
  Q (T, ROTL, M[ 7], M[ 6], M[ 5], M[ 4], M[ 3], M[ 2], M[ 1], M[ 0],           \
              p[ 0], p[ 1], p[ 2], p[ 3], p[ 4], p[ 5], p[ 6], p[ 7],           \
              H[ 0], H[ 1], H[ 2], H[ 3], H[ 4], H[ 5], H[ 6], H[ 7]);          \
  Q (T, ROTL, H[ 0], H[ 1], H[ 2], H[ 3], H[ 4], H[ 5], H[ 6], H[ 7],           \
              p[ 8], p[ 9], p[10], p[11], p[12], p[13], p[14], p[15],           \
              H[ 8], H[ 9], H[10], H[11], H[12], H[13], H[14], H[15]);          \
}

// EDON-R 256

DECLSPEC void edonr256_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w)
{
  EDONR_TRANSFORM (EDONR256_Q, u32, hc_rotl32_S, h, w);
}

// The initial chaining values are the bytes 0x40 to 0x7f in order, each word read big endian.

DECLSPEC void edonr256_init (PRIVATE_AS edonr256_ctx_t *ctx)
{
  for (u32 i = 0; i < 16; i++) ctx->h[i] = 0x40414243 + (i * 0x04040404);
  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void edonr256_block (PRIVATE_AS edonr256_ctx_t *ctx)
{
  edonr256_transform (ctx->h, ctx->w);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void edonr256_absorb (PRIVATE_AS edonr256_ctx_t *ctx, const u32 v, const int n)
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
    edonr256_block (ctx);

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

DECLSPEC void edonr256_update (PRIVATE_AS edonr256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    edonr256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void edonr256_absorb_utf16le (PRIVATE_AS edonr256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  edonr256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) edonr256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void edonr256_update_utf16le (PRIVATE_AS edonr256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      edonr256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    edonr256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void edonr256_update_global (PRIVATE_AS edonr256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    edonr256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void edonr256_update_global_utf16le (PRIVATE_AS edonr256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      edonr256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    edonr256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding of MD5: the 0x80 byte, zeros up to byte 56 and the message length in bits. A context
// with invalid UTF-8 input produces a digest with every bit flipped, so that no candidate matches
// it by chance.

DECLSPEC void edonr256_final (PRIVATE_AS edonr256_ctx_t *ctx)
{
  const u32 len = (u32) ctx->len;

  edonr256_absorb (ctx, 0x80, 1);

  if (ctx->pos > 56) edonr256_block (ctx);

  ctx->w[14] = len << 3;
  ctx->w[15] = len >> 29;

  edonr256_block (ctx);

  if (ctx->len < 0)
  {
    for (u32 i = 8; i < 16; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void edonr256_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w)
{
  EDONR_TRANSFORM (EDONR256_Q, u32x, hc_rotl32, h, w);
}

DECLSPEC void edonr256_init_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx)
{
  for (u32 i = 0; i < 16; i++) ctx->h[i] = make_u32x (0x40414243 + (i * 0x04040404));
  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void edonr256_block_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx)
{
  edonr256_transform_vector (ctx->h, ctx->w);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void edonr256_absorb_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx, const u32x v, const int n)
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
    edonr256_block_vector (ctx);

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

DECLSPEC void edonr256_update_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    edonr256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void edonr256_update_vector_utf16le (PRIVATE_AS edonr256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    edonr256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) edonr256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void edonr256_final_vector (PRIVATE_AS edonr256_ctx_vector_t *ctx)
{
  const u32 len = (u32) ctx->len;

  edonr256_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 56) edonr256_block_vector (ctx);

  ctx->w[14] = len << 3;
  ctx->w[15] = len >> 29;

  edonr256_block_vector (ctx);
}

// EDON-R 512

DECLSPEC void edonr512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *w)
{
  EDONR_TRANSFORM (EDONR512_Q, u64, hc_rotl64_S, h, w);
}

// The initial chaining values are the bytes 0x80 to 0xff in order, each word read big endian.

DECLSPEC void edonr512_init (PRIVATE_AS edonr512_ctx_t *ctx)
{
  for (u32 i = 0; i < 16; i++) ctx->h[i] = 0x8081828384858687 + ((u64) i * 0x0808080808080808);
  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void edonr512_block (PRIVATE_AS edonr512_ctx_t *ctx)
{
  edonr512_transform (ctx->h, ctx->w);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// The same as edonr256_absorb (), but the block is 128 bytes in 64 bit words.

DECLSPEC void edonr512_absorb (PRIVATE_AS edonr512_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64 x = (u64) (v & mask);

  const int idx = pos / 8;
  const int off = pos & 7;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 8) ctx->w[idx + 1] |= x >> ((8 - off) * 8);

  if (fit == room)
  {
    edonr512_block (ctx);

    if (n > fit)
    {
      ctx->w[0] = (u64) (v >> (fit * 8));

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void edonr512_update (PRIVATE_AS edonr512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    edonr512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void edonr512_absorb_utf16le (PRIVATE_AS edonr512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  edonr512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) edonr512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void edonr512_update_utf16le (PRIVATE_AS edonr512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      edonr512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    edonr512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void edonr512_update_global (PRIVATE_AS edonr512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    edonr512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void edonr512_update_global_utf16le (PRIVATE_AS edonr512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      edonr512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    edonr512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding: the 0x80 byte, zeros up to byte 120 and the message length in bits as one 64 bit
// word. A context with invalid UTF-8 input produces a digest with every bit flipped, so that no
// candidate matches it by chance.

DECLSPEC void edonr512_final (PRIVATE_AS edonr512_ctx_t *ctx)
{
  const u32 len = (u32) ctx->len;

  edonr512_absorb (ctx, 0x80, 1);

  if (ctx->pos > 120) edonr512_block (ctx);

  ctx->w[15] = (u64) len << 3;

  edonr512_block (ctx);

  if (ctx->len < 0)
  {
    for (u32 i = 8; i < 16; i++) ctx->h[i] = ~ctx->h[i];
  }
}

DECLSPEC void edonr512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *w)
{
  EDONR_TRANSFORM (EDONR512_Q, u64x, hc_rotl64, h, w);
}

DECLSPEC void edonr512_init_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx)
{
  for (u32 i = 0; i < 16; i++) ctx->h[i] = make_u64x (0x8081828384858687 + ((u64) i * 0x0808080808080808));
  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void edonr512_block_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx)
{
  edonr512_transform_vector (ctx->h, ctx->w);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void edonr512_absorb_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64x x = hl32_to_64 (0, v & mask);

  const int idx = pos / 8;
  const int off = pos & 7;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 8) ctx->w[idx + 1] |= x >> ((8 - off) * 8);

  if (fit == room)
  {
    edonr512_block_vector (ctx);

    if (n > fit)
    {
      ctx->w[0] = hl32_to_64 (0, v >> (fit * 8));

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void edonr512_update_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    edonr512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void edonr512_update_vector_utf16le (PRIVATE_AS edonr512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    edonr512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) edonr512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void edonr512_final_vector (PRIVATE_AS edonr512_ctx_vector_t *ctx)
{
  const u32 len = (u32) ctx->len;

  edonr512_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 120) edonr512_block_vector (ctx);

  ctx->w[15] = make_u64x ((u64) len << 3);

  edonr512_block_vector (ctx);
}
