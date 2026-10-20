/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_radiogatun.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off. RadioGatun[32] and RadioGatun[64] differ only in the word size, and
// therefore in the block size and in the rotation counts, which are reduced modulo the word size.

// One round. The mill feeds words 1 to 12 forward into belt stages 0 to 11, one word per stage.
// The mill function follows: gamma, pi with its rotations, theta and iota. Then belt stage 12
// feeds mill words 13 to 15, and the belt turns by one stage, so that stage 12 becomes stage 0,
// where the next block goes in. M is the word size minus one.

#define RADIOGATUN_ROUND(T,ROTR,M,ONE,A,B)                                      \
{                                                                               \
  for (u32 i = 0; i < 12; i++) B[i][i % 3] ^= A[i + 1];                         \
                                                                                \
  T g[19];                                                                      \
                                                                                \
  for (u32 i = 0; i < 19; i++)                                                  \
  {                                                                             \
    g[i] = A[i] ^ (A[(i + 1) % 19] | ~A[(i + 2) % 19]);                         \
  }                                                                             \
                                                                                \
  T p[19];                                                                      \
                                                                                \
  p[ 0] = g[ 0];                                                                \
  p[ 1] = ROTR (g[ 7], (  1) & (M));                                            \
  p[ 2] = ROTR (g[14], (  3) & (M));                                            \
  p[ 3] = ROTR (g[ 2], (  6) & (M));                                            \
  p[ 4] = ROTR (g[ 9], ( 10) & (M));                                            \
  p[ 5] = ROTR (g[16], ( 15) & (M));                                            \
  p[ 6] = ROTR (g[ 4], ( 21) & (M));                                            \
  p[ 7] = ROTR (g[11], ( 28) & (M));                                            \
  p[ 8] = ROTR (g[18], ( 36) & (M));                                            \
  p[ 9] = ROTR (g[ 6], ( 45) & (M));                                            \
  p[10] = ROTR (g[13], ( 55) & (M));                                            \
  p[11] = ROTR (g[ 1], ( 66) & (M));                                            \
  p[12] = ROTR (g[ 8], ( 78) & (M));                                            \
  p[13] = ROTR (g[15], ( 91) & (M));                                            \
  p[14] = ROTR (g[ 3], (105) & (M));                                            \
  p[15] = ROTR (g[10], (120) & (M));                                            \
  p[16] = ROTR (g[17], (136) & (M));                                            \
  p[17] = ROTR (g[ 5], (153) & (M));                                            \
  p[18] = ROTR (g[12], (171) & (M));                                            \
                                                                                \
  for (u32 i = 0; i < 19; i++)                                                  \
  {                                                                             \
    A[i] = p[i] ^ p[(i + 1) % 19] ^ p[(i + 4) % 19];                            \
  }                                                                             \
                                                                                \
  A[0] ^= ONE;                                                                  \
                                                                                \
  for (u32 i = 0; i < 3; i++) A[13 + i] ^= B[12][i];                            \
                                                                                \
  T t[3];                                                                       \
                                                                                \
  for (u32 i = 0; i < 3; i++) t[i] = B[12][i];                                  \
                                                                                \
  for (u32 s = 12; s > 0; s--)                                                  \
  {                                                                             \
    for (u32 i = 0; i < 3; i++) B[s][i] = B[s - 1][i];                          \
  }                                                                             \
                                                                                \
  for (u32 i = 0; i < 3; i++) B[0][i] = t[i];                                   \
}

// RadioGatun[32]

DECLSPEC void radiogatun32_round (PRIVATE_AS radiogatun32_ctx_t *ctx)
{
  RADIOGATUN_ROUND (u32, hc_rotr32_S, 31, (u32) 1, ctx->a, ctx->b);
}

DECLSPEC void radiogatun32_init (PRIVATE_AS radiogatun32_ctx_t *ctx)
{
  for (u32 i = 0; i < 19; i++) ctx->a[i] = 0;

  for (u32 i = 0; i < 13; i++)
  {
    for (u32 j = 0; j < 3; j++) ctx->b[i][j] = 0;
  }

  for (u32 i = 0; i < 3; i++) ctx->m[i] = 0;
  for (u32 i = 0; i < 8; i++) ctx->h[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

// The block in m goes into belt stage 0 and into mill words 16 to 18, and a round follows.

DECLSPEC void radiogatun32_block (PRIVATE_AS radiogatun32_ctx_t *ctx)
{
  for (u32 i = 0; i < 3; i++)
  {
    ctx->b[0][i]   ^= ctx->m[i];
    ctx->a[16 + i] ^= ctx->m[i];
  }

  radiogatun32_round (ctx);

  for (u32 i = 0; i < 3; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, process it and use any remaining
// bytes to start the next block.

DECLSPEC void radiogatun32_absorb (PRIVATE_AS radiogatun32_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 12 - pos;

  const int fit = (n > room) ? room : n;

  const u32 x = (fit >= 4) ? v : (v & ((1u << (fit * 8)) - 1));

  const int word = pos / 4;
  const int off  = pos & 3;

  ctx->m[word] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[word + 1] |= x >> ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  radiogatun32_block (ctx);

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void radiogatun32_update (PRIVATE_AS radiogatun32_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    radiogatun32_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void radiogatun32_absorb_utf16le (PRIVATE_AS radiogatun32_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  radiogatun32_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) radiogatun32_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void radiogatun32_update_utf16le (PRIVATE_AS radiogatun32_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      radiogatun32_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    radiogatun32_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void radiogatun32_update_global (PRIVATE_AS radiogatun32_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    radiogatun32_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void radiogatun32_update_global_utf16le (PRIVATE_AS radiogatun32_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      radiogatun32_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    radiogatun32_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x01 byte and zeros up to the end of the block, which is processed. 17 blank rounds
// follow, then the output: mill words 1 and 2, with a round before each further pair. A context
// with invalid UTF-8 input produces a digest with every bit flipped, so that no candidate matches
// it by chance.

DECLSPEC void radiogatun32_final (PRIVATE_AS radiogatun32_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x01u << ((pos & 3) * 8);

  radiogatun32_block (ctx);

  for (u32 i = 0; i < 17; i++) radiogatun32_round (ctx);

  ctx->h[0] = ctx->a[1];
  ctx->h[1] = ctx->a[2];

  for (u32 i = 2; i < 8; i += 2)
  {
    radiogatun32_round (ctx);

    ctx->h[i + 0] = ctx->a[1];
    ctx->h[i + 1] = ctx->a[2];
  }

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// RadioGatun[64]

DECLSPEC void radiogatun64_round (PRIVATE_AS radiogatun64_ctx_t *ctx)
{
  RADIOGATUN_ROUND (u64, hc_rotr64_S, 63, (u64) 1, ctx->a, ctx->b);
}

DECLSPEC void radiogatun64_init (PRIVATE_AS radiogatun64_ctx_t *ctx)
{
  for (u32 i = 0; i < 19; i++) ctx->a[i] = 0;

  for (u32 i = 0; i < 13; i++)
  {
    for (u32 j = 0; j < 3; j++) ctx->b[i][j] = 0;
  }

  for (u32 i = 0; i < 3; i++) ctx->m[i] = 0;
  for (u32 i = 0; i < 4; i++) ctx->h[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void radiogatun64_block (PRIVATE_AS radiogatun64_ctx_t *ctx)
{
  for (u32 i = 0; i < 3; i++)
  {
    ctx->b[0][i]   ^= ctx->m[i];
    ctx->a[16 + i] ^= ctx->m[i];
  }

  radiogatun64_round (ctx);

  for (u32 i = 0; i < 3; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void radiogatun64_absorb (PRIVATE_AS radiogatun64_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 24 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64 x = (u64) (v & mask);

  const int word = pos / 8;
  const int off  = pos & 7;

  ctx->m[word] |= x << (off * 8);

  if ((off + fit) > 8) ctx->m[word + 1] |= x >> ((8 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  radiogatun64_block (ctx);

  if (n > fit)
  {
    ctx->m[0] = (u64) (v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void radiogatun64_update (PRIVATE_AS radiogatun64_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    radiogatun64_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void radiogatun64_absorb_utf16le (PRIVATE_AS radiogatun64_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  radiogatun64_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) radiogatun64_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void radiogatun64_update_utf16le (PRIVATE_AS radiogatun64_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      radiogatun64_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    radiogatun64_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void radiogatun64_update_global (PRIVATE_AS radiogatun64_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    radiogatun64_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void radiogatun64_update_global_utf16le (PRIVATE_AS radiogatun64_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      radiogatun64_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    radiogatun64_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The same padding and blank rounds as RadioGatun[32]. Its 64 bit words give 16 bytes per output
// round, so the 32 byte digest takes 2 of them.

DECLSPEC void radiogatun64_final (PRIVATE_AS radiogatun64_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 8] |= ((u64) 0x01) << ((pos & 7) * 8);

  radiogatun64_block (ctx);

  for (u32 i = 0; i < 17; i++) radiogatun64_round (ctx);

  ctx->h[0] = ctx->a[1];
  ctx->h[1] = ctx->a[2];

  radiogatun64_round (ctx);

  ctx->h[2] = ctx->a[1];
  ctx->h[3] = ctx->a[2];

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 4; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void radiogatun32_round_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx)
{
  RADIOGATUN_ROUND (u32x, hc_rotr32, 31, (u32) 1, ctx->a, ctx->b);
}

DECLSPEC void radiogatun32_init_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx)
{
  for (u32 i = 0; i < 19; i++) ctx->a[i] = 0;

  for (u32 i = 0; i < 13; i++)
  {
    for (u32 j = 0; j < 3; j++) ctx->b[i][j] = 0;
  }

  for (u32 i = 0; i < 3; i++) ctx->m[i] = 0;
  for (u32 i = 0; i < 8; i++) ctx->h[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void radiogatun32_block_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx)
{
  for (u32 i = 0; i < 3; i++)
  {
    ctx->b[0][i]   ^= ctx->m[i];
    ctx->a[16 + i] ^= ctx->m[i];
  }

  radiogatun32_round_vector (ctx);

  for (u32 i = 0; i < 3; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void radiogatun32_absorb_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 12 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int word = pos / 4;
  const int off  = pos & 3;

  ctx->m[word] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[word + 1] |= x >> ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  radiogatun32_block_vector (ctx);

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void radiogatun32_update_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    radiogatun32_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void radiogatun32_update_vector_utf16le (PRIVATE_AS radiogatun32_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    radiogatun32_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) radiogatun32_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void radiogatun32_final_vector (PRIVATE_AS radiogatun32_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x01u << ((pos & 3) * 8);

  radiogatun32_block_vector (ctx);

  for (u32 i = 0; i < 17; i++) radiogatun32_round_vector (ctx);

  ctx->h[0] = ctx->a[1];
  ctx->h[1] = ctx->a[2];

  for (u32 i = 2; i < 8; i += 2)
  {
    radiogatun32_round_vector (ctx);

    ctx->h[i + 0] = ctx->a[1];
    ctx->h[i + 1] = ctx->a[2];
  }
}

DECLSPEC void radiogatun64_round_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx)
{
  RADIOGATUN_ROUND (u64x, hc_rotr64, 63, (u64) 1, ctx->a, ctx->b);
}

DECLSPEC void radiogatun64_init_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx)
{
  for (u32 i = 0; i < 19; i++) ctx->a[i] = 0;

  for (u32 i = 0; i < 13; i++)
  {
    for (u32 j = 0; j < 3; j++) ctx->b[i][j] = 0;
  }

  for (u32 i = 0; i < 3; i++) ctx->m[i] = 0;
  for (u32 i = 0; i < 4; i++) ctx->h[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void radiogatun64_block_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx)
{
  for (u32 i = 0; i < 3; i++)
  {
    ctx->b[0][i]   ^= ctx->m[i];
    ctx->a[16 + i] ^= ctx->m[i];
  }

  radiogatun64_round_vector (ctx);

  for (u32 i = 0; i < 3; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void radiogatun64_absorb_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 24 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64x x = hl32_to_64 (0, v & mask);

  const int word = pos / 8;
  const int off  = pos & 7;

  ctx->m[word] |= x << (off * 8);

  if ((off + fit) > 8) ctx->m[word + 1] |= x >> ((8 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  radiogatun64_block_vector (ctx);

  if (n > fit)
  {
    ctx->m[0] = hl32_to_64 (0, v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void radiogatun64_update_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    radiogatun64_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void radiogatun64_update_vector_utf16le (PRIVATE_AS radiogatun64_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    radiogatun64_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) radiogatun64_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void radiogatun64_final_vector (PRIVATE_AS radiogatun64_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 8] |= make_u64x (0x01) << ((pos & 7) * 8);

  radiogatun64_block_vector (ctx);

  for (u32 i = 0; i < 17; i++) radiogatun64_round_vector (ctx);

  ctx->h[0] = ctx->a[1];
  ctx->h[1] = ctx->a[2];

  radiogatun64_round_vector (ctx);

  ctx->h[2] = ctx->a[1];
  ctx->h[3] = ctx->a[2];
}
