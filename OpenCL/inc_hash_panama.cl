/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_panama.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off.

// One PANAMA step, the same for push and pull. X1 feeds the buffer and X2 the state. A push
// feeds the input block to both. A pull feeds state words 1 to 8 to the buffer and buffer stage 4
// to the state, read before the step changes them. The buffer turns by moving PTR: stage 0 is
// b[PTR], and stage N is b[(PTR - N) & 31]. Afterwards the old stage 31 is the new stage 0.

#define PANAMA_STEP(T,ROTL,B,A,PTR,X1,X2)                                       \
{                                                                               \
  const int p24 = ((PTR) - 8) & 31;                                             \
  const int p31 = ((PTR) - 1) & 31;                                             \
  const int p16 = (PTR) ^ 16;                                                   \
                                                                                \
  for (u32 i = 0; i < 8; i++)                                                   \
  {                                                                             \
    const u32 j = (i + 2) & 7;                                                  \
                                                                                \
    B[p24][i] ^= B[p31][j];                                                     \
    B[p31][j] ^= X1[j];                                                         \
  }                                                                             \
                                                                                \
  T g[17];                                                                      \
                                                                                \
  for (u32 i = 0; i < 17; i++)                                                  \
  {                                                                             \
    g[i] = A[i] ^ (A[(i + 1) % 17] | ~A[(i + 2) % 17]);                         \
  }                                                                             \
                                                                                \
  T p[17];                                                                      \
                                                                                \
  p[ 0] = g[0];                                                                 \
  p[ 1] = ROTL (g[ 7],  1);                                                     \
  p[ 2] = ROTL (g[14],  3);                                                     \
  p[ 3] = ROTL (g[ 4],  6);                                                     \
  p[ 4] = ROTL (g[11], 10);                                                     \
  p[ 5] = ROTL (g[ 1], 15);                                                     \
  p[ 6] = ROTL (g[ 8], 21);                                                     \
  p[ 7] = ROTL (g[15], 28);                                                     \
  p[ 8] = ROTL (g[ 5],  4);                                                     \
  p[ 9] = ROTL (g[12], 13);                                                     \
  p[10] = ROTL (g[ 2], 23);                                                     \
  p[11] = ROTL (g[ 9],  2);                                                     \
  p[12] = ROTL (g[16], 14);                                                     \
  p[13] = ROTL (g[ 6], 27);                                                     \
  p[14] = ROTL (g[13],  9);                                                     \
  p[15] = ROTL (g[ 3], 24);                                                     \
  p[16] = ROTL (g[10],  8);                                                     \
                                                                                \
  T t[17];                                                                      \
                                                                                \
  for (u32 i = 0; i < 17; i++)                                                  \
  {                                                                             \
    t[i] = p[i] ^ p[(i + 1) % 17] ^ p[(i + 4) % 17];                            \
  }                                                                             \
                                                                                \
  A[0] = t[0] ^ (u32) 1;                                                        \
                                                                                \
  for (u32 i = 0; i < 8; i++)                                                   \
  {                                                                             \
    A[1 + i] = t[1 + i] ^ X2[i];                                                \
    A[9 + i] = t[9 + i] ^ B[p16][i];                                            \
  }                                                                             \
                                                                                \
  PTR = p31;                                                                    \
}

DECLSPEC void panama_step (PRIVATE_AS panama_ctx_t *ctx, PRIVATE_AS const u32 *x1, PRIVATE_AS const u32 *x2)
{
  PANAMA_STEP (u32, hc_rotl32_S, ctx->b, ctx->st, ctx->ptr, x1, x2);
}

DECLSPEC void panama_init (PRIVATE_AS panama_ctx_t *ctx)
{
  for (u32 i = 0; i < 32; i++)
  {
    for (u32 j = 0; j < 8; j++) ctx->b[i][j] = 0;
  }

  for (u32 i = 0; i < 17; i++) ctx->st[i] = 0;
  for (u32 i = 0; i <  8; i++) ctx->m[i]  = 0;

  ctx->ptr = 0;
  ctx->pos = 0;
  ctx->len = 0;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, push it and use any remaining
// bytes to start the next block.

DECLSPEC void panama_absorb (PRIVATE_AS panama_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 32 - pos;

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

  panama_step (ctx, ctx->m, ctx->m);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void panama_update (PRIVATE_AS panama_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    panama_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void panama_absorb_utf16le (PRIVATE_AS panama_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  panama_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) panama_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void panama_update_utf16le (PRIVATE_AS panama_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      panama_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    panama_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void panama_update_global (PRIVATE_AS panama_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    panama_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void panama_update_global_utf16le (PRIVATE_AS panama_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  // Decoding UTF-8 straight from global memory faults on NVIDIA GPUs in the combinator kernel of
  // mode 4000, so the decoder reads a private copy. hc_enc takes up to 256 bytes, and a longer input
  // with a non-ASCII byte is invalid either way.

  if (hc_enc_scan_global (w, len))
  {
    if (len > 256)
    {
      ctx->len = -1;

      return;
    }

    u32 buf[64] = { 0 };

    for (int i = 0; i < len; i += 4) buf[i / 4] = w[i / 4];

    panama_update_utf16le (ctx, buf, len);

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    panama_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x01 byte and zeros up to the end of the block, which is pushed. 32 pulls follow.
// A context with invalid UTF-8 input produces a digest with every bit flipped, so that no
// candidate matches it by chance.

DECLSPEC void panama_final (PRIVATE_AS panama_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x01u << ((pos & 3) * 8);

  panama_step (ctx, ctx->m, ctx->m);

  for (u32 i = 0; i < 32; i++)
  {
    panama_step (ctx, ctx->st + 1, ctx->b[(ctx->ptr + 4) & 31]);
  }

  if (ctx->len < 0)
  {
    for (u32 i = 9; i < 17; i++) ctx->st[i] = ~ctx->st[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void panama_step_vector (PRIVATE_AS panama_ctx_vector_t *ctx, PRIVATE_AS const u32x *x1, PRIVATE_AS const u32x *x2)
{
  PANAMA_STEP (u32x, hc_rotl32, ctx->b, ctx->st, ctx->ptr, x1, x2);
}

DECLSPEC void panama_init_vector (PRIVATE_AS panama_ctx_vector_t *ctx)
{
  for (u32 i = 0; i < 32; i++)
  {
    for (u32 j = 0; j < 8; j++) ctx->b[i][j] = 0;
  }

  for (u32 i = 0; i < 17; i++) ctx->st[i] = 0;
  for (u32 i = 0; i <  8; i++) ctx->m[i]  = 0;

  ctx->ptr = 0;
  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void panama_absorb_vector (PRIVATE_AS panama_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 32 - pos;

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

  panama_step_vector (ctx, ctx->m, ctx->m);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void panama_update_vector (PRIVATE_AS panama_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    panama_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void panama_update_vector_utf16le (PRIVATE_AS panama_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    panama_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) panama_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void panama_final_vector (PRIVATE_AS panama_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x01u << ((pos & 3) * 8);

  panama_step_vector (ctx, ctx->m, ctx->m);

  for (u32 i = 0; i < 32; i++)
  {
    panama_step_vector (ctx, ctx->st + 1, ctx->b[(ctx->ptr + 4) & 31]);
  }
}
