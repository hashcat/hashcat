/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_has160.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off.

#define HAS160_F1(b,c,d) ((d) ^ ((b) & ((c) ^ (d))))
#define HAS160_F2(b,c,d) ((b) ^ (c) ^ (d))
#define HAS160_F3(b,c,d) ((c) ^ ((b) | ~(d)))

// One step. The message word X and the rotation S of A change with every step, the function F,
// the constant K and the rotation R of B with every round.

#define HAS160_STEP(ROTL,F,K,R,A,B,C,D,E,X,S)                                   \
{                                                                               \
  E += ROTL (A, S) + F (B, C, D) + (X) + (K);                                   \
  B  = ROTL (B, R);                                                             \
}

// 20 steps with the message words X[I0] to X[I19]. The rotations of A are the same in every round.

#define HAS160_ROUND(ROTL,F,K,R,X,A,B,C,D,E,I0,I1,I2,I3,I4,I5,I6,I7,I8,I9,I10,I11,I12,I13,I14,I15,I16,I17,I18,I19) \
{                                                                               \
  HAS160_STEP (ROTL, F, K, R, A, B, C, D, E, X[I0],   5);                       \
  HAS160_STEP (ROTL, F, K, R, E, A, B, C, D, X[I1],  11);                       \
  HAS160_STEP (ROTL, F, K, R, D, E, A, B, C, X[I2],   7);                       \
  HAS160_STEP (ROTL, F, K, R, C, D, E, A, B, X[I3],  15);                       \
  HAS160_STEP (ROTL, F, K, R, B, C, D, E, A, X[I4],   6);                       \
  HAS160_STEP (ROTL, F, K, R, A, B, C, D, E, X[I5],  13);                       \
  HAS160_STEP (ROTL, F, K, R, E, A, B, C, D, X[I6],   8);                       \
  HAS160_STEP (ROTL, F, K, R, D, E, A, B, C, X[I7],  14);                       \
  HAS160_STEP (ROTL, F, K, R, C, D, E, A, B, X[I8],   7);                       \
  HAS160_STEP (ROTL, F, K, R, B, C, D, E, A, X[I9],  12);                       \
  HAS160_STEP (ROTL, F, K, R, A, B, C, D, E, X[I10],  9);                       \
  HAS160_STEP (ROTL, F, K, R, E, A, B, C, D, X[I11], 11);                       \
  HAS160_STEP (ROTL, F, K, R, D, E, A, B, C, X[I12],  8);                       \
  HAS160_STEP (ROTL, F, K, R, C, D, E, A, B, X[I13], 15);                       \
  HAS160_STEP (ROTL, F, K, R, B, C, D, E, A, X[I14],  6);                       \
  HAS160_STEP (ROTL, F, K, R, A, B, C, D, E, X[I15], 12);                       \
  HAS160_STEP (ROTL, F, K, R, E, A, B, C, D, X[I16],  9);                       \
  HAS160_STEP (ROTL, F, K, R, D, E, A, B, C, X[I17], 14);                       \
  HAS160_STEP (ROTL, F, K, R, C, D, E, A, B, X[I18],  5);                       \
  HAS160_STEP (ROTL, F, K, R, B, C, D, E, A, X[I19], 13);                       \
}

// Each round mixes in 4 extra words, each the XOR of 4 message words, in steps 0, 5, 10 and 15.

#define HAS160_TRANSFORM(T,ROTL,H,M)                                            \
{                                                                               \
  T x[32];                                                                      \
                                                                                \
  for (u32 i = 0; i < 16; i++) x[i] = M[i];                                     \
                                                                                \
  x[16] = x[ 0] ^ x[ 1] ^ x[ 2] ^ x[ 3];                                        \
  x[17] = x[ 4] ^ x[ 5] ^ x[ 6] ^ x[ 7];                                        \
  x[18] = x[ 8] ^ x[ 9] ^ x[10] ^ x[11];                                        \
  x[19] = x[12] ^ x[13] ^ x[14] ^ x[15];                                        \
  x[20] = x[ 3] ^ x[ 6] ^ x[ 9] ^ x[12];                                        \
  x[21] = x[ 2] ^ x[ 5] ^ x[ 8] ^ x[15];                                        \
  x[22] = x[ 1] ^ x[ 4] ^ x[11] ^ x[14];                                        \
  x[23] = x[ 0] ^ x[ 7] ^ x[10] ^ x[13];                                        \
  x[24] = x[ 5] ^ x[ 7] ^ x[12] ^ x[14];                                        \
  x[25] = x[ 0] ^ x[ 2] ^ x[ 9] ^ x[11];                                        \
  x[26] = x[ 4] ^ x[ 6] ^ x[13] ^ x[15];                                        \
  x[27] = x[ 1] ^ x[ 3] ^ x[ 8] ^ x[10];                                        \
  x[28] = x[ 2] ^ x[ 7] ^ x[ 8] ^ x[13];                                        \
  x[29] = x[ 3] ^ x[ 4] ^ x[ 9] ^ x[14];                                        \
  x[30] = x[ 0] ^ x[ 5] ^ x[10] ^ x[15];                                        \
  x[31] = x[ 1] ^ x[ 6] ^ x[11] ^ x[12];                                        \
                                                                                \
  T a = H[0];                                                                   \
  T b = H[1];                                                                   \
  T c = H[2];                                                                   \
  T d = H[3];                                                                   \
  T e = H[4];                                                                   \
                                                                                \
  HAS160_ROUND (ROTL, HAS160_F1, 0x00000000, 10, x, a, b, c, d, e,              \
                18,  0,  1,  2,  3, 19,  4,  5,  6,  7, 16,  8,  9, 10, 11, 17, 12, 13, 14, 15); \
  HAS160_ROUND (ROTL, HAS160_F2, 0x5a827999, 17, x, a, b, c, d, e,              \
                22,  3,  6,  9, 12, 23, 15,  2,  5,  8, 20, 11, 14,  1,  4, 21,  7, 10, 13,  0); \
  HAS160_ROUND (ROTL, HAS160_F3, 0x6ed9eba1, 25, x, a, b, c, d, e,              \
                26, 12,  5, 14,  7, 27,  0,  9,  2, 11, 24,  4, 13,  6, 15, 25,  8,  1, 10,  3); \
  HAS160_ROUND (ROTL, HAS160_F2, 0x8f1bbcdc, 30, x, a, b, c, d, e,              \
                30,  7,  2, 13,  8, 31,  3, 14,  9,  4, 28, 15, 10,  5,  0, 29, 11,  6,  1, 12); \
                                                                                \
  H[0] += a;                                                                    \
  H[1] += b;                                                                    \
  H[2] += c;                                                                    \
  H[3] += d;                                                                    \
  H[4] += e;                                                                    \
}

DECLSPEC void has160_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *w)
{
  HAS160_TRANSFORM (u32, hc_rotl32_S, h, w);
}

DECLSPEC void has160_init (PRIVATE_AS has160_ctx_t *ctx)
{
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0xc3d2e1f0;

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void has160_block (PRIVATE_AS has160_ctx_t *ctx)
{
  has160_transform (ctx->h, ctx->w);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void has160_absorb (PRIVATE_AS has160_ctx_t *ctx, const u32 v, const int n)
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
    has160_block (ctx);

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

DECLSPEC void has160_update (PRIVATE_AS has160_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    has160_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void has160_absorb_utf16le (PRIVATE_AS has160_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  has160_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) has160_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void has160_update_utf16le (PRIVATE_AS has160_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      has160_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    has160_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void has160_update_global (PRIVATE_AS has160_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    has160_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void has160_update_global_utf16le (PRIVATE_AS has160_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      has160_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    has160_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding of MD5: the 0x80 byte, zeros up to byte 56 and the message length in bits. A context
// with invalid UTF-8 input produces a digest with every bit flipped, so that no candidate matches
// it by chance.

DECLSPEC void has160_final (PRIVATE_AS has160_ctx_t *ctx)
{
  const u32 len = (u32) ctx->len;

  has160_absorb (ctx, 0x80, 1);

  if (ctx->pos > 56) has160_block (ctx);

  ctx->w[14] = len << 3;
  ctx->w[15] = len >> 29;

  has160_block (ctx);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 5; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void has160_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *w)
{
  HAS160_TRANSFORM (u32x, hc_rotl32, h, w);
}

DECLSPEC void has160_init_vector (PRIVATE_AS has160_ctx_vector_t *ctx)
{
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0xc3d2e1f0;

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;
}

DECLSPEC void has160_block_vector (PRIVATE_AS has160_ctx_vector_t *ctx)
{
  has160_transform_vector (ctx->h, ctx->w);

  for (u32 i = 0; i < 16; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void has160_absorb_vector (PRIVATE_AS has160_ctx_vector_t *ctx, const u32x v, const int n)
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
    has160_block_vector (ctx);

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

DECLSPEC void has160_update_vector (PRIVATE_AS has160_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    has160_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void has160_update_vector_utf16le (PRIVATE_AS has160_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    has160_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) has160_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void has160_final_vector (PRIVATE_AS has160_ctx_vector_t *ctx)
{
  const u32 len = (u32) ctx->len;

  has160_absorb_vector (ctx, make_u32x (0x80), 1);

  if (ctx->pos > 56) has160_block_vector (ctx);

  ctx->w[14] = len << 3;
  ctx->w[15] = len >> 29;

  has160_block_vector (ctx);
}
