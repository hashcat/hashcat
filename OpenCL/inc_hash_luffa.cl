/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_luffa.h"

// Input is little endian words, as for MD5. The block in the context keeps that byte order and is
// swapped to big endian words when it is injected. A partial last word may hold bytes past the
// length, which the updates mask off.

// The starting value of each of the 5 lanes. A digest size uses the first 3, 4 or 5.

CONSTANT_VK u32a luffa_iv[5][8] =
{
  { 0x6d251e69, 0x44b051e0, 0x4eaa6fb4, 0xdbf78465, 0x6e292011, 0x90152df4, 0xee058139, 0xdef610bb },
  { 0xc3b44b95, 0xd9d2f256, 0x70eee9a0, 0xde099fa3, 0x5d9b0557, 0x8fc944b3, 0xcf1ccf0e, 0x746cd581 },
  { 0xf7efc89d, 0x5dba5781, 0x04016ce5, 0xad659c05, 0x0306194f, 0x666d1836, 0x24aa230a, 0x8b264ae7 },
  { 0x858075d5, 0x36d79cce, 0xe571f7d7, 0x204b1f67, 0x35870c6a, 0x57e9e923, 0x14bcb808, 0x7cde72ce },
  { 0x6c68e9be, 0x5ec41e22, 0xc825b7c7, 0xaffb4363, 0xf5df3999, 0x0fc688f1, 0xb07224cc, 0x03e86cea },
};

// The round constants of the step function of lane J, for its words 0 and 4, one per round.

CONSTANT_VK u32a luffa_rc[5][2][8] =
{
  {
    { 0x303994a6, 0xc0e65299, 0x6cc33a12, 0xdc56983e, 0x1e00108f, 0x7800423d, 0x8f5b7882, 0x96e1db12 },
    { 0xe0337818, 0x441ba90d, 0x7f34d442, 0x9389217f, 0xe5a8bce6, 0x5274baf4, 0x26889ba7, 0x9a226e9d },
  },
  {
    { 0xb6de10ed, 0x70f47aae, 0x0707a3d4, 0x1c1e8f51, 0x707a3d45, 0xaeb28562, 0xbaca1589, 0x40a46f3e },
    { 0x01685f3d, 0x05a17cf4, 0xbd09caca, 0xf4272b28, 0x144ae5cc, 0xfaa7ae2b, 0x2e48f1c1, 0xb923c704 },
  },
  {
    { 0xfc20d9d2, 0x34552e25, 0x7ad8818f, 0x8438764a, 0xbb6de032, 0xedb780c8, 0xd9847356, 0xa2c78434 },
    { 0xe25e72c1, 0xe623bb72, 0x5c58a4a4, 0x1e38e2e7, 0x78e38b9d, 0x27586719, 0x36eda57f, 0x703aace7 },
  },
  {
    { 0xb213afa5, 0xc84ebe95, 0x4e608a22, 0x56d858fe, 0x343b138f, 0xd0ec4e3d, 0x2ceb4882, 0xb3ad2208 },
    { 0xe028c9bf, 0x44756f91, 0x7e8fce32, 0x956548be, 0xfe191be2, 0x3cb226e5, 0x5944a28e, 0xa1c4c355 },
  },
  {
    { 0xf0d2e9e3, 0xac11d7fa, 0x1bcb66f2, 0x6f2d9bc9, 0x78602649, 0x8edae952, 0x3b6ba548, 0xedae9520 },
    { 0x5090d577, 0x2d1925ab, 0xb46496ac, 0xd1925ab0, 0x29131ab6, 0x0fc053c3, 0x3f014f0c, 0xfc053c31 },
  },
};

// Multiplication of the 8 words of S by 2 in the field of the message injection, written to D,
// which may be S itself. The words are written in descending order for that reason.

#define LUFFA_M2(T,D,S)                                                         \
{                                                                               \
  const T t = S[7];                                                             \
                                                                                \
  D[7] = S[6];                                                                  \
  D[6] = S[5];                                                                  \
  D[5] = S[4];                                                                  \
  D[4] = S[3] ^ t;                                                              \
  D[3] = S[2] ^ t;                                                              \
  D[2] = S[1];                                                                  \
  D[1] = S[0] ^ t;                                                              \
  D[0] = t;                                                                     \
}

#define LUFFA_XOR(D,S)                                                          \
{                                                                               \
  for (u32 k = 0; k < 8; k++) D[k] ^= S[k];                                     \
}

#define LUFFA_SUB_CRUMB(T,A0,A1,A2,A3)                                          \
{                                                                               \
  T t = A0;                                                                     \
                                                                                \
  A0 |= A1;                                                                     \
  A2 ^= A3;                                                                     \
  A1  = ~A1;                                                                    \
  A0 ^= A3;                                                                     \
  A3 &= t;                                                                      \
  A1 ^= A3;                                                                     \
  A3 ^= A2;                                                                     \
  A2 &= A0;                                                                     \
  A0  = ~A0;                                                                    \
  A2 ^= A1;                                                                     \
  A1 |= A3;                                                                     \
  t  ^= A1;                                                                     \
  A3 ^= A2;                                                                     \
  A2 &= A1;                                                                     \
  A1 ^= A0;                                                                     \
  A0  = t;                                                                      \
}

#define LUFFA_MIX_WORD(ROTL,U,V)                                                \
{                                                                               \
  V ^= U;                                                                       \
  U  = ROTL (U,  2) ^ V;                                                        \
  V  = ROTL (V, 14) ^ U;                                                        \
  U  = ROTL (U, 10) ^ V;                                                        \
  V  = ROTL (V,  1);                                                            \
}

// One round: the message injection of the block M into the lanes of V, then the permutation. The
// injection mixes the XOR of all lanes into each lane. With 4 or 5 lanes, a chain of
// multiplications by 2 then mixes neighboring lanes. Lane J absorbs the block multiplied by 2 J
// times. The permutation rotates the words 4 to 7 of lane J left by J, then runs 8 rounds of the
// step function on each lane independently. SWAP reads the words of M, which are in memory byte
// order, as big endian words.

#define LUFFA_ROUND(T,ROTL,SWAP,V,M,LANES)                                      \
{                                                                               \
  T a[8];                                                                       \
                                                                                \
  for (u32 k = 0; k < 8; k++) a[k] = V[0][k];                                   \
                                                                                \
  for (int j = 1; j < (LANES); j++) LUFFA_XOR (a, V[j]);                        \
                                                                                \
  LUFFA_M2 (T, a, a);                                                           \
                                                                                \
  for (int j = 0; j < (LANES); j++) LUFFA_XOR (V[j], a);                        \
                                                                                \
  if ((LANES) == 4)                                                             \
  {                                                                             \
    T b[8];                                                                     \
                                                                                \
    LUFFA_M2 (T, b, V[0]);    LUFFA_XOR (b, V[3]);                              \
    LUFFA_M2 (T, V[3], V[3]); LUFFA_XOR (V[3], V[2]);                           \
    LUFFA_M2 (T, V[2], V[2]); LUFFA_XOR (V[2], V[1]);                           \
    LUFFA_M2 (T, V[1], V[1]); LUFFA_XOR (V[1], V[0]);                           \
                                                                                \
    for (u32 k = 0; k < 8; k++) V[0][k] = b[k];                                 \
  }                                                                             \
                                                                                \
  if ((LANES) == 5)                                                             \
  {                                                                             \
    T b[8];                                                                     \
                                                                                \
    LUFFA_M2 (T, b, V[0]);    LUFFA_XOR (b, V[1]);                              \
    LUFFA_M2 (T, V[1], V[1]); LUFFA_XOR (V[1], V[2]);                           \
    LUFFA_M2 (T, V[2], V[2]); LUFFA_XOR (V[2], V[3]);                           \
    LUFFA_M2 (T, V[3], V[3]); LUFFA_XOR (V[3], V[4]);                           \
    LUFFA_M2 (T, V[4], V[4]); LUFFA_XOR (V[4], V[0]);                           \
    LUFFA_M2 (T, V[0], b);    LUFFA_XOR (V[0], V[4]);                           \
    LUFFA_M2 (T, V[4], V[4]); LUFFA_XOR (V[4], V[3]);                           \
    LUFFA_M2 (T, V[3], V[3]); LUFFA_XOR (V[3], V[2]);                           \
    LUFFA_M2 (T, V[2], V[2]); LUFFA_XOR (V[2], V[1]);                           \
    LUFFA_M2 (T, V[1], V[1]); LUFFA_XOR (V[1], b);                              \
  }                                                                             \
                                                                                \
  T x[8];                                                                       \
                                                                                \
  for (u32 k = 0; k < 8; k++) x[k] = SWAP (M[k]);                               \
                                                                                \
  for (int j = 0; j < (LANES); j++)                                             \
  {                                                                             \
    if (j > 0) LUFFA_M2 (T, x, x);                                              \
                                                                                \
    LUFFA_XOR (V[j], x);                                                        \
  }                                                                             \
                                                                                \
  for (int j = 1; j < (LANES); j++)                                             \
  {                                                                             \
    for (u32 k = 4; k < 8; k++) V[j][k] = ROTL (V[j][k], j);                    \
  }                                                                             \
                                                                                \
  for (int j = 0; j < (LANES); j++)                                             \
  {                                                                             \
    T a0 = V[j][0];                                                             \
    T a1 = V[j][1];                                                             \
    T a2 = V[j][2];                                                             \
    T a3 = V[j][3];                                                             \
    T a4 = V[j][4];                                                             \
    T a5 = V[j][5];                                                             \
    T a6 = V[j][6];                                                             \
    T a7 = V[j][7];                                                             \
                                                                                \
    for (u32 r = 0; r < 8; r++)                                                 \
    {                                                                           \
      LUFFA_SUB_CRUMB (T, a0, a1, a2, a3);                                      \
      LUFFA_SUB_CRUMB (T, a5, a6, a7, a4);                                      \
                                                                                \
      LUFFA_MIX_WORD (ROTL, a0, a4);                                            \
      LUFFA_MIX_WORD (ROTL, a1, a5);                                            \
      LUFFA_MIX_WORD (ROTL, a2, a6);                                            \
      LUFFA_MIX_WORD (ROTL, a3, a7);                                            \
                                                                                \
      a0 ^= luffa_rc[j][0][r];                                                  \
      a4 ^= luffa_rc[j][1][r];                                                  \
    }                                                                           \
                                                                                \
    V[j][0] = a0;                                                               \
    V[j][1] = a1;                                                               \
    V[j][2] = a2;                                                               \
    V[j][3] = a3;                                                               \
    V[j][4] = a4;                                                               \
    V[j][5] = a5;                                                               \
    V[j][6] = a6;                                                               \
    V[j][7] = a7;                                                               \
  }                                                                             \
}

// The output of a round is the XOR of all lanes, 8 words written to H from word O on.

#define LUFFA_OUTPUT(V,H,O,LANES)                                               \
{                                                                               \
  for (u32 k = 0; k < 8; k++)                                                   \
  {                                                                             \
    H[(O) + k] = V[0][k];                                                       \
                                                                                \
    for (int j = 1; j < (LANES); j++) H[(O) + k] ^= V[j][k];                    \
  }                                                                             \
}

DECLSPEC int luffa_lanes (const int dlen)
{
  if (dlen == 64) return 5;
  if (dlen == 48) return 4;

  return 3;
}

DECLSPEC void luffa_round (PRIVATE_AS luffa_ctx_t *ctx)
{
  LUFFA_ROUND (u32, hc_rotl32_S, hc_swap32_S, ctx->v, ctx->m, ctx->lanes);
}

DECLSPEC void luffa_init (PRIVATE_AS luffa_ctx_t *ctx, const int dlen)
{
  for (u32 i = 0; i < 5; i++)
  {
    for (u32 k = 0; k < 8; k++) ctx->v[i][k] = luffa_iv[i][k];
  }

  for (u32 i = 0; i <  8; i++) ctx->m[i] = 0;
  for (u32 i = 0; i < 16; i++) ctx->h[i] = 0;

  ctx->pos   = 0;
  ctx->len   = 0;
  ctx->lanes = luffa_lanes (dlen);
  ctx->dlen  = dlen;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, process it and use any remaining
// bytes to start the next block. The padding always adds a block, so a full block never waits.

DECLSPEC void luffa_absorb (PRIVATE_AS luffa_ctx_t *ctx, const u32 v, const int n)
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

  luffa_round (ctx);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void luffa_update (PRIVATE_AS luffa_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    luffa_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void luffa_absorb_utf16le (PRIVATE_AS luffa_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  luffa_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) luffa_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void luffa_update_utf16le (PRIVATE_AS luffa_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      luffa_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    luffa_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void luffa_update_global (PRIVATE_AS luffa_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    luffa_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void luffa_update_global_utf16le (PRIVATE_AS luffa_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      luffa_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    luffa_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x80 byte and zeros up to the end of the block, which is processed. No length is
// encoded. Rounds with an all zero block follow: 1 for 3 lanes, whose output is the digest, and
// 2 for 4 or 5 lanes, whose outputs are the first and the second 32 bytes of the digest. A
// context with invalid UTF-8 input produces a digest with every bit flipped, so that no candidate
// matches it by chance.

DECLSPEC void luffa_final (PRIVATE_AS luffa_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  luffa_round (ctx);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  luffa_round (ctx);

  LUFFA_OUTPUT (ctx->v, ctx->h, 0, ctx->lanes);

  if (ctx->lanes > 3)
  {
    luffa_round (ctx);

    LUFFA_OUTPUT (ctx->v, ctx->h, 8, ctx->lanes);
  }

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 16; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void luffa_round_vector (PRIVATE_AS luffa_ctx_vector_t *ctx)
{
  LUFFA_ROUND (u32x, hc_rotl32, hc_swap32, ctx->v, ctx->m, ctx->lanes);
}

DECLSPEC void luffa_init_vector (PRIVATE_AS luffa_ctx_vector_t *ctx, const int dlen)
{
  for (u32 i = 0; i < 5; i++)
  {
    for (u32 k = 0; k < 8; k++) ctx->v[i][k] = make_u32x (luffa_iv[i][k]);
  }

  for (u32 i = 0; i <  8; i++) ctx->m[i] = 0;
  for (u32 i = 0; i < 16; i++) ctx->h[i] = 0;

  ctx->pos   = 0;
  ctx->len   = 0;
  ctx->lanes = luffa_lanes (dlen);
  ctx->dlen  = dlen;
}

DECLSPEC void luffa_absorb_vector (PRIVATE_AS luffa_ctx_vector_t *ctx, const u32x v, const int n)
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

  luffa_round_vector (ctx);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void luffa_update_vector (PRIVATE_AS luffa_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    luffa_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void luffa_update_vector_utf16le (PRIVATE_AS luffa_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    luffa_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) luffa_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void luffa_final_vector (PRIVATE_AS luffa_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  luffa_round_vector (ctx);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  luffa_round_vector (ctx);

  LUFFA_OUTPUT (ctx->v, ctx->h, 0, ctx->lanes);

  if (ctx->lanes > 3)
  {
    luffa_round_vector (ctx);

    LUFFA_OUTPUT (ctx->v, ctx->h, 8, ctx->lanes);
  }
}
