/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_cubehash.h"

// Input is little endian words, as for MD5: CubeHash reads its blocks as little endian words.
// A partial last word may hold bytes past the length, which the updates mask off.

// The state after the 160 rounds of initialization, for digests of 28, 32, 48 and 64 bytes

CONSTANT_VK u32a cubehash_iv[4][32] =
{
  { 0xb0fc8217, 0x1bee1a90, 0x829e1a22, 0x6362c342, 0x24d91c30, 0x03a7aa24, 0xa63721c8, 0x85b0e2ef,
    0xf35d13f3, 0x41da807d, 0x21a70ca6, 0x1f4e9774, 0xb3e1c932, 0xeb0a79a8, 0xcddaaa66, 0xe2f6ecaa,
    0x0a713362, 0xaa3080e0, 0xd8f23a32, 0xcef15e28, 0xdb086314, 0x7f709df7, 0xacd228a4, 0x704d6ece,
    0xaa3ec95f, 0xe387c214, 0x3a6445ff, 0x9cab81c3, 0xc73d4b98, 0xd277aebe, 0xfd20151c, 0x00cb573e },
  { 0xea2bd4b4, 0xccd6f29f, 0x63117e71, 0x35481eae, 0x22512d5b, 0xe5d94e63, 0x7e624131, 0xf4cc12be,
    0xc2d0b696, 0x42af2070, 0xd0720c35, 0x3361da8c, 0x28cceca4, 0x8ef8ad83, 0x4680ac00, 0x40e5fbab,
    0xd89041c3, 0x6107fbd5, 0x6c859d41, 0xf0b26679, 0x09392549, 0x5fa25603, 0x65c892fd, 0x93cb6285,
    0x2af2b5ae, 0x9e4b4e60, 0x774abfdd, 0x85254725, 0x15815aeb, 0x4ab6aad6, 0x9cdaf8af, 0xd6032c0a },
  { 0xe623087e, 0x04c00c87, 0x5ef46453, 0x69524b13, 0x1a05c7a9, 0x3528df88, 0x6bdd01b5, 0x5057b792,
    0x6aa7a922, 0x649c7eee, 0xf426309f, 0xcb629052, 0xfc8e20ed, 0xb3482bab, 0xf89e5e7e, 0xd83d4de4,
    0x44bfc10d, 0x5fc1e63d, 0x2104e6cb, 0x17958f7f, 0xdbeaef70, 0xb4b97e1e, 0x32c195f6, 0x6184a8e4,
    0x796c2543, 0x23de176d, 0xd33bbaec, 0x0c12e5d2, 0x4eb95a7b, 0x2d18ba01, 0x04ee475f, 0x1fc5f22e },
  { 0x2aea2a61, 0x50f494d4, 0x2d538b8b, 0x4167d83e, 0x3fee2313, 0xc701cf8c, 0xcc39968e, 0x50ac5695,
    0x4d42c787, 0xa647a8b3, 0x97cf0bef, 0x825b4537, 0xeef864d2, 0xf22090c4, 0xd0e5cd33, 0xa23911ae,
    0xfcd398d9, 0x148fe485, 0x1b017bef, 0xb6444532, 0x6a536159, 0x2ff5781c, 0x91fa7934, 0x0dbadea9,
    0xd65c8a2b, 0xa5a70e75, 0xb1c62456, 0xbc796576, 0x1921c8f7, 0xe7989af1, 0x7795d246, 0xd43e3b44 },
};

// A CubeHash round has 2 steps. Each adds the low half of the state into the high half, rotates
// the low half, swaps words within the low half, XORs the high half into the low half and swaps
// words within the high half. The steps differ in their rotation and in the words they swap. Every
// swap exchanges the words whose indices differ in one bit, and the swaps of 2 rounds cancel out.
// Rather than move words, each step reaches the partner of word I at index I ^ M, with the swaps
// still pending folded into M, as sphlib does with its even and odd rounds.

#define CUBEHASH_ADD1(ROTL,S,I,M,R)                                             \
{                                                                               \
  S[16 + ((I) ^ (M))] += S[I];                                                  \
                                                                                \
  S[I] = ROTL (S[I], R);                                                        \
}

#define CUBEHASH_ADD(ROTL,S,M,R)                                                \
{                                                                               \
  CUBEHASH_ADD1 (ROTL, S,  0, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  1, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  2, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  3, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  4, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  5, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  6, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  7, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  8, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S,  9, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S, 10, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S, 11, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S, 12, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S, 13, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S, 14, M, R);                                            \
  CUBEHASH_ADD1 (ROTL, S, 15, M, R);                                            \
}

#define CUBEHASH_XOR(S,M)                                                       \
{                                                                               \
  S[ 0 ^ (M)] ^= S[16 +  0];                                                    \
  S[ 1 ^ (M)] ^= S[16 +  1];                                                    \
  S[ 2 ^ (M)] ^= S[16 +  2];                                                    \
  S[ 3 ^ (M)] ^= S[16 +  3];                                                    \
  S[ 4 ^ (M)] ^= S[16 +  4];                                                    \
  S[ 5 ^ (M)] ^= S[16 +  5];                                                    \
  S[ 6 ^ (M)] ^= S[16 +  6];                                                    \
  S[ 7 ^ (M)] ^= S[16 +  7];                                                    \
  S[ 8 ^ (M)] ^= S[16 +  8];                                                    \
  S[ 9 ^ (M)] ^= S[16 +  9];                                                    \
  S[10 ^ (M)] ^= S[16 + 10];                                                    \
  S[11 ^ (M)] ^= S[16 + 11];                                                    \
  S[12 ^ (M)] ^= S[16 + 12];                                                    \
  S[13 ^ (M)] ^= S[16 + 13];                                                    \
  S[14 ^ (M)] ^= S[16 + 14];                                                    \
  S[15 ^ (M)] ^= S[16 + 15];                                                    \
}

// 2 rounds, after which no swap is pending

#define CUBEHASH_ROUND2(ROTL,S)                                                 \
{                                                                               \
  CUBEHASH_ADD (ROTL, S,  0,  7);                                               \
  CUBEHASH_XOR (S,  8);                                                         \
  CUBEHASH_ADD (ROTL, S, 10, 11);                                               \
  CUBEHASH_XOR (S, 14);                                                         \
  CUBEHASH_ADD (ROTL, S, 15,  7);                                               \
  CUBEHASH_XOR (S,  7);                                                         \
  CUBEHASH_ADD (ROTL, S,  5, 11);                                               \
  CUBEHASH_XOR (S,  1);                                                         \
}

// N times 16 rounds on the state X, in a copy that the constant indices keep in registers

#define CUBEHASH_ROUNDS(T,ROTL,X,N)                                             \
{                                                                               \
  T s[32];                                                                      \
                                                                                \
  for (u32 i = 0; i < 32; i++) s[i] = X[i];                                     \
                                                                                \
  for (int r = 0; r < (N) * 8; r++)                                             \
  {                                                                             \
    CUBEHASH_ROUND2 (ROTL, s);                                                  \
  }                                                                             \
                                                                                \
  for (u32 i = 0; i < 32; i++) X[i] = s[i];                                     \
}

DECLSPEC int cubehash_iv_index (const int dlen)
{
  if (dlen == 28) return 0;
  if (dlen == 32) return 1;
  if (dlen == 48) return 2;

  return 3;
}

DECLSPEC void cubehash_rounds (PRIVATE_AS u32 *x, const int n)
{
  CUBEHASH_ROUNDS (u32, hc_rotl32_S, x, n);
}

DECLSPEC void cubehash_init (PRIVATE_AS cubehash_ctx_t *ctx, const int dlen)
{
  const int iv = cubehash_iv_index (dlen);

  for (u32 i = 0; i < 32; i++) ctx->x[i] = cubehash_iv[iv][i];

  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// XOR the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, run the rounds and use any
// remaining bytes to start the next block. The block ends on a word boundary, so bytes that do
// not fit shift out of its last word and need no mask.

DECLSPEC void cubehash_absorb (PRIVATE_AS cubehash_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 32 - pos;

  const int fit = (n > room) ? room : n;

  const int word = pos / 4;
  const int off  = pos & 3;

  ctx->x[word] ^= v << (off * 8);

  if ((off + fit) > 4) ctx->x[word + 1] ^= v >> ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  cubehash_rounds (ctx->x, 1);

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->x[0] ^= v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void cubehash_update (PRIVATE_AS cubehash_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    cubehash_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void cubehash_absorb_utf16le (PRIVATE_AS cubehash_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  cubehash_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) cubehash_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void cubehash_update_utf16le (PRIVATE_AS cubehash_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      cubehash_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    cubehash_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void cubehash_update_global (PRIVATE_AS cubehash_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    cubehash_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void cubehash_update_global_utf16le (PRIVATE_AS cubehash_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      cubehash_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    cubehash_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x80 byte and zeros up to the end of the block, which gets its 16 rounds. Then the
// last state word is flipped in its lowest bit and 160 rounds follow. A context with invalid
// UTF-8 input produces a digest with every bit flipped, so that no candidate matches it by chance.

DECLSPEC void cubehash_final (PRIVATE_AS cubehash_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->x[pos / 4] ^= 0x80u << ((pos & 3) * 8);

  cubehash_rounds (ctx->x, 1);

  ctx->x[31] ^= 1u;

  cubehash_rounds (ctx->x, 10);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 16; i++) ctx->x[i] = ~ctx->x[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void cubehash_rounds_vector (PRIVATE_AS u32x *x, const int n)
{
  CUBEHASH_ROUNDS (u32x, hc_rotl32, x, n);
}

DECLSPEC void cubehash_init_vector (PRIVATE_AS cubehash_ctx_vector_t *ctx, const int dlen)
{
  const int iv = cubehash_iv_index (dlen);

  for (u32 i = 0; i < 32; i++) ctx->x[i] = make_u32x (cubehash_iv[iv][i]);

  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void cubehash_absorb_vector (PRIVATE_AS cubehash_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 32 - pos;

  const int fit = (n > room) ? room : n;

  const int word = pos / 4;
  const int off  = pos & 3;

  ctx->x[word] ^= v << (off * 8);

  if ((off + fit) > 4) ctx->x[word + 1] ^= v >> ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  cubehash_rounds_vector (ctx->x, 1);

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->x[0] ^= v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void cubehash_update_vector (PRIVATE_AS cubehash_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    cubehash_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void cubehash_update_vector_utf16le (PRIVATE_AS cubehash_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    cubehash_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) cubehash_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void cubehash_final_vector (PRIVATE_AS cubehash_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->x[pos / 4] ^= 0x80u << ((pos & 3) * 8);

  cubehash_rounds_vector (ctx->x, 1);

  ctx->x[31] ^= 1u;

  cubehash_rounds_vector (ctx->x, 10);
}
