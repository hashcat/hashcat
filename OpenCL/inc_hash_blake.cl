/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_blake.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off. The absorbs swap each word, because the blocks are kept in big
// endian words, the order in which BLAKE reads them.

// The constants of the 32 bit core, the first digits of pi

#define BLAKE256_C_0  0x243f6a88u
#define BLAKE256_C_1  0x85a308d3u
#define BLAKE256_C_2  0x13198a2eu
#define BLAKE256_C_3  0x03707344u
#define BLAKE256_C_4  0xa4093822u
#define BLAKE256_C_5  0x299f31d0u
#define BLAKE256_C_6  0x082efa98u
#define BLAKE256_C_7  0xec4e6c89u
#define BLAKE256_C_8  0x452821e6u
#define BLAKE256_C_9  0x38d01377u
#define BLAKE256_C_10 0xbe5466cfu
#define BLAKE256_C_11 0x34e90c6cu
#define BLAKE256_C_12 0xc0ac29b7u
#define BLAKE256_C_13 0xc97c50ddu
#define BLAKE256_C_14 0x3f84d5b5u
#define BLAKE256_C_15 0xb5470917u

// The constants of the 64 bit core, more digits of the same

#define BLAKE512_C_0  0x243f6a8885a308d3UL
#define BLAKE512_C_1  0x13198a2e03707344UL
#define BLAKE512_C_2  0xa4093822299f31d0UL
#define BLAKE512_C_3  0x082efa98ec4e6c89UL
#define BLAKE512_C_4  0x452821e638d01377UL
#define BLAKE512_C_5  0xbe5466cf34e90c6cUL
#define BLAKE512_C_6  0xc0ac29b7c97c50ddUL
#define BLAKE512_C_7  0x3f84d5b5b5470917UL
#define BLAKE512_C_8  0x9216d5d98979fb1bUL
#define BLAKE512_C_9  0xd1310ba698dfb5acUL
#define BLAKE512_C_10 0x2ffd72dbd01adfb7UL
#define BLAKE512_C_11 0xb8e1afed6a267e96UL
#define BLAKE512_C_12 0xba7c9045f12c7f99UL
#define BLAKE512_C_13 0x24a19947b3916cf7UL
#define BLAKE512_C_14 0x0801f2e2858efc16UL
#define BLAKE512_C_15 0x636920d871574e69UL

// The G function on the words A, B, C and D of the work state. I0 and I1 are the entries of the
// message permutation for this G, literal numbers, which select both the message words and the
// constants at compile time.

#define BLAKE256_G(ROTR,M,A,B,C,D,I0,I1)                                        \
{                                                                               \
  A = A + B + (M[I0] ^ BLAKE256_C_##I1);                                        \
  D = ROTR (D ^ A, 16);                                                         \
  C = C + D;                                                                    \
  B = ROTR (B ^ C, 12);                                                         \
  A = A + B + (M[I1] ^ BLAKE256_C_##I0);                                        \
  D = ROTR (D ^ A,  8);                                                         \
  C = C + D;                                                                    \
  B = ROTR (B ^ C,  7);                                                         \
}

#define BLAKE512_G(ROTR,M,A,B,C,D,I0,I1)                                        \
{                                                                               \
  A = A + B + (M[I0] ^ BLAKE512_C_##I1);                                        \
  D = ROTR (D ^ A, 32);                                                         \
  C = C + D;                                                                    \
  B = ROTR (B ^ C, 25);                                                         \
  A = A + B + (M[I1] ^ BLAKE512_C_##I0);                                        \
  D = ROTR (D ^ A, 16);                                                         \
  C = C + D;                                                                    \
  B = ROTR (B ^ C, 11);                                                         \
}

// One round: G on the columns, then on the diagonals of the 4x4 work state V. The S arguments are
// one row of the message permutation.

#define BLAKE_ROUND(G,ROTR,M,V,S0,S1,S2,S3,S4,S5,S6,S7,S8,S9,SA,SB,SC,SD,SE,SF) \
{                                                                               \
  G (ROTR, M, V[0], V[4], V[ 8], V[12], S0, S1);                                \
  G (ROTR, M, V[1], V[5], V[ 9], V[13], S2, S3);                                \
  G (ROTR, M, V[2], V[6], V[10], V[14], S4, S5);                                \
  G (ROTR, M, V[3], V[7], V[11], V[15], S6, S7);                                \
  G (ROTR, M, V[0], V[5], V[10], V[15], S8, S9);                                \
  G (ROTR, M, V[1], V[6], V[11], V[12], SA, SB);                                \
  G (ROTR, M, V[2], V[7], V[ 8], V[13], SC, SD);                                \
  G (ROTR, M, V[3], V[4], V[ 9], V[14], SE, SF);                                \
}

// The 10 rows of the message permutation, each as one round. Rounds 10 and up reuse them from
// the start.

#define BLAKE_ROUND_0(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15)
#define BLAKE_ROUND_1(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V, 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3)
#define BLAKE_ROUND_2(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V, 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4)
#define BLAKE_ROUND_3(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V,  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8)
#define BLAKE_ROUND_4(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V,  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13)
#define BLAKE_ROUND_5(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V,  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9)
#define BLAKE_ROUND_6(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V, 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11)
#define BLAKE_ROUND_7(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V, 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10)
#define BLAKE_ROUND_8(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V,  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5)
#define BLAKE_ROUND_9(G,ROTR,M,V) BLAKE_ROUND (G, ROTR, M, V, 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0)

// One compression of the block M into the chaining value H with the counter T0 (low half) and T1
// (high half): the message bits up to the end of this block, or zero for a block without any.
// The salt is zero, which drops it from the initialization and the finalization. C turns a
// constant into the type T. The 32 bit core runs 14 rounds, the 64 bit core 16.

#define BLAKE256_TRANSFORM(T,ROTR,C,H,M,T0,T1)                                  \
{                                                                               \
  T v[16];                                                                      \
                                                                                \
  v[ 0] = H[0];                                                                 \
  v[ 1] = H[1];                                                                 \
  v[ 2] = H[2];                                                                 \
  v[ 3] = H[3];                                                                 \
  v[ 4] = H[4];                                                                 \
  v[ 5] = H[5];                                                                 \
  v[ 6] = H[6];                                                                 \
  v[ 7] = H[7];                                                                 \
  v[ 8] = C (BLAKE256_C_0);                                                     \
  v[ 9] = C (BLAKE256_C_1);                                                     \
  v[10] = C (BLAKE256_C_2);                                                     \
  v[11] = C (BLAKE256_C_3);                                                     \
  v[12] = C ((T0) ^ BLAKE256_C_4);                                              \
  v[13] = C ((T0) ^ BLAKE256_C_5);                                              \
  v[14] = C ((T1) ^ BLAKE256_C_6);                                              \
  v[15] = C ((T1) ^ BLAKE256_C_7);                                              \
                                                                                \
  BLAKE_ROUND_0 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_1 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_2 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_3 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_4 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_5 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_6 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_7 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_8 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_9 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_0 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_1 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_2 (BLAKE256_G, ROTR, M, v);                                       \
  BLAKE_ROUND_3 (BLAKE256_G, ROTR, M, v);                                       \
                                                                                \
  H[0] ^= v[0] ^ v[ 8];                                                         \
  H[1] ^= v[1] ^ v[ 9];                                                         \
  H[2] ^= v[2] ^ v[10];                                                         \
  H[3] ^= v[3] ^ v[11];                                                         \
  H[4] ^= v[4] ^ v[12];                                                         \
  H[5] ^= v[5] ^ v[13];                                                         \
  H[6] ^= v[6] ^ v[14];                                                         \
  H[7] ^= v[7] ^ v[15];                                                         \
}

#define BLAKE512_TRANSFORM(T,ROTR,C,H,M,T0,T1)                                  \
{                                                                               \
  T v[16];                                                                      \
                                                                                \
  v[ 0] = H[0];                                                                 \
  v[ 1] = H[1];                                                                 \
  v[ 2] = H[2];                                                                 \
  v[ 3] = H[3];                                                                 \
  v[ 4] = H[4];                                                                 \
  v[ 5] = H[5];                                                                 \
  v[ 6] = H[6];                                                                 \
  v[ 7] = H[7];                                                                 \
  v[ 8] = C (BLAKE512_C_0);                                                     \
  v[ 9] = C (BLAKE512_C_1);                                                     \
  v[10] = C (BLAKE512_C_2);                                                     \
  v[11] = C (BLAKE512_C_3);                                                     \
  v[12] = C ((T0) ^ BLAKE512_C_4);                                              \
  v[13] = C ((T0) ^ BLAKE512_C_5);                                              \
  v[14] = C ((T1) ^ BLAKE512_C_6);                                              \
  v[15] = C ((T1) ^ BLAKE512_C_7);                                              \
                                                                                \
  BLAKE_ROUND_0 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_1 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_2 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_3 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_4 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_5 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_6 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_7 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_8 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_9 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_0 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_1 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_2 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_3 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_4 (BLAKE512_G, ROTR, M, v);                                       \
  BLAKE_ROUND_5 (BLAKE512_G, ROTR, M, v);                                       \
                                                                                \
  H[0] ^= v[0] ^ v[ 8];                                                         \
  H[1] ^= v[1] ^ v[ 9];                                                         \
  H[2] ^= v[2] ^ v[10];                                                         \
  H[3] ^= v[3] ^ v[11];                                                         \
  H[4] ^= v[4] ^ v[12];                                                         \
  H[5] ^= v[5] ^ v[13];                                                         \
  H[6] ^= v[6] ^ v[14];                                                         \
  H[7] ^= v[7] ^ v[15];                                                         \
}

// The initial chaining values: BLAKE-224 and BLAKE-384 take those of SHA-224 and SHA-384,
// BLAKE-256 and BLAKE-512 those of SHA-256 and SHA-512.

#define BLAKE256_IV(C,H,DLEN)                                                   \
{                                                                               \
  H[0] = C (((DLEN) == 28) ? 0xc1059ed8u : 0x6a09e667u);                        \
  H[1] = C (((DLEN) == 28) ? 0x367cd507u : 0xbb67ae85u);                        \
  H[2] = C (((DLEN) == 28) ? 0x3070dd17u : 0x3c6ef372u);                        \
  H[3] = C (((DLEN) == 28) ? 0xf70e5939u : 0xa54ff53au);                        \
  H[4] = C (((DLEN) == 28) ? 0xffc00b31u : 0x510e527fu);                        \
  H[5] = C (((DLEN) == 28) ? 0x68581511u : 0x9b05688cu);                        \
  H[6] = C (((DLEN) == 28) ? 0x64f98fa7u : 0x1f83d9abu);                        \
  H[7] = C (((DLEN) == 28) ? 0xbefa4fa4u : 0x5be0cd19u);                        \
}

#define BLAKE512_IV(C,H,DLEN)                                                   \
{                                                                               \
  H[0] = C (((DLEN) == 48) ? 0xcbbb9d5dc1059ed8UL : 0x6a09e667f3bcc908UL);      \
  H[1] = C (((DLEN) == 48) ? 0x629a292a367cd507UL : 0xbb67ae8584caa73bUL);      \
  H[2] = C (((DLEN) == 48) ? 0x9159015a3070dd17UL : 0x3c6ef372fe94f82bUL);      \
  H[3] = C (((DLEN) == 48) ? 0x152fecd8f70e5939UL : 0xa54ff53a5f1d36f1UL);      \
  H[4] = C (((DLEN) == 48) ? 0x67332667ffc00b31UL : 0x510e527fade682d1UL);      \
  H[5] = C (((DLEN) == 48) ? 0x8eb44a8768581511UL : 0x9b05688c2b3e6c1fUL);      \
  H[6] = C (((DLEN) == 48) ? 0xdb0c2e0d64f98fa7UL : 0x1f83d9abfb41bd6bUL);      \
  H[7] = C (((DLEN) == 48) ? 0x47b5481dbefa4fa4UL : 0x5be0cd19137e2179UL);      \
}

#define BLAKE_C_S(V)   (V)
#define BLAKE_C_V32(V) make_u32x (V)
#define BLAKE_C_V64(V) make_u64x (V)

// BLAKE-224 and BLAKE-256

DECLSPEC void blake256_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m, const u32 t0, const u32 t1)
{
  BLAKE256_TRANSFORM (u32, hc_rotr32_S, BLAKE_C_S, h, m, t0, t1);
}

DECLSPEC void blake256_init (PRIVATE_AS blake256_ctx_t *ctx, const int dlen)
{
  BLAKE256_IV (BLAKE_C_S, ctx->h, dlen);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// Compress the block in m with the counter t0 and t1 and start an empty block.

DECLSPEC void blake256_block (PRIVATE_AS blake256_ctx_t *ctx, const u32 t0, const u32 t1)
{
  blake256_transform (ctx->h, ctx->m, t0, t1);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, compress it and use any
// remaining bytes to start the next block. A full block always holds message bytes, so its
// counter is the message length up to its end.

DECLSPEC void blake256_absorb (PRIVATE_AS blake256_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 x = hc_swap32_S ((fit >= 4) ? v : (v & ((1u << (fit * 8)) - 1)));

  const int word = pos / 4;
  const int off  = pos & 3;

  ctx->m[word] |= x >> (off * 8);

  if ((off + fit) > 4) ctx->m[word + 1] |= x << ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  ctx->cnt += 64;

  blake256_block (ctx, ctx->cnt << 3, ctx->cnt >> 29);

  if (n > fit)
  {
    ctx->m[0] = hc_swap32_S (v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void blake256_update (PRIVATE_AS blake256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    blake256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void blake256_absorb_utf16le (PRIVATE_AS blake256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  blake256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) blake256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void blake256_update_utf16le (PRIVATE_AS blake256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      blake256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    blake256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void blake256_update_global (PRIVATE_AS blake256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    blake256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void blake256_update_global_utf16le (PRIVATE_AS blake256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      blake256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    blake256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 1 bit, zeros, a 1 bit for BLAKE-256 only, and the message length in bits as a big
// endian 64 bit number in the last 8 bytes of the block. If those do not fit behind the message,
// the padding takes one more block. A block without message bytes is compressed with a zero
// counter. A context with invalid UTF-8 input produces a digest with every bit flipped, so that
// no candidate matches it by chance.

DECLSPEC void blake256_final (PRIVATE_AS blake256_ctx_t *ctx)
{
  const int pos = ctx->pos;

  const u32 total = ctx->cnt + (u32) pos;

  const u32 bl = total << 3;
  const u32 bh = total >> 29;

  ctx->m[pos / 4] |= 0x80000000u >> ((pos & 3) * 8);

  u32 t0 = (pos == 0) ? 0 : bl;
  u32 t1 = (pos == 0) ? 0 : bh;

  if (pos >= 56)
  {
    blake256_block (ctx, bl, bh);

    t0 = 0;
    t1 = 0;
  }

  ctx->m[13] |= (ctx->dlen == 28) ? 0u : 1u;
  ctx->m[14]  = bh;
  ctx->m[15]  = bl;

  blake256_transform (ctx->h, ctx->m, t0, t1);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void blake256_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m, const u32 t0, const u32 t1)
{
  BLAKE256_TRANSFORM (u32x, hc_rotr32, BLAKE_C_V32, h, m, t0, t1);
}

DECLSPEC void blake256_init_vector (PRIVATE_AS blake256_ctx_vector_t *ctx, const int dlen)
{
  BLAKE256_IV (BLAKE_C_V32, ctx->h, dlen);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void blake256_block_vector (PRIVATE_AS blake256_ctx_vector_t *ctx, const u32 t0, const u32 t1)
{
  blake256_transform_vector (ctx->h, ctx->m, t0, t1);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void blake256_absorb_vector (PRIVATE_AS blake256_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = hc_swap32 (v & mask);

  const int word = pos / 4;
  const int off  = pos & 3;

  ctx->m[word] |= x >> (off * 8);

  if ((off + fit) > 4) ctx->m[word + 1] |= x << ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  ctx->cnt += 64;

  blake256_block_vector (ctx, ctx->cnt << 3, ctx->cnt >> 29);

  if (n > fit)
  {
    ctx->m[0] = hc_swap32 (v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void blake256_update_vector (PRIVATE_AS blake256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    blake256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void blake256_update_vector_utf16le (PRIVATE_AS blake256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    blake256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) blake256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void blake256_final_vector (PRIVATE_AS blake256_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  const u32 total = ctx->cnt + (u32) pos;

  const u32 bl = total << 3;
  const u32 bh = total >> 29;

  ctx->m[pos / 4] |= 0x80000000u >> ((pos & 3) * 8);

  u32 t0 = (pos == 0) ? 0 : bl;
  u32 t1 = (pos == 0) ? 0 : bh;

  if (pos >= 56)
  {
    blake256_block_vector (ctx, bl, bh);

    t0 = 0;
    t1 = 0;
  }

  ctx->m[13] |= (ctx->dlen == 28) ? 0u : 1u;
  ctx->m[14]  = make_u32x (bh);
  ctx->m[15]  = make_u32x (bl);

  blake256_transform_vector (ctx->h, ctx->m, t0, t1);
}

// BLAKE-384 and BLAKE-512. The counter and the length are 128 bit numbers whose high halves stay
// zero for any message hashcat can hold.

DECLSPEC void blake512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m, const u64 t0, const u64 t1)
{
  BLAKE512_TRANSFORM (u64, hc_rotr64_S, BLAKE_C_S, h, m, t0, t1);
}

DECLSPEC void blake512_init (PRIVATE_AS blake512_ctx_t *ctx, const int dlen)
{
  BLAKE512_IV (BLAKE_C_S, ctx->h, dlen);

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// Compress the block in m with the counter t0 and start an empty block.

DECLSPEC void blake512_block (PRIVATE_AS blake512_ctx_t *ctx, const u64 t0)
{
  u64 m[16];

  for (u32 i = 0; i < 16; i++) m[i] = hl32_to_64_S (ctx->m[(i * 2) + 0], ctx->m[(i * 2) + 1]);

  blake512_transform (ctx->h, m, t0, 0);

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void blake512_absorb (PRIVATE_AS blake512_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 x = hc_swap32_S ((fit >= 4) ? v : (v & ((1u << (fit * 8)) - 1)));

  const int word = pos / 4;
  const int off  = pos & 3;

  ctx->m[word] |= x >> (off * 8);

  if ((off + fit) > 4) ctx->m[word + 1] |= x << ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  ctx->cnt += 128;

  blake512_block (ctx, ((u64) ctx->cnt) << 3);

  if (n > fit)
  {
    ctx->m[0] = hc_swap32_S (v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void blake512_update (PRIVATE_AS blake512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    blake512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void blake512_absorb_utf16le (PRIVATE_AS blake512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  blake512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) blake512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void blake512_update_utf16le (PRIVATE_AS blake512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      blake512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    blake512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void blake512_update_global (PRIVATE_AS blake512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    blake512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void blake512_update_global_utf16le (PRIVATE_AS blake512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      blake512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    blake512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding as for the 32 bit core, but with the 1 bit before the length for BLAKE-512 only and the
// length as a big endian 128 bit number in the last 16 bytes of the 128 byte block.

DECLSPEC void blake512_final (PRIVATE_AS blake512_ctx_t *ctx)
{
  const int pos = ctx->pos;

  const u64 bits = ((u64) (ctx->cnt + (u32) pos)) << 3;

  ctx->m[pos / 4] |= 0x80000000u >> ((pos & 3) * 8);

  u64 t0 = (pos == 0) ? 0 : bits;

  if (pos >= 112)
  {
    blake512_block (ctx, bits);

    t0 = 0;
  }

  ctx->m[27] |= (ctx->dlen == 48) ? 0u : 1u;
  ctx->m[30]  = h32_from_64_S (bits);
  ctx->m[31]  = l32_from_64_S (bits);

  blake512_block (ctx, t0);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

DECLSPEC void blake512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, const u64 t0, const u64 t1)
{
  BLAKE512_TRANSFORM (u64x, hc_rotr64, BLAKE_C_V64, h, m, t0, t1);
}

DECLSPEC void blake512_init_vector (PRIVATE_AS blake512_ctx_vector_t *ctx, const int dlen)
{
  BLAKE512_IV (BLAKE_C_V64, ctx->h, dlen);

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void blake512_block_vector (PRIVATE_AS blake512_ctx_vector_t *ctx, const u64 t0)
{
  u64x m[16];

  for (u32 i = 0; i < 16; i++) m[i] = hl32_to_64 (ctx->m[(i * 2) + 0], ctx->m[(i * 2) + 1]);

  blake512_transform_vector (ctx->h, m, t0, 0);

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void blake512_absorb_vector (PRIVATE_AS blake512_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = hc_swap32 (v & mask);

  const int word = pos / 4;
  const int off  = pos & 3;

  ctx->m[word] |= x >> (off * 8);

  if ((off + fit) > 4) ctx->m[word + 1] |= x << ((4 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  ctx->cnt += 128;

  blake512_block_vector (ctx, ((u64) ctx->cnt) << 3);

  if (n > fit)
  {
    ctx->m[0] = hc_swap32 (v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void blake512_update_vector (PRIVATE_AS blake512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    blake512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void blake512_update_vector_utf16le (PRIVATE_AS blake512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    blake512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) blake512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void blake512_final_vector (PRIVATE_AS blake512_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  const u64 bits = ((u64) (ctx->cnt + (u32) pos)) << 3;

  ctx->m[pos / 4] |= 0x80000000u >> ((pos & 3) * 8);

  u64 t0 = (pos == 0) ? 0 : bits;

  if (pos >= 112)
  {
    blake512_block_vector (ctx, bits);

    t0 = 0;
  }

  ctx->m[27] |= (ctx->dlen == 48) ? 0u : 1u;
  ctx->m[30]  = make_u32x (h32_from_64_S (bits));
  ctx->m[31]  = make_u32x (l32_from_64_S (bits));

  blake512_block_vector (ctx, t0);
}
