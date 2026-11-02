/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_simd.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off. The shared helpers use the simdh_ prefix, because Metal names
// built-in functions simd_*.

// The powers of 41 modulo 257. 41 has order 256, so the table holds the roots of unity for both
// NTT sizes, and the constants that are added to the NTT output.

CONSTANT_VK u32a simdh_alpha[256] =
{
    1,  41, 139,  45,  46,  87, 226,  14,  60, 147, 116, 130, 190,  80, 196,  69,
    2,  82,  21,  90,  92, 174, 195,  28, 120,  37, 232,   3, 123, 160, 135, 138,
    4, 164,  42, 180, 184,  91, 133,  56, 240,  74, 207,   6, 246,  63,  13,  19,
    8,  71,  84, 103, 111, 182,   9, 112, 223, 148, 157,  12, 235, 126,  26,  38,
   16, 142, 168, 206, 222, 107,  18, 224, 189,  39,  57,  24, 213, 252,  52,  76,
   32,  27,  79, 155, 187, 214,  36, 191, 121,  78, 114,  48, 169, 247, 104, 152,
   64,  54, 158,  53, 117, 171,  72, 125, 242, 156, 228,  96,  81, 237, 208,  47,
  128, 108,  59, 106, 234,  85, 144, 250, 227,  55, 199, 192, 162, 217, 159,  94,
  256, 216, 118, 212, 211, 170,  31, 243, 197, 110, 141, 127,  67, 177,  61, 188,
  255, 175, 236, 167, 165,  83,  62, 229, 137, 220,  25, 254, 134,  97, 122, 119,
  253,  93, 215,  77,  73, 166, 124, 201,  17, 183,  50, 251,  11, 194, 244, 238,
  249, 186, 173, 154, 146,  75, 248, 145,  34, 109, 100, 245,  22, 131, 231, 219,
  241, 115,  89,  51,  35, 150, 239,  33,  68, 218, 200, 233,  44,   5, 205, 181,
  225, 230, 178, 102,  70,  43, 221,  66, 136, 179, 143, 209,  88,  10, 153, 105,
  193, 203,  99, 204, 140,  86, 185, 132,  15, 101,  29, 161, 176,  20,  49, 210,
  129, 149, 198, 151,  23, 172, 113,   7,  30, 202,  58,  65,  95,  40,  98, 163
};

// The group of expanded message words each step reads, and the rotation amounts of the 4 rounds

CONSTANT_VK u32a simdh_wsp[32] =
{
   4,  6,  0,  2,  7,  5,  3,  1,
  15, 11, 12,  8,  9, 13, 10, 14,
  17, 18, 23, 20, 22, 21, 16, 19,
  30, 24, 25, 31, 27, 29, 28, 26
};

CONSTANT_VK u32a simdh_rot[4][4] =
{
  {  3, 23, 17, 27 },
  { 28, 19, 22,  7 },
  { 29,  9, 15,  5 },
  {  4, 13, 10, 25 },
};

// The lane permutation of each step as an XOR mask, which repeats every 3 steps in the small
// function and every 7 steps in the big one. The eighth word is never read. CUDA packs constant
// tables back to back, and the host clears generic_constant with 16 byte stores, so every table in
// front of it has to fill a multiple of 16 bytes.

CONSTANT_VK u32a simdh_pp8[8] = { 1, 6, 2, 3, 5, 7, 4, 0 };

#define SIMDH_PX4(t) (((t) % 3) + 1)
#define SIMDH_PX8(t) (simdh_pp8[(t) % 7])

// The IVs of SIMD-224 and SIMD-256, and of SIMD-384 and SIMD-512

CONSTANT_VK u32a simd256_iv[2][16] =
{
  {
    0x33586e9f, 0x12fff033, 0xb2d9f64d, 0x6f8fea53,
    0xde943106, 0x2742e439, 0x4fbab5ac, 0x62b9ff96,
    0x22e7b0af, 0xc862b3a8, 0x33e00cdc, 0x236b86a6,
    0xf64ae77c, 0xfa373b76, 0x7dc1ee5b, 0x7fb29ce8,
  },
  {
    0x4d567983, 0x07190ba9, 0x8474577b, 0x39d726e9,
    0xaaf3d925, 0x3ee20b03, 0xafd5e751, 0xc96006d3,
    0xc2c2ba14, 0x49b3bcb4, 0xf67caf46, 0x668626c9,
    0xe2eaa8d2, 0x1ff47833, 0xd0c661a5, 0x55693de1,
  },
};

CONSTANT_VK u32a simd512_iv[2][32] =
{
  {
    0x8a36eebc, 0x94a3bd90, 0xd1537b83, 0xb25b070b,
    0xf463f1b5, 0xb6f81e20, 0x0055c339, 0xb4d144d1,
    0x7360ca61, 0x18361a03, 0x17dcb4b9, 0x3414c45a,
    0xa699a9d2, 0xe39e9664, 0x468bfe77, 0x51d062f8,
    0xb9e3bfe8, 0x63bece2a, 0x8fe506b9, 0xf8cc4ac2,
    0x7ae11542, 0xb1aadda1, 0x64b06794, 0x28d2f462,
    0xe64071ec, 0x1deb91a8, 0x8ac8db23, 0x3f782ab5,
    0x039b5cb8, 0x71ddd962, 0xfade2cea, 0x1416df71,
  },
  {
    0x0ba16b95, 0x72f999ad, 0x9fecc2ae, 0xba3264fc,
    0x5e894929, 0x8e9f30e5, 0x2f1daa37, 0xf0f2c558,
    0xac506643, 0xa90635a5, 0xe25b878b, 0xaab7878f,
    0x88817f7a, 0x0a02892b, 0x559a7550, 0x598f657e,
    0x7eef60a1, 0x6b70e3e8, 0x9c1714d1, 0xb958e2a8,
    0xab02675e, 0xed1c014f, 0xcd8d65bb, 0xfdb7a257,
    0x09254899, 0xd699c7bc, 0x9019b6dc, 0x2b9022e4,
    0x8fa14956, 0x21bf9bd3, 0xb94d0943, 0x6ffddc22,
  },
};

#define SIMDH_IF(x,y,z)  ((((y) ^ (z)) & (x)) ^ (z))
#define SIMDH_MAJ(x,y,z) (((x) & (y)) | (((x) | (y)) & (z)))

// The NTT over Z_257 of the NB message bytes in M, zero padded to 2 * NB points, in natural order:
// Q[i] is the sum of byte j times w^(i * j), where w = 41^(128 / NB) is a primitive root of unity
// of order 2 * NB. The radix-2 transform takes its input in bit reversed order, which puts the
// padding in the odd positions, so its first stage only copies each byte to 2 positions. The
// arithmetic is unsigned, so that the vector flavor can use it: a product is reduced to 258..769,
// and the difference adds 771, a multiple of 257. The results stay below 5700.

#define SIMDH_NTT(T,Q,M,NB,BITS)                                                \
{                                                                               \
  for (u32 i = 0; i < (NB); i++)                                                \
  {                                                                             \
    const u32 j = simdh_rev (i, (BITS));                                        \
                                                                                \
    const T b = ((M)[j / 4] >> ((j & 3) * 8)) & 0xff;                           \
                                                                                \
    (Q)[2 * i + 0] = b;                                                         \
    (Q)[2 * i + 1] = b;                                                         \
  }                                                                             \
                                                                                \
  for (u32 len = 4; len <= 2 * (NB); len *= 2)                                  \
  {                                                                             \
    const u32 hl = len / 2;                                                     \
    const u32 ts = 256 / len;                                                   \
                                                                                \
    for (u32 k = 0; k < 2 * (NB); k += len)                                     \
    {                                                                           \
      for (u32 i = 0; i < hl; i++)                                              \
      {                                                                         \
        const T u = (Q)[k + i];                                                 \
        const T x = (Q)[k + i + hl] * simdh_alpha[i * ts];                      \
        const T y = (x & 0xffff) + (x >> 16);                                   \
        const T v = ((y & 0xff) + 514) - (y >> 8);                              \
                                                                                \
        (Q)[k + i]      = u + v;                                                \
        (Q)[k + i + hl] = (u + 771) - v;                                        \
      }                                                                         \
    }                                                                           \
  }                                                                             \
}

// One step on the NL lanes of the state S, which holds A, B, C and D with NL words each. The
// permutation PX picks the rotated A of another lane for each lane.

#define SIMDH_STEP(T,ROTL,NL,S,W,MAJ,R,RS,PX)                                   \
{                                                                               \
  T ta[NL];                                                                     \
                                                                                \
  for (u32 n = 0; n < (NL); n++) ta[n] = ROTL ((S)[n], (R));                    \
                                                                                \
  for (u32 n = 0; n < (NL); n++)                                                \
  {                                                                             \
    const T a = (S)[0 * (NL) + n];                                              \
    const T b = (S)[1 * (NL) + n];                                              \
    const T c = (S)[2 * (NL) + n];                                              \
    const T d = (S)[3 * (NL) + n];                                              \
                                                                                \
    const T f = ((MAJ) != 0) ? SIMDH_MAJ (a, b, c) : SIMDH_IF (a, b, c);        \
                                                                                \
    (S)[0 * (NL) + n] = ROTL (d + (W)[n] + f, (RS)) + ta[n ^ (PX)];             \
    (S)[1 * (NL) + n] = ta[n];                                                  \
    (S)[2 * (NL) + n] = b;                                                      \
    (S)[3 * (NL) + n] = c;                                                      \
  }                                                                             \
}

// The compression function with NL lanes, 4 for SIMD-256 and 8 for SIMD-512. Output i of the NTT
// plus the constant 41^(E1 * i), and 41^(E2 * i) as well for the final block, is reduced to
// -128..128, kept as u32 in two's complement. The 4 rounds of 8 steps read pairs of these values
// multiplied by 185 or 233 as their message words. 4 more steps feed the old state forward. BITS
// is log2 of the block size.

#define SIMDH_TRANSFORM(T,ROTL,NL,PX,H,M,LAST,E1,E2,BITS)                       \
{                                                                               \
  T q[32 * (NL)];                                                               \
                                                                                \
  SIMDH_NTT (T, q, M, 16 * (NL), BITS);                                         \
                                                                                \
  for (u32 i = 0; i < 32 * (NL); i++)                                           \
  {                                                                             \
    u32 e = simdh_alpha[(i * (E1)) & 255];                                      \
                                                                                \
    if ((LAST) != 0) e += simdh_alpha[(i * (E2)) & 255];                        \
                                                                                \
    const T y = q[i] + e;                                                       \
                                                                                \
    q[i] = y - ((((y + 128) * 65281) >> 24) * 257);                             \
  }                                                                             \
                                                                                \
  T s[4 * (NL)];                                                                \
                                                                                \
  for (u32 i = 0; i < 4 * (NL); i++) s[i] = (H)[i] ^ (M)[i];                    \
                                                                                \
  for (u32 t = 0; t < 32; t++)                                                  \
  {                                                                             \
    const u32 r = t / 8;                                                        \
                                                                                \
    u32 g  = simdh_wsp[t] * 2 * (NL);                                           \
    u32 hd = 1;                                                                 \
    u32 mm = 185;                                                               \
                                                                                \
    if (r == 2)                                                                 \
    {                                                                           \
      g  = g - (32 * (NL));                                                     \
      hd = 16 * (NL);                                                           \
      mm = 233;                                                                 \
    }                                                                           \
                                                                                \
    if (r == 3)                                                                 \
    {                                                                           \
      g  = g - (48 * (NL)) + 1;                                                 \
      hd = 16 * (NL);                                                           \
      mm = 233;                                                                 \
    }                                                                           \
                                                                                \
    T w[NL];                                                                    \
                                                                                \
    for (u32 n = 0; n < (NL); n++)                                              \
    {                                                                           \
      const T lo = q[g + 2 * n] * mm;                                           \
      const T hi = q[g + 2 * n + hd] * mm;                                      \
                                                                                \
      w[n] = (lo & 0xffff) + (hi << 16);                                        \
    }                                                                           \
                                                                                \
    const u32 r0 = simdh_rot[r][(t + 0) & 3];                                   \
    const u32 r1 = simdh_rot[r][(t + 1) & 3];                                   \
                                                                                \
    SIMDH_STEP (T, ROTL, NL, s, w, t & 4, r0, r1, PX (t));                      \
  }                                                                             \
                                                                                \
  for (u32 t = 32; t < 36; t++)                                                 \
  {                                                                             \
    T w[NL];                                                                    \
                                                                                \
    for (u32 n = 0; n < (NL); n++) w[n] = (H)[(t - 32) * (NL) + n];             \
                                                                                \
    const u32 r0 = simdh_rot[3][(t + 0) & 3];                                   \
    const u32 r1 = simdh_rot[3][(t + 1) & 3];                                   \
                                                                                \
    SIMDH_STEP (T, ROTL, NL, s, w, 0, r0, r1, PX (t));                          \
  }                                                                             \
                                                                                \
  for (u32 i = 0; i < 4 * (NL); i++) (H)[i] = s[i];                             \
}

DECLSPEC u32 simdh_rev (const u32 v, const u32 bits)
{
  u32 r = 0;

  for (u32 k = 0; k < bits; k++) r |= ((v >> k) & 1) << (bits - 1 - k);

  return r;
}

// The transforms are kept out of line on CPUs, see SIMDH_NOINLINE in inc_hash_simd.h.

DECLSPEC SIMDH_NOINLINE void simd256_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m, const int last)
{
  SIMDH_TRANSFORM (u32, hc_rotl32_S, 4, SIMDH_PX4, h, m, last, 254, 250, 6);
}

DECLSPEC void simd256_init (PRIVATE_AS simd256_ctx_t *ctx, const int dlen)
{
  const u32 iv = (dlen == 28) ? 0 : 1;

  for (u32 i = 0; i < 16; i++) ctx->h[i] = simd256_iv[iv][i];
  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, compress it and use any
// remaining bytes to start the next block.

DECLSPEC void simd256_absorb (PRIVATE_AS simd256_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

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

  simd256_transform (ctx->h, ctx->m, 0);

  ctx->cnt++;

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void simd256_update (PRIVATE_AS simd256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    simd256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void simd256_absorb_utf16le (PRIVATE_AS simd256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  simd256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) simd256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void simd256_update_utf16le (PRIVATE_AS simd256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      simd256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    simd256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void simd256_update_global (PRIVATE_AS simd256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    simd256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void simd256_update_global_utf16le (PRIVATE_AS simd256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      simd256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    simd256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// A partial last block is zero padded and compressed as usual. The final block holds the message
// length in bits and uses the second set of NTT constants. A context with invalid UTF-8 input
// produces a digest with every bit flipped, so that no candidate matches it by chance.

DECLSPEC void simd256_final (PRIVATE_AS simd256_ctx_t *ctx)
{
  if (ctx->pos > 0) simd256_transform (ctx->h, ctx->m, 0);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->m[0] = (ctx->cnt << 9) + ((u32) ctx->pos << 3);
  ctx->m[1] = ctx->cnt >> 23;

  simd256_transform (ctx->h, ctx->m, 1);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 16; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC SIMDH_NOINLINE void simd256_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m, const int last)
{
  SIMDH_TRANSFORM (u32x, hc_rotl32, 4, SIMDH_PX4, h, m, last, 254, 250, 6);
}

DECLSPEC void simd256_init_vector (PRIVATE_AS simd256_ctx_vector_t *ctx, const int dlen)
{
  const u32 iv = (dlen == 28) ? 0 : 1;

  for (u32 i = 0; i < 16; i++) ctx->h[i] = make_u32x (simd256_iv[iv][i]);
  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void simd256_absorb_vector (PRIVATE_AS simd256_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 64 - pos;

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

  simd256_transform_vector (ctx->h, ctx->m, 0);

  ctx->cnt++;

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void simd256_update_vector (PRIVATE_AS simd256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    simd256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void simd256_update_vector_utf16le (PRIVATE_AS simd256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    simd256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) simd256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void simd256_final_vector (PRIVATE_AS simd256_ctx_vector_t *ctx)
{
  if (ctx->pos > 0) simd256_transform_vector (ctx->h, ctx->m, 0);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->m[0] = make_u32x ((ctx->cnt << 9) + ((u32) ctx->pos << 3));
  ctx->m[1] = make_u32x (ctx->cnt >> 23);

  simd256_transform_vector (ctx->h, ctx->m, 1);
}

// SIMD-384 and SIMD-512, the same code with 8 lanes and a 128 byte block

DECLSPEC SIMDH_NOINLINE void simd512_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m, const int last)
{
  SIMDH_TRANSFORM (u32, hc_rotl32_S, 8, SIMDH_PX8, h, m, last, 255, 253, 7);
}

DECLSPEC void simd512_init (PRIVATE_AS simd512_ctx_t *ctx, const int dlen)
{
  const u32 iv = (dlen == 48) ? 0 : 1;

  for (u32 i = 0; i < 32; i++) ctx->h[i] = simd512_iv[iv][i];
  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void simd512_absorb (PRIVATE_AS simd512_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

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

  simd512_transform (ctx->h, ctx->m, 0);

  ctx->cnt++;

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void simd512_update (PRIVATE_AS simd512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    simd512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void simd512_absorb_utf16le (PRIVATE_AS simd512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  simd512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) simd512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void simd512_update_utf16le (PRIVATE_AS simd512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      simd512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    simd512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void simd512_update_global (PRIVATE_AS simd512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    simd512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void simd512_update_global_utf16le (PRIVATE_AS simd512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      simd512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    simd512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void simd512_final (PRIVATE_AS simd512_ctx_t *ctx)
{
  if (ctx->pos > 0) simd512_transform (ctx->h, ctx->m, 0);

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->m[0] = (ctx->cnt << 10) + ((u32) ctx->pos << 3);
  ctx->m[1] = ctx->cnt >> 22;

  simd512_transform (ctx->h, ctx->m, 1);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 32; i++) ctx->h[i] = ~ctx->h[i];
  }
}

DECLSPEC SIMDH_NOINLINE void simd512_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m, const int last)
{
  SIMDH_TRANSFORM (u32x, hc_rotl32, 8, SIMDH_PX8, h, m, last, 255, 253, 7);
}

DECLSPEC void simd512_init_vector (PRIVATE_AS simd512_ctx_vector_t *ctx, const int dlen)
{
  const u32 iv = (dlen == 48) ? 0 : 1;

  for (u32 i = 0; i < 32; i++) ctx->h[i] = make_u32x (simd512_iv[iv][i]);
  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void simd512_absorb_vector (PRIVATE_AS simd512_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

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

  simd512_transform_vector (ctx->h, ctx->m, 0);

  ctx->cnt++;

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->pos = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void simd512_update_vector (PRIVATE_AS simd512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    simd512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void simd512_update_vector_utf16le (PRIVATE_AS simd512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    simd512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) simd512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void simd512_final_vector (PRIVATE_AS simd512_ctx_vector_t *ctx)
{
  if (ctx->pos > 0) simd512_transform_vector (ctx->h, ctx->m, 0);

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->m[0] = make_u32x ((ctx->cnt << 10) + ((u32) ctx->pos << 3));
  ctx->m[1] = make_u32x (ctx->cnt >> 22);

  simd512_transform_vector (ctx->h, ctx->m, 1);
}
