/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_skein512.h"

// Input is little endian words, as for MD5: Skein reads its blocks as little endian 64 bit words.
// A partial last word may hold bytes past the length, which the updates mask off.

// The chaining values after the configuration block, for digests of 28, 32, 48 and 64 bytes

CONSTANT_VK u64a skein512_iv[4][8] =
{
  { 0xccd0616248677224, 0xcba65cf3a92339ef, 0x8ccd69d652ff4b64, 0x398aed7b3ab890b4,
    0x0f59d1b1457d2bd0, 0x6776fe6575d4eb3d, 0x99fbc70e997413e9, 0x9e2cfccfe1c41ef7 },
  { 0xccd044a12fdb3e13, 0xe83590301a79a9eb, 0x55aea0614f816e6f, 0x2a2767a4ae9b94db,
    0xec06025e74dd7683, 0xe7a436cdc4746251, 0xc36fbaf9393ad185, 0x3eedba1833edfc13 },
  { 0xa3f6c6bf3a75ef5f, 0xb0fef9ccfd84faa4, 0x9d77dd663d770cfe, 0xd798cbf3b468fdda,
    0x1bc4a6668a0e4465, 0x7ed7d434e5807407, 0x548fc1acd4ec44d6, 0x266e17546aa18ff8 },
  { 0x4903adff749c51ce, 0x0d95de399746df03, 0x8fd1934127c79bce, 0x9a255629ff352cb1,
    0x5db62599df6ca7b0, 0xeabe394ca9d5c3f4, 0x991112c71a75b523, 0xae18a40b660fcc33 },
};

// The tweak's second word: the block type in bits 56 to 61, and the flags for the first and the
// last block of a UBI call. Its first word counts the bytes up to the end of the block.

#define SKEIN512_T_MSG   0x3000000000000000
#define SKEIN512_T_OUT   0x3f00000000000000
#define SKEIN512_T_FIRST 0x4000000000000000
#define SKEIN512_T_FINAL 0x8000000000000000

#define SKEIN512_KS_PARITY 0x1bd11bdaa9fc1a22

#define SKEIN512_MIX(ROTL,X0,X1,RC)                                             \
{                                                                               \
  X0 += X1;                                                                     \
  X1  = ROTL (X1, RC) ^ X0;                                                     \
}

#define SKEIN512_MIX8(ROTL,P0,P1,P2,P3,P4,P5,P6,P7,R0,R1,R2,R3)                 \
{                                                                               \
  SKEIN512_MIX (ROTL, P0, P1, R0);                                              \
  SKEIN512_MIX (ROTL, P2, P3, R1);                                              \
  SKEIN512_MIX (ROTL, P4, P5, R2);                                              \
  SKEIN512_MIX (ROTL, P6, P7, R3);                                              \
}

// Subkey S of the Threefish-512 key schedule, from the 9 key words and the 3 tweak words.

#define SKEIN512_ADDKEY(S)                                                      \
{                                                                               \
  p0 += k[((S) + 0) % 9];                                                       \
  p1 += k[((S) + 1) % 9];                                                       \
  p2 += k[((S) + 2) % 9];                                                       \
  p3 += k[((S) + 3) % 9];                                                       \
  p4 += k[((S) + 4) % 9];                                                       \
  p5 += k[((S) + 5) % 9] + t[((S) + 0) % 3];                                    \
  p6 += k[((S) + 6) % 9] + t[((S) + 1) % 3];                                    \
  p7 += k[((S) + 7) % 9] + (u64) (S);                                           \
}

// One UBI block: Threefish-512 with the chaining value as its key encrypts the block M, and the
// result XOR M is the new chaining value. 72 rounds, a subkey every 4 rounds, the word permutation
// written out in the order of the MIX8 arguments. C turns a constant into the type T.

#define SKEIN512_TRANSFORM(T,ROTL,C,H,M,T0,T1)                                  \
{                                                                               \
  T k[9];                                                                       \
                                                                                \
  k[0] = H[0];                                                                  \
  k[1] = H[1];                                                                  \
  k[2] = H[2];                                                                  \
  k[3] = H[3];                                                                  \
  k[4] = H[4];                                                                  \
  k[5] = H[5];                                                                  \
  k[6] = H[6];                                                                  \
  k[7] = H[7];                                                                  \
  k[8] = k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4] ^ k[5] ^ k[6] ^ k[7]                  \
       ^ C (SKEIN512_KS_PARITY);                                                \
                                                                                \
  u64 t[3];                                                                     \
                                                                                \
  t[0] = (T0);                                                                  \
  t[1] = (T1);                                                                  \
  t[2] = (T0) ^ (T1);                                                           \
                                                                                \
  T p0 = M[0];                                                                  \
  T p1 = M[1];                                                                  \
  T p2 = M[2];                                                                  \
  T p3 = M[3];                                                                  \
  T p4 = M[4];                                                                  \
  T p5 = M[5];                                                                  \
  T p6 = M[6];                                                                  \
  T p7 = M[7];                                                                  \
                                                                                \
  for (u32 s = 0; s < 18; s += 2)                                               \
  {                                                                             \
    SKEIN512_ADDKEY (s + 0);                                                    \
                                                                                \
    SKEIN512_MIX8 (ROTL, p0, p1, p2, p3, p4, p5, p6, p7, 46, 36, 19, 37);       \
    SKEIN512_MIX8 (ROTL, p2, p1, p4, p7, p6, p5, p0, p3, 33, 27, 14, 42);       \
    SKEIN512_MIX8 (ROTL, p4, p1, p6, p3, p0, p5, p2, p7, 17, 49, 36, 39);       \
    SKEIN512_MIX8 (ROTL, p6, p1, p0, p7, p2, p5, p4, p3, 44,  9, 54, 56);       \
                                                                                \
    SKEIN512_ADDKEY (s + 1);                                                    \
                                                                                \
    SKEIN512_MIX8 (ROTL, p0, p1, p2, p3, p4, p5, p6, p7, 39, 30, 34, 24);       \
    SKEIN512_MIX8 (ROTL, p2, p1, p4, p7, p6, p5, p0, p3, 13, 50, 10, 17);       \
    SKEIN512_MIX8 (ROTL, p4, p1, p6, p3, p0, p5, p2, p7, 25, 29, 39, 43);       \
    SKEIN512_MIX8 (ROTL, p6, p1, p0, p7, p2, p5, p4, p3,  8, 35, 56, 22);       \
  }                                                                             \
                                                                                \
  SKEIN512_ADDKEY (18);                                                         \
                                                                                \
  H[0] = M[0] ^ p0;                                                             \
  H[1] = M[1] ^ p1;                                                             \
  H[2] = M[2] ^ p2;                                                             \
  H[3] = M[3] ^ p3;                                                             \
  H[4] = M[4] ^ p4;                                                             \
  H[5] = M[5] ^ p5;                                                             \
  H[6] = M[6] ^ p6;                                                             \
  H[7] = M[7] ^ p7;                                                             \
}

#define SKEIN512_C_S(V) (V)
#define SKEIN512_C_V(V) make_u64x (V)

DECLSPEC int skein512_iv_index (const int dlen)
{
  if (dlen == 28) return 0;
  if (dlen == 32) return 1;
  if (dlen == 48) return 2;

  return 3;
}

DECLSPEC void skein512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m, const u64 t0, const u64 t1)
{
  SKEIN512_TRANSFORM (u64, hc_rotl64_S, SKEIN512_C_S, h, m, t0, t1);
}

DECLSPEC void skein512_init (PRIVATE_AS skein512_ctx_t *ctx, const int dlen)
{
  const int iv = skein512_iv_index (dlen);

  for (u32 i = 0; i < 8; i++) ctx->h[i] = skein512_iv[iv][i];
  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// Process the full block in m. Only skein512_absorb () calls this, once more input follows, so
// the block is never the last one.

DECLSPEC void skein512_block (PRIVATE_AS skein512_ctx_t *ctx)
{
  ctx->cnt += 64;

  const u64 t1 = (ctx->cnt == 64) ? (SKEIN512_T_MSG | SKEIN512_T_FIRST) : SKEIN512_T_MSG;

  skein512_transform (ctx->h, ctx->m, ctx->cnt, t1);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. A full block is processed first if more bytes arrive for it.

DECLSPEC void skein512_absorb (PRIVATE_AS skein512_ctx_t *ctx, const u32 v, const int n)
{
  if (ctx->pos == 64) skein512_block (ctx);

  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64 x = (u64) (v & mask);

  const int lane = pos / 8;
  const int off  = pos & 7;

  ctx->m[lane] |= x << (off * 8);

  if ((off + fit) > 8) ctx->m[lane + 1] |= x >> ((8 - off) * 8);

  ctx->pos = pos + fit;

  if (fit == n) return;

  skein512_block (ctx);

  ctx->m[0] = (u64) (v >> (fit * 8));

  ctx->pos = n - fit;
}

DECLSPEC void skein512_update (PRIVATE_AS skein512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    skein512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void skein512_absorb_utf16le (PRIVATE_AS skein512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  skein512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) skein512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void skein512_update_utf16le (PRIVATE_AS skein512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      skein512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    skein512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void skein512_update_global (PRIVATE_AS skein512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    skein512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void skein512_update_global_utf16le (PRIVATE_AS skein512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      skein512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    skein512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The last block, zero padded and possibly empty, goes through UBI with the final flag. Then the
// output UBI encrypts the counter 0 as one 8 byte block. A context with invalid UTF-8 input
// produces a digest with every bit flipped, so that no candidate matches it by chance.

DECLSPEC void skein512_final (PRIVATE_AS skein512_ctx_t *ctx)
{
  const u64 t0 = ctx->cnt + (u64) ctx->pos;

  const u64 t1 = (ctx->cnt == 0) ? (SKEIN512_T_MSG | SKEIN512_T_FIRST | SKEIN512_T_FINAL) : (SKEIN512_T_MSG | SKEIN512_T_FINAL);

  skein512_transform (ctx->h, ctx->m, t0, t1);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  skein512_transform (ctx->h, ctx->m, 8, SKEIN512_T_OUT | SKEIN512_T_FIRST | SKEIN512_T_FINAL);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 8; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void skein512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, const u64 t0, const u64 t1)
{
  SKEIN512_TRANSFORM (u64x, hc_rotl64, SKEIN512_C_V, h, m, t0, t1);
}

DECLSPEC void skein512_init_vector (PRIVATE_AS skein512_ctx_vector_t *ctx, const int dlen)
{
  const int iv = skein512_iv_index (dlen);

  for (u32 i = 0; i < 8; i++) ctx->h[i] = make_u64x (skein512_iv[iv][i]);
  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void skein512_block_vector (PRIVATE_AS skein512_ctx_vector_t *ctx)
{
  ctx->cnt += 64;

  const u64 t1 = (ctx->cnt == 64) ? (SKEIN512_T_MSG | SKEIN512_T_FIRST) : SKEIN512_T_MSG;

  skein512_transform_vector (ctx->h, ctx->m, ctx->cnt, t1);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void skein512_absorb_vector (PRIVATE_AS skein512_ctx_vector_t *ctx, const u32x v, const int n)
{
  if (ctx->pos == 64) skein512_block_vector (ctx);

  const int pos = ctx->pos;

  const int room = 64 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64x x = hl32_to_64 (0, v & mask);

  const int lane = pos / 8;
  const int off  = pos & 7;

  ctx->m[lane] |= x << (off * 8);

  if ((off + fit) > 8) ctx->m[lane + 1] |= x >> ((8 - off) * 8);

  ctx->pos = pos + fit;

  if (fit == n) return;

  skein512_block_vector (ctx);

  ctx->m[0] = hl32_to_64 (0, v >> (fit * 8));

  ctx->pos = n - fit;
}

DECLSPEC void skein512_update_vector (PRIVATE_AS skein512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    skein512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void skein512_update_vector_utf16le (PRIVATE_AS skein512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    skein512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) skein512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void skein512_final_vector (PRIVATE_AS skein512_ctx_vector_t *ctx)
{
  const u64 t0 = ctx->cnt + (u64) ctx->pos;

  const u64 t1 = (ctx->cnt == 0) ? (SKEIN512_T_MSG | SKEIN512_T_FIRST | SKEIN512_T_FINAL) : (SKEIN512_T_MSG | SKEIN512_T_FINAL);

  skein512_transform_vector (ctx->h, ctx->m, t0, t1);

  for (u32 i = 0; i < 8; i++) ctx->m[i] = 0;

  skein512_transform_vector (ctx->h, ctx->m, 8, SKEIN512_T_OUT | SKEIN512_T_FIRST | SKEIN512_T_FINAL);
}
