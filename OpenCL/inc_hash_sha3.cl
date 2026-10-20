/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha3.h"

// Input is little endian words, as for MD5: the sponge absorbs bytes in memory order. A partial
// last word may hold bytes past the length, which the updates mask off.

CONSTANT_VK u64a sha3_rndc[24] =
{
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
  0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
  0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
  0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
  0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

// rho and pi of Keccak-f[1600] follow one walk through the lanes. The lane order and rotation
// counts are written out so that the state remains in registers.

#define SHA3_RHO_PI(ROTL,T,ST)                                                  \
{                                                                               \
  T t = ST[1];                                                                  \
                                                                                \
  T u;                                                                          \
                                                                                \
  u = ST[10]; ST[10] = ROTL (t,  1); t = u;                                     \
  u = ST[ 7]; ST[ 7] = ROTL (t,  3); t = u;                                     \
  u = ST[11]; ST[11] = ROTL (t,  6); t = u;                                     \
  u = ST[17]; ST[17] = ROTL (t, 10); t = u;                                     \
  u = ST[18]; ST[18] = ROTL (t, 15); t = u;                                     \
  u = ST[ 3]; ST[ 3] = ROTL (t, 21); t = u;                                     \
  u = ST[ 5]; ST[ 5] = ROTL (t, 28); t = u;                                     \
  u = ST[16]; ST[16] = ROTL (t, 36); t = u;                                     \
  u = ST[ 8]; ST[ 8] = ROTL (t, 45); t = u;                                     \
  u = ST[21]; ST[21] = ROTL (t, 55); t = u;                                     \
  u = ST[24]; ST[24] = ROTL (t,  2); t = u;                                     \
  u = ST[ 4]; ST[ 4] = ROTL (t, 14); t = u;                                     \
  u = ST[15]; ST[15] = ROTL (t, 27); t = u;                                     \
  u = ST[23]; ST[23] = ROTL (t, 41); t = u;                                     \
  u = ST[19]; ST[19] = ROTL (t, 56); t = u;                                     \
  u = ST[13]; ST[13] = ROTL (t,  8); t = u;                                     \
  u = ST[12]; ST[12] = ROTL (t, 25); t = u;                                     \
  u = ST[ 2]; ST[ 2] = ROTL (t, 43); t = u;                                     \
  u = ST[20]; ST[20] = ROTL (t, 62); t = u;                                     \
  u = ST[14]; ST[14] = ROTL (t, 18); t = u;                                     \
  u = ST[22]; ST[22] = ROTL (t, 39); t = u;                                     \
  u = ST[ 9]; ST[ 9] = ROTL (t, 61); t = u;                                     \
  u = ST[ 6]; ST[ 6] = ROTL (t, 20); t = u;                                     \
  u = ST[ 1]; ST[ 1] = ROTL (t, 44); t = u;                                     \
}

// One round: theta, rho and pi, chi and iota.

#define SHA3_ROUND(ROTL,T,ST,RC)                                                \
{                                                                               \
  const T c0 = ST[0] ^ ST[5] ^ ST[10] ^ ST[15] ^ ST[20];                        \
  const T c1 = ST[1] ^ ST[6] ^ ST[11] ^ ST[16] ^ ST[21];                        \
  const T c2 = ST[2] ^ ST[7] ^ ST[12] ^ ST[17] ^ ST[22];                        \
  const T c3 = ST[3] ^ ST[8] ^ ST[13] ^ ST[18] ^ ST[23];                        \
  const T c4 = ST[4] ^ ST[9] ^ ST[14] ^ ST[19] ^ ST[24];                        \
                                                                                \
  const T d0 = c4 ^ ROTL (c1, 1);                                               \
  const T d1 = c0 ^ ROTL (c2, 1);                                               \
  const T d2 = c1 ^ ROTL (c3, 1);                                               \
  const T d3 = c2 ^ ROTL (c4, 1);                                               \
  const T d4 = c3 ^ ROTL (c0, 1);                                               \
                                                                                \
  for (u32 j = 0; j < 25; j += 5)                                               \
  {                                                                             \
    ST[j + 0] ^= d0;                                                            \
    ST[j + 1] ^= d1;                                                            \
    ST[j + 2] ^= d2;                                                            \
    ST[j + 3] ^= d3;                                                            \
    ST[j + 4] ^= d4;                                                            \
  }                                                                             \
                                                                                \
  SHA3_RHO_PI (ROTL, T, ST)                                                     \
                                                                                \
  for (u32 j = 0; j < 25; j += 5)                                               \
  {                                                                             \
    const T b0 = ST[j + 0];                                                     \
    const T b1 = ST[j + 1];                                                     \
    const T b2 = ST[j + 2];                                                     \
    const T b3 = ST[j + 3];                                                     \
    const T b4 = ST[j + 4];                                                     \
                                                                                \
    ST[j + 0] = b0 ^ ((~b1) & b2);                                              \
    ST[j + 1] = b1 ^ ((~b2) & b3);                                              \
    ST[j + 2] = b2 ^ ((~b3) & b4);                                              \
    ST[j + 3] = b3 ^ ((~b4) & b0);                                              \
    ST[j + 4] = b4 ^ ((~b0) & b1);                                              \
  }                                                                             \
                                                                                \
  ST[0] ^= (RC);                                                                \
}

DECLSPEC void sha3_transform (PRIVATE_AS u64 *st)
{
  for (u32 r = 0; r < 24; r++)
  {
    SHA3_ROUND (hc_rotl64_S, u64, st, sha3_rndc[r]);
  }
}

DECLSPEC void sha3_init (PRIVATE_AS sha3_ctx_t *ctx, const int dlen, const u32 pad)
{
  for (u32 i = 0; i < 25; i++) ctx->st[i] = 0;

  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->rate = 200 - (2 * dlen);
  ctx->dlen = dlen;
  ctx->pad  = pad;
}

// XOR the n bytes of v into the state at the current position, starting with its low bytes.
// The bytes of v beyond n are zero. Every rate is a multiple of 8, so a block ends at a lane
// boundary. When these bytes fill the block, permute the state and use any remaining bytes
// to start the next block.

DECLSPEC void sha3_absorb (PRIVATE_AS sha3_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = ctx->rate - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64 x = (u64) (v & mask);

  const int lane = pos / 8;
  const int off  = pos & 7;

  ctx->st[lane] ^= x << (off * 8);

  if ((off + fit) > 8) ctx->st[lane + 1] ^= x >> ((8 - off) * 8);

  if (fit == room)
  {
    sha3_transform (ctx->st);

    ctx->pos = 0;

    if (n > fit)
    {
      ctx->st[0] ^= (u64) (v >> (fit * 8));

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void sha3_update (PRIVATE_AS sha3_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    sha3_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void sha3_absorb_utf16le (PRIVATE_AS sha3_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  sha3_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) sha3_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void sha3_update_utf16le (PRIVATE_AS sha3_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      sha3_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    sha3_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void sha3_update_global (PRIVATE_AS sha3_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    sha3_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void sha3_update_global_utf16le (PRIVATE_AS sha3_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      sha3_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    sha3_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding uses the padding byte at the current position and 0x80 in the last byte of the block.
// Both positions can be the same byte. A context with invalid UTF-8 input produces a digest with
// every bit flipped, so that no candidate matches it by chance.

DECLSPEC void sha3_final (PRIVATE_AS sha3_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->st[pos / 8] ^= ((u64) ctx->pad) << ((pos & 7) * 8);

  ctx->st[(ctx->rate - 1) / 8] ^= 0x8000000000000000;

  sha3_transform (ctx->st);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 8; i++) ctx->st[i] = ~ctx->st[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void sha3_transform_vector (PRIVATE_AS u64x *st)
{
  for (u32 r = 0; r < 24; r++)
  {
    SHA3_ROUND (hc_rotl64, u64x, st, sha3_rndc[r]);
  }
}

DECLSPEC void sha3_init_vector (PRIVATE_AS sha3_ctx_vector_t *ctx, const int dlen, const u32 pad)
{
  for (u32 i = 0; i < 25; i++) ctx->st[i] = 0;

  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->rate = 200 - (2 * dlen);
  ctx->dlen = dlen;
  ctx->pad  = pad;
}

DECLSPEC void sha3_absorb_vector (PRIVATE_AS sha3_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = ctx->rate - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64x x = hl32_to_64 (0, v & mask);

  const int lane = pos / 8;
  const int off  = pos & 7;

  ctx->st[lane] ^= x << (off * 8);

  if ((off + fit) > 8) ctx->st[lane + 1] ^= x >> ((8 - off) * 8);

  if (fit == room)
  {
    sha3_transform_vector (ctx->st);

    ctx->pos = 0;

    if (n > fit)
    {
      ctx->st[0] ^= hl32_to_64 (0, v >> (fit * 8));

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void sha3_update_vector (PRIVATE_AS sha3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    sha3_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void sha3_update_vector_utf16le (PRIVATE_AS sha3_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    sha3_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) sha3_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void sha3_final_vector (PRIVATE_AS sha3_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->st[pos / 8] ^= make_u64x ((u64) ctx->pad << ((pos & 7) * 8));

  ctx->st[(ctx->rate - 1) / 8] ^= make_u64x (0x8000000000000000);

  sha3_transform_vector (ctx->st);
}
