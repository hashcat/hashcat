/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "paw64.h"

// The constants are the top 64 bits of the fractional part of sqrt (p) for the first primes, with
// the low bit forced to 1 so every multiplier is odd and therefore invertible modulo 2^64. Anyone
// can regenerate them from that sentence, which is the point: they are nobody's property and they
// hide nothing.

#define PAW64_P0 0x6a09e667f3bcc909ULL // frac (sqrt (2))
#define PAW64_P1 0xbb67ae8584caa73bULL // frac (sqrt (3))
#define PAW64_P2 0x3c6ef372fe94f82bULL // frac (sqrt (5))
#define PAW64_P3 0xa54ff53a5f1d36f1ULL // frac (sqrt (7))
#define PAW64_P4 0x510e527fade682d1ULL // frac (sqrt (11))
#define PAW64_P5 0x9b05688c2b3e6c1fULL // frac (sqrt (13))

static u64 paw64_rd64 (const u8 *p)
{
  u64 v;

  memcpy (&v, p, 8);

  return v;
}

static u64 paw64_rd32 (const u8 *p)
{
  u32 v;

  memcpy (&v, p, 4);

  return (u64) v;
}

// 64x64 to 128, folded to 64 by xor, with both operands folded back in.
//
// The fold-back is not decoration. Without it a product with a zero operand is zero, so the other
// operand stops mattering: every input of length 16 whose first 8 bytes equalled P1 produced one
// digest, which is 2^64 inputs sharing an answer. Folding a and b back in means a zero operand
// leaves the other one standing.

static u64 paw64_mix (const u64 a, const u64 b)
{
  #ifdef __SIZEOF_INT128__

  const unsigned __int128 r = (unsigned __int128) a * (unsigned __int128) b;

  return (u64) r ^ (u64) (r >> 64) ^ a ^ b;

  #else

  const u64 a_lo = (u32) a, a_hi = a >> 32;
  const u64 b_lo = (u32) b, b_hi = b >> 32;

  const u64 p_ll = a_lo * b_lo;
  const u64 p_lh = a_lo * b_hi;
  const u64 p_hl = a_hi * b_lo;
  const u64 p_hh = a_hi * b_hi;

  const u64 carry = ((p_ll >> 32) + (u32) p_lh + (u32) p_hl) >> 32;

  const u64 lo = p_ll + (p_lh << 32) + (p_hl << 32);
  const u64 hi = p_hh + (p_lh >> 32) + (p_hl >> 32) + carry;

  return lo ^ hi ^ a ^ b;

  #endif
}

static u64 paw64_rotl (const u64 x, const int r)
{
  return (x << r) | (x >> (64 - r));
}

// The seed must not be interchangeable with the data. Feeding "data ^ seed" into one operand while
// the other is a constant makes the two swappable, and any two pairs with the same xor collide.
// SMHasher3's PerlinNoise keyset, which varies the data and the seed at once, collided on 15728640
// of 16777216 keys before this was added. Expanding the seed first and pinning it in the second
// operand means matching one operand no longer implies matching the pair.

static u64 paw64_seed (const u64 seed)
{
  return paw64_mix (seed ^ PAW64_P0, PAW64_P5);
}

static u64 paw64_absorb (const u64 h, const u8 *p)
{
  const u64 w0 = paw64_rd64 (p +  0);
  const u64 w1 = paw64_rd64 (p +  8);
  const u64 w2 = paw64_rd64 (p + 16);
  const u64 w3 = paw64_rd64 (p + 24);

  const u64 m0 = paw64_mix (h ^ w0 ^ PAW64_P1, h ^ w1 ^ PAW64_P2);
  const u64 m1 = paw64_mix (    w2 ^ PAW64_P3,     w3 ^ PAW64_P4);

  return m0 ^ m1 ^ PAW64_P0;
}

// The length classes below are a coverage rule, not a speed tweak. Every path reads every input
// byte at least once, and no path reads a word wider than the input it was given. Collapsing the 4
// to 7 case into the 3 byte gather was measured: it left 4 bytes of a 7 byte input unread and
// produced 25322 collisions on 128416 real candidates.

static u64 paw64_tiny (const u8 *p, const size_t len)
{
  const size_t i1 = len >> 1;
  const size_t i2 = len - 1;

  return ((u64) p[0] << 16) | ((u64) p[i1] << 8) | ((u64) p[i2]);
}

static u64 paw64_narrow (const u8 *p, const size_t len)
{
  const u64 a = paw64_rd32 (p + 0);
  const u64 b = paw64_rd32 (p + len - 4);

  return (a << 32) | b;
}

// Everything at or under one block, given an already expanded seed. One implementation, called by
// both the one shot and the streaming final, so the two cannot drift apart.

static u64 paw64_small (const u8 *p, const size_t len, const u64 s)
{
  if (len >= 8)
  {
    const size_t o1 = (len >= 16) ? 8        : 0;
    const size_t o2 = (len >= 16) ? len - 16 : 0;

    const u64 a = paw64_rd64 (p + 0);
    const u64 b = paw64_rd64 (p + o1);
    const u64 c = paw64_rd64 (p + o2);
    const u64 d = paw64_rd64 (p + len - 8);

    const u64 m0 = paw64_mix (a ^ PAW64_P1 ^ s, b ^ PAW64_P2 ^ paw64_rotl (s, 32));
    const u64 m1 = paw64_mix (c ^ PAW64_P3,     d ^ PAW64_P4);

    return m0 ^ m1 ^ PAW64_P0;
  }

  const u64 w = (len >= 4) ? paw64_narrow (p, len)
              : (len)      ? paw64_tiny   (p, len)
                           : 0;

  return paw64_mix (w ^ PAW64_P1 ^ s, PAW64_P2 ^ paw64_rotl (s, 32));
}

// Three multiply rounds, not two. With two, SMHasher3's Permutation and Seed Zeroes keysets showed
// low bit collisions at 2.7 to 3.6 times expected while the full 64 bit and the high bits sat at
// expectation, which is a finalizer that does not spread evenly across bit ranges. Four variants
// were measured and this was the only one that cleared both keysets. The extra round costs nothing
// that can be measured on a candidate.

static u64 paw64_fin (u64 h, const u64 total)
{
  h ^= total;

  h ^= h >> 32;
  h *= PAW64_P3;
  h ^= h >> 29;
  h *= PAW64_P5;
  h ^= h >> 32;
  h *= PAW64_P4;
  h ^= h >> 29;

  return h;
}

void paw64_init (paw64_ctx_t *ctx, const u64 seed)
{
  ctx->seed    = paw64_seed (seed);
  ctx->h       = ctx->seed ^ PAW64_P0;
  ctx->total   = 0;
  ctx->buf_len = 0;
}

void paw64_update (paw64_ctx_t *ctx, const void *buf, const size_t len)
{
  const u8 *p = (const u8 *) buf;

  size_t left = len;

  ctx->total += (u64) len;

  if (ctx->buf_len)
  {
    const size_t want = PAW64_BLOCK - ctx->buf_len;
    const size_t take = (left < want) ? left : want;

    memcpy (ctx->buf + ctx->buf_len, p, take);

    ctx->buf_len += (u32) take;
    p            += take;
    left         -= take;

    if (ctx->buf_len < PAW64_BLOCK) return;

    ctx->h = paw64_absorb (ctx->h, ctx->buf);

    ctx->buf_len = 0;
  }

  while (left >= PAW64_BLOCK)
  {
    ctx->h = paw64_absorb (ctx->h, p);

    p    += PAW64_BLOCK;
    left -= PAW64_BLOCK;
  }

  if (left)
  {
    memcpy (ctx->buf, p, left);

    ctx->buf_len = (u32) left;
  }
}

u64 paw64_final (const paw64_ctx_t *ctx)
{
  u64 h = ctx->h;

  if (ctx->total < PAW64_BLOCK)
  {
    h = paw64_small (ctx->buf, (size_t) ctx->total, ctx->seed);
  }
  else if (ctx->buf_len)
  {
    u8 tail[PAW64_BLOCK];

    memset (tail, 0, sizeof (tail));
    memcpy (tail, ctx->buf, ctx->buf_len);

    h = paw64_absorb (h, tail);
  }

  const u64 digest = paw64_fin (h, ctx->total);

  return digest;
}

// One shot. The same constants, the same rounds and the same finalizer as the streaming form: it
// reads the caller's buffer where the streaming form reads its own. Staging a short input through
// the context needs a memcpy with a runtime size, which measured 3 to 4 times the cost of the hash
// itself, so the two paths are held equal by a test over every length and every split point rather
// than by one calling the other.

u64 paw64 (const void *buf, const size_t len, const u64 seed)
{
  const u8 *p = (const u8 *) buf;

  const u64 s = paw64_seed (seed);

  if (len < PAW64_BLOCK)
  {
    const u64 digest = paw64_fin (paw64_small (p, len, s), (u64) len);

    return digest;
  }

  u64 h = s ^ PAW64_P0;

  size_t left = len;

  while (left >= PAW64_BLOCK)
  {
    h = paw64_absorb (h, p);

    p    += PAW64_BLOCK;
    left -= PAW64_BLOCK;
  }

  // The only copy in the design, and only for an input longer than one block. Everything at or
  // under PAW64_BLOCK, which is every realistic candidate, reads the caller's buffer directly.

  if (left)
  {
    u8 tail[PAW64_BLOCK];

    memset (tail, 0, sizeof (tail));
    memcpy (tail, p, left);

    h = paw64_absorb (h, tail);
  }

  const u64 digest = paw64_fin (h, (u64) len);

  return digest;
}
