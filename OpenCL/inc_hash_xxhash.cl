/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_xxhash.h"

// Input arrives as little endian 32 bit words. Every read the algorithms make starts at a multiple
// of 4 bytes, so a 64 bit lane is two whole words and only the last few bytes are taken apart. Bytes
// past len are never read, which leaves the padding of a buffer free to hold anything.

DECLSPEC u64 xxh64_round (u64 acc, const u64 lane)
{
  acc += lane * XXH64_PRIME_2;
  acc  = hc_rotl64_S (acc, 31);
  acc *= XXH64_PRIME_1;

  return acc;
}

DECLSPEC u64 xxh64_merge (u64 acc, const u64 lane)
{
  acc ^= xxh64_round (0, lane);
  acc  = (acc * XXH64_PRIME_1) + XXH64_PRIME_4;

  return acc;
}

DECLSPEC u64 xxh64_converge (const u64 v1, const u64 v2, const u64 v3, const u64 v4)
{
  u64 h = hc_rotl64_S (v1, 1) + hc_rotl64_S (v2, 7) + hc_rotl64_S (v3, 12) + hc_rotl64_S (v4, 18);

  h = xxh64_merge (h, v1);
  h = xxh64_merge (h, v2);
  h = xxh64_merge (h, v3);
  h = xxh64_merge (h, v4);

  return h;
}

// The bytes from pos to len that did not fill a whole stripe, then the final mix.

DECLSPEC u64 xxh64_tail (u64 h, PRIVATE_AS const u32 *w, u32 pos, const u32 len)
{
  for (; (pos + 8) <= len; pos += 8)
  {
    const u32 i = pos / 4;

    h ^= xxh64_round (0, hl32_to_64_S (w[i + 1], w[i + 0]));
    h  = (hc_rotl64_S (h, 27) * XXH64_PRIME_1) + XXH64_PRIME_4;
  }

  if ((pos + 4) <= len)
  {
    h ^= (u64) w[pos / 4] * XXH64_PRIME_1;
    h  = (hc_rotl64_S (h, 23) * XXH64_PRIME_2) + XXH64_PRIME_3;

    pos += 4;
  }

  for (; pos < len; pos++)
  {
    const u32 c = (w[pos / 4] >> ((pos & 3) * 8)) & 0xff;

    h ^= (u64) c * XXH64_PRIME_5;
    h  = hc_rotl64_S (h, 11) * XXH64_PRIME_1;
  }

  h ^= h >> 33;
  h *= XXH64_PRIME_2;
  h ^= h >> 29;
  h *= XXH64_PRIME_3;
  h ^= h >> 32;

  return h;
}

DECLSPEC void xxh64_stripe (PRIVATE_AS xxh64_ctx_t *ctx)
{
  ctx->v[0] = xxh64_round (ctx->v[0], hl32_to_64_S (ctx->buf[1], ctx->buf[0]));
  ctx->v[1] = xxh64_round (ctx->v[1], hl32_to_64_S (ctx->buf[3], ctx->buf[2]));
  ctx->v[2] = xxh64_round (ctx->v[2], hl32_to_64_S (ctx->buf[5], ctx->buf[4]));
  ctx->v[3] = xxh64_round (ctx->v[3], hl32_to_64_S (ctx->buf[7], ctx->buf[6]));
}

DECLSPEC void xxh64_init (PRIVATE_AS xxh64_ctx_t *ctx, const u64 seed)
{
  ctx->v[0] = seed + XXH64_PRIME_1 + XXH64_PRIME_2;
  ctx->v[1] = seed + XXH64_PRIME_2;
  ctx->v[2] = seed + 0;
  ctx->v[3] = seed - XXH64_PRIME_1;

  ctx->seed = seed;
  ctx->h    = 0;

  for (int i = 0; i < 8; i++) ctx->buf[i] = 0;

  ctx->len = 0;
}

// One byte into the stripe buffer, which is hashed once it is full.

DECLSPEC void xxh64_byte (PRIVATE_AS xxh64_ctx_t *ctx, const u32 c)
{
  const int pos = ctx->len & 31;

  const u32 sh = (pos & 3) * 8;

  if (sh == 0) ctx->buf[pos / 4]  = c;
  else         ctx->buf[pos / 4] |= c << sh;

  ctx->len++;

  if ((ctx->len & 31) == 0) xxh64_stripe (ctx);
}

// While the buffer is filled to a whole word, whole words go into it. The bytes after the last
// whole word, or all of them once the buffer is not aligned, go one at a time.

DECLSPEC void xxh64_update (PRIVATE_AS xxh64_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len & 31) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len & 31) == 0) xxh64_stripe (ctx);
    }
  }

  for (; i < len; i++) xxh64_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void xxh64_update_global (PRIVATE_AS xxh64_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len & 31) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len & 31) == 0) xxh64_stripe (ctx);
    }
  }

  for (; i < len; i++) xxh64_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void xxh64_final (PRIVATE_AS xxh64_ctx_t *ctx)
{
  u64 h = ctx->seed + XXH64_PRIME_5;

  if (ctx->len >= 32) h = xxh64_converge (ctx->v[0], ctx->v[1], ctx->v[2], ctx->v[3]);

  h += (u64) ctx->len;

  ctx->h = xxh64_tail (h, ctx->buf, 0, ctx->len & 31);
}

// The whole candidate at once, for the optimized kernels, which hold up to 63 bytes in w[0] to
// w[15]. Every word is read at a constant index and the length only decides which reads count, so
// the candidate stays in registers. A runtime index makes the compiler keep it in memory instead,
// which costs most of the speed. 63 bytes hold one stripe at most.

DECLSPEC u64 xxh64_opti (PRIVATE_AS const u32 *w, const u32 len, const u64 seed)
{
  u64 h = seed + XXH64_PRIME_5;

  if (len >= 32)
  {
    const u64 v1 = xxh64_round (seed + XXH64_PRIME_1 + XXH64_PRIME_2, hl32_to_64_S (w[1], w[0]));
    const u64 v2 = xxh64_round (seed + XXH64_PRIME_2,                 hl32_to_64_S (w[3], w[2]));
    const u64 v3 = xxh64_round (seed + 0,                             hl32_to_64_S (w[5], w[4]));
    const u64 v4 = xxh64_round (seed - XXH64_PRIME_1,                 hl32_to_64_S (w[7], w[6]));

    h = xxh64_converge (v1, v2, v3, v4);
  }

  h += len;

  // the 8 byte lanes after the stripe

  const u32 pos = (len >= 32) ? 32 : 0;

  for (u32 i = 0; i < 16; i += 2)
  {
    if ((i * 4) < pos) continue;

    if (((i * 4) + 8) > len) break;

    h ^= xxh64_round (0, hl32_to_64_S (w[i + 1], w[i + 0]));
    h  = (hc_rotl64_S (h, 27) * XXH64_PRIME_1) + XXH64_PRIME_4;
  }

  // a 4 byte lane, then the last bytes, each from the one word they sit in

  u32 lane = 0;
  u32 last = 0;

  for (u32 i = 0; i < 16; i++)
  {
    if (i == ((len / 8) * 2)) lane = w[i];
    if (i ==  (len / 4))      last = w[i];
  }

  if ((len & 4) == 4)
  {
    h ^= (u64) lane * XXH64_PRIME_1;
    h  = (hc_rotl64_S (h, 23) * XXH64_PRIME_2) + XXH64_PRIME_3;
  }

  for (u32 i = 0; i < (len & 3); i++)
  {
    const u32 c = (last >> (i * 8)) & 0xff;

    h ^= (u64) c * XXH64_PRIME_5;
    h  = hc_rotl64_S (h, 11) * XXH64_PRIME_1;
  }

  h ^= h >> 33;
  h *= XXH64_PRIME_2;
  h ^= h >> 29;
  h *= XXH64_PRIME_3;
  h ^= h >> 32;

  return h;
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths.

DECLSPEC u64x xxh64_round_vector (u64x acc, const u64x lane)
{
  acc += lane * XXH64_PRIME_2;
  acc  = hc_rotl64 (acc, 31);
  acc *= XXH64_PRIME_1;

  return acc;
}

DECLSPEC u64x xxh64_merge_vector (u64x acc, const u64x lane)
{
  acc ^= xxh64_round_vector (make_u64x (0), lane);
  acc  = (acc * XXH64_PRIME_1) + XXH64_PRIME_4;

  return acc;
}

DECLSPEC void xxh64_stripe_vector (PRIVATE_AS xxh64_ctx_vector_t *ctx)
{
  ctx->v[0] = xxh64_round_vector (ctx->v[0], hl32_to_64 (ctx->buf[1], ctx->buf[0]));
  ctx->v[1] = xxh64_round_vector (ctx->v[1], hl32_to_64 (ctx->buf[3], ctx->buf[2]));
  ctx->v[2] = xxh64_round_vector (ctx->v[2], hl32_to_64 (ctx->buf[5], ctx->buf[4]));
  ctx->v[3] = xxh64_round_vector (ctx->v[3], hl32_to_64 (ctx->buf[7], ctx->buf[6]));
}

DECLSPEC void xxh64_init_vector (PRIVATE_AS xxh64_ctx_vector_t *ctx, const u64x seed)
{
  ctx->v[0] = seed + XXH64_PRIME_1 + XXH64_PRIME_2;
  ctx->v[1] = seed + XXH64_PRIME_2;
  ctx->v[2] = seed + 0;
  ctx->v[3] = seed - XXH64_PRIME_1;

  ctx->seed = seed;
  ctx->h    = 0;

  for (int i = 0; i < 8; i++) ctx->buf[i] = 0;

  ctx->len = 0;
}

DECLSPEC void xxh64_byte_vector (PRIVATE_AS xxh64_ctx_vector_t *ctx, const u32x c)
{
  const int pos = ctx->len & 31;

  const u32 sh = (pos & 3) * 8;

  if (sh == 0) ctx->buf[pos / 4]  = c;
  else         ctx->buf[pos / 4] |= c << sh;

  ctx->len++;

  if ((ctx->len & 31) == 0) xxh64_stripe_vector (ctx);
}

DECLSPEC void xxh64_update_vector (PRIVATE_AS xxh64_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len & 31) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len & 31) == 0) xxh64_stripe_vector (ctx);
    }
  }

  for (; i < len; i++) xxh64_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void xxh64_final_vector (PRIVATE_AS xxh64_ctx_vector_t *ctx)
{
  u64x h = ctx->seed + XXH64_PRIME_5;

  if (ctx->len >= 32)
  {
    h = hc_rotl64 (ctx->v[0], 1) + hc_rotl64 (ctx->v[1], 7) + hc_rotl64 (ctx->v[2], 12) + hc_rotl64 (ctx->v[3], 18);

    h = xxh64_merge_vector (h, ctx->v[0]);
    h = xxh64_merge_vector (h, ctx->v[1]);
    h = xxh64_merge_vector (h, ctx->v[2]);
    h = xxh64_merge_vector (h, ctx->v[3]);
  }

  h += (u64) ctx->len;

  const u32 len = ctx->len & 31;

  u32 pos = 0;

  for (; (pos + 8) <= len; pos += 8)
  {
    const u32 i = pos / 4;

    h ^= xxh64_round_vector (make_u64x (0), hl32_to_64 (ctx->buf[i + 1], ctx->buf[i + 0]));
    h  = (hc_rotl64 (h, 27) * XXH64_PRIME_1) + XXH64_PRIME_4;
  }

  if ((pos + 4) <= len)
  {
    h ^= hl32_to_64 (make_u32x (0), ctx->buf[pos / 4]) * XXH64_PRIME_1;
    h  = (hc_rotl64 (h, 23) * XXH64_PRIME_2) + XXH64_PRIME_3;

    pos += 4;
  }

  for (; pos < len; pos++)
  {
    const u32x c = (ctx->buf[pos / 4] >> ((pos & 3) * 8)) & 0xff;

    h ^= hl32_to_64 (make_u32x (0), c) * XXH64_PRIME_5;
    h  = hc_rotl64 (h, 11) * XXH64_PRIME_1;
  }

  h ^= h >> 33;
  h *= XXH64_PRIME_2;
  h ^= h >> 29;
  h *= XXH64_PRIME_3;
  h ^= h >> 32;

  ctx->h = h;
}

DECLSPEC u32 xxh32_round (u32 acc, const u32 lane)
{
  acc += lane * XXH32_PRIME_2;
  acc  = hc_rotl32_S (acc, 13);
  acc *= XXH32_PRIME_1;

  return acc;
}

DECLSPEC u32 xxh32_tail (u32 h, PRIVATE_AS const u32 *w, u32 pos, const u32 len)
{
  for (; (pos + 4) <= len; pos += 4)
  {
    h += w[pos / 4] * XXH32_PRIME_3;
    h  = hc_rotl32_S (h, 17) * XXH32_PRIME_4;
  }

  for (; pos < len; pos++)
  {
    const u32 c = (w[pos / 4] >> ((pos & 3) * 8)) & 0xff;

    h += c * XXH32_PRIME_5;
    h  = hc_rotl32_S (h, 11) * XXH32_PRIME_1;
  }

  h ^= h >> 15;
  h *= XXH32_PRIME_2;
  h ^= h >> 13;
  h *= XXH32_PRIME_3;
  h ^= h >> 16;

  return h;
}

DECLSPEC void xxh32_stripe (PRIVATE_AS xxh32_ctx_t *ctx)
{
  ctx->v[0] = xxh32_round (ctx->v[0], ctx->buf[0]);
  ctx->v[1] = xxh32_round (ctx->v[1], ctx->buf[1]);
  ctx->v[2] = xxh32_round (ctx->v[2], ctx->buf[2]);
  ctx->v[3] = xxh32_round (ctx->v[3], ctx->buf[3]);
}

DECLSPEC void xxh32_init (PRIVATE_AS xxh32_ctx_t *ctx, const u32 seed)
{
  ctx->v[0] = seed + XXH32_PRIME_1 + XXH32_PRIME_2;
  ctx->v[1] = seed + XXH32_PRIME_2;
  ctx->v[2] = seed + 0;
  ctx->v[3] = seed - XXH32_PRIME_1;

  ctx->seed = seed;
  ctx->h    = 0;

  for (int i = 0; i < 4; i++) ctx->buf[i] = 0;

  ctx->len = 0;
}

DECLSPEC void xxh32_byte (PRIVATE_AS xxh32_ctx_t *ctx, const u32 c)
{
  const int pos = ctx->len & 15;

  const u32 sh = (pos & 3) * 8;

  if (sh == 0) ctx->buf[pos / 4]  = c;
  else         ctx->buf[pos / 4] |= c << sh;

  ctx->len++;

  if ((ctx->len & 15) == 0) xxh32_stripe (ctx);
}

DECLSPEC void xxh32_update (PRIVATE_AS xxh32_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len & 15) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len & 15) == 0) xxh32_stripe (ctx);
    }
  }

  for (; i < len; i++) xxh32_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void xxh32_update_global (PRIVATE_AS xxh32_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len & 15) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len & 15) == 0) xxh32_stripe (ctx);
    }
  }

  for (; i < len; i++) xxh32_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void xxh32_final (PRIVATE_AS xxh32_ctx_t *ctx)
{
  u32 h = ctx->seed + XXH32_PRIME_5;

  if (ctx->len >= 16) h = hc_rotl32_S (ctx->v[0], 1) + hc_rotl32_S (ctx->v[1], 7) + hc_rotl32_S (ctx->v[2], 12) + hc_rotl32_S (ctx->v[3], 18);

  h += (u32) ctx->len;

  ctx->h = xxh32_tail (h, ctx->buf, 0, ctx->len & 15);
}

// As xxh64_opti (), for 16 byte stripes. 63 bytes hold three of them at most.

DECLSPEC u32 xxh32_opti (PRIVATE_AS const u32 *w, const u32 len, const u32 seed)
{
  u32 v1 = seed + XXH32_PRIME_1 + XXH32_PRIME_2;
  u32 v2 = seed + XXH32_PRIME_2;
  u32 v3 = seed + 0;
  u32 v4 = seed - XXH32_PRIME_1;

  for (u32 i = 0; i < 12; i += 4)
  {
    if (((i * 4) + 16) > len) break;

    v1 = xxh32_round (v1, w[i + 0]);
    v2 = xxh32_round (v2, w[i + 1]);
    v3 = xxh32_round (v3, w[i + 2]);
    v4 = xxh32_round (v4, w[i + 3]);
  }

  u32 h = seed + XXH32_PRIME_5;

  if (len >= 16) h = hc_rotl32_S (v1, 1) + hc_rotl32_S (v2, 7) + hc_rotl32_S (v3, 12) + hc_rotl32_S (v4, 18);

  h += len;

  // the 4 byte lanes after the last stripe

  const u32 pos = len & ~15u;

  for (u32 i = 0; i < 16; i++)
  {
    if ((i * 4) < pos) continue;

    if (((i * 4) + 4) > len) break;

    h += w[i] * XXH32_PRIME_3;
    h  = hc_rotl32_S (h, 17) * XXH32_PRIME_4;
  }

  // the last bytes, from the one word they sit in

  u32 last = 0;

  for (u32 i = 0; i < 16; i++)
  {
    if (i == (len / 4)) last = w[i];
  }

  for (u32 i = 0; i < (len & 3); i++)
  {
    const u32 c = (last >> (i * 8)) & 0xff;

    h += c * XXH32_PRIME_5;
    h  = hc_rotl32_S (h, 11) * XXH32_PRIME_1;
  }

  h ^= h >> 15;
  h *= XXH32_PRIME_2;
  h ^= h >> 13;
  h *= XXH32_PRIME_3;
  h ^= h >> 16;

  return h;
}

DECLSPEC u32x xxh32_round_vector (u32x acc, const u32x lane)
{
  acc += lane * XXH32_PRIME_2;
  acc  = hc_rotl32 (acc, 13);
  acc *= XXH32_PRIME_1;

  return acc;
}

DECLSPEC void xxh32_stripe_vector (PRIVATE_AS xxh32_ctx_vector_t *ctx)
{
  ctx->v[0] = xxh32_round_vector (ctx->v[0], ctx->buf[0]);
  ctx->v[1] = xxh32_round_vector (ctx->v[1], ctx->buf[1]);
  ctx->v[2] = xxh32_round_vector (ctx->v[2], ctx->buf[2]);
  ctx->v[3] = xxh32_round_vector (ctx->v[3], ctx->buf[3]);
}

DECLSPEC void xxh32_init_vector (PRIVATE_AS xxh32_ctx_vector_t *ctx, const u32x seed)
{
  ctx->v[0] = seed + XXH32_PRIME_1 + XXH32_PRIME_2;
  ctx->v[1] = seed + XXH32_PRIME_2;
  ctx->v[2] = seed + 0;
  ctx->v[3] = seed - XXH32_PRIME_1;

  ctx->seed = seed;
  ctx->h    = 0;

  for (int i = 0; i < 4; i++) ctx->buf[i] = 0;

  ctx->len = 0;
}

DECLSPEC void xxh32_byte_vector (PRIVATE_AS xxh32_ctx_vector_t *ctx, const u32x c)
{
  const int pos = ctx->len & 15;

  const u32 sh = (pos & 3) * 8;

  if (sh == 0) ctx->buf[pos / 4]  = c;
  else         ctx->buf[pos / 4] |= c << sh;

  ctx->len++;

  if ((ctx->len & 15) == 0) xxh32_stripe_vector (ctx);
}

DECLSPEC void xxh32_update_vector (PRIVATE_AS xxh32_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len & 15) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len & 15) == 0) xxh32_stripe_vector (ctx);
    }
  }

  for (; i < len; i++) xxh32_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void xxh32_final_vector (PRIVATE_AS xxh32_ctx_vector_t *ctx)
{
  u32x h = ctx->seed + XXH32_PRIME_5;

  if (ctx->len >= 16) h = hc_rotl32 (ctx->v[0], 1) + hc_rotl32 (ctx->v[1], 7) + hc_rotl32 (ctx->v[2], 12) + hc_rotl32 (ctx->v[3], 18);

  h += (u32) ctx->len;

  const u32 len = ctx->len & 15;

  u32 pos = 0;

  for (; (pos + 4) <= len; pos += 4)
  {
    h += ctx->buf[pos / 4] * XXH32_PRIME_3;
    h  = hc_rotl32 (h, 17) * XXH32_PRIME_4;
  }

  for (; pos < len; pos++)
  {
    const u32x c = (ctx->buf[pos / 4] >> ((pos & 3) * 8)) & 0xff;

    h += c * XXH32_PRIME_5;
    h  = hc_rotl32 (h, 11) * XXH32_PRIME_1;
  }

  h ^= h >> 15;
  h *= XXH32_PRIME_2;
  h ^= h >> 13;
  h *= XXH32_PRIME_3;
  h ^= h >> 16;

  ctx->h = h;
}
