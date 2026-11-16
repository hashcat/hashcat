/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_lookup8.h"

// Input arrives as little endian 32 bit words, the byte order lookup8 reads its 64 bit lanes in. A
// block is 24 bytes, so a lane is two whole words. The tail is masked to its length, which leaves
// the bytes of a buffer past len free to hold anything.

#define LOOKUP8_MIX(a,b,c)        \
{                                 \
  a -= b; a -= c; a ^= (c >> 43); \
  b -= c; b -= a; b ^= (a <<  9); \
  c -= a; c -= b; c ^= (b >>  8); \
  a -= b; a -= c; a ^= (c >> 38); \
  b -= c; b -= a; b ^= (a << 23); \
  c -= a; c -= b; c ^= (b >>  5); \
  a -= b; a -= c; a ^= (c >> 35); \
  b -= c; b -= a; b ^= (a << 49); \
  c -= a; c -= b; c ^= (b >> 11); \
  a -= b; a -= c; a ^= (c >> 12); \
  b -= c; b -= a; b ^= (a << 18); \
  c -= a; c -= b; c ^= (b >> 22); \
}

// The bytes of word j of the tail that lie below len.

DECLSPEC u32 lookup8_mask (const u32 j, const u32 len)
{
  const u32 lo = j * 4;

  if (len >= (lo + 4)) return 0xffffffff;
  if (lo  >= len)      return 0;

  const u32 mask = (1u << ((len - lo) * 8)) - 1;

  return mask;
}

DECLSPEC void lookup8_block (PRIVATE_AS lookup8_ctx_t *ctx)
{
  ctx->a += hl32_to_64_S (ctx->buf[1], ctx->buf[0]);
  ctx->b += hl32_to_64_S (ctx->buf[3], ctx->buf[2]);
  ctx->c += hl32_to_64_S (ctx->buf[5], ctx->buf[4]);

  LOOKUP8_MIX (ctx->a, ctx->b, ctx->c);
}

DECLSPEC void lookup8_init (PRIVATE_AS lookup8_ctx_t *ctx, const u64 level)
{
  ctx->a = level;
  ctx->b = level;
  ctx->c = LOOKUP8_GOLDEN;

  for (int i = 0; i < 6; i++) ctx->buf[i] = 0;

  ctx->len = 0;
}

// One byte into the block buffer, which is mixed in once it is full.

DECLSPEC void lookup8_byte (PRIVATE_AS lookup8_ctx_t *ctx, const u32 c)
{
  const int pos = ctx->len % 24;

  const u32 sh = (pos & 3) * 8;

  if (sh == 0) ctx->buf[pos / 4]  = c;
  else         ctx->buf[pos / 4] |= c << sh;

  ctx->len++;

  if ((ctx->len % 24) == 0) lookup8_block (ctx);
}

// While the buffer is filled to a whole word, whole words go into it. The bytes after the last
// whole word, or all of them once the buffer is not aligned, go one at a time.

DECLSPEC void lookup8_update (PRIVATE_AS lookup8_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len % 24) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len % 24) == 0) lookup8_block (ctx);
    }
  }

  for (; i < len; i++) lookup8_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void lookup8_update_global (PRIVATE_AS lookup8_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len % 24) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len % 24) == 0) lookup8_block (ctx);
    }
  }

  for (; i < len; i++) lookup8_byte (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

// The length of the whole input goes into c, and the tail of up to 23 bytes into a, b and c. c gets
// its bytes one place up, because its lowest byte is the one the length went into.

DECLSPEC void lookup8_final (PRIVATE_AS lookup8_ctx_t *ctx)
{
  const u32 tail = (u32) (ctx->len % 24);

  u32 t[6];

  for (u32 j = 0; j < 6; j++) t[j] = ctx->buf[j] & lookup8_mask (j, tail);

  ctx->c += (u64) ctx->len;

  ctx->a += hl32_to_64_S (t[1], t[0]);
  ctx->b += hl32_to_64_S (t[3], t[2]);
  ctx->c += hl32_to_64_S (t[5], t[4]) << 8;

  LOOKUP8_MIX (ctx->a, ctx->b, ctx->c);
}

// The whole candidate at once, for the optimized kernels, which hold up to 63 bytes in w[0] to
// w[15]. Every word is read at a constant index and the length only decides which reads count, so
// the candidate stays in registers. 63 bytes hold two whole blocks at most, and the tail after the
// second is never longer than 15 bytes.

DECLSPEC u64 lookup8_opti (PRIVATE_AS const u32 *w, const u32 len, const u64 level)
{
  u64 a = level;
  u64 b = level;
  u64 c = LOOKUP8_GOLDEN;

  if (len >= 24)
  {
    a += hl32_to_64_S (w[1], w[0]);
    b += hl32_to_64_S (w[3], w[2]);
    c += hl32_to_64_S (w[5], w[4]);

    LOOKUP8_MIX (a, b, c);
  }

  if (len >= 48)
  {
    a += hl32_to_64_S (w[ 7], w[ 6]);
    b += hl32_to_64_S (w[ 9], w[ 8]);
    c += hl32_to_64_S (w[11], w[10]);

    LOOKUP8_MIX (a, b, c);
  }

  const u32 tail = len % 24;

  u32 t[6];

  for (u32 j = 0; j < 6; j++)
  {
    const u32 w0 = w[j];
    const u32 w1 = w[j + 6];
    const u32 w2 = (j < 4) ? w[j + 12] : 0;

    const u32 v = (len >= 48) ? w2 : (len >= 24) ? w1 : w0;

    t[j] = v & lookup8_mask (j, tail);
  }

  c += (u64) len;

  a += hl32_to_64_S (t[1], t[0]);
  b += hl32_to_64_S (t[3], t[2]);
  c += hl32_to_64_S (t[5], t[4]) << 8;

  LOOKUP8_MIX (a, b, c);

  return c;
}

DECLSPEC void lookup8_block_vector (PRIVATE_AS lookup8_ctx_vector_t *ctx)
{
  ctx->a += hl32_to_64 (ctx->buf[1], ctx->buf[0]);
  ctx->b += hl32_to_64 (ctx->buf[3], ctx->buf[2]);
  ctx->c += hl32_to_64 (ctx->buf[5], ctx->buf[4]);

  LOOKUP8_MIX (ctx->a, ctx->b, ctx->c);
}

DECLSPEC void lookup8_init_vector (PRIVATE_AS lookup8_ctx_vector_t *ctx, const u64x level)
{
  ctx->a = level;
  ctx->b = level;
  ctx->c = make_u64x (LOOKUP8_GOLDEN);

  for (int i = 0; i < 6; i++) ctx->buf[i] = 0;

  ctx->len = 0;
}

DECLSPEC void lookup8_byte_vector (PRIVATE_AS lookup8_ctx_vector_t *ctx, const u32x c)
{
  const int pos = ctx->len % 24;

  const u32 sh = (pos & 3) * 8;

  if (sh == 0) ctx->buf[pos / 4]  = c;
  else         ctx->buf[pos / 4] |= c << sh;

  ctx->len++;

  if ((ctx->len % 24) == 0) lookup8_block_vector (ctx);
}

DECLSPEC void lookup8_update_vector (PRIVATE_AS lookup8_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  int i = 0;

  if ((ctx->len & 3) == 0)
  {
    for (; (i + 4) <= len; i += 4)
    {
      ctx->buf[(ctx->len % 24) / 4] = w[i / 4];

      ctx->len += 4;

      if ((ctx->len % 24) == 0) lookup8_block_vector (ctx);
    }
  }

  for (; i < len; i++) lookup8_byte_vector (ctx, (w[i / 4] >> ((i & 3) * 8)) & 0xff);
}

DECLSPEC void lookup8_final_vector (PRIVATE_AS lookup8_ctx_vector_t *ctx)
{
  const u32 tail = (u32) (ctx->len % 24);

  u32x t[6];

  for (u32 j = 0; j < 6; j++) t[j] = ctx->buf[j] & lookup8_mask (j, tail);

  ctx->c += (u64) ctx->len;

  ctx->a += hl32_to_64 (t[1], t[0]);
  ctx->b += hl32_to_64 (t[3], t[2]);
  ctx->c += hl32_to_64 (t[5], t[4]) << 8;

  LOOKUP8_MIX (ctx->a, ctx->b, ctx->c);
}
