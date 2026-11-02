/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_md6.h"

CONSTANT_VK u64 MD6_S0 = 0x0123456789abcdefUL;
CONSTANT_VK u64 MD6_Smask = 0x7311c2812425cfa0UL;

/* w == 64, standard version */

CONSTANT_VK u64 MD6_Q[15] =
{
  0x7311c2812425cfa0UL,
  0x6432286434aac8e7UL,
  0xb60450e9ef68b7c1UL,
  0xe8fb23908d9f06f1UL,
  0xdd2e76cba691e5bfUL,
  0x0cd0d63b2c30bc41UL,
  0x1f8ccf6823058f8aUL,
  0x54e5ed5b88e3775dUL,
  0x4ad12aae0a6d6031UL,
  0x3e7f16bb88222e0dUL,
  0x8af8671d3fb50c2cUL,
  0x995ad1178bd25c31UL,
  0xc878c1dd04c4b633UL,
  0x3b72066c7a1552acUL,
  0x0d6f3522631effcbUL
};

/* hc optimized values */

CONSTANT_VK u64 MD6_256_DEFAULT_NODEID = 0x0100000000000000UL; // ell = 1, i = 0
CONSTANT_VK u64 MD6_Vs = 0x0068401000000000UL;
CONSTANT_VK u64 MD6_Ve = 0x0000000000000100UL;

// MD6 for the hash recipes, with any of its digest sizes. Input is little endian words, as for
// MD5. A partial last word may hold bytes past the length, which the updates mask off.

// One step of the compression. The 89 input words and the words computed from them are kept in a
// ring of 128 words, so word i of the reference's array A sits at a[i & 127]. Step K + I computes
// word 89 + K + I from the words 89, 17, 18, 21, 31 and 67 places back.

#define MD6_STEP(T,A,S,K,I,RS,LS)                                               \
{                                                                               \
  const u32 p = (K) + (I);                                                      \
                                                                                \
  T x = (S) ^ A[(p + 0) & 127] ^ A[(p + 72) & 127]                              \
      ^ (A[(p + 71) & 127] & A[(p + 68) & 127])                                 \
      ^ (A[(p + 58) & 127] & A[(p + 22) & 127]);                                \
                                                                                \
  x ^= x >> (RS);                                                               \
                                                                                \
  A[(p + 89) & 127] = x ^ (x << (LS));                                          \
}

// One compression. The input is Q, a zero key, the node ID U, the control word V and the 64 data
// words M. R rounds of 16 steps follow, and the last 16 words computed are the result. C turns a
// constant into the type T.

#define MD6_TRANSFORM(T,C,H,M,U,V,R)                                            \
{                                                                               \
  T a[128];                                                                     \
                                                                                \
  for (u32 j =  0; j < 15; j++) a[j] = C (MD6_Q[j]);                            \
  for (u32 j = 15; j < 23; j++) a[j] = C (0);                                   \
                                                                                \
  a[23] = C (U);                                                                \
  a[24] = C (V);                                                                \
                                                                                \
  for (u32 j = 0; j < 64; j++) a[25 + j] = M[j];                                \
                                                                                \
  const u32 t = (u32) (R) * 16;                                                 \
                                                                                \
  u64 s = MD6_S0;                                                               \
                                                                                \
  for (u32 k = 0; k < t; k += 16)                                               \
  {                                                                             \
    const T sv = C (s);                                                         \
                                                                                \
    MD6_STEP (T, a, sv, k,  0, 10, 11);                                         \
    MD6_STEP (T, a, sv, k,  1,  5, 24);                                         \
    MD6_STEP (T, a, sv, k,  2, 13,  9);                                         \
    MD6_STEP (T, a, sv, k,  3, 10, 16);                                         \
    MD6_STEP (T, a, sv, k,  4, 11, 15);                                         \
    MD6_STEP (T, a, sv, k,  5, 12,  9);                                         \
    MD6_STEP (T, a, sv, k,  6,  2, 27);                                         \
    MD6_STEP (T, a, sv, k,  7,  7, 15);                                         \
    MD6_STEP (T, a, sv, k,  8, 14,  6);                                         \
    MD6_STEP (T, a, sv, k,  9, 15,  2);                                         \
    MD6_STEP (T, a, sv, k, 10,  7, 29);                                         \
    MD6_STEP (T, a, sv, k, 11, 13,  8);                                         \
    MD6_STEP (T, a, sv, k, 12, 11, 15);                                         \
    MD6_STEP (T, a, sv, k, 13,  7,  5);                                         \
    MD6_STEP (T, a, sv, k, 14,  6, 31);                                         \
    MD6_STEP (T, a, sv, k, 15, 12,  9);                                         \
                                                                                \
    s = hc_rotl64_S (s, 1) ^ (s & MD6_Smask);                                   \
  }                                                                             \
                                                                                \
  for (u32 j = 0; j < 16; j++) H[j] = a[(t + 73 + j) & 127];                    \
}

#define MD6_C_S(V) (V)
#define MD6_C_V(V) make_u64x (V)

DECLSPEC void md6_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m, const u64 u, const u64 v, const int r)
{
  MD6_TRANSFORM (u64, MD6_C_S, h, m, u, v, r);
}

DECLSPEC void md6_init (PRIVATE_AS md6_ctx_t *ctx, const int dlen)
{
  for (u32 i = 0; i < MD6_LEVELS; i++)
  {
    for (u32 j = 0; j < 64; j++) ctx->b[i][j] = 0;

    ctx->fill[i] = 0;
    ctx->cnt[i]  = 0;
  }

  for (u32 i = 0; i < 8; i++) ctx->h[i] = 0;

  ctx->top  = 0;
  ctx->r    = 40 + (dlen * 2);
  ctx->dlen = dlen;
  ctx->len  = 0;
}

// Compress the block of level l into c and empty the level. The node ID holds the level as the
// reference counts it, from 1, and the index of the node within its level. The control word holds
// the rounds, L = 64, the flag z of the very last compression, the bits of padding in the block,
// the key length 0 and the digest bits.

DECLSPEC void md6_node (PRIVATE_AS md6_ctx_t *ctx, const int l, const int z, PRIVATE_AS u64 *c)
{
  const u64 p = (u64) (4096 - (ctx->fill[l] * 8));

  const u64 u = ((u64) (l + 1) << 56) | (u64) ctx->cnt[l];

  const u64 v = ((u64) ctx->r << 48) | ((u64) 64 << 40) | ((u64) z << 36) | (p << 20) | (u64) (ctx->dlen * 8);

  md6_transform (c, ctx->b[l], u, v, ctx->r);

  for (u32 j = 0; j < 64; j++) ctx->b[l][j] = 0;

  ctx->fill[l]  = 0;
  ctx->cnt[l]  += 1;
}

// Compress the full block of level l, which is not the last because more input follows, and add
// the result to level l + 1. A level above the leaves is compressed as soon as it holds 4 results,
// as the reference does. When the highest level fills up, the message is too long for the tree,
// and the context is marked as for invalid UTF-8.

DECLSPEC void md6_push (PRIVATE_AS md6_ctx_t *ctx, const int l)
{
  u64 c[16];

  for (int i = l; i < (MD6_LEVELS - 1); i++)
  {
    md6_node (ctx, i, 0, c);

    const int k = i + 1;

    const int f = ctx->fill[k] / 8;

    for (u32 j = 0; j < 16; j++) ctx->b[k][f + j] = c[j];

    ctx->fill[k] += 128;

    if (k > ctx->top) ctx->top = k;

    if (ctx->fill[k] < 512) return;
  }

  for (u32 j = 0; j < 64; j++) ctx->b[MD6_LEVELS - 1][j] = 0;

  ctx->fill[MD6_LEVELS - 1] = 0;

  ctx->len = -1;
}

// Put the n bytes of v into the leaf block at the current position, starting with its low bytes.
// The bytes of v beyond n are zero. A full block is compressed first if more bytes arrive for it,
// because the last block of the message is compressed differently.

DECLSPEC void md6_absorb (PRIVATE_AS md6_ctx_t *ctx, const u32 v, const int n)
{
  if (ctx->fill[0] == 512) md6_push (ctx, 0);

  const int pos = ctx->fill[0];

  const int room = 512 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64 x = hl32_to_64_S (hc_swap32_S (v & mask), 0);

  const int word = pos / 8;
  const int off  = pos & 7;

  ctx->b[0][word] |= x >> (off * 8);

  if ((off + fit) > 8) ctx->b[0][word + 1] |= x << ((8 - off) * 8);

  ctx->fill[0] = pos + fit;

  if (fit == n) return;

  md6_push (ctx, 0);

  ctx->b[0][0] = hl32_to_64_S (hc_swap32_S (v >> (fit * 8)), 0);

  ctx->fill[0] = n - fit;
}

DECLSPEC void md6_update (PRIVATE_AS md6_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    md6_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void md6_absorb_utf16le (PRIVATE_AS md6_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  md6_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) md6_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void md6_update_utf16le (PRIVATE_AS md6_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      md6_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    md6_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void md6_update_global (PRIVATE_AS md6_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    md6_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void md6_update_global_utf16le (PRIVATE_AS md6_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  // Decoding UTF-8 straight from global memory faults on NVIDIA GPUs in the combinator kernel of
  // mode 4000, so the decoder reads a private copy. hc_enc takes up to 256 bytes, and a longer input
  // with a non-ASCII byte is invalid either way.

  if (hc_enc_scan_global (w, len))
  {
    if (len > 256)
    {
      ctx->len = -1;

      return;
    }

    u32 buf[64] = { 0 };

    for (int i = 0; i < len; i += 4) buf[i / 4] = w[i / 4];

    md6_update_utf16le (ctx, buf, len);

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    md6_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Each level below the top compresses what it holds and passes the result up, and the top level
// is the root, compressed with z = 1. The leaf block always holds data here, since it is
// compressed early only when more input arrives. The digest is the last dlen bytes of the root's
// result. A context with invalid UTF-8 input produces a digest with every bit flipped, so that no
// candidate matches it by chance.

DECLSPEC void md6_final (PRIVATE_AS md6_ctx_t *ctx)
{
  u64 c[16];

  for (int i = 0; i < ctx->top; i++)
  {
    md6_node (ctx, i, 0, c);

    const int k = i + 1;

    const int f = ctx->fill[k] / 8;

    for (u32 j = 0; j < 16; j++) ctx->b[k][f + j] = c[j];

    ctx->fill[k] += 128;
  }

  md6_node (ctx, ctx->top, 1, c);

  const int nw = ctx->dlen / 8;

  for (int j = 0; j < nw; j++) ctx->h[j] = c[16 - nw + j];

  if (ctx->len < 0)
  {
    for (int j = 0; j < nw; j++) ctx->h[j] = ~ctx->h[j];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void md6_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m, const u64 u, const u64 v, const int r)
{
  MD6_TRANSFORM (u64x, MD6_C_V, h, m, u, v, r);
}

DECLSPEC void md6_init_vector (PRIVATE_AS md6_ctx_vector_t *ctx, const int dlen)
{
  for (u32 i = 0; i < MD6_LEVELS; i++)
  {
    for (u32 j = 0; j < 64; j++) ctx->b[i][j] = 0;

    ctx->fill[i] = 0;
    ctx->cnt[i]  = 0;
  }

  for (u32 i = 0; i < 8; i++) ctx->h[i] = 0;

  ctx->top  = 0;
  ctx->r    = 40 + (dlen * 2);
  ctx->dlen = dlen;
  ctx->len  = 0;
}

DECLSPEC void md6_node_vector (PRIVATE_AS md6_ctx_vector_t *ctx, const int l, const int z, PRIVATE_AS u64x *c)
{
  const u64 p = (u64) (4096 - (ctx->fill[l] * 8));

  const u64 u = ((u64) (l + 1) << 56) | (u64) ctx->cnt[l];

  const u64 v = ((u64) ctx->r << 48) | ((u64) 64 << 40) | ((u64) z << 36) | (p << 20) | (u64) (ctx->dlen * 8);

  md6_transform_vector (c, ctx->b[l], u, v, ctx->r);

  for (u32 j = 0; j < 64; j++) ctx->b[l][j] = 0;

  ctx->fill[l]  = 0;
  ctx->cnt[l]  += 1;
}

DECLSPEC void md6_push_vector (PRIVATE_AS md6_ctx_vector_t *ctx, const int l)
{
  u64x c[16];

  for (int i = l; i < (MD6_LEVELS - 1); i++)
  {
    md6_node_vector (ctx, i, 0, c);

    const int k = i + 1;

    const int f = ctx->fill[k] / 8;

    for (u32 j = 0; j < 16; j++) ctx->b[k][f + j] = c[j];

    ctx->fill[k] += 128;

    if (k > ctx->top) ctx->top = k;

    if (ctx->fill[k] < 512) return;
  }

  for (u32 j = 0; j < 64; j++) ctx->b[MD6_LEVELS - 1][j] = 0;

  ctx->fill[MD6_LEVELS - 1] = 0;

  ctx->len = -1;
}

DECLSPEC void md6_absorb_vector (PRIVATE_AS md6_ctx_vector_t *ctx, const u32x v, const int n)
{
  if (ctx->fill[0] == 512) md6_push_vector (ctx, 0);

  const int pos = ctx->fill[0];

  const int room = 512 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64x x = hl32_to_64 (hc_swap32 (v & mask), 0);

  const int word = pos / 8;
  const int off  = pos & 7;

  ctx->b[0][word] |= x >> (off * 8);

  if ((off + fit) > 8) ctx->b[0][word + 1] |= x << ((8 - off) * 8);

  ctx->fill[0] = pos + fit;

  if (fit == n) return;

  md6_push_vector (ctx, 0);

  ctx->b[0][0] = hl32_to_64 (hc_swap32 (v >> (fit * 8)), 0);

  ctx->fill[0] = n - fit;
}

DECLSPEC void md6_update_vector (PRIVATE_AS md6_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    md6_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void md6_update_vector_utf16le (PRIVATE_AS md6_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    md6_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) md6_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void md6_final_vector (PRIVATE_AS md6_ctx_vector_t *ctx)
{
  u64x c[16];

  for (int i = 0; i < ctx->top; i++)
  {
    md6_node_vector (ctx, i, 0, c);

    const int k = i + 1;

    const int f = ctx->fill[k] / 8;

    for (u32 j = 0; j < 16; j++) ctx->b[k][f + j] = c[j];

    ctx->fill[k] += 128;
  }

  md6_node_vector (ctx, ctx->top, 1, c);

  const int nw = ctx->dlen / 8;

  for (int j = 0; j < nw; j++) ctx->h[j] = c[16 - nw + j];

  if (ctx->len < 0)
  {
    for (int j = 0; j < nw; j++) ctx->h[j] = ~ctx->h[j];
  }
}
