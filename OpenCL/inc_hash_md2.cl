/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_md2.h"

// The S-box of RFC 1319, a permutation of 0 to 255 taken from the digits of pi. Each entry is a word
// so that a lookup gives a byte without masking.

CONSTANT_VK u32a md2_sbox[256] =
{
  0x29, 0x2e, 0x43, 0xc9, 0xa2, 0xd8, 0x7c, 0x01, 0x3d, 0x36, 0x54, 0xa1, 0xec, 0xf0, 0x06, 0x13,
  0x62, 0xa7, 0x05, 0xf3, 0xc0, 0xc7, 0x73, 0x8c, 0x98, 0x93, 0x2b, 0xd9, 0xbc, 0x4c, 0x82, 0xca,
  0x1e, 0x9b, 0x57, 0x3c, 0xfd, 0xd4, 0xe0, 0x16, 0x67, 0x42, 0x6f, 0x18, 0x8a, 0x17, 0xe5, 0x12,
  0xbe, 0x4e, 0xc4, 0xd6, 0xda, 0x9e, 0xde, 0x49, 0xa0, 0xfb, 0xf5, 0x8e, 0xbb, 0x2f, 0xee, 0x7a,
  0xa9, 0x68, 0x79, 0x91, 0x15, 0xb2, 0x07, 0x3f, 0x94, 0xc2, 0x10, 0x89, 0x0b, 0x22, 0x5f, 0x21,
  0x80, 0x7f, 0x5d, 0x9a, 0x5a, 0x90, 0x32, 0x27, 0x35, 0x3e, 0xcc, 0xe7, 0xbf, 0xf7, 0x97, 0x03,
  0xff, 0x19, 0x30, 0xb3, 0x48, 0xa5, 0xb5, 0xd1, 0xd7, 0x5e, 0x92, 0x2a, 0xac, 0x56, 0xaa, 0xc6,
  0x4f, 0xb8, 0x38, 0xd2, 0x96, 0xa4, 0x7d, 0xb6, 0x76, 0xfc, 0x6b, 0xe2, 0x9c, 0x74, 0x04, 0xf1,
  0x45, 0x9d, 0x70, 0x59, 0x64, 0x71, 0x87, 0x20, 0x86, 0x5b, 0xcf, 0x65, 0xe6, 0x2d, 0xa8, 0x02,
  0x1b, 0x60, 0x25, 0xad, 0xae, 0xb0, 0xb9, 0xf6, 0x1c, 0x46, 0x61, 0x69, 0x34, 0x40, 0x7e, 0x0f,
  0x55, 0x47, 0xa3, 0x23, 0xdd, 0x51, 0xaf, 0x3a, 0xc3, 0x5c, 0xf9, 0xce, 0xba, 0xc5, 0xea, 0x26,
  0x2c, 0x53, 0x0d, 0x6e, 0x85, 0x28, 0x84, 0x09, 0xd3, 0xdf, 0xcd, 0xf4, 0x41, 0x81, 0x4d, 0x52,
  0x6a, 0xdc, 0x37, 0xc8, 0x6c, 0xc1, 0xab, 0xfa, 0x24, 0xe1, 0x7b, 0x08, 0x0c, 0xbd, 0xb1, 0x4a,
  0x78, 0x88, 0x95, 0x8b, 0xe3, 0x63, 0xe8, 0x6d, 0xe9, 0xcb, 0xd5, 0xfe, 0x3b, 0x00, 0x1d, 0x39,
  0xf2, 0xef, 0xb7, 0x0e, 0x66, 0x58, 0xd0, 0xe4, 0xa6, 0x77, 0x72, 0xf8, 0xeb, 0x75, 0x4b, 0x0a,
  0x31, 0x44, 0x50, 0xb4, 0x8f, 0xed, 0x1f, 0x1a, 0xdb, 0x99, 0x8d, 0x33, 0x9f, 0x11, 0x83, 0x14,
};

#if   VECT_SIZE == 1
#define MD2_BOX(S,i) ((S)[(i)])
#elif VECT_SIZE == 2
#define MD2_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define MD2_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define MD2_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define MD2_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

#define MD2_BOX_S(S,i) ((S)[(i)])

// The 4 bytes of word v, copied to x[o] through x[o + 3] and back again.

#define MD2_UNPACK(x,o,v)            \
{                                    \
  (x)[(o) + 0] = ((v) >>  0) & 0xff; \
  (x)[(o) + 1] = ((v) >>  8) & 0xff; \
  (x)[(o) + 2] = ((v) >> 16) & 0xff; \
  (x)[(o) + 3] = ((v) >> 24) & 0xff; \
}

#define MD2_PACK(x,o) (((x)[(o) + 0] << 0) | ((x)[(o) + 1] << 8) | ((x)[(o) + 2] << 16) | ((x)[(o) + 3] << 24))

// The checksum processes the block byte by byte, each step chained to the preceding one through l.

#define MD2_SUM(BOX,k,x,l)                              \
{                                                       \
  (k)[ 0] ^= BOX (s_md2, (x)[16] ^ (l)); (l) = (k)[ 0]; \
  (k)[ 1] ^= BOX (s_md2, (x)[17] ^ (l)); (l) = (k)[ 1]; \
  (k)[ 2] ^= BOX (s_md2, (x)[18] ^ (l)); (l) = (k)[ 2]; \
  (k)[ 3] ^= BOX (s_md2, (x)[19] ^ (l)); (l) = (k)[ 3]; \
  (k)[ 4] ^= BOX (s_md2, (x)[20] ^ (l)); (l) = (k)[ 4]; \
  (k)[ 5] ^= BOX (s_md2, (x)[21] ^ (l)); (l) = (k)[ 5]; \
  (k)[ 6] ^= BOX (s_md2, (x)[22] ^ (l)); (l) = (k)[ 6]; \
  (k)[ 7] ^= BOX (s_md2, (x)[23] ^ (l)); (l) = (k)[ 7]; \
  (k)[ 8] ^= BOX (s_md2, (x)[24] ^ (l)); (l) = (k)[ 8]; \
  (k)[ 9] ^= BOX (s_md2, (x)[25] ^ (l)); (l) = (k)[ 9]; \
  (k)[10] ^= BOX (s_md2, (x)[26] ^ (l)); (l) = (k)[10]; \
  (k)[11] ^= BOX (s_md2, (x)[27] ^ (l)); (l) = (k)[11]; \
  (k)[12] ^= BOX (s_md2, (x)[28] ^ (l)); (l) = (k)[12]; \
  (k)[13] ^= BOX (s_md2, (x)[29] ^ (l)); (l) = (k)[13]; \
  (k)[14] ^= BOX (s_md2, (x)[30] ^ (l)); (l) = (k)[14]; \
  (k)[15] ^= BOX (s_md2, (x)[31] ^ (l)); (l) = (k)[15]; \
}

// One round with 48 steps over the state. Each step is chained to the preceding step through t.

#define MD2_ROW(BOX,x,t)                      \
{                                             \
  (x)[ 0] ^= BOX (s_md2, (t)); (t) = (x)[ 0]; \
  (x)[ 1] ^= BOX (s_md2, (t)); (t) = (x)[ 1]; \
  (x)[ 2] ^= BOX (s_md2, (t)); (t) = (x)[ 2]; \
  (x)[ 3] ^= BOX (s_md2, (t)); (t) = (x)[ 3]; \
  (x)[ 4] ^= BOX (s_md2, (t)); (t) = (x)[ 4]; \
  (x)[ 5] ^= BOX (s_md2, (t)); (t) = (x)[ 5]; \
  (x)[ 6] ^= BOX (s_md2, (t)); (t) = (x)[ 6]; \
  (x)[ 7] ^= BOX (s_md2, (t)); (t) = (x)[ 7]; \
  (x)[ 8] ^= BOX (s_md2, (t)); (t) = (x)[ 8]; \
  (x)[ 9] ^= BOX (s_md2, (t)); (t) = (x)[ 9]; \
  (x)[10] ^= BOX (s_md2, (t)); (t) = (x)[10]; \
  (x)[11] ^= BOX (s_md2, (t)); (t) = (x)[11]; \
  (x)[12] ^= BOX (s_md2, (t)); (t) = (x)[12]; \
  (x)[13] ^= BOX (s_md2, (t)); (t) = (x)[13]; \
  (x)[14] ^= BOX (s_md2, (t)); (t) = (x)[14]; \
  (x)[15] ^= BOX (s_md2, (t)); (t) = (x)[15]; \
  (x)[16] ^= BOX (s_md2, (t)); (t) = (x)[16]; \
  (x)[17] ^= BOX (s_md2, (t)); (t) = (x)[17]; \
  (x)[18] ^= BOX (s_md2, (t)); (t) = (x)[18]; \
  (x)[19] ^= BOX (s_md2, (t)); (t) = (x)[19]; \
  (x)[20] ^= BOX (s_md2, (t)); (t) = (x)[20]; \
  (x)[21] ^= BOX (s_md2, (t)); (t) = (x)[21]; \
  (x)[22] ^= BOX (s_md2, (t)); (t) = (x)[22]; \
  (x)[23] ^= BOX (s_md2, (t)); (t) = (x)[23]; \
  (x)[24] ^= BOX (s_md2, (t)); (t) = (x)[24]; \
  (x)[25] ^= BOX (s_md2, (t)); (t) = (x)[25]; \
  (x)[26] ^= BOX (s_md2, (t)); (t) = (x)[26]; \
  (x)[27] ^= BOX (s_md2, (t)); (t) = (x)[27]; \
  (x)[28] ^= BOX (s_md2, (t)); (t) = (x)[28]; \
  (x)[29] ^= BOX (s_md2, (t)); (t) = (x)[29]; \
  (x)[30] ^= BOX (s_md2, (t)); (t) = (x)[30]; \
  (x)[31] ^= BOX (s_md2, (t)); (t) = (x)[31]; \
  (x)[32] ^= BOX (s_md2, (t)); (t) = (x)[32]; \
  (x)[33] ^= BOX (s_md2, (t)); (t) = (x)[33]; \
  (x)[34] ^= BOX (s_md2, (t)); (t) = (x)[34]; \
  (x)[35] ^= BOX (s_md2, (t)); (t) = (x)[35]; \
  (x)[36] ^= BOX (s_md2, (t)); (t) = (x)[36]; \
  (x)[37] ^= BOX (s_md2, (t)); (t) = (x)[37]; \
  (x)[38] ^= BOX (s_md2, (t)); (t) = (x)[38]; \
  (x)[39] ^= BOX (s_md2, (t)); (t) = (x)[39]; \
  (x)[40] ^= BOX (s_md2, (t)); (t) = (x)[40]; \
  (x)[41] ^= BOX (s_md2, (t)); (t) = (x)[41]; \
  (x)[42] ^= BOX (s_md2, (t)); (t) = (x)[42]; \
  (x)[43] ^= BOX (s_md2, (t)); (t) = (x)[43]; \
  (x)[44] ^= BOX (s_md2, (t)); (t) = (x)[44]; \
  (x)[45] ^= BOX (s_md2, (t)); (t) = (x)[45]; \
  (x)[46] ^= BOX (s_md2, (t)); (t) = (x)[46]; \
  (x)[47] ^= BOX (s_md2, (t)); (t) = (x)[47]; \
}

// One block: the checksum processes the block first, followed by 18 rounds over the 48 bytes of the
// state, the block and their xor. Each byte is stored in a word of its own, so that each step uses
// one lookup and one xor.

DECLSPEC void md2_transform (PRIVATE_AS u32 *h, PRIVATE_AS u32 *c, PRIVATE_AS const u32 *w, SHM_TYPE u32a *s_md2)
{
  u32 x[48];

  MD2_UNPACK (x,  0, h[0]);
  MD2_UNPACK (x,  4, h[1]);
  MD2_UNPACK (x,  8, h[2]);
  MD2_UNPACK (x, 12, h[3]);

  MD2_UNPACK (x, 16, w[0]);
  MD2_UNPACK (x, 20, w[1]);
  MD2_UNPACK (x, 24, w[2]);
  MD2_UNPACK (x, 28, w[3]);

  u32 k[16];

  MD2_UNPACK (k,  0, c[0]);
  MD2_UNPACK (k,  4, c[1]);
  MD2_UNPACK (k,  8, c[2]);
  MD2_UNPACK (k, 12, c[3]);

  u32 l = k[15];

  MD2_SUM (MD2_BOX_S, k, x, l);

  c[0] = MD2_PACK (k,  0);
  c[1] = MD2_PACK (k,  4);
  c[2] = MD2_PACK (k,  8);
  c[3] = MD2_PACK (k, 12);

  for (int i = 0; i < 16; i++) x[32 + i] = x[16 + i] ^ x[i];

  u32 t = 0;

  for (int j = 0; j < 18; j++)
  {
    MD2_ROW (MD2_BOX_S, x, t);

    t = (t + j) & 0xff;
  }

  h[0] = MD2_PACK (x,  0);
  h[1] = MD2_PACK (x,  4);
  h[2] = MD2_PACK (x,  8);
  h[3] = MD2_PACK (x, 12);
}

DECLSPEC void md2_init (PRIVATE_AS md2_ctx_t *ctx, SHM_TYPE u32a *s_md2)
{
  for (int i = 0; i < 4; i++) ctx->h[i] = 0;
  for (int i = 0; i < 4; i++) ctx->c[i] = 0;
  for (int i = 0; i < 4; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->s_md2 = s_md2;
}

DECLSPEC void md2_block (PRIVATE_AS md2_ctx_t *ctx)
{
  md2_transform (ctx->h, ctx->c, ctx->w, ctx->s_md2);

  for (int i = 0; i < 4; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

// Add the n bytes of v to the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, hash it and use any remaining
// bytes to start the next block.

DECLSPEC void md2_absorb (PRIVATE_AS md2_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 16 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    md2_block (ctx);

    if (n > fit)
    {
      ctx->w[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void md2_update (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    md2_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void md2_absorb_utf16le (PRIVATE_AS md2_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  md2_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) md2_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void md2_update_utf16le (PRIVATE_AS md2_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      md2_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    md2_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void md2_update_global (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    md2_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void md2_update_global_utf16le (PRIVATE_AS md2_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      md2_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    md2_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Pad to the end of the block with p bytes of value p, from 1 to 16, then hash the checksum as one
// more block. A context with invalid UTF-8 input produces a digest with every bit flipped, so that
// no candidate matches it by chance.

DECLSPEC void md2_final (PRIVATE_AS md2_ctx_t *ctx)
{
  const int p = 16 - ctx->pos;

  const u32 v = (u32) p * 0x01010101;

  for (int i = 0; i < p; i += 4)
  {
    const int n = ((p - i) > 4) ? 4 : (p - i);

    md2_absorb (ctx, v, n);
  }

  for (int i = 0; i < 4; i++) ctx->w[i] = ctx->c[i];

  md2_block (ctx);

  if (ctx->len < 0)
  {
    for (int i = 0; i < 4; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void md2_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS u32x *c, PRIVATE_AS const u32x *w, SHM_TYPE u32a *s_md2)
{
  u32x x[48];

  MD2_UNPACK (x,  0, h[0]);
  MD2_UNPACK (x,  4, h[1]);
  MD2_UNPACK (x,  8, h[2]);
  MD2_UNPACK (x, 12, h[3]);

  MD2_UNPACK (x, 16, w[0]);
  MD2_UNPACK (x, 20, w[1]);
  MD2_UNPACK (x, 24, w[2]);
  MD2_UNPACK (x, 28, w[3]);

  u32x k[16];

  MD2_UNPACK (k,  0, c[0]);
  MD2_UNPACK (k,  4, c[1]);
  MD2_UNPACK (k,  8, c[2]);
  MD2_UNPACK (k, 12, c[3]);

  u32x l = k[15];

  MD2_SUM (MD2_BOX, k, x, l);

  c[0] = MD2_PACK (k,  0);
  c[1] = MD2_PACK (k,  4);
  c[2] = MD2_PACK (k,  8);
  c[3] = MD2_PACK (k, 12);

  for (int i = 0; i < 16; i++) x[32 + i] = x[16 + i] ^ x[i];

  u32x t = 0;

  for (int j = 0; j < 18; j++)
  {
    MD2_ROW (MD2_BOX, x, t);

    t = (t + j) & 0xff;
  }

  h[0] = MD2_PACK (x,  0);
  h[1] = MD2_PACK (x,  4);
  h[2] = MD2_PACK (x,  8);
  h[3] = MD2_PACK (x, 12);
}

DECLSPEC void md2_init_vector (PRIVATE_AS md2_ctx_vector_t *ctx, SHM_TYPE u32a *s_md2)
{
  for (int i = 0; i < 4; i++) ctx->h[i] = 0;
  for (int i = 0; i < 4; i++) ctx->c[i] = 0;
  for (int i = 0; i < 4; i++) ctx->w[i] = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->s_md2 = s_md2;
}

DECLSPEC void md2_block_vector (PRIVATE_AS md2_ctx_vector_t *ctx)
{
  md2_transform_vector (ctx->h, ctx->c, ctx->w, ctx->s_md2);

  for (int i = 0; i < 4; i++) ctx->w[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void md2_absorb_vector (PRIVATE_AS md2_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 16 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->w[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->w[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    md2_block_vector (ctx);

    if (n > fit)
    {
      ctx->w[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void md2_update_vector (PRIVATE_AS md2_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    md2_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void md2_update_vector_utf16le (PRIVATE_AS md2_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    md2_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) md2_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void md2_final_vector (PRIVATE_AS md2_ctx_vector_t *ctx)
{
  const int p = 16 - ctx->pos;

  const u32 v = (u32) p * 0x01010101;

  for (int i = 0; i < p; i += 4)
  {
    const int n = ((p - i) > 4) ? 4 : (p - i);

    md2_absorb_vector (ctx, make_u32x (v), n);
  }

  for (int i = 0; i < 4; i++) ctx->w[i] = ctx->c[i];

  md2_block_vector (ctx);
}
