/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_shabal.h"

// Input is little endian words, as for MD5: Shabal reads its blocks as little endian words. A
// partial last word may hold bytes past the length, which the updates mask off.

// The initial states A, B and C for digests of 28, 32, 48 and 64 bytes

CONSTANT_VK u32a shabal_iv_a[4][12] =
{
  { 0xa5201467, 0xa9b8d94a, 0xd4ced997, 0x68379d7b,
    0xa7fc73ba, 0xf1a2546b, 0x606782bf, 0xe0bcfd0f,
    0x2f25374e, 0x069a149f, 0x5e2dff25, 0xfaecf061 },
  { 0x52f84552, 0xe54b7999, 0x2d8ee3ec, 0xb9645191,
    0xe0078b86, 0xbb7c44c9, 0xd2b5c1ca, 0xb0d2eb8c,
    0x14ce5a45, 0x22af50dc, 0xeffdbc6b, 0xeb21b74a },
  { 0xc8fca331, 0xe55c504e, 0x003ebf26, 0xbb6b8d83,
    0x7b0448c1, 0x41b82789, 0x0a7c9601, 0x8d659cff,
    0xb6e2673e, 0xca54c77b, 0x1460fd7e, 0x3fcb8f2d },
  { 0x20728dfd, 0x46c0bd53, 0xe782b699, 0x55304632,
    0x71b4ef90, 0x0ea9e82c, 0xdbb930f1, 0xfad06b8b,
    0xbe0cae40, 0x8bd14410, 0x76d2adac, 0x28acab7f },
};

CONSTANT_VK u32a shabal_iv_b[4][16] =
{
  { 0xec9905d8, 0xf21850cf, 0xc0a746c8, 0x21dad498,
    0x35156eeb, 0x088c97f2, 0x26303e40, 0x8a2d4fb5,
    0xfeee44b6, 0x8a1e9573, 0x7b81111a, 0xcbc139f0,
    0xa3513861, 0x1d2c362e, 0x918c580e, 0xb58e1b9c },
  { 0xb555c6ee, 0x3e710596, 0xa72a652f, 0x9301515f,
    0xda28c1fa, 0x696fd868, 0x9cb6bf72, 0x0afe4002,
    0xa6e03615, 0x5138c1d4, 0xbe216306, 0xb38b8890,
    0x3ea8b96b, 0x3299ace4, 0x30924dd4, 0x55cb34a5 },
  { 0x527291fc, 0x2a16455f, 0x78e627e5, 0x944f169f,
    0x1ca6f016, 0xa854ea25, 0x8db98abe, 0xf2c62641,
    0x30117dcb, 0xcf5c4309, 0x93711a25, 0xf9f671b8,
    0xb01d2116, 0x333f4b89, 0xb285d165, 0x86829b36 },
  { 0xc1099cb7, 0x07b385f3, 0xe7442c26, 0xcc8ad640,
    0xeb6f56c7, 0x1ea81aa9, 0x73b9d314, 0x1de85d08,
    0x48910a5a, 0x893b22db, 0xc5a0df44, 0xbbc4324e,
    0x72d2f240, 0x75941d99, 0x6d8bde82, 0xa1a7502b },
};

CONSTANT_VK u32a shabal_iv_c[4][16] =
{
  { 0xe4b573a1, 0x4c1a0880, 0x1e907c51, 0x04807efd,
    0x3ad8cde5, 0x16b21302, 0x02512c53, 0x2204cb18,
    0x99405f2d, 0xe5b648a1, 0x70ab1d43, 0xa10c25c2,
    0x16f1ac05, 0x38bbeb56, 0x9b01dc60, 0xb1096d83 },
  { 0xb405f031, 0xc4233eba, 0xb3733979, 0xc0dd9d55,
    0xc51c28ae, 0xa327b8e1, 0x56c56167, 0xed614433,
    0x88b59d60, 0x60e2ceba, 0x758b4b8b, 0x83e82a7f,
    0xbc968828, 0xe6e00bf7, 0xba839e55, 0x9b491c60 },
  { 0xf764b11a, 0x76172146, 0xcef6934d, 0xc6d28399,
    0xfe095f61, 0x5e6018b4, 0x5048ecf5, 0x51353261,
    0x6e6e36dc, 0x63130dad, 0xa9c69bd6, 0x1e90ea0c,
    0x7c35073b, 0x28d95e6d, 0xaa340e0d, 0xcb3dee70 },
  { 0xd9bf68d1, 0x58bad750, 0x56028cb2, 0x8134f359,
    0xb5d469d8, 0x941a8cc2, 0x418b2a6e, 0x04052780,
    0x7f07d787, 0x5194358f, 0x3c60d665, 0xbe97d79a,
    0x950c3434, 0xaed9a06d, 0x2537dc8d, 0x7cdb5969 },
};

// One element of the keyed permutation P. O is the position in A where the step starts, which
// moves by 4 words per step of 16 elements, and I is the element of the step. Every index is a
// constant, so that A, B and C can stay in registers.

#define SHABAL_ELT(ROTL,A,B,C,M,O,I)                                            \
{                                                                               \
  const int ja = ((O) + (I) +  0) % 12;                                         \
  const int jp = ((O) + (I) + 11) % 12;                                         \
                                                                                \
  A[ja] = ((A[ja] ^ (ROTL (A[jp], 15) * 5u) ^ C[(24 - (I)) & 15]) * 3u)         \
        ^ B[((I) + 13) & 15] ^ (B[((I) + 9) & 15] & ~B[((I) + 6) & 15]) ^ M[I]; \
                                                                                \
  B[I] = ~(ROTL (B[I], 1) ^ A[ja]);                                             \
}

#define SHABAL_STEP(ROTL,A,B,C,M,O)                                             \
{                                                                               \
  SHABAL_ELT (ROTL, A, B, C, M, O,  0);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  1);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  2);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  3);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  4);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  5);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  6);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  7);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  8);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O,  9);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O, 10);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O, 11);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O, 12);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O, 13);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O, 14);                                         \
  SHABAL_ELT (ROTL, A, B, C, M, O, 15);                                         \
}

// The counter W goes into A first. P then mixes the block M into A and B, keyed by C, in 3 steps,
// and adds 3 words of C to every word of A.

#define SHABAL_PERM(ROTL,A,B,C,M,CNT)                                           \
{                                                                               \
  A[0] ^= (u32) ((CNT) >>  0);                                                  \
  A[1] ^= (u32) ((CNT) >> 32);                                                  \
                                                                                \
  for (u32 i = 0; i < 16; i++) B[i] = ROTL (B[i], 17);                          \
                                                                                \
  SHABAL_STEP (ROTL, A, B, C, M, 0);                                            \
  SHABAL_STEP (ROTL, A, B, C, M, 4);                                            \
  SHABAL_STEP (ROTL, A, B, C, M, 8);                                            \
                                                                                \
  for (u32 i = 0; i < 12; i++)                                                  \
  {                                                                             \
    A[i] += C[(i + 3) & 15] + C[(i + 11) & 15] + C[(i + 15) & 15];              \
  }                                                                             \
}

DECLSPEC int shabal_iv_index (const int dlen)
{
  if (dlen == 28) return 0;
  if (dlen == 32) return 1;
  if (dlen == 48) return 2;

  return 3;
}

DECLSPEC void shabal_perm (PRIVATE_AS shabal_ctx_t *ctx)
{
  SHABAL_PERM (hc_rotl32_S, ctx->a, ctx->b, ctx->c, ctx->m, ctx->cnt);
}

DECLSPEC void shabal_init (PRIVATE_AS shabal_ctx_t *ctx, const int dlen)
{
  const int iv = shabal_iv_index (dlen);

  for (u32 i = 0; i < 12; i++) ctx->a[i] = shabal_iv_a[iv][i];
  for (u32 i = 0; i < 16; i++) ctx->b[i] = shabal_iv_b[iv][i];
  for (u32 i = 0; i < 16; i++) ctx->c[i] = shabal_iv_c[iv][i];
  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 1;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

// Process the full block in m: add it to B, apply P, subtract it from C and swap B and C.

DECLSPEC void shabal_block (PRIVATE_AS shabal_ctx_t *ctx)
{
  for (u32 i = 0; i < 16; i++) ctx->b[i] += ctx->m[i];

  shabal_perm (ctx);

  for (u32 i = 0; i < 16; i++)
  {
    const u32 t = ctx->c[i] - ctx->m[i];

    ctx->c[i] = ctx->b[i];
    ctx->b[i] = t;
  }

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt += 1;
  ctx->pos  = 0;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, process it and use any remaining
// bytes to start the next block.

DECLSPEC void shabal_absorb (PRIVATE_AS shabal_ctx_t *ctx, const u32 v, const int n)
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

  shabal_block (ctx);

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void shabal_update (PRIVATE_AS shabal_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shabal_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void shabal_absorb_utf16le (PRIVATE_AS shabal_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  shabal_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) shabal_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void shabal_update_utf16le (PRIVATE_AS shabal_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      shabal_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shabal_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void shabal_update_global (PRIVATE_AS shabal_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shabal_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void shabal_update_global_utf16le (PRIVATE_AS shabal_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      shabal_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    shabal_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x80 byte and zeros up to the end of the block, with no length. The last block is
// added to B and goes through P, then 3 more rounds of swapping B and C and applying P follow,
// with the same block and counter. A context with invalid UTF-8 input produces a digest with
// every bit flipped, so that no candidate matches it by chance.

DECLSPEC void shabal_final (PRIVATE_AS shabal_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  for (u32 i = 0; i < 16; i++) ctx->b[i] += ctx->m[i];

  shabal_perm (ctx);

  for (u32 r = 0; r < 3; r++)
  {
    for (u32 i = 0; i < 16; i++)
    {
      const u32 t = ctx->b[i];

      ctx->b[i] = ctx->c[i];
      ctx->c[i] = t;
    }

    shabal_perm (ctx);
  }

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 16; i++) ctx->b[i] = ~ctx->b[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void shabal_perm_vector (PRIVATE_AS shabal_ctx_vector_t *ctx)
{
  SHABAL_PERM (hc_rotl32, ctx->a, ctx->b, ctx->c, ctx->m, ctx->cnt);
}

DECLSPEC void shabal_init_vector (PRIVATE_AS shabal_ctx_vector_t *ctx, const int dlen)
{
  const int iv = shabal_iv_index (dlen);

  for (u32 i = 0; i < 12; i++) ctx->a[i] = make_u32x (shabal_iv_a[iv][i]);
  for (u32 i = 0; i < 16; i++) ctx->b[i] = make_u32x (shabal_iv_b[iv][i]);
  for (u32 i = 0; i < 16; i++) ctx->c[i] = make_u32x (shabal_iv_c[iv][i]);
  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 1;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = dlen;
}

DECLSPEC void shabal_block_vector (PRIVATE_AS shabal_ctx_vector_t *ctx)
{
  for (u32 i = 0; i < 16; i++) ctx->b[i] += ctx->m[i];

  shabal_perm_vector (ctx);

  for (u32 i = 0; i < 16; i++)
  {
    const u32x t = ctx->c[i] - ctx->m[i];

    ctx->c[i] = ctx->b[i];
    ctx->b[i] = t;
  }

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt += 1;
  ctx->pos  = 0;
}

DECLSPEC void shabal_absorb_vector (PRIVATE_AS shabal_ctx_vector_t *ctx, const u32x v, const int n)
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

  shabal_block_vector (ctx);

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void shabal_update_vector (PRIVATE_AS shabal_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    shabal_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void shabal_update_vector_utf16le (PRIVATE_AS shabal_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    shabal_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) shabal_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void shabal_final_vector (PRIVATE_AS shabal_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  for (u32 i = 0; i < 16; i++) ctx->b[i] += ctx->m[i];

  shabal_perm_vector (ctx);

  for (u32 r = 0; r < 3; r++)
  {
    for (u32 i = 0; i < 16; i++)
    {
      const u32x t = ctx->b[i];

      ctx->b[i] = ctx->c[i];
      ctx->c[i] = t;
    }

    shabal_perm_vector (ctx);
  }
}
