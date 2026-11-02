/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_echo.h"

// Input is little endian words, as for MD5. A partial last word may hold bytes past the length,
// which the updates mask off.

// ECHO reads its message and its state as little endian words and uses AES tables in the same
// byte order. The tables te0 to te3 of inc_cipher_aes.cl hold the same words byte swapped. Every
// other step is an XOR or works on single bytes, so the transforms swap the message words and the
// counter instead, and run the AES rounds in the form of inc_cipher_aes.cl. The chaining value
// stays swapped between blocks, and final swaps it back.

#if   VECT_SIZE == 1
#define ECHO_BOX(S,i) (S)[(i)]
#elif VECT_SIZE == 2
#define ECHO_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1])
#elif VECT_SIZE == 4
#define ECHO_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3])
#elif VECT_SIZE == 8
#define ECHO_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7])
#elif VECT_SIZE == 16
#define ECHO_BOX(S,i) make_u32x ((S)[(i).s0], (S)[(i).s1], (S)[(i).s2], (S)[(i).s3], (S)[(i).s4], (S)[(i).s5], (S)[(i).s6], (S)[(i).s7], (S)[(i).s8], (S)[(i).s9], (S)[(i).sa], (S)[(i).sb], (S)[(i).sc], (S)[(i).sd], (S)[(i).se], (S)[(i).sf])
#endif

#define ECHO_BOX_S(S,i) (S)[(i)]

// One unkeyed AES round of the 128 bit word X0 to X3 into Y0 to Y3. It reads the tables s_te0 to
// s_te3 of the calling function.

#define ECHO_AES_COL(BOX,Y,A,B,C,D)                                                                 \
{                                                                                                   \
  Y = BOX (s_te0, ((A) >> 24) & 0xff) ^ BOX (s_te1, ((B) >> 16) & 0xff)                             \
    ^ BOX (s_te2, ((C) >>  8) & 0xff) ^ BOX (s_te3, ((D) >>  0) & 0xff);                            \
}

#define ECHO_AES(BOX,X0,X1,X2,X3,Y0,Y1,Y2,Y3)                                                       \
{                                                                                                   \
  ECHO_AES_COL (BOX, Y0, X0, X1, X2, X3);                                                           \
  ECHO_AES_COL (BOX, Y1, X1, X2, X3, X0);                                                           \
  ECHO_AES_COL (BOX, Y2, X2, X3, X0, X1);                                                           \
  ECHO_AES_COL (BOX, Y3, X3, X0, X1, X2);                                                           \
}

// Both AES rounds of word S of the state w into word D of t. The first round is keyed by KEY + S,
// the counter plus the number of words processed before this one in the compression. D is where
// the row shift of the round moves word S.

#define ECHO_SUB_WORD(T,BOX,KEY,S,D)                                                                \
{                                                                                                   \
  T y0;                                                                                             \
  T y1;                                                                                             \
  T y2;                                                                                             \
  T y3;                                                                                             \
                                                                                                    \
  ECHO_AES (BOX, w[((S) * 4) + 0], w[((S) * 4) + 1], w[((S) * 4) + 2], w[((S) * 4) + 3],            \
            y0, y1, y2, y3);                                                                        \
                                                                                                    \
  y0 ^= hc_swap32_S (l32_from_64_S ((KEY) + (S)));                                                  \
  y1 ^= hc_swap32_S (h32_from_64_S ((KEY) + (S)));                                                  \
                                                                                                    \
  ECHO_AES (BOX, y0, y1, y2, y3,                                                                    \
            t[((D) * 4) + 0], t[((D) * 4) + 1], t[((D) * 4) + 2], t[((D) * 4) + 3]);                \
}

// One compression of the block M into the swapped chaining value V of NV words. The state holds
// 16 words of 128 bits, first V and then M, where word 4 * j + i sits in column j and row i. Each
// round applies 2 AES rounds to every word, the first keyed and the second not. Row i then
// shifts left by i columns, so word 4 * j + i moves to column (j - i) & 3, and the columns mix
// byte by byte as in AES. At the end, the input and output words at the same position modulo NV
// fold into V. The upper 64 bits of the counter stay zero for any message length an int can hold,
// so they are left out. The 16 words are written out rather than looped over, which keeps every
// index constant and the state in registers on compilers that would not unroll the loop.

#define ECHO_TRANSFORM(T,BOX,SWAP,V,M,CNT,NV,ROUNDS)                                                \
{                                                                                                   \
  T w[64];                                                                                          \
                                                                                                    \
  for (u32 i = 0; i < (NV); i++) w[i] = (V)[i];                                                     \
                                                                                                    \
  for (u32 i = (NV); i < 64; i++) w[i] = SWAP ((M)[i - (NV)]);                                      \
                                                                                                    \
  u64 key = (CNT);                                                                                  \
                                                                                                    \
  for (u32 r = 0; r < (ROUNDS); r++)                                                                \
  {                                                                                                 \
    T t[64];                                                                                        \
                                                                                                    \
    ECHO_SUB_WORD (T, BOX, key,  0,  0);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  1, 13);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  2, 10);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  3,  7);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  4,  4);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  5,  1);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  6, 14);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  7, 11);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  8,  8);                                                            \
    ECHO_SUB_WORD (T, BOX, key,  9,  5);                                                            \
    ECHO_SUB_WORD (T, BOX, key, 10,  2);                                                            \
    ECHO_SUB_WORD (T, BOX, key, 11, 15);                                                            \
    ECHO_SUB_WORD (T, BOX, key, 12, 12);                                                            \
    ECHO_SUB_WORD (T, BOX, key, 13,  9);                                                            \
    ECHO_SUB_WORD (T, BOX, key, 14,  6);                                                            \
    ECHO_SUB_WORD (T, BOX, key, 15,  3);                                                            \
                                                                                                    \
    key += 16;                                                                                      \
                                                                                                    \
    for (u32 j = 0; j < 4; j++)                                                                     \
    {                                                                                               \
      for (u32 n = 0; n < 4; n++)                                                                   \
      {                                                                                             \
        const T x0 = t[(j * 16) +  0 + n];                                                          \
        const T x1 = t[(j * 16) +  4 + n];                                                          \
        const T x2 = t[(j * 16) +  8 + n];                                                          \
        const T x3 = t[(j * 16) + 12 + n];                                                          \
                                                                                                    \
        const T x01 = x0 ^ x1;                                                                      \
        const T x12 = x1 ^ x2;                                                                      \
        const T x23 = x2 ^ x3;                                                                      \
                                                                                                    \
        const T d01 = (((x01 & 0x80808080) >> 7) * 27) ^ ((x01 & 0x7f7f7f7f) << 1);                 \
        const T d12 = (((x12 & 0x80808080) >> 7) * 27) ^ ((x12 & 0x7f7f7f7f) << 1);                 \
        const T d23 = (((x23 & 0x80808080) >> 7) * 27) ^ ((x23 & 0x7f7f7f7f) << 1);                 \
                                                                                                    \
        w[(j * 16) +  0 + n] = d01 ^ x12 ^ x3;                                                      \
        w[(j * 16) +  4 + n] = d12 ^ x0  ^ x23;                                                     \
        w[(j * 16) +  8 + n] = d23 ^ x01 ^ x3;                                                      \
        w[(j * 16) + 12 + n] = d01 ^ d12 ^ d23 ^ x01 ^ x2;                                          \
      }                                                                                             \
    }                                                                                               \
  }                                                                                                 \
                                                                                                    \
  for (u32 i = 0; i < (NV); i++) (V)[i] ^= w[i];                                                    \
                                                                                                    \
  for (u32 i = (NV); i < 64; i++) (V)[i & ((NV) - 1)] ^= SWAP ((M)[i - (NV)]) ^ w[i];               \
}

// ECHO-256, for digests of 28 and 32 bytes, with blocks of 192 bytes and 8 rounds

DECLSPEC void echo256_transform (PRIVATE_AS u32 *v, PRIVATE_AS const u32 *m, const u64 cnt, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  ECHO_TRANSFORM (u32, ECHO_BOX_S, hc_swap32_S, v, m, cnt, 16, 8);
}

// Every 128 bit word of the chaining value starts as the digest size in bits, byte swapped here.

DECLSPEC void echo256_init (PRIVATE_AS echo256_ctx_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  for (u32 i = 0; i < 16; i++) ctx->v[i] = ((i & 3) == 0) ? hc_swap32_S ((u32) (dlen * 8)) : 0;

  for (u32 i = 0; i < 48; i++) ctx->m[i] = 0;

  ctx->cnt = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->dlen = dlen;

  ctx->s_te0 = s_te0;
  ctx->s_te1 = s_te1;
  ctx->s_te2 = s_te2;
  ctx->s_te3 = s_te3;
}

// Process the full block in m. Its counter includes the bits of the block itself.

DECLSPEC void echo256_block (PRIVATE_AS echo256_ctx_t *ctx)
{
  ctx->cnt += 192 * 8;

  echo256_transform (ctx->v, ctx->m, ctx->cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

  for (u32 i = 0; i < 48; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, process it and use any remaining
// bytes to start the next block.

DECLSPEC void echo256_absorb (PRIVATE_AS echo256_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 192 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->m[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    echo256_block (ctx);

    if (n > fit)
    {
      ctx->m[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void echo256_update (PRIVATE_AS echo256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    echo256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void echo256_absorb_utf16le (PRIVATE_AS echo256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  echo256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) echo256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void echo256_update_utf16le (PRIVATE_AS echo256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      echo256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    echo256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void echo256_update_global (PRIVATE_AS echo256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    echo256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void echo256_update_global_utf16le (PRIVATE_AS echo256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      echo256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    echo256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// The padding is a 0x80 byte and zeros, and the block ends with the digest size in bits as 2
// bytes and the message size in bits as 16 bytes, little endian. When these 18 bytes do not fit
// after the 0x80 byte, that block is processed and a block of only zeros and these bytes follows.
// A last block that holds no message bits is processed with a counter of 0. The chaining value,
// swapped back, is the digest. A context with invalid UTF-8 input produces a digest with every
// bit flipped, so that no candidate matches it by chance.

DECLSPEC void echo256_final (PRIVATE_AS echo256_ctx_t *ctx)
{
  const int pos = ctx->pos;

  const u64 bits = ctx->cnt + ((u64) pos * 8);

  u64 cnt = (pos > 0) ? bits : 0;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  if (pos >= (192 - 18))
  {
    echo256_transform (ctx->v, ctx->m, cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

    for (u32 i = 0; i < 48; i++) ctx->m[i] = 0;

    cnt = 0;
  }

  ctx->m[43] |= ((u32) (ctx->dlen * 8)) << 16;
  ctx->m[44]  = l32_from_64_S (bits);
  ctx->m[45]  = h32_from_64_S (bits);

  echo256_transform (ctx->v, ctx->m, cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

  for (u32 i = 0; i < 16; i++) ctx->v[i] = hc_swap32_S (ctx->v[i]);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 16; i++) ctx->v[i] = ~ctx->v[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void echo256_transform_vector (PRIVATE_AS u32x *v, PRIVATE_AS const u32x *m, const u64 cnt, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  ECHO_TRANSFORM (u32x, ECHO_BOX, hc_swap32, v, m, cnt, 16, 8);
}

DECLSPEC void echo256_init_vector (PRIVATE_AS echo256_ctx_vector_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  for (u32 i = 0; i < 16; i++) ctx->v[i] = ((i & 3) == 0) ? hc_swap32_S ((u32) (dlen * 8)) : 0;

  for (u32 i = 0; i < 48; i++) ctx->m[i] = 0;

  ctx->cnt = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->dlen = dlen;

  ctx->s_te0 = s_te0;
  ctx->s_te1 = s_te1;
  ctx->s_te2 = s_te2;
  ctx->s_te3 = s_te3;
}

DECLSPEC void echo256_block_vector (PRIVATE_AS echo256_ctx_vector_t *ctx)
{
  ctx->cnt += 192 * 8;

  echo256_transform_vector (ctx->v, ctx->m, ctx->cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

  for (u32 i = 0; i < 48; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void echo256_absorb_vector (PRIVATE_AS echo256_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 192 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->m[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    echo256_block_vector (ctx);

    if (n > fit)
    {
      ctx->m[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void echo256_update_vector (PRIVATE_AS echo256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    echo256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void echo256_update_vector_utf16le (PRIVATE_AS echo256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    echo256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) echo256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void echo256_final_vector (PRIVATE_AS echo256_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  const u64 bits = ctx->cnt + ((u64) pos * 8);

  u64 cnt = (pos > 0) ? bits : 0;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  if (pos >= (192 - 18))
  {
    echo256_transform_vector (ctx->v, ctx->m, cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

    for (u32 i = 0; i < 48; i++) ctx->m[i] = 0;

    cnt = 0;
  }

  ctx->m[43] |= ((u32) (ctx->dlen * 8)) << 16;
  ctx->m[44]  = l32_from_64_S (bits);
  ctx->m[45]  = h32_from_64_S (bits);

  echo256_transform_vector (ctx->v, ctx->m, cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

  for (u32 i = 0; i < 16; i++) ctx->v[i] = hc_swap32 (ctx->v[i]);
}

// ECHO-512, for digests of 48 and 64 bytes, with blocks of 128 bytes and 10 rounds

DECLSPEC void echo512_transform (PRIVATE_AS u32 *v, PRIVATE_AS const u32 *m, const u64 cnt, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  ECHO_TRANSFORM (u32, ECHO_BOX_S, hc_swap32_S, v, m, cnt, 32, 10);
}

DECLSPEC void echo512_init (PRIVATE_AS echo512_ctx_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  for (u32 i = 0; i < 32; i++) ctx->v[i] = ((i & 3) == 0) ? hc_swap32_S ((u32) (dlen * 8)) : 0;

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->cnt = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->dlen = dlen;

  ctx->s_te0 = s_te0;
  ctx->s_te1 = s_te1;
  ctx->s_te2 = s_te2;
  ctx->s_te3 = s_te3;
}

DECLSPEC void echo512_block (PRIVATE_AS echo512_ctx_t *ctx)
{
  ctx->cnt += 128 * 8;

  echo512_transform (ctx->v, ctx->m, ctx->cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void echo512_absorb (PRIVATE_AS echo512_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32 x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->m[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    echo512_block (ctx);

    if (n > fit)
    {
      ctx->m[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void echo512_update (PRIVATE_AS echo512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    echo512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void echo512_absorb_utf16le (PRIVATE_AS echo512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  echo512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) echo512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void echo512_update_utf16le (PRIVATE_AS echo512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      echo512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    echo512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void echo512_update_global (PRIVATE_AS echo512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    echo512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void echo512_update_global_utf16le (PRIVATE_AS echo512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      echo512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    echo512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void echo512_final (PRIVATE_AS echo512_ctx_t *ctx)
{
  const int pos = ctx->pos;

  const u64 bits = ctx->cnt + ((u64) pos * 8);

  u64 cnt = (pos > 0) ? bits : 0;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  if (pos >= (128 - 18))
  {
    echo512_transform (ctx->v, ctx->m, cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

    for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

    cnt = 0;
  }

  ctx->m[27] |= ((u32) (ctx->dlen * 8)) << 16;
  ctx->m[28]  = l32_from_64_S (bits);
  ctx->m[29]  = h32_from_64_S (bits);

  echo512_transform (ctx->v, ctx->m, cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

  for (u32 i = 0; i < 32; i++) ctx->v[i] = hc_swap32_S (ctx->v[i]);

  if (ctx->len < 0)
  {
    for (u32 i = 0; i < 32; i++) ctx->v[i] = ~ctx->v[i];
  }
}

DECLSPEC void echo512_transform_vector (PRIVATE_AS u32x *v, PRIVATE_AS const u32x *m, const u64 cnt, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  ECHO_TRANSFORM (u32x, ECHO_BOX, hc_swap32, v, m, cnt, 32, 10);
}

DECLSPEC void echo512_init_vector (PRIVATE_AS echo512_ctx_vector_t *ctx, const int dlen, SHM_TYPE const u32 *s_te0, SHM_TYPE const u32 *s_te1, SHM_TYPE const u32 *s_te2, SHM_TYPE const u32 *s_te3)
{
  for (u32 i = 0; i < 32; i++) ctx->v[i] = ((i & 3) == 0) ? hc_swap32_S ((u32) (dlen * 8)) : 0;

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->cnt = 0;

  ctx->pos = 0;
  ctx->len = 0;

  ctx->dlen = dlen;

  ctx->s_te0 = s_te0;
  ctx->s_te1 = s_te1;
  ctx->s_te2 = s_te2;
  ctx->s_te3 = s_te3;
}

DECLSPEC void echo512_block_vector (PRIVATE_AS echo512_ctx_vector_t *ctx)
{
  ctx->cnt += 128 * 8;

  echo512_transform_vector (ctx->v, ctx->m, ctx->cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

  for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

  ctx->pos = 0;
}

DECLSPEC void echo512_absorb_vector (PRIVATE_AS echo512_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u32x x = v & mask;

  const int idx = pos / 4;
  const int off = pos & 3;

  ctx->m[idx] |= x << (off * 8);

  if ((off + fit) > 4) ctx->m[idx + 1] |= x >> ((4 - off) * 8);

  if (fit == room)
  {
    echo512_block_vector (ctx);

    if (n > fit)
    {
      ctx->m[0] = v >> (fit * 8);

      ctx->pos = n - fit;
    }
  }
  else
  {
    ctx->pos = pos + fit;
  }
}

DECLSPEC void echo512_update_vector (PRIVATE_AS echo512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    echo512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void echo512_update_vector_utf16le (PRIVATE_AS echo512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    echo512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) echo512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void echo512_final_vector (PRIVATE_AS echo512_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  const u64 bits = ctx->cnt + ((u64) pos * 8);

  u64 cnt = (pos > 0) ? bits : 0;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  if (pos >= (128 - 18))
  {
    echo512_transform_vector (ctx->v, ctx->m, cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

    for (u32 i = 0; i < 32; i++) ctx->m[i] = 0;

    cnt = 0;
  }

  ctx->m[27] |= ((u32) (ctx->dlen * 8)) << 16;
  ctx->m[28]  = l32_from_64_S (bits);
  ctx->m[29]  = h32_from_64_S (bits);

  echo512_transform_vector (ctx->v, ctx->m, cnt, ctx->s_te0, ctx->s_te1, ctx->s_te2, ctx->s_te3);

  for (u32 i = 0; i < 32; i++) ctx->v[i] = hc_swap32 (ctx->v[i]);
}
