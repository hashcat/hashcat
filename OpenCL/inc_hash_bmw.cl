/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_bmw.h"

// Input is little endian words, as for MD5: BMW reads its blocks as little endian 32 or 64 bit
// words. A partial last word may hold bytes past the length, which the updates mask off.

// The functions s0 to s5 and r1 to r7 and the constants K16 to K31 of the specification. The 2
// cores differ only in their rotation counts and in K.

#define BMW_S(ROTL,X,SR,SL,R1,R2) (((X) >> (SR)) ^ ((X) << (SL)) ^ ROTL ((X), (R1)) ^ ROTL ((X), (R2)))

#define BMW_S4(X) (((X) >> 1) ^ (X))
#define BMW_S5(X) (((X) >> 2) ^ (X))

#define BMW256_S0(ROTL,X) BMW_S (ROTL, X, 1, 3,  4, 19)
#define BMW256_S1(ROTL,X) BMW_S (ROTL, X, 1, 2,  8, 23)
#define BMW256_S2(ROTL,X) BMW_S (ROTL, X, 2, 1, 12, 25)
#define BMW256_S3(ROTL,X) BMW_S (ROTL, X, 2, 2, 15, 29)

#define BMW256_R1  3
#define BMW256_R2  7
#define BMW256_R3 13
#define BMW256_R4 16
#define BMW256_R5 19
#define BMW256_R6 23
#define BMW256_R7 27

#define BMW256_K(J) ((u32) (J) * 0x05555555)

#define BMW512_S0(ROTL,X) BMW_S (ROTL, X, 1, 3,  4, 37)
#define BMW512_S1(ROTL,X) BMW_S (ROTL, X, 1, 2, 13, 43)
#define BMW512_S2(ROTL,X) BMW_S (ROTL, X, 2, 1, 19, 53)
#define BMW512_S3(ROTL,X) BMW_S (ROTL, X, 2, 2, 28, 59)

#define BMW512_R1  5
#define BMW512_R2 11
#define BMW512_R3 27
#define BMW512_R4 32
#define BMW512_R5 37
#define BMW512_R6 43
#define BMW512_R7 53

#define BMW512_K(J) ((u64) (J) * 0x0555555555555555)

// The message part of expanded word Q[J + 16]: 3 rotated message words, the constant, and a
// word of the chaining value.

#define BMW_ADD_ELT(ROTL,C,P,M,H,J)                                             \
  ((ROTL (M[(J)], (J) + 1)                                                      \
  + ROTL (M[((J) + 3) & 15], (((J) + 3) & 15) + 1)                              \
  - ROTL (M[((J) + 10) & 15], (((J) + 10) & 15) + 1)                            \
  + C (P##_K ((J) + 16))) ^ H[((J) + 7) & 15])

#define BMW_EXP1(ROTL,C,P,Q,M,H,J)                                              \
{                                                                               \
  Q[(J) + 16] = P##_S1 (ROTL, Q[(J) +  0]) + P##_S2 (ROTL, Q[(J) +  1])         \
              + P##_S3 (ROTL, Q[(J) +  2]) + P##_S0 (ROTL, Q[(J) +  3])         \
              + P##_S1 (ROTL, Q[(J) +  4]) + P##_S2 (ROTL, Q[(J) +  5])         \
              + P##_S3 (ROTL, Q[(J) +  6]) + P##_S0 (ROTL, Q[(J) +  7])         \
              + P##_S1 (ROTL, Q[(J) +  8]) + P##_S2 (ROTL, Q[(J) +  9])         \
              + P##_S3 (ROTL, Q[(J) + 10]) + P##_S0 (ROTL, Q[(J) + 11])         \
              + P##_S1 (ROTL, Q[(J) + 12]) + P##_S2 (ROTL, Q[(J) + 13])         \
              + P##_S3 (ROTL, Q[(J) + 14]) + P##_S0 (ROTL, Q[(J) + 15])         \
              + BMW_ADD_ELT (ROTL, C, P, M, H, J);                              \
}

#define BMW_EXP2(ROTL,C,P,Q,M,H,J)                                              \
{                                                                               \
  Q[(J) + 16] = Q[(J) +  0] + ROTL (Q[(J) +  1], P##_R1)                        \
              + Q[(J) +  2] + ROTL (Q[(J) +  3], P##_R2)                        \
              + Q[(J) +  4] + ROTL (Q[(J) +  5], P##_R3)                        \
              + Q[(J) +  6] + ROTL (Q[(J) +  7], P##_R4)                        \
              + Q[(J) +  8] + ROTL (Q[(J) +  9], P##_R5)                        \
              + Q[(J) + 10] + ROTL (Q[(J) + 11], P##_R6)                        \
              + Q[(J) + 12] + ROTL (Q[(J) + 13], P##_R7)                        \
              + BMW_S4 (Q[(J) + 14]) + BMW_S5 (Q[(J) + 15])                     \
              + BMW_ADD_ELT (ROTL, C, P, M, H, J);                              \
}

// One compression: the chaining value H and the block M give the new chaining value, written
// back to H. H is read only while Q is computed, so the update in place is safe. P selects the
// core, C turns a constant into the type T.

#define BMW_TRANSFORM(T,ROTL,C,P,H,M)                                           \
{                                                                               \
  T t[16];                                                                      \
                                                                                \
  for (u32 i = 0; i < 16; i++) t[i] = M[i] ^ H[i];                              \
                                                                                \
  T w[16];                                                                      \
                                                                                \
  w[ 0] = t[ 5] - t[ 7] + t[10] + t[13] + t[14];                                \
  w[ 1] = t[ 6] - t[ 8] + t[11] + t[14] - t[15];                                \
  w[ 2] = t[ 0] + t[ 7] + t[ 9] - t[12] + t[15];                                \
  w[ 3] = t[ 0] - t[ 1] + t[ 8] - t[10] + t[13];                                \
  w[ 4] = t[ 1] + t[ 2] + t[ 9] - t[11] - t[14];                                \
  w[ 5] = t[ 3] - t[ 2] + t[10] - t[12] + t[15];                                \
  w[ 6] = t[ 4] - t[ 0] - t[ 3] - t[11] + t[13];                                \
  w[ 7] = t[ 1] - t[ 4] - t[ 5] - t[12] - t[14];                                \
  w[ 8] = t[ 2] - t[ 5] - t[ 6] + t[13] - t[15];                                \
  w[ 9] = t[ 0] - t[ 3] + t[ 6] - t[ 7] + t[14];                                \
  w[10] = t[ 8] - t[ 1] - t[ 4] - t[ 7] + t[15];                                \
  w[11] = t[ 8] - t[ 0] - t[ 2] - t[ 5] + t[ 9];                                \
  w[12] = t[ 1] + t[ 3] - t[ 6] - t[ 9] + t[10];                                \
  w[13] = t[ 2] + t[ 4] + t[ 7] + t[10] + t[11];                                \
  w[14] = t[ 3] - t[ 5] + t[ 8] - t[11] - t[12];                                \
  w[15] = t[12] - t[ 4] - t[ 6] - t[ 9] + t[13];                                \
                                                                                \
  T q[32];                                                                      \
                                                                                \
  q[ 0] = P##_S0 (ROTL, w[ 0]) + H[ 1];                                         \
  q[ 1] = P##_S1 (ROTL, w[ 1]) + H[ 2];                                         \
  q[ 2] = P##_S2 (ROTL, w[ 2]) + H[ 3];                                         \
  q[ 3] = P##_S3 (ROTL, w[ 3]) + H[ 4];                                         \
  q[ 4] = BMW_S4 (w[ 4]) + H[ 5];                                               \
  q[ 5] = P##_S0 (ROTL, w[ 5]) + H[ 6];                                         \
  q[ 6] = P##_S1 (ROTL, w[ 6]) + H[ 7];                                         \
  q[ 7] = P##_S2 (ROTL, w[ 7]) + H[ 8];                                         \
  q[ 8] = P##_S3 (ROTL, w[ 8]) + H[ 9];                                         \
  q[ 9] = BMW_S4 (w[ 9]) + H[10];                                               \
  q[10] = P##_S0 (ROTL, w[10]) + H[11];                                         \
  q[11] = P##_S1 (ROTL, w[11]) + H[12];                                         \
  q[12] = P##_S2 (ROTL, w[12]) + H[13];                                         \
  q[13] = P##_S3 (ROTL, w[13]) + H[14];                                         \
  q[14] = BMW_S4 (w[14]) + H[15];                                               \
  q[15] = P##_S0 (ROTL, w[15]) + H[ 0];                                         \
                                                                                \
  BMW_EXP1 (ROTL, C, P, q, M, H,  0);                                           \
  BMW_EXP1 (ROTL, C, P, q, M, H,  1);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H,  2);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H,  3);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H,  4);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H,  5);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H,  6);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H,  7);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H,  8);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H,  9);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H, 10);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H, 11);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H, 12);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H, 13);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H, 14);                                           \
  BMW_EXP2 (ROTL, C, P, q, M, H, 15);                                           \
                                                                                \
  const T xl = q[16] ^ q[17] ^ q[18] ^ q[19] ^ q[20] ^ q[21] ^ q[22] ^ q[23];   \
  const T xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27] ^ q[28] ^ q[29] ^ q[30]       \
             ^ q[31];                                                           \
                                                                                \
  H[ 0] = ((xh <<  5) ^ (q[16] >>  5) ^ M[ 0]) + (xl ^ q[24] ^ q[ 0]);          \
  H[ 1] = ((xh >>  7) ^ (q[17] <<  8) ^ M[ 1]) + (xl ^ q[25] ^ q[ 1]);          \
  H[ 2] = ((xh >>  5) ^ (q[18] <<  5) ^ M[ 2]) + (xl ^ q[26] ^ q[ 2]);          \
  H[ 3] = ((xh >>  1) ^ (q[19] <<  5) ^ M[ 3]) + (xl ^ q[27] ^ q[ 3]);          \
  H[ 4] = ((xh >>  3) ^ (q[20] <<  0) ^ M[ 4]) + (xl ^ q[28] ^ q[ 4]);          \
  H[ 5] = ((xh <<  6) ^ (q[21] >>  6) ^ M[ 5]) + (xl ^ q[29] ^ q[ 5]);          \
  H[ 6] = ((xh >>  4) ^ (q[22] <<  6) ^ M[ 6]) + (xl ^ q[30] ^ q[ 6]);          \
  H[ 7] = ((xh >> 11) ^ (q[23] <<  2) ^ M[ 7]) + (xl ^ q[31] ^ q[ 7]);          \
                                                                                \
  H[ 8] = ROTL (H[4],  9) + (xh ^ q[24] ^ M[ 8]) + ((xl << 8) ^ q[23] ^ q[ 8]); \
  H[ 9] = ROTL (H[5], 10) + (xh ^ q[25] ^ M[ 9]) + ((xl >> 6) ^ q[16] ^ q[ 9]); \
  H[10] = ROTL (H[6], 11) + (xh ^ q[26] ^ M[10]) + ((xl << 6) ^ q[17] ^ q[10]); \
  H[11] = ROTL (H[7], 12) + (xh ^ q[27] ^ M[11]) + ((xl << 4) ^ q[18] ^ q[11]); \
  H[12] = ROTL (H[0], 13) + (xh ^ q[28] ^ M[12]) + ((xl >> 3) ^ q[19] ^ q[12]); \
  H[13] = ROTL (H[1], 14) + (xh ^ q[29] ^ M[13]) + ((xl >> 4) ^ q[20] ^ q[13]); \
  H[14] = ROTL (H[2], 15) + (xh ^ q[30] ^ M[14]) + ((xl >> 7) ^ q[21] ^ q[14]); \
  H[15] = ROTL (H[3], 16) + (xh ^ q[31] ^ M[15]) + ((xl >> 2) ^ q[22] ^ q[15]); \
}

#define BMW_C_S(V)   (V)
#define BMW_C_V32(V) make_u32x (V)
#define BMW_C_V64(V) make_u64x (V)

// The IV words count up bytewise: bmw224 starts with 0x00010203 and bmw256 with 0x40414243,
// bmw384 with 0x0001020304050607 and bmw512 with 0x8081828384858687. The last compression uses
// the chaining value 0xaa..a0, 0xaa..a1 and so on. A dlen other than 28 or 48 selects bmw256 or
// bmw512 with its full digest length, so that final never copies words from outside h.

#define BMW256_IV(DLEN)   (((DLEN) == 28) ? 0x00010203 : 0x40414243)
#define BMW256_IV_STEP    0x04040404
#define BMW256_FINAL      0xaaaaaaa0
#define BMW256_DLEN(DLEN) (((DLEN) == 28) ? 28 : 32)

#define BMW512_IV(DLEN)   (((DLEN) == 48) ? 0x0001020304050607 : 0x8081828384858687)
#define BMW512_IV_STEP    0x0808080808080808
#define BMW512_FINAL      0xaaaaaaaaaaaaaaa0
#define BMW512_DLEN(DLEN) (((DLEN) == 48) ? 48 : 64)

DECLSPEC void bmw256_transform (PRIVATE_AS u32 *h, PRIVATE_AS const u32 *m)
{
  BMW_TRANSFORM (u32, hc_rotl32_S, BMW_C_S, BMW256, h, m);
}

DECLSPEC void bmw256_init (PRIVATE_AS bmw256_ctx_t *ctx, const int dlen)
{
  const u32 iv = BMW256_IV (dlen);

  for (u32 i = 0; i < 16; i++) ctx->h[i] = iv + (i * BMW256_IV_STEP);
  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = BMW256_DLEN (dlen);
}

// Put the n bytes of v into the block at the current position, starting with its low bytes. The
// bytes of v beyond n are zero. When these bytes fill the block, compress it and use any remaining
// bytes to start the next block.

DECLSPEC void bmw256_absorb (PRIVATE_AS bmw256_ctx_t *ctx, const u32 v, const int n)
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

  bmw256_transform (ctx->h, ctx->m);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt += 64;
  ctx->pos  = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void bmw256_update (PRIVATE_AS bmw256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    bmw256_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

// Widen ASCII to UTF-16LE by placing a zero byte after each input byte, in 2 absorbs of up to 4
// bytes per word.

DECLSPEC void bmw256_absorb_utf16le (PRIVATE_AS bmw256_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  bmw256_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) bmw256_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void bmw256_update_utf16le (PRIVATE_AS bmw256_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      bmw256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    bmw256_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void bmw256_update_global (PRIVATE_AS bmw256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    bmw256_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void bmw256_update_global_utf16le (PRIVATE_AS bmw256_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      bmw256_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    bmw256_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

// Padding is a 0x80 byte, zeros and the message length in bits as a little endian 64 bit number
// at the end of the block. A last compression with the constant chaining value takes the result
// as its block, and the digest is the last dlen bytes of its output, moved to the start of h. A
// context with invalid UTF-8 input produces a digest with every bit flipped, so that no candidate
// matches it by chance.

DECLSPEC void bmw256_final (PRIVATE_AS bmw256_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  if (pos >= 56)
  {
    bmw256_transform (ctx->h, ctx->m);

    for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;
  }

  const u64 bits = (ctx->cnt + (u64) pos) * 8;

  ctx->m[14] = l32_from_64_S (bits);
  ctx->m[15] = h32_from_64_S (bits);

  bmw256_transform (ctx->h, ctx->m);

  for (u32 i = 0; i < 16; i++)
  {
    ctx->m[i] = ctx->h[i];
    ctx->h[i] = BMW256_FINAL + i;
  }

  bmw256_transform (ctx->h, ctx->m);

  const int nw = ctx->dlen / 4;

  for (int i = 0; i < nw; i++) ctx->h[i] = ctx->h[16 - nw + i];

  if (ctx->len < 0)
  {
    for (int i = 0; i < nw; i++) ctx->h[i] = ~ctx->h[i];
  }
}

// The vector flavor, for VECT_SIZE candidates whose parts have the same lengths. Its UTF-16LE
// update widens ASCII only, as the vector updates of the other families do.

DECLSPEC void bmw256_transform_vector (PRIVATE_AS u32x *h, PRIVATE_AS const u32x *m)
{
  BMW_TRANSFORM (u32x, hc_rotl32, BMW_C_V32, BMW256, h, m);
}

DECLSPEC void bmw256_init_vector (PRIVATE_AS bmw256_ctx_vector_t *ctx, const int dlen)
{
  const u32 iv = BMW256_IV (dlen);

  for (u32 i = 0; i < 16; i++) ctx->h[i] = make_u32x (iv + (i * BMW256_IV_STEP));
  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = BMW256_DLEN (dlen);
}

DECLSPEC void bmw256_absorb_vector (PRIVATE_AS bmw256_ctx_vector_t *ctx, const u32x v, const int n)
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

  bmw256_transform_vector (ctx->h, ctx->m);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt += 64;
  ctx->pos  = 0;

  if (n > fit)
  {
    ctx->m[0] = v >> (fit * 8);

    ctx->pos = n - fit;
  }
}

DECLSPEC void bmw256_update_vector (PRIVATE_AS bmw256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    bmw256_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void bmw256_update_vector_utf16le (PRIVATE_AS bmw256_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    bmw256_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) bmw256_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void bmw256_final_vector (PRIVATE_AS bmw256_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 4] |= 0x80u << ((pos & 3) * 8);

  if (pos >= 56)
  {
    bmw256_transform_vector (ctx->h, ctx->m);

    for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;
  }

  const u64 bits = (ctx->cnt + (u64) pos) * 8;

  ctx->m[14] = make_u32x (l32_from_64_S (bits));
  ctx->m[15] = make_u32x (h32_from_64_S (bits));

  bmw256_transform_vector (ctx->h, ctx->m);

  for (u32 i = 0; i < 16; i++)
  {
    ctx->m[i] = ctx->h[i];
    ctx->h[i] = make_u32x (BMW256_FINAL + i);
  }

  bmw256_transform_vector (ctx->h, ctx->m);

  const int nw = ctx->dlen / 4;

  for (int i = 0; i < nw; i++) ctx->h[i] = ctx->h[16 - nw + i];
}

// The 64 bit core works the same way on 128 byte blocks, with the length in the last 8 bytes.

DECLSPEC void bmw512_transform (PRIVATE_AS u64 *h, PRIVATE_AS const u64 *m)
{
  BMW_TRANSFORM (u64, hc_rotl64_S, BMW_C_S, BMW512, h, m);
}

DECLSPEC void bmw512_init (PRIVATE_AS bmw512_ctx_t *ctx, const int dlen)
{
  const u64 iv = BMW512_IV (dlen);

  for (u32 i = 0; i < 16; i++) ctx->h[i] = iv + ((u64) i * BMW512_IV_STEP);
  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = BMW512_DLEN (dlen);
}

DECLSPEC void bmw512_absorb (PRIVATE_AS bmw512_ctx_t *ctx, const u32 v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64 x = (u64) (v & mask);

  const int lane = pos / 8;
  const int off  = pos & 7;

  ctx->m[lane] |= x << (off * 8);

  if ((off + fit) > 8) ctx->m[lane + 1] |= x >> ((8 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  bmw512_transform (ctx->h, ctx->m);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt += 128;
  ctx->pos  = 0;

  if (n > fit)
  {
    ctx->m[0] = (u64) (v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void bmw512_update (PRIVATE_AS bmw512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    bmw512_absorb (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void bmw512_absorb_utf16le (PRIVATE_AS bmw512_ctx_t *ctx, const u32 v, const int n)
{
  const u32 lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
  const u32 hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

  bmw512_absorb (ctx, lo, ((n > 2) ? 2 : n) * 2);

  if (n > 2) bmw512_absorb (ctx, hi, (n - 2) * 2);
}

DECLSPEC void bmw512_update_utf16le (PRIVATE_AS bmw512_ctx_t *ctx, PRIVATE_AS const u32 *w, const int len)
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

      bmw512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    bmw512_absorb_utf16le (ctx, hc_bounded_word_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void bmw512_update_global (PRIVATE_AS bmw512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    bmw512_absorb (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void bmw512_update_global_utf16le (PRIVATE_AS bmw512_ctx_t *ctx, GLOBAL_AS const u32 *w, const int len)
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

      bmw512_update (ctx, enc_buf, enc_len);
    }

    return;
  }

  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    bmw512_absorb_utf16le (ctx, hc_bounded_word_global_le_S (w, i / 4, len - i), n);
  }
}

DECLSPEC void bmw512_final (PRIVATE_AS bmw512_ctx_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 8] |= ((u64) 0x80) << ((pos & 7) * 8);

  if (pos >= 120)
  {
    bmw512_transform (ctx->h, ctx->m);

    for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;
  }

  ctx->m[15] = (ctx->cnt + (u64) pos) * 8;

  bmw512_transform (ctx->h, ctx->m);

  for (u32 i = 0; i < 16; i++)
  {
    ctx->m[i] = ctx->h[i];
    ctx->h[i] = BMW512_FINAL + i;
  }

  bmw512_transform (ctx->h, ctx->m);

  const int nw = ctx->dlen / 8;

  for (int i = 0; i < nw; i++) ctx->h[i] = ctx->h[16 - nw + i];

  if (ctx->len < 0)
  {
    for (int i = 0; i < nw; i++) ctx->h[i] = ~ctx->h[i];
  }
}

DECLSPEC void bmw512_transform_vector (PRIVATE_AS u64x *h, PRIVATE_AS const u64x *m)
{
  BMW_TRANSFORM (u64x, hc_rotl64, BMW_C_V64, BMW512, h, m);
}

DECLSPEC void bmw512_init_vector (PRIVATE_AS bmw512_ctx_vector_t *ctx, const int dlen)
{
  const u64 iv = BMW512_IV (dlen);

  for (u32 i = 0; i < 16; i++) ctx->h[i] = make_u64x (iv + ((u64) i * BMW512_IV_STEP));
  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt  = 0;
  ctx->pos  = 0;
  ctx->len  = 0;
  ctx->dlen = BMW512_DLEN (dlen);
}

DECLSPEC void bmw512_absorb_vector (PRIVATE_AS bmw512_ctx_vector_t *ctx, const u32x v, const int n)
{
  const int pos = ctx->pos;

  const int room = 128 - pos;

  const int fit = (n > room) ? room : n;

  const u32 mask = (fit >= 4) ? 0xffffffff : ((1u << (fit * 8)) - 1);

  const u64x x = hl32_to_64 (0, v & mask);

  const int lane = pos / 8;
  const int off  = pos & 7;

  ctx->m[lane] |= x << (off * 8);

  if ((off + fit) > 8) ctx->m[lane + 1] |= x >> ((8 - off) * 8);

  if (fit < room)
  {
    ctx->pos = pos + fit;

    return;
  }

  bmw512_transform_vector (ctx->h, ctx->m);

  for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;

  ctx->cnt += 128;
  ctx->pos  = 0;

  if (n > fit)
  {
    ctx->m[0] = hl32_to_64 (0, v >> (fit * 8));

    ctx->pos = n - fit;
  }
}

DECLSPEC void bmw512_update_vector (PRIVATE_AS bmw512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    bmw512_absorb_vector (ctx, w[i / 4] & mask, n);
  }
}

DECLSPEC void bmw512_update_vector_utf16le (PRIVATE_AS bmw512_ctx_vector_t *ctx, PRIVATE_AS const u32x *w, const int len)
{
  if (ctx->len >= 0) ctx->len += len * 2;

  for (int i = 0; i < len; i += 4)
  {
    const int n = ((len - i) > 4) ? 4 : (len - i);

    const u32 mask = (n >= 4) ? 0xffffffff : ((1u << (n * 8)) - 1);

    const u32x v = w[i / 4] & mask;

    const u32x lo = ((v >>  0) & 0xff) | (((v >>  8) & 0xff) << 16);
    const u32x hi = ((v >> 16) & 0xff) | (((v >> 24) & 0xff) << 16);

    bmw512_absorb_vector (ctx, lo, ((n > 2) ? 2 : n) * 2);

    if (n > 2) bmw512_absorb_vector (ctx, hi, (n - 2) * 2);
  }
}

DECLSPEC void bmw512_final_vector (PRIVATE_AS bmw512_ctx_vector_t *ctx)
{
  const int pos = ctx->pos;

  ctx->m[pos / 8] |= make_u64x (((u64) 0x80) << ((pos & 7) * 8));

  if (pos >= 120)
  {
    bmw512_transform_vector (ctx->h, ctx->m);

    for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;
  }

  ctx->m[15] = make_u64x ((ctx->cnt + (u64) pos) * 8);

  bmw512_transform_vector (ctx->h, ctx->m);

  for (u32 i = 0; i < 16; i++)
  {
    ctx->m[i] = ctx->h[i];
    ctx->h[i] = make_u64x (BMW512_FINAL + i);
  }

  bmw512_transform_vector (ctx->h, ctx->m);

  const int nw = ctx->dlen / 8;

  for (int i = 0; i < nw; i++) ctx->h[i] = ctx->h[16 - nw + i];
}
