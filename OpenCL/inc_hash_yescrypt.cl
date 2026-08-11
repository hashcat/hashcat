/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_yescrypt.h"

DECLSPEC void yescrypt_simd_shuffle (PRIVATE_AS const u32 *src, PRIVATE_AS u32 *dst, const u32 r)
{
  for (u32 k = 0; k < 2 * r; k++)
  {
    const u32 off = k * 16;

    dst[off +  0] = src[off +  0];
    dst[off +  1] = src[off +  5];
    dst[off +  2] = src[off + 10];
    dst[off +  3] = src[off + 15];
    dst[off +  4] = src[off +  4];
    dst[off +  5] = src[off +  9];
    dst[off +  6] = src[off + 14];
    dst[off +  7] = src[off +  3];
    dst[off +  8] = src[off +  8];
    dst[off +  9] = src[off + 13];
    dst[off + 10] = src[off +  2];
    dst[off + 11] = src[off +  7];
    dst[off + 12] = src[off + 12];
    dst[off + 13] = src[off +  1];
    dst[off + 14] = src[off +  6];
    dst[off + 15] = src[off + 11];
  }
}

DECLSPEC void yescrypt_simd_unshuffle (PRIVATE_AS const u32 *src, PRIVATE_AS u32 *dst, const u32 r)
{
  for (u32 k = 0; k < 2 * r; k++)
  {
    const u32 off = k * 16;

    dst[off +  0] = src[off +  0];
    dst[off +  1] = src[off + 13];
    dst[off +  2] = src[off + 10];
    dst[off +  3] = src[off +  7];
    dst[off +  4] = src[off +  4];
    dst[off +  5] = src[off +  1];
    dst[off +  6] = src[off + 14];
    dst[off +  7] = src[off + 11];
    dst[off +  8] = src[off +  8];
    dst[off +  9] = src[off +  5];
    dst[off + 10] = src[off +  2];
    dst[off + 11] = src[off + 15];
    dst[off + 12] = src[off + 12];
    dst[off + 13] = src[off +  9];
    dst[off + 14] = src[off +  6];
    dst[off + 15] = src[off +  3];
  }
}

DECLSPEC u64 yescrypt_integerify (PRIVATE_AS const u32 *X, const u32 r)
{
  PRIVATE_AS const u32 *last = &X[(2 * r - 1) * 16];

  return ((u64) last[13] << 32) | last[0];
}

DECLSPEC u64 yescrypt_p2floor (u64 x)
{
  u64 y;

  while ((y = x & (x - 1)))
    x = y;

  return x;
}

DECLSPEC u64 yescrypt_wrap (u64 x, u64 i)
{
  u64 n = yescrypt_p2floor (i);

  return (x & (n - 1)) + (i - n);
}

DECLSPEC void yescrypt_salsa20_2 (PRIVATE_AS u32 *TI)
{
  u32 TT[16];

  for (int j = 0; j < 16; j++) TT[j] = TI[j];

  u32 t0, t1, t2, t3;

  t0 = TT[ 0] + TT[12]; t1 = TT[ 1] + TT[13]; t2 = TT[ 2] + TT[14]; t3 = TT[ 3] + TT[15];
  TT[ 4] ^= hc_rotl32_S (t0,  7); TT[ 5] ^= hc_rotl32_S (t1,  7); TT[ 6] ^= hc_rotl32_S (t2,  7); TT[ 7] ^= hc_rotl32_S (t3,  7);

  t0 = TT[ 4] + TT[ 0]; t1 = TT[ 5] + TT[ 1]; t2 = TT[ 6] + TT[ 2]; t3 = TT[ 7] + TT[ 3];
  TT[ 8] ^= hc_rotl32_S (t0,  9); TT[ 9] ^= hc_rotl32_S (t1,  9); TT[10] ^= hc_rotl32_S (t2,  9); TT[11] ^= hc_rotl32_S (t3,  9);

  t0 = TT[ 8] + TT[ 4]; t1 = TT[ 9] + TT[ 5]; t2 = TT[10] + TT[ 6]; t3 = TT[11] + TT[ 7];
  TT[12] ^= hc_rotl32_S (t0, 13); TT[13] ^= hc_rotl32_S (t1, 13); TT[14] ^= hc_rotl32_S (t2, 13); TT[15] ^= hc_rotl32_S (t3, 13);

  t0 = TT[12] + TT[ 8]; t1 = TT[13] + TT[ 9]; t2 = TT[14] + TT[10]; t3 = TT[15] + TT[11];
  TT[ 0] ^= hc_rotl32_S (t0, 18); TT[ 1] ^= hc_rotl32_S (t1, 18); TT[ 2] ^= hc_rotl32_S (t2, 18); TT[ 3] ^= hc_rotl32_S (t3, 18);

  t0 = TT[ 4]; TT[ 4] = TT[ 7]; TT[ 7] = TT[ 6]; TT[ 6] = TT[ 5]; TT[ 5] = t0;
  t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0; t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
  t0 = TT[12]; TT[12] = TT[13]; TT[13] = TT[14]; TT[14] = TT[15]; TT[15] = t0;

  t0 = TT[ 0] + TT[ 4]; t1 = TT[ 1] + TT[ 5]; t2 = TT[ 2] + TT[ 6]; t3 = TT[ 3] + TT[ 7];
  TT[12] ^= hc_rotl32_S (t0,  7); TT[13] ^= hc_rotl32_S (t1,  7); TT[14] ^= hc_rotl32_S (t2,  7); TT[15] ^= hc_rotl32_S (t3,  7);

  t0 = TT[12] + TT[ 0]; t1 = TT[13] + TT[ 1]; t2 = TT[14] + TT[ 2]; t3 = TT[15] + TT[ 3];
  TT[ 8] ^= hc_rotl32_S (t0,  9); TT[ 9] ^= hc_rotl32_S (t1,  9); TT[10] ^= hc_rotl32_S (t2,  9); TT[11] ^= hc_rotl32_S (t3,  9);

  t0 = TT[ 8] + TT[12]; t1 = TT[ 9] + TT[13]; t2 = TT[10] + TT[14]; t3 = TT[11] + TT[15];
  TT[ 4] ^= hc_rotl32_S (t0, 13); TT[ 5] ^= hc_rotl32_S (t1, 13); TT[ 6] ^= hc_rotl32_S (t2, 13); TT[ 7] ^= hc_rotl32_S (t3, 13);

  t0 = TT[ 4] + TT[ 8]; t1 = TT[ 5] + TT[ 9]; t2 = TT[ 6] + TT[10]; t3 = TT[ 7] + TT[11];
  TT[ 0] ^= hc_rotl32_S (t0, 18); TT[ 1] ^= hc_rotl32_S (t1, 18); TT[ 2] ^= hc_rotl32_S (t2, 18); TT[ 3] ^= hc_rotl32_S (t3, 18);

  t0 = TT[ 4]; TT[ 4] = TT[ 5]; TT[ 5] = TT[ 6]; TT[ 6] = TT[ 7]; TT[ 7] = t0;
  t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0; t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
  t0 = TT[15]; TT[15] = TT[14]; TT[14] = TT[13]; TT[13] = TT[12]; TT[12] = t0;

  for (int j = 0; j < 16; j++) TI[j] += TT[j];
}

DECLSPEC void yescrypt_salsa20_8 (PRIVATE_AS u32 *TI)
{
  u32 TT[16];

  for (int j = 0; j < 16; j++) TT[j] = TI[j];

  for (int rnd = 0; rnd < 4; rnd++)
  {
    u32 t0, t1, t2, t3;

    t0 = TT[ 0] + TT[12]; t1 = TT[ 1] + TT[13]; t2 = TT[ 2] + TT[14]; t3 = TT[ 3] + TT[15];
    TT[ 4] ^= hc_rotl32_S (t0,  7); TT[ 5] ^= hc_rotl32_S (t1,  7); TT[ 6] ^= hc_rotl32_S (t2,  7); TT[ 7] ^= hc_rotl32_S (t3,  7);

    t0 = TT[ 4] + TT[ 0]; t1 = TT[ 5] + TT[ 1]; t2 = TT[ 6] + TT[ 2]; t3 = TT[ 7] + TT[ 3];
    TT[ 8] ^= hc_rotl32_S (t0,  9); TT[ 9] ^= hc_rotl32_S (t1,  9); TT[10] ^= hc_rotl32_S (t2,  9); TT[11] ^= hc_rotl32_S (t3,  9);

    t0 = TT[ 8] + TT[ 4]; t1 = TT[ 9] + TT[ 5]; t2 = TT[10] + TT[ 6]; t3 = TT[11] + TT[ 7];
    TT[12] ^= hc_rotl32_S (t0, 13); TT[13] ^= hc_rotl32_S (t1, 13); TT[14] ^= hc_rotl32_S (t2, 13); TT[15] ^= hc_rotl32_S (t3, 13);

    t0 = TT[12] + TT[ 8]; t1 = TT[13] + TT[ 9]; t2 = TT[14] + TT[10]; t3 = TT[15] + TT[11];
    TT[ 0] ^= hc_rotl32_S (t0, 18); TT[ 1] ^= hc_rotl32_S (t1, 18); TT[ 2] ^= hc_rotl32_S (t2, 18); TT[ 3] ^= hc_rotl32_S (t3, 18);

    t0 = TT[ 4]; TT[ 4] = TT[ 7]; TT[ 7] = TT[ 6]; TT[ 6] = TT[ 5]; TT[ 5] = t0;
    t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0; t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
    t0 = TT[12]; TT[12] = TT[13]; TT[13] = TT[14]; TT[14] = TT[15]; TT[15] = t0;

    t0 = TT[ 0] + TT[ 4]; t1 = TT[ 1] + TT[ 5]; t2 = TT[ 2] + TT[ 6]; t3 = TT[ 3] + TT[ 7];
    TT[12] ^= hc_rotl32_S (t0,  7); TT[13] ^= hc_rotl32_S (t1,  7); TT[14] ^= hc_rotl32_S (t2,  7); TT[15] ^= hc_rotl32_S (t3,  7);

    t0 = TT[12] + TT[ 0]; t1 = TT[13] + TT[ 1]; t2 = TT[14] + TT[ 2]; t3 = TT[15] + TT[ 3];
    TT[ 8] ^= hc_rotl32_S (t0,  9); TT[ 9] ^= hc_rotl32_S (t1,  9); TT[10] ^= hc_rotl32_S (t2,  9); TT[11] ^= hc_rotl32_S (t3,  9);

    t0 = TT[ 8] + TT[12]; t1 = TT[ 9] + TT[13]; t2 = TT[10] + TT[14]; t3 = TT[11] + TT[15];
    TT[ 4] ^= hc_rotl32_S (t0, 13); TT[ 5] ^= hc_rotl32_S (t1, 13); TT[ 6] ^= hc_rotl32_S (t2, 13); TT[ 7] ^= hc_rotl32_S (t3, 13);

    t0 = TT[ 4] + TT[ 8]; t1 = TT[ 5] + TT[ 9]; t2 = TT[ 6] + TT[10]; t3 = TT[ 7] + TT[11];
    TT[ 0] ^= hc_rotl32_S (t0, 18); TT[ 1] ^= hc_rotl32_S (t1, 18); TT[ 2] ^= hc_rotl32_S (t2, 18); TT[ 3] ^= hc_rotl32_S (t3, 18);

    t0 = TT[ 4]; TT[ 4] = TT[ 5]; TT[ 5] = TT[ 6]; TT[ 6] = TT[ 7]; TT[ 7] = t0;
    t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0; t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
    t0 = TT[15]; TT[15] = TT[14]; TT[14] = TT[13]; TT[13] = TT[12]; TT[12] = t0;
  }

  for (int j = 0; j < 16; j++) TI[j] += TT[j];
}

DECLSPEC void yescrypt_blockmix_salsa8 (PRIVATE_AS u32 *X, const u32 r)
{
  u32 TT[16];

  for (int j = 0; j < 16; j++) TT[j] = X[(2 * r - 1) * 16 + j];

  for (u32 i = 0; i < 2 * r; i++)
  {
    for (int j = 0; j < 16; j++) TT[j] ^= X[i * 16 + j];
    for (int j = 0; j < 16; j++) X[i * 16 + j] = TT[j];

    yescrypt_salsa20_8 (&X[i * 16]);

    for (int j = 0; j < 16; j++) TT[j] = X[i * 16 + j];
  }

  if (r > 1)
  {
    u32 Y[YESCRYPT_STATE_CNT4];

    for (u32 i = 0; i < r; i++)
      for (int j = 0; j < 16; j++)
        Y[i * 16 + j] = X[(i * 2) * 16 + j];

    for (u32 i = 0; i < r; i++)
      for (int j = 0; j < 16; j++)
        Y[(i + r) * 16 + j] = X[(i * 2 + 1) * 16 + j];

    for (u32 i = 0; i < YESCRYPT_STATE_CNT4; i++)
      X[i] = Y[i];
  }
}

DECLSPEC void yescrypt_pwxform (PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state_ptr, PRIVATE_AS u32 *w_ptr)
{
  u32 ss = *s_state_ptr;
  u32 w  = *w_ptr;

  u32 S0_off = ((ss == 0) ? 2 : (ss == 1) ? 0 : 1) * SBOX_THIRD_WORDS;
  u32 S1_off = ((ss == 0) ? 1 : (ss == 1) ? 2 : 0) * SBOX_THIRD_WORDS;
  u32 S2_off = ((ss == 0) ? 0 : (ss == 1) ? 1 : 2) * SBOX_THIRD_WORDS;

  for (u32 i = 0; i < PWXrounds; i++)
  {
    for (u32 j = 0; j < PWXgather; j++)
    {
      u32 xl = B[j * 4 + 0];
      u32 xh = B[j * 4 + 1];

      u32 p0_base = S0_off + ((xl & Smask) >> 2);
      u32 p1_base = S1_off + ((xh & Smask) >> 2);

      for (u32 k = 0; k < PWXsimple; k++)
      {
        xl = B[j * 4 + k * 2 + 0];
        xh = B[j * 4 + k * 2 + 1];

        u32 s0_lo = sbox[p0_base + k * 2 + 0];
        u32 s0_hi = sbox[p0_base + k * 2 + 1];
        u32 s1_lo = sbox[p1_base + k * 2 + 0];
        u32 s1_hi = sbox[p1_base + k * 2 + 1];

        u64 x = (u64) xh * (u64) xl;
        x += ((u64) s0_hi << 32) | s0_lo;
        x ^= ((u64) s1_hi << 32) | s1_lo;

        B[j * 4 + k * 2 + 0] = (u32) x;
        B[j * 4 + k * 2 + 1] = (u32) (x >> 32);

        if (i != 0 && i != (PWXrounds - 1))
        {
          sbox[S2_off + w * 2 + 0] = (u32) x;
          sbox[S2_off + w * 2 + 1] = (u32) (x >> 32);
          w++;
        }
      }
    }
  }

  ss = (ss + 1) % 3;
  w = w & (((1 << Swidth) * PWXsimple) - 1);

  *s_state_ptr = ss;
  *w_ptr = w;
}

DECLSPEC void yescrypt_blockmix_pwxform (PRIVATE_AS u32 *X, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r)
{
  const u32 r1 = 128 * r / PWXbytes;

  u32 PX[PWXwords];

  for (u32 j = 0; j < PWXwords; j++)
    PX[j] = X[(r1 - 1) * PWXwords + j];

  for (u32 i = 0; i < r1; i++)
  {
    if (r1 > 1)
    {
      for (u32 j = 0; j < PWXwords; j++)
        PX[j] ^= X[i * PWXwords + j];
    }

    yescrypt_pwxform (PX, sbox, s_state, w_ptr);

    for (u32 j = 0; j < PWXwords; j++)
      X[i * PWXwords + j] = PX[j];
  }

  u32 si = (r1 - 1) * PWXbytes / 64;

  yescrypt_salsa20_2 (&X[si * 16]);

  for (u32 i = si + 1; i < 2 * r; i++)
  {
    for (u32 j = 0; j < 16; j++)
      X[i * 16 + j] ^= X[(i - 1) * 16 + j];

    yescrypt_salsa20_2 (&X[i * 16]);
  }
}

DECLSPEC void yescrypt_sbox_init (PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox, const u32 r_unused)
{
  const u32 sbox_N = Sbytes / 128;

  u32 X[32];

  yescrypt_simd_shuffle (B, X, 1);

  for (u32 i = 0; i < sbox_N; i++)
  {
    for (u32 j = 0; j < 32; j++)
      sbox[i * 32 + j] = X[j];

    yescrypt_blockmix_salsa8 (X, 1);
  }

  yescrypt_simd_unshuffle (X, B, 1);
}

DECLSPEC void yescrypt_smix1_step (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 N, const u32 i, const u32 flags)
{
  const u32 s = 32 * r;

  GLOBAL_AS u32 *Vi = &V[i * s];

  for (u32 j = 0; j < s; j++)
    Vi[j] = X[j];

  if ((flags & 0x002) && i > 1)
  {
    u64 idx = yescrypt_wrap (yescrypt_integerify (X, r), i);
    GLOBAL_AS u32 *Vj = &V[(u32) idx * s];

    for (u32 j = 0; j < s; j++)
      X[j] ^= Vj[j];
  }

  yescrypt_blockmix_pwxform (X, sbox, s_state, w_ptr, r);
}

DECLSPEC void yescrypt_smix2_step (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 N, const u32 flags)
{
  const u32 s = 32 * r;

  u32 j = (u32) (yescrypt_integerify (X, r) & (u64) (N - 1));

  GLOBAL_AS u32 *Vj = &V[j * s];

  for (u32 k = 0; k < s; k++)
    X[k] ^= Vj[k];

  if (flags & 0x002)
  {
    for (u32 k = 0; k < s; k++)
      Vj[k] = X[k];
  }

  yescrypt_blockmix_pwxform (X, sbox, s_state, w_ptr, r);
}
