/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_yescrypt.h"

DECLSPEC void yescrypt_pbkdf2_body_pp (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, PRIVATE_AS u32 *out_buf, const u32 out_len)
{
  for (u32 i = 0, blk = 1; i < out_len; i += 32, blk++)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = *sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = blk;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    // this will not work if the caller asks for an output length that is not a
    // multiple of 4, which never happens here

    const u32 remain = ((out_len - i) < 32) ? (out_len - i) : 32;

    const u32 k = i / 4;

    if (remain >=  4) out_buf[k + 0] = hc_swap32_S (sha256_hmac_ctx2.opad.h[0]);
    if (remain >=  8) out_buf[k + 1] = hc_swap32_S (sha256_hmac_ctx2.opad.h[1]);
    if (remain >= 12) out_buf[k + 2] = hc_swap32_S (sha256_hmac_ctx2.opad.h[2]);
    if (remain >= 16) out_buf[k + 3] = hc_swap32_S (sha256_hmac_ctx2.opad.h[3]);
    if (remain >= 20) out_buf[k + 4] = hc_swap32_S (sha256_hmac_ctx2.opad.h[4]);
    if (remain >= 24) out_buf[k + 5] = hc_swap32_S (sha256_hmac_ctx2.opad.h[5]);
    if (remain >= 28) out_buf[k + 6] = hc_swap32_S (sha256_hmac_ctx2.opad.h[6]);
    if (remain >= 32) out_buf[k + 7] = hc_swap32_S (sha256_hmac_ctx2.opad.h[7]);
  }
}

DECLSPEC void yescrypt_pbkdf2_ppp (PRIVATE_AS const u32 *pw_buf, const u32 pw_len, PRIVATE_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *out_buf, const u32 out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  yescrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void yescrypt_pbkdf2_pgp (PRIVATE_AS const u32 *pw_buf, const u32 pw_len, GLOBAL_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *out_buf, const u32 out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  yescrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void yescrypt_hmac_final_pp (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, PRIVATE_AS u32 *out_buf)
{
  sha256_hmac_final (sha256_hmac_ctx);

  out_buf[0] = hc_swap32_S (sha256_hmac_ctx->opad.h[0]);
  out_buf[1] = hc_swap32_S (sha256_hmac_ctx->opad.h[1]);
  out_buf[2] = hc_swap32_S (sha256_hmac_ctx->opad.h[2]);
  out_buf[3] = hc_swap32_S (sha256_hmac_ctx->opad.h[3]);
  out_buf[4] = hc_swap32_S (sha256_hmac_ctx->opad.h[4]);
  out_buf[5] = hc_swap32_S (sha256_hmac_ctx->opad.h[5]);
  out_buf[6] = hc_swap32_S (sha256_hmac_ctx->opad.h[6]);
  out_buf[7] = hc_swap32_S (sha256_hmac_ctx->opad.h[7]);
}

DECLSPEC void yescrypt_hmac_ppp (PRIVATE_AS const u32 *key_buf, const u32 key_len, PRIVATE_AS const u32 *msg_buf, const u32 msg_len, PRIVATE_AS u32 *out_buf)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, key_buf, key_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, msg_buf, msg_len);

  yescrypt_hmac_final_pp (&sha256_hmac_ctx, out_buf);
}

DECLSPEC void yescrypt_hmac_pgp (PRIVATE_AS const u32 *key_buf, const u32 key_len, GLOBAL_AS const u32 *msg_buf, const u32 msg_len, PRIVATE_AS u32 *out_buf)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, key_buf, key_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, msg_buf, msg_len);

  yescrypt_hmac_final_pp (&sha256_hmac_ctx, out_buf);
}

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
  const u32 off = (2 * r - 1) * 16;

  const u64 v = ((u64) X[off + 13] << 32) | X[off + 0];

  return v;
}

DECLSPEC u64 yescrypt_p2floor (const u64 x)
{
  u64 v = x;
  u64 y = v & (v - 1);

  while (y != 0)
  {
    v = y;
    y = v & (v - 1);
  }

  return v;
}

DECLSPEC u64 yescrypt_wrap (const u64 x, const u64 i)
{
  const u64 n = yescrypt_p2floor (i);

  const u64 v = (x & (n - 1)) + (i - n);

  return v;
}

DECLSPEC void yescrypt_salsa20_2 (PRIVATE_AS u32 *TI)
{
  u32 TT[16];

  for (u32 j = 0; j < 16; j++) TT[j] = TI[j];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = TT[ 0] + TT[12];
  t1 = TT[ 1] + TT[13];
  t2 = TT[ 2] + TT[14];
  t3 = TT[ 3] + TT[15];
  TT[ 4] ^= hc_rotl32_S (t0, 7);
  TT[ 5] ^= hc_rotl32_S (t1, 7);
  TT[ 6] ^= hc_rotl32_S (t2, 7);
  TT[ 7] ^= hc_rotl32_S (t3, 7);

  t0 = TT[ 4] + TT[ 0];
  t1 = TT[ 5] + TT[ 1];
  t2 = TT[ 6] + TT[ 2];
  t3 = TT[ 7] + TT[ 3];
  TT[ 8] ^= hc_rotl32_S (t0, 9);
  TT[ 9] ^= hc_rotl32_S (t1, 9);
  TT[10] ^= hc_rotl32_S (t2, 9);
  TT[11] ^= hc_rotl32_S (t3, 9);

  t0 = TT[ 8] + TT[ 4];
  t1 = TT[ 9] + TT[ 5];
  t2 = TT[10] + TT[ 6];
  t3 = TT[11] + TT[ 7];
  TT[12] ^= hc_rotl32_S (t0, 13);
  TT[13] ^= hc_rotl32_S (t1, 13);
  TT[14] ^= hc_rotl32_S (t2, 13);
  TT[15] ^= hc_rotl32_S (t3, 13);

  t0 = TT[12] + TT[ 8];
  t1 = TT[13] + TT[ 9];
  t2 = TT[14] + TT[10];
  t3 = TT[15] + TT[11];
  TT[ 0] ^= hc_rotl32_S (t0, 18);
  TT[ 1] ^= hc_rotl32_S (t1, 18);
  TT[ 2] ^= hc_rotl32_S (t2, 18);
  TT[ 3] ^= hc_rotl32_S (t3, 18);

  t0 = TT[ 4]; TT[ 4] = TT[ 7]; TT[ 7] = TT[ 6]; TT[ 6] = TT[ 5]; TT[ 5] = t0;
  t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0;
  t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
  t0 = TT[12]; TT[12] = TT[13]; TT[13] = TT[14]; TT[14] = TT[15]; TT[15] = t0;

  t0 = TT[ 0] + TT[ 4];
  t1 = TT[ 1] + TT[ 5];
  t2 = TT[ 2] + TT[ 6];
  t3 = TT[ 3] + TT[ 7];
  TT[12] ^= hc_rotl32_S (t0, 7);
  TT[13] ^= hc_rotl32_S (t1, 7);
  TT[14] ^= hc_rotl32_S (t2, 7);
  TT[15] ^= hc_rotl32_S (t3, 7);

  t0 = TT[12] + TT[ 0];
  t1 = TT[13] + TT[ 1];
  t2 = TT[14] + TT[ 2];
  t3 = TT[15] + TT[ 3];
  TT[ 8] ^= hc_rotl32_S (t0, 9);
  TT[ 9] ^= hc_rotl32_S (t1, 9);
  TT[10] ^= hc_rotl32_S (t2, 9);
  TT[11] ^= hc_rotl32_S (t3, 9);

  t0 = TT[ 8] + TT[12];
  t1 = TT[ 9] + TT[13];
  t2 = TT[10] + TT[14];
  t3 = TT[11] + TT[15];
  TT[ 4] ^= hc_rotl32_S (t0, 13);
  TT[ 5] ^= hc_rotl32_S (t1, 13);
  TT[ 6] ^= hc_rotl32_S (t2, 13);
  TT[ 7] ^= hc_rotl32_S (t3, 13);

  t0 = TT[ 4] + TT[ 8];
  t1 = TT[ 5] + TT[ 9];
  t2 = TT[ 6] + TT[10];
  t3 = TT[ 7] + TT[11];
  TT[ 0] ^= hc_rotl32_S (t0, 18);
  TT[ 1] ^= hc_rotl32_S (t1, 18);
  TT[ 2] ^= hc_rotl32_S (t2, 18);
  TT[ 3] ^= hc_rotl32_S (t3, 18);

  t0 = TT[ 4]; TT[ 4] = TT[ 5]; TT[ 5] = TT[ 6]; TT[ 6] = TT[ 7]; TT[ 7] = t0;
  t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0;
  t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
  t0 = TT[15]; TT[15] = TT[14]; TT[14] = TT[13]; TT[13] = TT[12]; TT[12] = t0;

  for (u32 j = 0; j < 16; j++) TI[j] += TT[j];
}

DECLSPEC void yescrypt_salsa20_8 (PRIVATE_AS u32 *TI)
{
  u32 TT[16];

  for (u32 j = 0; j < 16; j++) TT[j] = TI[j];

  for (u32 rnd = 0; rnd < 4; rnd++)
  {
    u32 t0;
    u32 t1;
    u32 t2;
    u32 t3;

    t0 = TT[ 0] + TT[12];
    t1 = TT[ 1] + TT[13];
    t2 = TT[ 2] + TT[14];
    t3 = TT[ 3] + TT[15];
    TT[ 4] ^= hc_rotl32_S (t0, 7);
    TT[ 5] ^= hc_rotl32_S (t1, 7);
    TT[ 6] ^= hc_rotl32_S (t2, 7);
    TT[ 7] ^= hc_rotl32_S (t3, 7);

    t0 = TT[ 4] + TT[ 0];
    t1 = TT[ 5] + TT[ 1];
    t2 = TT[ 6] + TT[ 2];
    t3 = TT[ 7] + TT[ 3];
    TT[ 8] ^= hc_rotl32_S (t0, 9);
    TT[ 9] ^= hc_rotl32_S (t1, 9);
    TT[10] ^= hc_rotl32_S (t2, 9);
    TT[11] ^= hc_rotl32_S (t3, 9);

    t0 = TT[ 8] + TT[ 4];
    t1 = TT[ 9] + TT[ 5];
    t2 = TT[10] + TT[ 6];
    t3 = TT[11] + TT[ 7];
    TT[12] ^= hc_rotl32_S (t0, 13);
    TT[13] ^= hc_rotl32_S (t1, 13);
    TT[14] ^= hc_rotl32_S (t2, 13);
    TT[15] ^= hc_rotl32_S (t3, 13);

    t0 = TT[12] + TT[ 8];
    t1 = TT[13] + TT[ 9];
    t2 = TT[14] + TT[10];
    t3 = TT[15] + TT[11];
    TT[ 0] ^= hc_rotl32_S (t0, 18);
    TT[ 1] ^= hc_rotl32_S (t1, 18);
    TT[ 2] ^= hc_rotl32_S (t2, 18);
    TT[ 3] ^= hc_rotl32_S (t3, 18);

    t0 = TT[ 4]; TT[ 4] = TT[ 7]; TT[ 7] = TT[ 6]; TT[ 6] = TT[ 5]; TT[ 5] = t0;
    t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0;
    t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
    t0 = TT[12]; TT[12] = TT[13]; TT[13] = TT[14]; TT[14] = TT[15]; TT[15] = t0;

    t0 = TT[ 0] + TT[ 4];
    t1 = TT[ 1] + TT[ 5];
    t2 = TT[ 2] + TT[ 6];
    t3 = TT[ 3] + TT[ 7];
    TT[12] ^= hc_rotl32_S (t0, 7);
    TT[13] ^= hc_rotl32_S (t1, 7);
    TT[14] ^= hc_rotl32_S (t2, 7);
    TT[15] ^= hc_rotl32_S (t3, 7);

    t0 = TT[12] + TT[ 0];
    t1 = TT[13] + TT[ 1];
    t2 = TT[14] + TT[ 2];
    t3 = TT[15] + TT[ 3];
    TT[ 8] ^= hc_rotl32_S (t0, 9);
    TT[ 9] ^= hc_rotl32_S (t1, 9);
    TT[10] ^= hc_rotl32_S (t2, 9);
    TT[11] ^= hc_rotl32_S (t3, 9);

    t0 = TT[ 8] + TT[12];
    t1 = TT[ 9] + TT[13];
    t2 = TT[10] + TT[14];
    t3 = TT[11] + TT[15];
    TT[ 4] ^= hc_rotl32_S (t0, 13);
    TT[ 5] ^= hc_rotl32_S (t1, 13);
    TT[ 6] ^= hc_rotl32_S (t2, 13);
    TT[ 7] ^= hc_rotl32_S (t3, 13);

    t0 = TT[ 4] + TT[ 8];
    t1 = TT[ 5] + TT[ 9];
    t2 = TT[ 6] + TT[10];
    t3 = TT[ 7] + TT[11];
    TT[ 0] ^= hc_rotl32_S (t0, 18);
    TT[ 1] ^= hc_rotl32_S (t1, 18);
    TT[ 2] ^= hc_rotl32_S (t2, 18);
    TT[ 3] ^= hc_rotl32_S (t3, 18);

    t0 = TT[ 4]; TT[ 4] = TT[ 5]; TT[ 5] = TT[ 6]; TT[ 6] = TT[ 7]; TT[ 7] = t0;
    t0 = TT[ 8]; TT[ 8] = TT[10]; TT[10] = t0;
    t0 = TT[ 9]; TT[ 9] = TT[11]; TT[11] = t0;
    t0 = TT[15]; TT[15] = TT[14]; TT[14] = TT[13]; TT[13] = TT[12]; TT[12] = t0;
  }

  for (u32 j = 0; j < 16; j++) TI[j] += TT[j];
}

DECLSPEC void yescrypt_blockmix_salsa8 (PRIVATE_AS u32 *X, const u32 r)
{
  u32 TT[16];

  for (u32 j = 0; j < 16; j++) TT[j] = X[(2 * r - 1) * 16 + j];

  for (u32 i = 0; i < 2 * r; i++)
  {
    for (u32 j = 0; j < 16; j++) TT[j] ^= X[i * 16 + j];
    for (u32 j = 0; j < 16; j++) X[i * 16 + j] = TT[j];

    yescrypt_salsa20_8 (&X[i * 16]);

    for (u32 j = 0; j < 16; j++) TT[j] = X[i * 16 + j];
  }

  if (r == 1) return;

  // the even blocks move to the front and the odd ones behind them

  u32 Y[YESCRYPT_STATE_CNT4];

  for (u32 i = 0; i < r; i++)
  {
    for (u32 j = 0; j < 16; j++) Y[i * 16 + j] = X[(i * 2 + 0) * 16 + j];
  }

  for (u32 i = 0; i < r; i++)
  {
    for (u32 j = 0; j < 16; j++) Y[(i + r) * 16 + j] = X[(i * 2 + 1) * 16 + j];
  }

  for (u32 i = 0; i < YESCRYPT_STATE_CNT4; i++) X[i] = Y[i];
}

DECLSPEC void yescrypt_pwxform (PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr)
{
  u32 ss = *s_state;
  u32 ww = *w_ptr;

  const u32 S0_off = ((ss == 0) ? 2 : (ss == 1) ? 0 : 1) * SBOX_THIRD_WORDS;
  const u32 S1_off = ((ss == 0) ? 1 : (ss == 1) ? 2 : 0) * SBOX_THIRD_WORDS;
  const u32 S2_off = ((ss == 0) ? 0 : (ss == 1) ? 1 : 2) * SBOX_THIRD_WORDS;

  for (u32 i = 0; i < PWXrounds; i++)
  {
    for (u32 j = 0; j < PWXgather; j++)
    {
      const u32 xl0 = B[j * 4 + 0];
      const u32 xh0 = B[j * 4 + 1];

      const u32 p0_base = S0_off + ((xl0 & Smask) >> 2);
      const u32 p1_base = S1_off + ((xh0 & Smask) >> 2);

      for (u32 k = 0; k < PWXsimple; k++)
      {
        const u32 xl = B[j * 4 + k * 2 + 0];
        const u32 xh = B[j * 4 + k * 2 + 1];

        const u32 s0_lo = sbox[p0_base + k * 2 + 0];
        const u32 s0_hi = sbox[p0_base + k * 2 + 1];
        const u32 s1_lo = sbox[p1_base + k * 2 + 0];
        const u32 s1_hi = sbox[p1_base + k * 2 + 1];

        u64 x = (u64) xh * (u64) xl;

        x += ((u64) s0_hi << 32) | s0_lo;
        x ^= ((u64) s1_hi << 32) | s1_lo;

        const u32 lo = (u32) (x >>  0);
        const u32 hi = (u32) (x >> 32);

        B[j * 4 + k * 2 + 0] = lo;
        B[j * 4 + k * 2 + 1] = hi;

        if ((i == 0) || (i == (PWXrounds - 1))) continue;

        sbox[S2_off + ww * 2 + 0] = lo;
        sbox[S2_off + ww * 2 + 1] = hi;

        ww++;
      }
    }
  }

  ss = (ss + 1) % 3;
  ww = ww & (((1 << Swidth) * PWXsimple) - 1);

  *s_state = ss;
  *w_ptr   = ww;
}

DECLSPEC void yescrypt_blockmix_pwxform (PRIVATE_AS u32 *X, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r)
{
  const u32 r1 = 128 * r / PWXbytes;

  u32 PX[PWXwords];

  for (u32 j = 0; j < PWXwords; j++) PX[j] = X[(r1 - 1) * PWXwords + j];

  for (u32 i = 0; i < r1; i++)
  {
    if (r1 > 1)
    {
      for (u32 j = 0; j < PWXwords; j++) PX[j] ^= X[i * PWXwords + j];
    }

    yescrypt_pwxform (PX, sbox, s_state, w_ptr);

    for (u32 j = 0; j < PWXwords; j++) X[i * PWXwords + j] = PX[j];
  }

  const u32 si = (r1 - 1) * PWXbytes / 64;

  yescrypt_salsa20_2 (&X[si * 16]);

  for (u32 i = si + 1; i < 2 * r; i++)
  {
    for (u32 j = 0; j < 16; j++) X[i * 16 + j] ^= X[(i - 1) * 16 + j];

    yescrypt_salsa20_2 (&X[i * 16]);
  }
}

DECLSPEC void yescrypt_sbox_init (PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox)
{
  const u32 sbox_N = Sbytes / 128;

  u32 X[32];

  yescrypt_simd_shuffle (B, X, 1);

  for (u32 i = 0; i < sbox_N; i++)
  {
    for (u32 j = 0; j < 32; j++) sbox[i * 32 + j] = X[j];

    yescrypt_blockmix_salsa8 (X, 1);
  }

  yescrypt_simd_unshuffle (X, B, 1);
}

DECLSPEC void yescrypt_smix1_step (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 i, const u32 flags)
{
  const u32 s = 32 * r;

  GLOBAL_AS u32 *Vi = &V[i * s];

  for (u32 j = 0; j < s; j++) Vi[j] = X[j];

  if (((flags & YESCRYPT_FLAG_RW) != 0) && (i > 1))
  {
    const u64 idx = yescrypt_wrap (yescrypt_integerify (X, r), i);

    GLOBAL_AS u32 *Vj = &V[(u32) idx * s];

    for (u32 j = 0; j < s; j++) X[j] ^= Vj[j];
  }

  yescrypt_blockmix_pwxform (X, sbox, s_state, w_ptr, r);
}

DECLSPEC void yescrypt_smix2_step (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 r, const u32 N, const u32 flags)
{
  const u32 s = 32 * r;

  const u32 j = (u32) (yescrypt_integerify (X, r) & (u64) (N - 1));

  GLOBAL_AS u32 *Vj = &V[j * s];

  for (u32 k = 0; k < s; k++) X[k] ^= Vj[k];

  if ((flags & YESCRYPT_FLAG_RW) != 0)
  {
    for (u32 k = 0; k < s; k++) Vj[k] = X[k];
  }

  yescrypt_blockmix_pwxform (X, sbox, s_state, w_ptr, r);
}

DECLSPEC void yescrypt_kdf_setup (GLOBAL_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *passwd, PRIVATE_AS u32 *B, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr)
{
  yescrypt_pbkdf2_pgp (passwd, 32, salt_buf, salt_len, B, YESCRYPT_STATE_SZ);

  for (u32 j = 0; j < 8; j++) passwd[j] = B[j];

  // the Sbox is seeded from the first 128 bytes of B, which come back modified

  u32 B_r1[32];

  for (u32 j = 0; j < 32; j++) B_r1[j] = B[j];

  yescrypt_sbox_init (B_r1, sbox);

  for (u32 j = 0; j < 32; j++) B[j] = B_r1[j];

  *s_state = 0;
  *w_ptr   = 0;

  // the last 64 bytes of B key an HMAC over the passwd derived above

  u32 b_tail[16];

  for (u32 j = 0; j < 16; j++) b_tail[j] = B[YESCRYPT_STATE_CNT4 - 16 + j];

  yescrypt_hmac_ppp (b_tail, 64, passwd, 32, passwd);

  u32 B_tmp[YESCRYPT_STATE_CNT4];

  for (u32 j = 0; j < YESCRYPT_STATE_CNT4; j++) B_tmp[j] = B[j];

  yescrypt_simd_shuffle (B_tmp, B, YESCRYPT_R);
}

// Folds the prehash result back into passwd. Kept separate so the two state sized temporaries it
// needs do not stay live for the rest of the init kernel.

DECLSPEC void yescrypt_prehash_passwd (PRIVATE_AS const u32 *B, PRIVATE_AS u32 *passwd)
{
  u32 B_unshuffled[YESCRYPT_STATE_CNT4];

  yescrypt_simd_unshuffle (B, B_unshuffled, YESCRYPT_R);

  u32 dk[8];

  yescrypt_pbkdf2_ppp (passwd, 32, B_unshuffled, YESCRYPT_STATE_SZ, dk, 32);

  for (u32 i = 0; i < 8; i++) passwd[i] = dk[i];
}

DECLSPEC void yescrypt_prehash_smix (PRIVATE_AS u32 *X, GLOBAL_AS u32 *V, GLOBAL_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 prehash_N, const u32 flags)
{
  for (u32 i = 0; i < prehash_N; i++)
  {
    yescrypt_smix1_step (X, V, sbox, s_state, w_ptr, YESCRYPT_R, i, flags);
  }

  u32 Nloop_rw = (prehash_N + 2) / 3;

  Nloop_rw++;
  Nloop_rw &= ~(u32) 1;

  for (u32 i = 0; i < Nloop_rw; i++)
  {
    yescrypt_smix2_step (X, V, sbox, s_state, w_ptr, YESCRYPT_R, prehash_N, flags);
  }
}

DECLSPEC void yescrypt_kdf_init (GLOBAL_AS const u32 *pw_buf, const u32 pw_len, GLOBAL_AS const u32 *salt_buf, const u32 salt_len, GLOBAL_AS yescrypt_tmp_t *tmp, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u64 gid)
{
  GLOBAL_AS u32 *sbox = tmp->S;

  u32 hmac_key[16];

  hmac_key[ 0] = 0x63736579; // "yesc" LE
  hmac_key[ 1] = 0x74707972; // "rypt" LE
  hmac_key[ 2] = 0;
  hmac_key[ 3] = 0;
  hmac_key[ 4] = 0;
  hmac_key[ 5] = 0;
  hmac_key[ 6] = 0;
  hmac_key[ 7] = 0;
  hmac_key[ 8] = 0;
  hmac_key[ 9] = 0;
  hmac_key[10] = 0;
  hmac_key[11] = 0;
  hmac_key[12] = 0;
  hmac_key[13] = 0;
  hmac_key[14] = 0;
  hmac_key[15] = 0;

  u32 passwd[16];

  passwd[ 0] = 0;
  passwd[ 1] = 0;
  passwd[ 2] = 0;
  passwd[ 3] = 0;
  passwd[ 4] = 0;
  passwd[ 5] = 0;
  passwd[ 6] = 0;
  passwd[ 7] = 0;
  passwd[ 8] = 0;
  passwd[ 9] = 0;
  passwd[10] = 0;
  passwd[11] = 0;
  passwd[12] = 0;
  passwd[13] = 0;
  passwd[14] = 0;
  passwd[15] = 0;

  u32 B[YESCRYPT_STATE_CNT4];

  u32 s_state = 0;
  u32 w       = 0;

  const u32 gid_d4 = gid / 4;
  const u32 gid_m4 = gid & 3;

  GLOBAL_AS u32 *V;

  switch (gid_m4)
  {
    case 0: V = (GLOBAL_AS u32 *) V0; break;
    case 1: V = (GLOBAL_AS u32 *) V1; break;
    case 2: V = (GLOBAL_AS u32 *) V2; break;
    case 3: V = (GLOBAL_AS u32 *) V3; break;
  }

  V += gid_d4 * YESCRYPT_STATE_CNT4 * YESCRYPT_N;

  #if YESCRYPT_PREHASH_NEEDED

  hmac_key[2] = 0x6572702d; // "-pre" LE
  hmac_key[3] = 0x68736168; // "hash" LE

  yescrypt_hmac_pgp (hmac_key, 16, pw_buf, pw_len, passwd);

  hmac_key[2] = 0;
  hmac_key[3] = 0;

  yescrypt_kdf_setup (salt_buf, salt_len, passwd, B, sbox, &s_state, &w);

  yescrypt_prehash_smix (B, V, sbox, &s_state, &w, YESCRYPT_PREHASH_N, YESCRYPT_FLAGS);

  yescrypt_prehash_passwd (B, passwd);

  yescrypt_hmac_ppp (hmac_key, 8, passwd, 32, passwd);

  #else

  yescrypt_hmac_pgp (hmac_key, 8, pw_buf, pw_len, passwd);

  #endif

  yescrypt_kdf_setup (salt_buf, salt_len, passwd, B, sbox, &s_state, &w);

  for (u32 i = 0; i < YESCRYPT_STATE_CNT4; i++) tmp->P[i] = B[i];

  for (u32 i = 0; i < 8; i++) tmp->passwd[i] = passwd[i];

  tmp->phase   = 0;
  tmp->iter    = 0;
  tmp->s_state = s_state;
  tmp->w       = w;
}

// Cooperative smix: one workgroup per hash, thread lid owns pwxform lane lid.
//
// Everything below shares X and the Sbox across the workgroup, so every loop that strides by lsz and
// every lane guarded by lid is a place where the threads meet. A read phase and a write phase of the
// same buffer need a SYNC_THREADS () between them even where one looks redundant: a GPU runs the 32
// threads as one warp and orders them for free, but a runtime that runs the work items one after
// another between barriers lets thread 0 finish its whole loop before thread 1 has started its own.

DECLSPEC u64 yescrypt_coop_integerify (XBUF_AS const u32 *X)
{
  const u32 off = (2 * YESCRYPT_R - 1) * 16;

  const u64 v = ((u64) X[off + 13] << 32) | X[off + 0];

  return v;
}

DECLSPEC void yescrypt_coop_blockmix_pwxform (XBUF_AS u32 *X, SBOX_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 lid)
{
  const u32 r1 = 128 * YESCRYPT_R / PWXbytes;

  const bool do_lane = (lid < COOP_PWX_LANES);

  const u32 t = lid;

  u32 px0 = 0;
  u32 px1 = 0;
  u32 px2 = 0;
  u32 px3 = 0;

  if (do_lane == true)
  {
    const u32 last = (r1 - 1) * 16 + 4 * t;

    px0 = X[last + 0];
    px1 = X[last + 1];
    px2 = X[last + 2];
    px3 = X[last + 3];
  }

  u32 ss = *s_state;
  u32 ww = *w_ptr;

  for (u32 i = 0; i < r1; i++)
  {
    if (do_lane == true)
    {
      const u32 base = i * 16 + 4 * t;

      px0 ^= X[base + 0];
      px1 ^= X[base + 1];
      px2 ^= X[base + 2];
      px3 ^= X[base + 3];

      const u32 S0_off = ((ss == 0) ? 2 : (ss == 1) ? 0 : 1) * SBOX_THIRD_WORDS;
      const u32 S1_off = ((ss == 0) ? 1 : (ss == 1) ? 2 : 0) * SBOX_THIRD_WORDS;
      const u32 S2_off = ((ss == 0) ? 0 : (ss == 1) ? 1 : 2) * SBOX_THIRD_WORDS;

      for (u32 round = 0; round < PWXrounds; round++)
      {
        const u32 xl = px0;
        const u32 xh = px1;

        const u32 p0_base = S0_off + ((xl & Smask) >> 2);
        const u32 p1_base = S1_off + ((xh & Smask) >> 2);

        // Smask keeps p0_base and p1_base a multiple of four words, so each
        // Sbox entry is one aligned 16 byte block. Reading it as a vector lets
        // the compiler use a single wide load instead of four scalar ones.

        const uint4 s0v = *((SBOX_AS uint4 *) (sbox + p0_base));
        const uint4 s1v = *((SBOX_AS uint4 *) (sbox + p1_base));

        for (u32 k = 0; k < PWXsimple; k++)
        {
          const u32 xlk = (k == 0) ? px0 : px2;
          const u32 xhk = (k == 0) ? px1 : px3;

          const u32 s0_lo = (k == 0) ? s0v.x : s0v.z;
          const u32 s0_hi = (k == 0) ? s0v.y : s0v.w;
          const u32 s1_lo = (k == 0) ? s1v.x : s1v.z;
          const u32 s1_hi = (k == 0) ? s1v.y : s1v.w;

          u64 x = (u64) xhk * (u64) xlk;

          x += ((u64) s0_hi << 32) | s0_lo;
          x ^= ((u64) s1_hi << 32) | s1_lo;

          const u32 lo = (u32) (x >>  0);
          const u32 hi = (u32) (x >> 32);

          if (k == 0)
          {
            px0 = lo;
            px1 = hi;
          }
          else
          {
            px2 = lo;
            px3 = hi;
          }

          if (round == 0) continue;
          if (round == (PWXrounds - 1)) continue;

          const u32 ai    = round - 1;
          const u32 wslot = ww + ai * 8 + t * 2 + k;

          sbox[S2_off + wslot * 2 + 0] = lo;
          sbox[S2_off + wslot * 2 + 1] = hi;
        }
      }

      X[base + 0] = px0;
      X[base + 1] = px1;
      X[base + 2] = px2;
      X[base + 3] = px3;
    }

    ss = (ss + 1) % 3;
    ww = (ww + 32) & (((1 << Swidth) * PWXsimple) - 1);

    SYNC_THREADS ();
  }

  if (lid == 0)
  {
    const u32 off = (r1 - 1) * 16;

    // yescrypt_salsa20_2 operates on private memory, while X can be local or global.

    u32 salsa[16];

    for (u32 i = 0; i < 16; i++) salsa[i] = X[off + i];

    yescrypt_salsa20_2 (salsa);

    for (u32 i = 0; i < 16; i++) X[off + i] = salsa[i];
  }

  SYNC_THREADS ();

  *s_state = ss;
  *w_ptr   = ww;
}

DECLSPEC void yescrypt_coop_smix1_step (XBUF_AS u32 *X, GLOBAL_AS u32 *V, SBOX_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 i, const u32 lid, const u32 lsz, const u32 flags)
{
  const u32 s = 32 * YESCRYPT_R;

  GLOBAL_AS u32 *Vi = &V[i * s];

  for (u32 j = lid; j < s; j += lsz) Vi[j] = X[j];

  // Every thread has to be done reading X before any of them writes it again, either through the xor
  // below or through the blockmix at the end. On a GPU the workgroup is one warp and gets that for
  // free, but a runtime that runs the work items one after another does not.

  SYNC_THREADS ();

  if (((flags & YESCRYPT_FLAG_RW) != 0) && (i > 1))
  {
    const u64 idx = yescrypt_wrap (yescrypt_coop_integerify (X), i);

    GLOBAL_AS u32 *Vj = &V[(u32) idx * s];

    // idx comes out of X and the xor below writes X, so every thread has to have its own idx before
    // the first of them writes. Otherwise the threads behind pick a different block to xor with.

    SYNC_THREADS ();

    for (u32 j = lid; j < s; j += lsz) X[j] ^= Vj[j];

    SYNC_THREADS ();
  }

  yescrypt_coop_blockmix_pwxform (X, sbox, s_state, w_ptr, lid);
}

DECLSPEC void yescrypt_coop_smix2_step (XBUF_AS u32 *X, GLOBAL_AS u32 *V, SBOX_AS u32 *sbox, PRIVATE_AS u32 *s_state, PRIVATE_AS u32 *w_ptr, const u32 lid, const u32 lsz, const u32 flags)
{
  const u32 s = 32 * YESCRYPT_R;

  const u32 j = (u32) (yescrypt_coop_integerify (X) & (u64) (YESCRYPT_N - 1));

  GLOBAL_AS u32 *Vj = &V[j * s];

  // j comes out of X and the xor below writes X, so every thread has to have read its j before the
  // first of them writes. Otherwise the threads that are behind pick a different block to xor with.

  SYNC_THREADS ();

  for (u32 k = lid; k < s; k += lsz) X[k] ^= Vj[k];

  SYNC_THREADS ();

  if ((flags & YESCRYPT_FLAG_RW) != 0)
  {
    for (u32 k = lid; k < s; k += lsz) Vj[k] = X[k];

    SYNC_THREADS ();
  }

  yescrypt_coop_blockmix_pwxform (X, sbox, s_state, w_ptr, lid);
}

DECLSPEC void yescrypt_smix_loop (XBUF_AS u32 *X, SBOX_AS u32 *sbox, GLOBAL_AS yescrypt_tmp_t *tmp, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u64 bid, const u32 lid, const u32 lsz, const u32 loop_cnt)
{
  #ifdef COOP_SBOX_LDS
  for (u32 i = lid; i < Swords; i += lsz) sbox[i] = tmp->S[i];
  #endif

  #ifndef COOP_X_GLOBAL
  for (u32 i = lid; i < YESCRYPT_STATE_CNT4; i += lsz) X[i] = tmp->P[i];
  #endif

  u32 phase   = tmp->phase;
  u32 iter    = tmp->iter;
  u32 s_state = tmp->s_state;
  u32 w       = tmp->w;

  const u32 bid_d4 = bid / 4;
  const u32 bid_m4 = bid & 3;

  GLOBAL_AS u32 *V;

  switch (bid_m4)
  {
    case 0: V = (GLOBAL_AS u32 *) V0; break;
    case 1: V = (GLOBAL_AS u32 *) V1; break;
    case 2: V = (GLOBAL_AS u32 *) V2; break;
    case 3: V = (GLOBAL_AS u32 *) V3; break;
  }

  V += bid_d4 * YESCRYPT_STATE_CNT4 * YESCRYPT_N;

  SYNC_THREADS ();

  for (u32 loop = 0; loop < loop_cnt; loop++)
  {
    if (phase == 0)
    {
      if (iter < YESCRYPT_N)
      {
        yescrypt_coop_smix1_step (X, V, sbox, &s_state, &w, iter, lid, lsz, YESCRYPT_FLAGS);

        iter++;

        if (iter >= YESCRYPT_N)
        {
          phase = 1;
          iter  = 0;
        }
      }
    }
    else if (phase == 1)
    {
      if (iter >= YESCRYPT_NLOOP_RW) break;

      yescrypt_coop_smix2_step (X, V, sbox, &s_state, &w, lid, lsz, YESCRYPT_FLAGS);

      iter++;
    }
  }

  SYNC_THREADS ();

  #ifndef COOP_X_GLOBAL
  for (u32 i = lid; i < YESCRYPT_STATE_CNT4; i += lsz) tmp->P[i] = X[i];
  #endif

  #ifdef COOP_SBOX_LDS
  for (u32 i = lid; i < Swords; i += lsz) tmp->S[i] = sbox[i];
  #endif

  if (lid == 0)
  {
    tmp->phase   = phase;
    tmp->iter    = iter;
    tmp->s_state = s_state;
    tmp->w       = w;
  }
}

// Turns the finished smix state into the 32 byte yescrypt output. dk must have room for 16 u32,
// because the caller may key an HMAC with it.

DECLSPEC void yescrypt_kdf_final (GLOBAL_AS yescrypt_tmp_t *tmp, PRIVATE_AS u32 *dk)
{
  u32 X[YESCRYPT_STATE_CNT4];

  for (u32 i = 0; i < YESCRYPT_STATE_CNT4; i++) X[i] = tmp->P[i];

  u32 passwd[16];

  for (u32 i = 0; i <  8; i++) passwd[i] = tmp->passwd[i];
  for (u32 i = 8; i < 16; i++) passwd[i] = 0;

  u32 B[YESCRYPT_STATE_CNT4];

  yescrypt_simd_unshuffle (X, B, YESCRYPT_R);

  for (u32 i = 0; i < 16; i++) dk[i] = 0;

  yescrypt_pbkdf2_ppp (passwd, 32, B, YESCRYPT_STATE_SZ, dk, 32);

  #if YESCRYPT_FLAGS != 0

  // the classic yescrypt output is HMAC("Client Key") folded through one more SHA-256

  u32 client_key_msg[16];

  client_key_msg[ 0] = 0x65696c43; // "Clie" LE
  client_key_msg[ 1] = 0x4b20746e; // "nt K" LE
  client_key_msg[ 2] = 0x00007965; // "ey\0\0" LE
  client_key_msg[ 3] = 0;
  client_key_msg[ 4] = 0;
  client_key_msg[ 5] = 0;
  client_key_msg[ 6] = 0;
  client_key_msg[ 7] = 0;
  client_key_msg[ 8] = 0;
  client_key_msg[ 9] = 0;
  client_key_msg[10] = 0;
  client_key_msg[11] = 0;
  client_key_msg[12] = 0;
  client_key_msg[13] = 0;
  client_key_msg[14] = 0;
  client_key_msg[15] = 0;

  u32 client_key[16];

  client_key[ 8] = 0;
  client_key[ 9] = 0;
  client_key[10] = 0;
  client_key[11] = 0;
  client_key[12] = 0;
  client_key[13] = 0;
  client_key[14] = 0;
  client_key[15] = 0;

  yescrypt_hmac_ppp (dk, 32, client_key_msg, 10, client_key);

  sha256_ctx_t sha256_ctx;

  sha256_init (&sha256_ctx);
  sha256_update_swap (&sha256_ctx, client_key, 32);
  sha256_final (&sha256_ctx);

  dk[0] = hc_swap32_S (sha256_ctx.h[0]);
  dk[1] = hc_swap32_S (sha256_ctx.h[1]);
  dk[2] = hc_swap32_S (sha256_ctx.h[2]);
  dk[3] = hc_swap32_S (sha256_ctx.h[3]);
  dk[4] = hc_swap32_S (sha256_ctx.h[4]);
  dk[5] = hc_swap32_S (sha256_ctx.h[5]);
  dk[6] = hc_swap32_S (sha256_ctx.h[6]);
  dk[7] = hc_swap32_S (sha256_ctx.h[7]);

  #endif
}
