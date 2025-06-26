/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_scrypt.h"

#if SCRYPT_R > 1
DECLSPEC void shuffle (PRIVATE_AS u32 *TI)
{
  u32 TT[STATE_CNT4 / 2];

  for (int dst_off = 0, src_off = SALSA_CNT4; src_off < STATE_CNT4; dst_off += SALSA_CNT4, src_off += SALSA_CNT4 * 2)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TT[dst_off + j] = TI[src_off + j];
  }

  for (int dst_off = SALSA_CNT4, src_off = SALSA_CNT4 * 2; src_off < STATE_CNT4; dst_off += SALSA_CNT4, src_off += SALSA_CNT4 * 2)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TI[dst_off + j] = TI[src_off + j];
  }

  for (int dst_off = STATE_CNT4 / 2, src_off = 0; dst_off < STATE_CNT4; dst_off += SALSA_CNT4, src_off += SALSA_CNT4)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TI[dst_off + j] = TT[src_off + j];
  }
}
#endif

DECLSPEC void salsa_r (PRIVATE_AS u32 *TI)
{
  u32 TT[16];

  for (int j = 0; j < SALSA_CNT4; j++) TT[j] = TI[STATE_CNT4 - 16 + j];

  for (int i = 0; i < STATE_CNT4; i += SALSA_CNT4)
  {
    for (int j = 0; j < SALSA_CNT4; j++) TT[j] ^= TI[i + j];

    for (int j = 0; j < SALSA_CNT4; j++) TI[i + j] = TT[j];

    for (int r = 0; r < 4; r++)
    {
      u32 t0, t1, t2, t3;

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

    for (int j = 0; j < SALSA_CNT4; j++) TT[j] += TI[i + j];

    for (int j = 0; j < SALSA_CNT4; j++) TI[i + j] = TT[j];
  }
}

DECLSPEC void scrypt_smix_init (GLOBAL_AS u32 *P, PRIVATE_AS u32 *X, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u32 gid, const u32 lid, const u32 lsz, const u32 bid)
{
  const u32 ySIZE = SCRYPT_N >> SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT44;

  const u32 xd4 = bid / 4;
  const u32 xm4 = bid & 3;

  PRIVATE_AS uint4 *X4 = (PRIVATE_AS uint4 *) X;

  GLOBAL_AS uint4 *V;

  switch (xm4)
  {
    case 0: V = (GLOBAL_AS uint4 *) V0; break;
    case 1: V = (GLOBAL_AS uint4 *) V1; break;
    case 2: V = (GLOBAL_AS uint4 *) V2; break;
    case 3: V = (GLOBAL_AS uint4 *) V3; break;
  }

  GLOBAL_AS uint4 *Vx = V + (xd4 * lsz * ySIZE * zSIZE) + (lid * ySIZE * zSIZE);

  for (u32 i = 0; i < STATE_CNT4; i++) X[i] = P[i];

  for (u32 y = 0; y < ySIZE; y++)
  {
    GLOBAL_AS uint4 *Vxx = Vx + (y * zSIZE);

    for (u32 z = 0; z < zSIZE; z++) *Vxx++ = X4[z];

    for (u32 i = 0; i < (1 << SCRYPT_TMTO); i++)
    {
      salsa_r (X);

      #if SCRYPT_R > 1
      shuffle (X);
      #endif
    }
  }

  for (u32 i = 0; i < STATE_CNT4; i++) P[i] = X[i];
}

DECLSPEC void scrypt_smix_loop (GLOBAL_AS u32 *P, PRIVATE_AS u32 *X, PRIVATE_AS u32 *T, GLOBAL_AS void *V0, GLOBAL_AS void *V1, GLOBAL_AS void *V2, GLOBAL_AS void *V3, const u32 gid, const u32 lid, const u32 lsz, const u32 bid)
{
  const u32 ySIZE = SCRYPT_N >> SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT44;

  const u32 xd4 = bid / 4;
  const u32 xm4 = bid & 3;

  PRIVATE_AS uint4 *X4 = (PRIVATE_AS uint4 *) X;
  PRIVATE_AS uint4 *T4 = (PRIVATE_AS uint4 *) T;

  GLOBAL_AS uint4 *V;

  switch (xm4)
  {
    case 0: V = (GLOBAL_AS uint4 *) V0; break;
    case 1: V = (GLOBAL_AS uint4 *) V1; break;
    case 2: V = (GLOBAL_AS uint4 *) V2; break;
    case 3: V = (GLOBAL_AS uint4 *) V3; break;
  }

  GLOBAL_AS uint4 *Vx = V + (xd4 * lsz * ySIZE * zSIZE) + (lid * ySIZE * zSIZE);

  for (u32 i = 0; i < STATE_CNT4; i++) X[i] = P[i];

  // note: max 1024 iterations = forced -u 2048

  const u32 N_max = (SCRYPT_N < 2048) ? SCRYPT_N : 2048;

  for (u32 N_pos = 0; N_pos < N_max; N_pos++)
  {
    const u32 k = X4[zSIZE - 4].x & (SCRYPT_N - 1);

    const u32 y = k >> SCRYPT_TMTO;

    const u32 km = k - (y << SCRYPT_TMTO);

    GLOBAL_AS uint4 *Vxx = Vx + (y * zSIZE);

    for (u32 z = 0; z < zSIZE; z++) T4[z] = *Vxx++;

    for (u32 i = 0; i < km; i++)
    {
      salsa_r (T);

      #if SCRYPT_R > 1
      shuffle (T);
      #endif
    }

    for (u32 z = 0; z < zSIZE; z++) X4[z] = X4[z] ^ T4[z];

    salsa_r (X);

    #if SCRYPT_R > 1
    shuffle (X);
    #endif
  }

  for (u32 i = 0; i < STATE_CNT4; i++) P[i] = X[i];
}

DECLSPEC void scrypt_blockmix_in (GLOBAL_AS u32 *in_buf, GLOBAL_AS u32 *out_buf, const int out_len)
{
  for (int i = 0, j = 0; i < out_len; i += SALSA_SZ, j += SALSA_CNT4)
  {
    u32 X[SALSA_CNT4];

    X[ 0] = in_buf[j +  0];
    X[ 1] = in_buf[j +  5];
    X[ 2] = in_buf[j + 10];
    X[ 3] = in_buf[j + 15];
    X[ 4] = in_buf[j +  4];
    X[ 5] = in_buf[j +  9];
    X[ 6] = in_buf[j + 14];
    X[ 7] = in_buf[j +  3];
    X[ 8] = in_buf[j +  8];
    X[ 9] = in_buf[j + 13];
    X[10] = in_buf[j +  2];
    X[11] = in_buf[j +  7];
    X[12] = in_buf[j + 12];
    X[13] = in_buf[j +  1];
    X[14] = in_buf[j +  6];
    X[15] = in_buf[j + 11];

    out_buf[j +  0] = X[ 0];
    out_buf[j +  1] = X[ 1];
    out_buf[j +  2] = X[ 2];
    out_buf[j +  3] = X[ 3];
    out_buf[j +  4] = X[ 4];
    out_buf[j +  5] = X[ 5];
    out_buf[j +  6] = X[ 6];
    out_buf[j +  7] = X[ 7];
    out_buf[j +  8] = X[ 8];
    out_buf[j +  9] = X[ 9];
    out_buf[j + 10] = X[10];
    out_buf[j + 11] = X[11];
    out_buf[j + 12] = X[12];
    out_buf[j + 13] = X[13];
    out_buf[j + 14] = X[14];
    out_buf[j + 15] = X[15];
  }
}

DECLSPEC void scrypt_blockmix_out (GLOBAL_AS u32 *in_buf, GLOBAL_AS u32 *out_buf, const int out_len)
{
  for (int i = 0, j = 0; i < out_len; i += SALSA_SZ, j += SALSA_CNT4)
  {
    u32 T[SALSA_CNT4];

    T[ 0] = in_buf[j +  0];
    T[ 1] = in_buf[j + 13];
    T[ 2] = in_buf[j + 10];
    T[ 3] = in_buf[j +  7];
    T[ 4] = in_buf[j +  4];
    T[ 5] = in_buf[j +  1];
    T[ 6] = in_buf[j + 14];
    T[ 7] = in_buf[j + 11];
    T[ 8] = in_buf[j +  8];
    T[ 9] = in_buf[j +  5];
    T[10] = in_buf[j +  2];
    T[11] = in_buf[j + 15];
    T[12] = in_buf[j + 12];
    T[13] = in_buf[j +  9];
    T[14] = in_buf[j +  6];
    T[15] = in_buf[j +  3];

    out_buf[j +  0] = T[ 0];
    out_buf[j +  1] = T[ 1];
    out_buf[j +  2] = T[ 2];
    out_buf[j +  3] = T[ 3];
    out_buf[j +  4] = T[ 4];
    out_buf[j +  5] = T[ 5];
    out_buf[j +  6] = T[ 6];
    out_buf[j +  7] = T[ 7];
    out_buf[j +  8] = T[ 8];
    out_buf[j +  9] = T[ 9];
    out_buf[j + 10] = T[10];
    out_buf[j + 11] = T[11];
    out_buf[j + 12] = T[12];
    out_buf[j + 13] = T[13];
    out_buf[j + 14] = T[14];
    out_buf[j + 15] = T[15];
  }
}

DECLSPEC void scrypt_pbkdf2_body_pp (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, PRIVATE_AS u32 *out_buf, const int out_len)
{
  for (int i = 0, j = 1, k = 0; i < out_len; i += 32, j += 1, k += 8)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = *sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
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

    // this will not work if user specifies output length not a multiple of 4
    // probably never happens...
    // let's hope the compiler will auto optimize this since out_len is very likely
    // a constant at caller level

    if (out_len >= (i +  4)) out_buf[k + 0] = hc_swap32_S (sha256_hmac_ctx2.opad.h[0]);
    if (out_len >= (i +  8)) out_buf[k + 1] = hc_swap32_S (sha256_hmac_ctx2.opad.h[1]);
    if (out_len >= (i + 12)) out_buf[k + 2] = hc_swap32_S (sha256_hmac_ctx2.opad.h[2]);
    if (out_len >= (i + 16)) out_buf[k + 3] = hc_swap32_S (sha256_hmac_ctx2.opad.h[3]);
    if (out_len >= (i + 20)) out_buf[k + 4] = hc_swap32_S (sha256_hmac_ctx2.opad.h[4]);
    if (out_len >= (i + 24)) out_buf[k + 5] = hc_swap32_S (sha256_hmac_ctx2.opad.h[5]);
    if (out_len >= (i + 28)) out_buf[k + 6] = hc_swap32_S (sha256_hmac_ctx2.opad.h[6]);
    if (out_len >= (i + 32)) out_buf[k + 7] = hc_swap32_S (sha256_hmac_ctx2.opad.h[7]);
  }
}

DECLSPEC void scrypt_pbkdf2_body_pg (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, GLOBAL_AS u32 *out_buf, const int out_len)
{
  for (int i = 0, j = 1, k = 0; i < out_len; i += 32, j += 1, k += 8)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = *sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
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

    // this will not work if user specifies output length not a multiple of 4
    // probably never happens...
    // let's hope the compiler will auto optimize this since out_len is very likely
    // a constant at caller level

    if (out_len >= (i +  4)) out_buf[k + 0] = hc_swap32_S (sha256_hmac_ctx2.opad.h[0]);
    if (out_len >= (i +  8)) out_buf[k + 1] = hc_swap32_S (sha256_hmac_ctx2.opad.h[1]);
    if (out_len >= (i + 12)) out_buf[k + 2] = hc_swap32_S (sha256_hmac_ctx2.opad.h[2]);
    if (out_len >= (i + 16)) out_buf[k + 3] = hc_swap32_S (sha256_hmac_ctx2.opad.h[3]);
    if (out_len >= (i + 20)) out_buf[k + 4] = hc_swap32_S (sha256_hmac_ctx2.opad.h[4]);
    if (out_len >= (i + 24)) out_buf[k + 5] = hc_swap32_S (sha256_hmac_ctx2.opad.h[5]);
    if (out_len >= (i + 28)) out_buf[k + 6] = hc_swap32_S (sha256_hmac_ctx2.opad.h[6]);
    if (out_len >= (i + 32)) out_buf[k + 7] = hc_swap32_S (sha256_hmac_ctx2.opad.h[7]);
  }
}

DECLSPEC void scrypt_pbkdf2_ppp (PRIVATE_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_pgp (PRIVATE_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_gpp (GLOBAL_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_ggp (GLOBAL_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pp (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_ppg (PRIVATE_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pg (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_pgg (PRIVATE_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pg (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_gpg (GLOBAL_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pg (&sha256_hmac_ctx, out_buf, out_len);
}

DECLSPEC void scrypt_pbkdf2_ggg (GLOBAL_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS u32 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body_pg (&sha256_hmac_ctx, out_buf, out_len);
}

