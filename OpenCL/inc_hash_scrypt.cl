/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_scrypt.h"

DECLSPEC void salsa_r_l (LOCAL_AS u32 *TI)
{
  u32 x[16];

  for (int j = 0; j < 16; j++) x[j] = TI[STATE_CNT - 16 + j];

  for (int i = 0; i < STATE_CNT; i += 16)
  {
    for (int j = 0; j < 16; j++)
    {
      x[j] ^= TI[i + j];
    }

    for (int j = 0; j < 16; j++)
    {
      TI[i + j] = x[j];
    }

    for (int r = 0; r < 4; r++)
    {
      u32 t0, t1, t2, t3;

      t0 = x[ 0] + x[12];
      t1 = x[ 1] + x[13];
      t2 = x[ 2] + x[14];
      t3 = x[ 3] + x[15];
      x[ 4] ^= hc_rotl32_S (t0, 7);
      x[ 5] ^= hc_rotl32_S (t1, 7);
      x[ 6] ^= hc_rotl32_S (t2, 7);
      x[ 7] ^= hc_rotl32_S (t3, 7);

      t0 = x[ 4] + x[ 0];
      t1 = x[ 5] + x[ 1];
      t2 = x[ 6] + x[ 2];
      t3 = x[ 7] + x[ 3];
      x[ 8] ^= hc_rotl32_S (t0, 9);
      x[ 9] ^= hc_rotl32_S (t1, 9);
      x[10] ^= hc_rotl32_S (t2, 9);
      x[11] ^= hc_rotl32_S (t3, 9);

      t0 = x[ 8] + x[ 4];
      t1 = x[ 9] + x[ 5];
      t2 = x[10] + x[ 6];
      t3 = x[11] + x[ 7];
      x[12] ^= hc_rotl32_S (t0, 13);
      x[13] ^= hc_rotl32_S (t1, 13);
      x[14] ^= hc_rotl32_S (t2, 13);
      x[15] ^= hc_rotl32_S (t3, 13);

      t0 = x[12] + x[ 8];
      t1 = x[13] + x[ 9];
      t2 = x[14] + x[10];
      t3 = x[15] + x[11];
      x[ 0] ^= hc_rotl32_S (t0, 18);
      x[ 1] ^= hc_rotl32_S (t1, 18);
      x[ 2] ^= hc_rotl32_S (t2, 18);
      x[ 3] ^= hc_rotl32_S (t3, 18);

      t0 = x[ 4]; x[ 4] = x[ 7]; x[ 7] = x[ 6]; x[ 6] = x[ 5]; x[ 5] = t0;
      t0 = x[ 8]; x[ 8] = x[10]; x[10] = t0;
      t0 = x[ 9]; x[ 9] = x[11]; x[11] = t0;
      t0 = x[12]; x[12] = x[13]; x[13] = x[14]; x[14] = x[15]; x[15] = t0;

      t0 = x[ 0] + x[ 4];
      t1 = x[ 1] + x[ 5];
      t2 = x[ 2] + x[ 6];
      t3 = x[ 3] + x[ 7];
      x[12] ^= hc_rotl32_S (t0, 7);
      x[13] ^= hc_rotl32_S (t1, 7);
      x[14] ^= hc_rotl32_S (t2, 7);
      x[15] ^= hc_rotl32_S (t3, 7);

      t0 = x[12] + x[ 0];
      t1 = x[13] + x[ 1];
      t2 = x[14] + x[ 2];
      t3 = x[15] + x[ 3];
      x[ 8] ^= hc_rotl32_S (t0, 9);
      x[ 9] ^= hc_rotl32_S (t1, 9);
      x[10] ^= hc_rotl32_S (t2, 9);
      x[11] ^= hc_rotl32_S (t3, 9);

      t0 = x[ 8] + x[12];
      t1 = x[ 9] + x[13];
      t2 = x[10] + x[14];
      t3 = x[11] + x[15];
      x[ 4] ^= hc_rotl32_S (t0, 13);
      x[ 5] ^= hc_rotl32_S (t1, 13);
      x[ 6] ^= hc_rotl32_S (t2, 13);
      x[ 7] ^= hc_rotl32_S (t3, 13);

      t0 = x[ 4] + x[ 8];
      t1 = x[ 5] + x[ 9];
      t2 = x[ 6] + x[10];
      t3 = x[ 7] + x[11];
      x[ 0] ^= hc_rotl32_S (t0, 18);
      x[ 1] ^= hc_rotl32_S (t1, 18);
      x[ 2] ^= hc_rotl32_S (t2, 18);
      x[ 3] ^= hc_rotl32_S (t3, 18);

      t0 = x[ 4]; x[ 4] = x[ 5]; x[ 5] = x[ 6]; x[ 6] = x[ 7]; x[ 7] = t0;
      t0 = x[ 8]; x[ 8] = x[10]; x[10] = t0;
      t0 = x[ 9]; x[ 9] = x[11]; x[11] = t0;
      t0 = x[15]; x[15] = x[14]; x[14] = x[13]; x[13] = x[12]; x[12] = t0;
    }

    for (int j = 0; j < 16; j++)
    {
      x[j] += TI[i + j];
    }

    for (int j = 0; j < 16; j++)
    {
      TI[i + j] = x[j];
    }
  }

  #if SCRYPT_R > 1

  u32 TT[STATE_CNT / 2];

  for (int dst_off = 0, src_off = 16; src_off < STATE_CNT; dst_off += 16, src_off += 32)
  {
    for (int j = 0; j < 16; j++) TT[dst_off + j] = TI[src_off + j];
  }

  for (int dst_off = 16, src_off = 32; src_off < STATE_CNT; dst_off += 16, src_off += 32)
  {
    for (int j = 0; j < 16; j++) TI[dst_off + j] = TI[src_off + j];
  }

  for (int dst_off = STATE_CNT / 2, src_off = 0; dst_off < STATE_CNT; dst_off += 16, src_off += 16)
  {
    for (int j = 0; j < 16; j++) TI[dst_off + j] = TT[src_off + j];
  }

  #endif
}

DECLSPEC void salsa_r_p (PRIVATE_AS u32 *TI)
{
  u32 x[16];

  for (int j = 0; j < 16; j++) x[j] = TI[STATE_CNT - 16 + j];

  for (int i = 0; i < STATE_CNT; i += 16)
  {
    for (int j = 0; j < 16; j++)
    {
      x[j] ^= TI[i + j];
    }

    for (int j = 0; j < 16; j++)
    {
      TI[i + j] = x[j];
    }

    for (int r = 0; r < 4; r++)
    {
      u32 t0, t1, t2, t3;

      t0 = x[ 0] + x[12];
      t1 = x[ 1] + x[13];
      t2 = x[ 2] + x[14];
      t3 = x[ 3] + x[15];
      x[ 4] ^= hc_rotl32_S (t0, 7);
      x[ 5] ^= hc_rotl32_S (t1, 7);
      x[ 6] ^= hc_rotl32_S (t2, 7);
      x[ 7] ^= hc_rotl32_S (t3, 7);

      t0 = x[ 4] + x[ 0];
      t1 = x[ 5] + x[ 1];
      t2 = x[ 6] + x[ 2];
      t3 = x[ 7] + x[ 3];
      x[ 8] ^= hc_rotl32_S (t0, 9);
      x[ 9] ^= hc_rotl32_S (t1, 9);
      x[10] ^= hc_rotl32_S (t2, 9);
      x[11] ^= hc_rotl32_S (t3, 9);

      t0 = x[ 8] + x[ 4];
      t1 = x[ 9] + x[ 5];
      t2 = x[10] + x[ 6];
      t3 = x[11] + x[ 7];
      x[12] ^= hc_rotl32_S (t0, 13);
      x[13] ^= hc_rotl32_S (t1, 13);
      x[14] ^= hc_rotl32_S (t2, 13);
      x[15] ^= hc_rotl32_S (t3, 13);

      t0 = x[12] + x[ 8];
      t1 = x[13] + x[ 9];
      t2 = x[14] + x[10];
      t3 = x[15] + x[11];
      x[ 0] ^= hc_rotl32_S (t0, 18);
      x[ 1] ^= hc_rotl32_S (t1, 18);
      x[ 2] ^= hc_rotl32_S (t2, 18);
      x[ 3] ^= hc_rotl32_S (t3, 18);

      t0 = x[ 4]; x[ 4] = x[ 7]; x[ 7] = x[ 6]; x[ 6] = x[ 5]; x[ 5] = t0;
      t0 = x[ 8]; x[ 8] = x[10]; x[10] = t0;
      t0 = x[ 9]; x[ 9] = x[11]; x[11] = t0;
      t0 = x[12]; x[12] = x[13]; x[13] = x[14]; x[14] = x[15]; x[15] = t0;

      t0 = x[ 0] + x[ 4];
      t1 = x[ 1] + x[ 5];
      t2 = x[ 2] + x[ 6];
      t3 = x[ 3] + x[ 7];
      x[12] ^= hc_rotl32_S (t0, 7);
      x[13] ^= hc_rotl32_S (t1, 7);
      x[14] ^= hc_rotl32_S (t2, 7);
      x[15] ^= hc_rotl32_S (t3, 7);

      t0 = x[12] + x[ 0];
      t1 = x[13] + x[ 1];
      t2 = x[14] + x[ 2];
      t3 = x[15] + x[ 3];
      x[ 8] ^= hc_rotl32_S (t0, 9);
      x[ 9] ^= hc_rotl32_S (t1, 9);
      x[10] ^= hc_rotl32_S (t2, 9);
      x[11] ^= hc_rotl32_S (t3, 9);

      t0 = x[ 8] + x[12];
      t1 = x[ 9] + x[13];
      t2 = x[10] + x[14];
      t3 = x[11] + x[15];
      x[ 4] ^= hc_rotl32_S (t0, 13);
      x[ 5] ^= hc_rotl32_S (t1, 13);
      x[ 6] ^= hc_rotl32_S (t2, 13);
      x[ 7] ^= hc_rotl32_S (t3, 13);

      t0 = x[ 4] + x[ 8];
      t1 = x[ 5] + x[ 9];
      t2 = x[ 6] + x[10];
      t3 = x[ 7] + x[11];
      x[ 0] ^= hc_rotl32_S (t0, 18);
      x[ 1] ^= hc_rotl32_S (t1, 18);
      x[ 2] ^= hc_rotl32_S (t2, 18);
      x[ 3] ^= hc_rotl32_S (t3, 18);

      t0 = x[ 4]; x[ 4] = x[ 5]; x[ 5] = x[ 6]; x[ 6] = x[ 7]; x[ 7] = t0;
      t0 = x[ 8]; x[ 8] = x[10]; x[10] = t0;
      t0 = x[ 9]; x[ 9] = x[11]; x[11] = t0;
      t0 = x[15]; x[15] = x[14]; x[14] = x[13]; x[13] = x[12]; x[12] = t0;
    }

    for (int j = 0; j < 16; j++)
    {
      x[j] += TI[i + j];
    }

    for (int j = 0; j < 16; j++)
    {
      TI[i + j] = x[j];
    }
  }

  #if SCRYPT_R > 1

  u32 TT[STATE_CNT / 2];

  for (int dst_off = 0, src_off = 16; src_off < STATE_CNT; dst_off += 16, src_off += 32)
  {
    for (int j = 0; j < 16; j++) TT[dst_off + j] = TI[src_off + j];
  }

  for (int dst_off = 16, src_off = 32; src_off < STATE_CNT; dst_off += 16, src_off += 32)
  {
    for (int j = 0; j < 16; j++) TI[dst_off + j] = TI[src_off + j];
  }

  for (int dst_off = STATE_CNT / 2, src_off = 0; dst_off < STATE_CNT; dst_off += 16, src_off += 16)
  {
    for (int j = 0; j < 16; j++) TI[dst_off + j] = TT[src_off + j];
  }

  #endif
}

#ifdef IS_HIP
DECLSPEC void scrypt_smix_init (LOCAL_AS uint4 *X, GLOBAL_AS uint4 *V0, GLOBAL_AS uint4 *V1, GLOBAL_AS uint4 *V2, GLOBAL_AS uint4 *V3, const u64 gid)
#else
DECLSPEC void scrypt_smix_init (PRIVATE_AS uint4 *X, GLOBAL_AS uint4 *V0, GLOBAL_AS uint4 *V1, GLOBAL_AS uint4 *V2, GLOBAL_AS uint4 *V3, const u64 gid)
#endif
{
  const u32 ySIZE = SCRYPT_N >> SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT4;

  const u32 x = (u32) gid;

  const u32 xd4 = x / 4;
  const u32 xm4 = x & 3;

  GLOBAL_AS uint4 *V;

  switch (xm4)
  {
    case 0: V = V0; break;
    case 1: V = V1; break;
    case 2: V = V2; break;
    case 3: V = V3; break;
  }

  for (u32 y = 0; y < ySIZE; y++)
  {
    for (u32 z = 0; z < zSIZE; z++) V[CO] = X[z];

    #ifdef IS_HIP
    for (u32 i = 0; i < (1 << SCRYPT_TMTO); i++) salsa_r_l ((LOCAL_AS u32 *) X);
    #else
    for (u32 i = 0; i < (1 << SCRYPT_TMTO); i++) salsa_r_p ((PRIVATE_AS u32 *) X);
    #endif
  }
}

#ifdef IS_HIP
DECLSPEC void scrypt_smix_loop (PRIVATE_AS uint4 *X, LOCAL_AS uint4 *T, GLOBAL_AS uint4 *V0, GLOBAL_AS uint4 *V1, GLOBAL_AS uint4 *V2, GLOBAL_AS uint4 *V3, const u64 gid)
#else
DECLSPEC void scrypt_smix_loop (PRIVATE_AS uint4 *X, PRIVATE_AS uint4 *T, GLOBAL_AS uint4 *V0, GLOBAL_AS uint4 *V1, GLOBAL_AS uint4 *V2, GLOBAL_AS uint4 *V3, const u64 gid)
#endif
{
  const u32 ySIZE = SCRYPT_N >> SCRYPT_TMTO;
  const u32 zSIZE = STATE_CNT4;

  const u32 x = (u32) gid;

  const u32 xd4 = x / 4;
  const u32 xm4 = x & 3;

  GLOBAL_AS uint4 *V;

  switch (xm4)
  {
    case 0: V = V0; break;
    case 1: V = V1; break;
    case 2: V = V2; break;
    case 3: V = V3; break;
  }

  // note: max 2048 iterations = forced -u 2048

  const u32 N_max = (2048 > ySIZE) ? ySIZE : 2048;

  for (u32 N_pos = 0; N_pos < N_max; N_pos++)
  {
    const u32 k = X[zSIZE - 4].x & (SCRYPT_N - 1);

    const u32 y = k >> SCRYPT_TMTO;

    const u32 km = k - (y << SCRYPT_TMTO);

    for (u32 z = 0; z < zSIZE; z++) T[z] = V[CO];

    #ifdef IS_HIP
    for (u32 i = 0; i < km; i++) salsa_r_l ((LOCAL_AS u32 *) T);
    #else
    for (u32 i = 0; i < km; i++) salsa_r_p ((PRIVATE_AS u32 *) T);
    #endif

    for (u32 z = 0; z < zSIZE; z++) X[z] ^= T[z];

    salsa_r_p ((PRIVATE_AS u32 *) X);
  }
}

DECLSPEC void scrypt_blockmix_in (GLOBAL_AS uint4 *out_buf, const int out_len)
{
  for (int i = 0, j = 0; i < out_len; i += 64, j += 4)
  {
    uint4 T[4];

    T[0] = out_buf[j + 0];
    T[1] = out_buf[j + 1];
    T[2] = out_buf[j + 2];
    T[3] = out_buf[j + 3];

    uint4 X[4];

    #if defined IS_CUDA || defined IS_HIP
    X[0] = make_uint4 (T[0].x, T[1].y, T[2].z, T[3].w);
    X[1] = make_uint4 (T[1].x, T[2].y, T[3].z, T[0].w);
    X[2] = make_uint4 (T[2].x, T[3].y, T[0].z, T[1].w);
    X[3] = make_uint4 (T[3].x, T[0].y, T[1].z, T[2].w);
    #elif defined IS_METAL
    X[0] = uint4 (T[0].x, T[1].y, T[2].z, T[3].w);
    X[1] = uint4 (T[1].x, T[2].y, T[3].z, T[0].w);
    X[2] = uint4 (T[2].x, T[3].y, T[0].z, T[1].w);
    X[3] = uint4 (T[3].x, T[0].y, T[1].z, T[2].w);
    #else
    X[0] = (uint4) (T[0].x, T[1].y, T[2].z, T[3].w);
    X[1] = (uint4) (T[1].x, T[2].y, T[3].z, T[0].w);
    X[2] = (uint4) (T[2].x, T[3].y, T[0].z, T[1].w);
    X[3] = (uint4) (T[3].x, T[0].y, T[1].z, T[2].w);
    #endif

    out_buf[j + 0] = X[0];
    out_buf[j + 1] = X[1];
    out_buf[j + 2] = X[2];
    out_buf[j + 3] = X[3];
  }
}

DECLSPEC void scrypt_blockmix_out (GLOBAL_AS uint4 *out_buf, const int out_len)
{
  for (int i = 0, j = 0; i < out_len; i += 64, j += 4)
  {
    uint4 X[4];

    X[0] = out_buf[j + 0];
    X[1] = out_buf[j + 1];
    X[2] = out_buf[j + 2];
    X[3] = out_buf[j + 3];

    uint4 T[4];

    #if defined IS_CUDA || defined IS_HIP
    T[0] = make_uint4 (X[0].x, X[3].y, X[2].z, X[1].w);
    T[1] = make_uint4 (X[1].x, X[0].y, X[3].z, X[2].w);
    T[2] = make_uint4 (X[2].x, X[1].y, X[0].z, X[3].w);
    T[3] = make_uint4 (X[3].x, X[2].y, X[1].z, X[0].w);
    #elif defined IS_METAL
    T[0] = uint4 (X[0].x, X[3].y, X[2].z, X[1].w);
    T[1] = uint4 (X[1].x, X[0].y, X[3].z, X[2].w);
    T[2] = uint4 (X[2].x, X[1].y, X[0].z, X[3].w);
    T[3] = uint4 (X[3].x, X[2].y, X[1].z, X[0].w);
    #else
    T[0] = (uint4) (X[0].x, X[3].y, X[2].z, X[1].w);
    T[1] = (uint4) (X[1].x, X[0].y, X[3].z, X[2].w);
    T[2] = (uint4) (X[2].x, X[1].y, X[0].z, X[3].w);
    T[3] = (uint4) (X[3].x, X[2].y, X[1].z, X[0].w);
    #endif

    out_buf[j + 0] = T[0];
    out_buf[j + 1] = T[1];
    out_buf[j + 2] = T[2];
    out_buf[j + 3] = T[3];
  }
}

DECLSPEC void scrypt_pbkdf2_body (PRIVATE_AS sha256_hmac_ctx_t *sha256_hmac_ctx, GLOBAL_AS uint4 *out_buf, const int out_len)
{
  for (int i = 0, j = 1, k = 0; i < out_len; i += 32, j += 1, k += 2)
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

    u32 digest[8];

    digest[0] = hc_swap32_S (sha256_hmac_ctx2.opad.h[0]);
    digest[1] = hc_swap32_S (sha256_hmac_ctx2.opad.h[1]);
    digest[2] = hc_swap32_S (sha256_hmac_ctx2.opad.h[2]);
    digest[3] = hc_swap32_S (sha256_hmac_ctx2.opad.h[3]);
    digest[4] = hc_swap32_S (sha256_hmac_ctx2.opad.h[4]);
    digest[5] = hc_swap32_S (sha256_hmac_ctx2.opad.h[5]);
    digest[6] = hc_swap32_S (sha256_hmac_ctx2.opad.h[6]);
    digest[7] = hc_swap32_S (sha256_hmac_ctx2.opad.h[7]);

    #if defined IS_CUDA || defined IS_HIP
    const uint4 tmp0 = make_uint4 (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = make_uint4 (digest[4], digest[5], digest[6], digest[7]);
    #elif defined IS_METAL
    const uint4 tmp0 = uint4 (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = uint4 (digest[4], digest[5], digest[6], digest[7]);
    #else
    const uint4 tmp0 = (uint4) (digest[0], digest[1], digest[2], digest[3]);
    const uint4 tmp1 = (uint4) (digest[4], digest[5], digest[6], digest[7]);
    #endif

    out_buf[k + 0] = tmp0;
    out_buf[k + 1] = tmp1;
  }
}

DECLSPEC void scrypt_pbkdf2 (GLOBAL_AS const u32 *pw_buf, const int pw_len, GLOBAL_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS uint4 *out_buf, const int out_len)
{
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pw_buf, pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_buf, salt_len);

  scrypt_pbkdf2_body (&sha256_hmac_ctx, out_buf, out_len);
}

