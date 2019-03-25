/* This is an independent implementation of the encryption algorithm:   */
/*                                                                      */
/*         Twofish by Bruce Schneier and colleagues                     */
/*                                                                      */
/* which is a candidate algorithm in the Advanced Encryption Standard   */
/* programme of the US National Institute of Standards and Technology.  */
/*                                                                      */
/* Copyright in this implementation is held by Dr B R Gladman but I     */
/* hereby give permission for its free direct or derivative use subject */
/* to acknowledgment of its origin and compliance with any conditions   */
/* that the originators of t he algorithm place on its exploitation.    */
/*                                                                      */
/* My thanks to Doug Whiting and Niels Ferguson for comments that led   */
/* to improvements in this implementation.                              */
/*                                                                      */
/* Dr Brian Gladman (gladman@seven77.demon.co.uk) 14th January 1999     */
/*                                                                      */
/* -------------------------------------------------------------------- */
/*                                                                      */
/* Cleaned and optimized for GPU use with hashcat by Jens Steube        */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_cipher_twofish.h"

#define extract_byte(x,n) (((x) >> (8 * (n))) & 0xff)

#define g1_fun128(x)                        \
  (mds (0, q20 (extract_byte (x, 3), sk)) ^ \
   mds (1, q21 (extract_byte (x, 0), sk)) ^ \
   mds (2, q22 (extract_byte (x, 1), sk)) ^ \
   mds (3, q23 (extract_byte (x, 2), sk)))

#define g0_fun128(x)                        \
  (mds (0, q20 (extract_byte (x, 0), sk)) ^ \
   mds (1, q21 (extract_byte (x, 1), sk)) ^ \
   mds (2, q22 (extract_byte (x, 2), sk)) ^ \
   mds (3, q23 (extract_byte (x, 3), sk)))

#define f_rnd128(i)                                                   \
{                                                                     \
  u32 t0 = g0_fun128 (data[0]);                                       \
  u32 t1 = g1_fun128 (data[1]);                                       \
  data[2] = hc_rotr32_S (data[2] ^ (t0 + t1 + lk[4 * (i) + 8]), 1);      \
  data[3] = hc_rotl32_S (data[3], 1) ^ (t0 + 2 * t1 + lk[4 * (i) + 9]);  \
  u32 t2 = g0_fun128 (data[2]);                                       \
  u32 t3 = g1_fun128 (data[3]);                                       \
  data[0] = hc_rotr32_S (data[0] ^ (t2 + t3 + lk[4 * (i) + 10]), 1);     \
  data[1] = hc_rotl32_S (data[1], 1) ^ (t2 + 2 * t3 + lk[4 * (i) + 11]); \
}

#define i_rnd128(i)                                                   \
{                                                                     \
  u32 t0 = g0_fun128 (data[0]);                                       \
  u32 t1 = g1_fun128 (data[1]);                                       \
  data[2] = hc_rotl32_S (data[2], 1) ^ (t0 + t1 + lk[4 * (i) + 10]);     \
  data[3] = hc_rotr32_S (data[3] ^ (t0 + 2 * t1 + lk[4 * (i) + 11]), 1); \
  u32 t2 = g0_fun128 (data[2]);                                       \
  u32 t3 = g1_fun128 (data[3]);                                       \
  data[0] = hc_rotl32_S (data[0], 1) ^ (t2 + t3 + lk[4 * (i) +  8]);     \
  data[1] = hc_rotr32_S (data[1] ^ (t2 + 2 * t3 + lk[4 * (i) +  9]), 1); \
}

#define f_rnd256(i)                                                   \
{                                                                     \
  u32 t0 = g0_fun256 (data[0]);                                       \
  u32 t1 = g1_fun256 (data[1]);                                       \
  data[2] = hc_rotr32_S (data[2] ^ (t0 + t1 + lk[4 * (i) + 8]), 1);      \
  data[3] = hc_rotl32_S (data[3], 1) ^ (t0 + 2 * t1 + lk[4 * (i) + 9]);  \
  u32 t2 = g0_fun256 (data[2]);                                       \
  u32 t3 = g1_fun256 (data[3]);                                       \
  data[0] = hc_rotr32_S (data[0] ^ (t2 + t3 + lk[4 * (i) + 10]), 1);     \
  data[1] = hc_rotl32_S (data[1], 1) ^ (t2 + 2 * t3 + lk[4 * (i) + 11]); \
}

#define i_rnd256(i)                                                   \
{                                                                     \
  u32 t0 = g0_fun256 (data[0]);                                       \
  u32 t1 = g1_fun256 (data[1]);                                       \
  data[2] = hc_rotl32_S (data[2], 1) ^ (t0 + t1 + lk[4 * (i) + 10]);     \
  data[3] = hc_rotr32_S (data[3] ^ (t0 + 2 * t1 + lk[4 * (i) + 11]), 1); \
  u32 t2 = g0_fun256 (data[2]);                                       \
  u32 t3 = g1_fun256 (data[3]);                                       \
  data[0] = hc_rotl32_S (data[0], 1) ^ (t2 + t3 + lk[4 * (i) +  8]);     \
  data[1] = hc_rotr32_S (data[1] ^ (t2 + 2 * t3 + lk[4 * (i) +  9]), 1); \
}

#define q(n,x) q_tab[n][x]

#define mds(n,x) m_tab[n][x]

#define q20(x,k) q (0, q (0, x) ^ extract_byte (k[1], 0)) ^ extract_byte (k[0], 0)
#define q21(x,k) q (0, q (1, x) ^ extract_byte (k[1], 1)) ^ extract_byte (k[0], 1)
#define q22(x,k) q (1, q (0, x) ^ extract_byte (k[1], 2)) ^ extract_byte (k[0], 2)
#define q23(x,k) q (1, q (1, x) ^ extract_byte (k[1], 3)) ^ extract_byte (k[0], 3)

#define q40(x,k) q (0, q (0, q (1, q (1, x) ^ extract_byte (k[3], 0)) ^ extract_byte (k[2], 0)) ^ extract_byte (k[1], 0)) ^ extract_byte (k[0], 0)
#define q41(x,k) q (0, q (1, q (1, q (0, x) ^ extract_byte (k[3], 1)) ^ extract_byte (k[2], 1)) ^ extract_byte (k[1], 1)) ^ extract_byte (k[0], 1)
#define q42(x,k) q (1, q (0, q (0, q (0, x) ^ extract_byte (k[3], 2)) ^ extract_byte (k[2], 2)) ^ extract_byte (k[1], 2)) ^ extract_byte (k[0], 2)
#define q43(x,k) q (1, q (1, q (0, q (1, x) ^ extract_byte (k[3], 3)) ^ extract_byte (k[2], 3)) ^ extract_byte (k[1], 3)) ^ extract_byte (k[0], 3)

DECLSPEC u32 mds_rem (u32 p0, u32 p1)
{
  #define G_MOD 0x14d

  #define MDS_REM_ROUND()           \
  {                                 \
    u32 t = p1 >> 24;               \
    p1 = (p1 << 8) | (p0 >> 24);    \
    p0 <<= 8;                       \
    u32 u = (t << 1);               \
    if (t & 0x80) u ^= G_MOD;       \
    p1 ^= t ^ (u << 16);            \
    u ^= (t >> 1);                  \
    if (t & 0x01) u ^= G_MOD >> 1;  \
    p1 ^= (u << 24) | (u << 8);     \
  }

  MDS_REM_ROUND();
  MDS_REM_ROUND();
  MDS_REM_ROUND();
  MDS_REM_ROUND();
  MDS_REM_ROUND();
  MDS_REM_ROUND();
  MDS_REM_ROUND();
  MDS_REM_ROUND();

  #undef MDS_REM_ROUND

  return p1;
}

DECLSPEC u32 h_fun128 (u32 *sk, u32 *lk, const u32 x, const u32 *key)
{
  u32  b0, b1, b2, b3;

  b0 = extract_byte (x, 0);
  b1 = extract_byte (x, 1);
  b2 = extract_byte (x, 2);
  b3 = extract_byte (x, 3);

  b0 = q (0, (q (0, b0) ^ extract_byte (key[1], 0))) ^ extract_byte (key[0], 0);
  b1 = q (0, (q (1, b1) ^ extract_byte (key[1], 1))) ^ extract_byte (key[0], 1);
  b2 = q (1, (q (0, b2) ^ extract_byte (key[1], 2))) ^ extract_byte (key[0], 2);
  b3 = q (1, (q (1, b3) ^ extract_byte (key[1], 3))) ^ extract_byte (key[0], 3);

  return mds (0, b0) ^ mds (1, b1) ^ mds (2, b2) ^ mds (3, b3);
}

DECLSPEC void twofish128_set_key (u32 *sk, u32 *lk, const u32 *ukey)
{
  u32 me_key[2];

  me_key[0] = ukey[0];
  me_key[1] = ukey[2];

  u32 mo_key[2];

  mo_key[0] = ukey[1];
  mo_key[1] = ukey[3];

  sk[1] = mds_rem (me_key[0], mo_key[0]);
  sk[0] = mds_rem (me_key[1], mo_key[1]);

  for (int i = 0; i < 40; i += 2)
  {
    u32 a = 0x01010101 * i;
    u32 b = 0x01010101 + a;

    a = h_fun128 (sk, lk, a, me_key);
    b = h_fun128 (sk, lk, b, mo_key);

    b = hc_rotl32_S (b, 8);

    lk[i + 0] = a + b;
    lk[i + 1] = hc_rotl32_S (a + 2 * b, 9);
  }
}

DECLSPEC void twofish128_encrypt (const u32 *sk, const u32 *lk, const u32 *in, u32 *out)
{
  u32 data[4];

  data[0] = in[0] ^ lk[0];
  data[1] = in[1] ^ lk[1];
  data[2] = in[2] ^ lk[2];
  data[3] = in[3] ^ lk[3];

  f_rnd128 (0);
  f_rnd128 (1);
  f_rnd128 (2);
  f_rnd128 (3);
  f_rnd128 (4);
  f_rnd128 (5);
  f_rnd128 (6);
  f_rnd128 (7);

  out[0] = data[2] ^ lk[4];
  out[1] = data[3] ^ lk[5];
  out[2] = data[0] ^ lk[6];
  out[3] = data[1] ^ lk[7];
}

DECLSPEC void twofish128_decrypt (const u32 *sk, const u32 *lk, const u32 *in, u32 *out)
{
  u32 data[4];

  data[0] = in[0] ^ lk[4];
  data[1] = in[1] ^ lk[5];
  data[2] = in[2] ^ lk[6];
  data[3] = in[3] ^ lk[7];

  i_rnd128 (7);
  i_rnd128 (6);
  i_rnd128 (5);
  i_rnd128 (4);
  i_rnd128 (3);
  i_rnd128 (2);
  i_rnd128 (1);
  i_rnd128 (0);

  out[0] = data[2] ^ lk[0];
  out[1] = data[3] ^ lk[1];
  out[2] = data[0] ^ lk[2];
  out[3] = data[1] ^ lk[3];
}

// 256 bit key

#define g1_fun256(x)                        \
  (mds (0, q40 (extract_byte (x, 3), sk)) ^ \
   mds (1, q41 (extract_byte (x, 0), sk)) ^ \
   mds (2, q42 (extract_byte (x, 1), sk)) ^ \
   mds (3, q43 (extract_byte (x, 2), sk)))

#define g0_fun256(x)                        \
  (mds (0, q40 (extract_byte (x, 0), sk)) ^ \
   mds (1, q41 (extract_byte (x, 1), sk)) ^ \
   mds (2, q42 (extract_byte (x, 2), sk)) ^ \
   mds (3, q43 (extract_byte (x, 3), sk)))

DECLSPEC u32 h_fun256 (u32 *sk, u32 *lk, const u32 x, const u32 *key)
{
  u32  b0, b1, b2, b3;

  b0 = extract_byte (x, 0);
  b1 = extract_byte (x, 1);
  b2 = extract_byte (x, 2);
  b3 = extract_byte (x, 3);

  b0 = q (1, b0) ^ extract_byte (key[3], 0);
  b1 = q (0, b1) ^ extract_byte (key[3], 1);
  b2 = q (0, b2) ^ extract_byte (key[3], 2);
  b3 = q (1, b3) ^ extract_byte (key[3], 3);

  b0 = q (1, b0) ^ extract_byte (key[2], 0);
  b1 = q (1, b1) ^ extract_byte (key[2], 1);
  b2 = q (0, b2) ^ extract_byte (key[2], 2);
  b3 = q (0, b3) ^ extract_byte (key[2], 3);

  b0 = q (0, (q (0, b0) ^ extract_byte (key[1], 0))) ^ extract_byte (key[0], 0);
  b1 = q (0, (q (1, b1) ^ extract_byte (key[1], 1))) ^ extract_byte (key[0], 1);
  b2 = q (1, (q (0, b2) ^ extract_byte (key[1], 2))) ^ extract_byte (key[0], 2);
  b3 = q (1, (q (1, b3) ^ extract_byte (key[1], 3))) ^ extract_byte (key[0], 3);

  return mds (0, b0) ^ mds (1, b1) ^ mds (2, b2) ^ mds (3, b3);
}

DECLSPEC void twofish256_set_key (u32 *sk, u32 *lk, const u32 *ukey)
{
  u32 me_key[4];

  me_key[0] = ukey[0];
  me_key[1] = ukey[2];
  me_key[2] = ukey[4];
  me_key[3] = ukey[6];

  u32 mo_key[4];

  mo_key[0] = ukey[1];
  mo_key[1] = ukey[3];
  mo_key[2] = ukey[5];
  mo_key[3] = ukey[7];

  sk[3] = mds_rem (me_key[0], mo_key[0]);
  sk[2] = mds_rem (me_key[1], mo_key[1]);
  sk[1] = mds_rem (me_key[2], mo_key[2]);
  sk[0] = mds_rem (me_key[3], mo_key[3]);

  for (int i = 0; i < 40; i += 2)
  {
    u32 a = 0x01010101 * i;
    u32 b = 0x01010101 + a;

    a = h_fun256 (sk, lk, a, me_key);
    b = h_fun256 (sk, lk, b, mo_key);

    b = hc_rotl32_S (b, 8);

    lk[i + 0] = a + b;
    lk[i + 1] = hc_rotl32_S (a + 2 * b, 9);
  }
}

DECLSPEC void twofish256_encrypt (const u32 *sk, const u32 *lk, const u32 *in, u32 *out)
{
  u32 data[4];

  data[0] = in[0] ^ lk[0];
  data[1] = in[1] ^ lk[1];
  data[2] = in[2] ^ lk[2];
  data[3] = in[3] ^ lk[3];

  f_rnd256 (0);
  f_rnd256 (1);
  f_rnd256 (2);
  f_rnd256 (3);
  f_rnd256 (4);
  f_rnd256 (5);
  f_rnd256 (6);
  f_rnd256 (7);

  out[0] = data[2] ^ lk[4];
  out[1] = data[3] ^ lk[5];
  out[2] = data[0] ^ lk[6];
  out[3] = data[1] ^ lk[7];
}

DECLSPEC void twofish256_decrypt (const u32 *sk, const u32 *lk, const u32 *in, u32 *out)
{
  u32 data[4];

  data[0] = in[0] ^ lk[4];
  data[1] = in[1] ^ lk[5];
  data[2] = in[2] ^ lk[6];
  data[3] = in[3] ^ lk[7];

  i_rnd256 (7);
  i_rnd256 (6);
  i_rnd256 (5);
  i_rnd256 (4);
  i_rnd256 (3);
  i_rnd256 (2);
  i_rnd256 (1);
  i_rnd256 (0);

  out[0] = data[2] ^ lk[0];
  out[1] = data[3] ^ lk[1];
  out[2] = data[0] ^ lk[2];
  out[3] = data[1] ^ lk[3];
}

#define g1_fun128
#define g0_fun128
#define f_rnd128
#define i_rnd128
#define f_rnd256
#define i_rnd256

#define q

#define mds

#define q20
#define q21
#define q22
#define q23
#define q40
#define q41
#define q42
#define q43
