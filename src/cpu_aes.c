/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define IS_GENERIC

#include "common.h"
#include "types_int.h"
#include "bitops.h"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "cpu_aes.h"

// 128 bit

static void AES128_ExpandKey (const u32 *userkey, u32 *rek)
{
  u32 userkey_s[4];

  userkey_s[0] = byte_swap_32 (userkey[0]);
  userkey_s[1] = byte_swap_32 (userkey[1]);
  userkey_s[2] = byte_swap_32 (userkey[2]);
  userkey_s[3] = byte_swap_32 (userkey[3]);

  rek[0] = userkey_s[0];
  rek[1] = userkey_s[1];
  rek[2] = userkey_s[2];
  rek[3] = userkey_s[3];

  int i;
  int j;

  for (i = 0, j = 0; i < 10; i += 1, j += 4)
  {
    u32 temp = rek[j + 3];

    temp = (te2[(temp >> 16) & 0xff] & 0xff000000)
         ^ (te3[(temp >>  8) & 0xff] & 0x00ff0000)
         ^ (te0[(temp >>  0) & 0xff] & 0x0000ff00)
         ^ (te1[(temp >> 24) & 0xff] & 0x000000ff);

    rek[j + 4] = rek[j + 0]
               ^ temp
               ^ rcon[i];

    rek[j + 5] = rek[j + 1] ^ rek[j + 4];
    rek[j + 6] = rek[j + 2] ^ rek[j + 5];
    rek[j + 7] = rek[j + 3] ^ rek[j + 6];
  }
}

static void AES128_InvertKey (u32 *rdk)
{
  int i;
  int j;

  for (i = 0, j = 40; i < j; i += 4, j -= 4)
  {
    u32 temp;

    temp = rdk[i + 0]; rdk[i + 0] = rdk[j + 0]; rdk[j + 0] = temp;
    temp = rdk[i + 1]; rdk[i + 1] = rdk[j + 1]; rdk[j + 1] = temp;
    temp = rdk[i + 2]; rdk[i + 2] = rdk[j + 2]; rdk[j + 2] = temp;
    temp = rdk[i + 3]; rdk[i + 3] = rdk[j + 3]; rdk[j + 3] = temp;
  }

  for (i = 1, j = 4; i < 10; i += 1, j += 4)
  {
    rdk[j + 0] =
      td0[te1[(rdk[j + 0] >> 24) & 0xff] & 0xff] ^
      td1[te1[(rdk[j + 0] >> 16) & 0xff] & 0xff] ^
      td2[te1[(rdk[j + 0] >>  8) & 0xff] & 0xff] ^
      td3[te1[(rdk[j + 0] >>  0) & 0xff] & 0xff];

    rdk[j + 1] =
      td0[te1[(rdk[j + 1] >> 24) & 0xff] & 0xff] ^
      td1[te1[(rdk[j + 1] >> 16) & 0xff] & 0xff] ^
      td2[te1[(rdk[j + 1] >>  8) & 0xff] & 0xff] ^
      td3[te1[(rdk[j + 1] >>  0) & 0xff] & 0xff];

    rdk[j + 2] =
      td0[te1[(rdk[j + 2] >> 24) & 0xff] & 0xff] ^
      td1[te1[(rdk[j + 2] >> 16) & 0xff] & 0xff] ^
      td2[te1[(rdk[j + 2] >>  8) & 0xff] & 0xff] ^
      td3[te1[(rdk[j + 2] >>  0) & 0xff] & 0xff];

    rdk[j + 3] =
      td0[te1[(rdk[j + 3] >> 24) & 0xff] & 0xff] ^
      td1[te1[(rdk[j + 3] >> 16) & 0xff] & 0xff] ^
      td2[te1[(rdk[j + 3] >>  8) & 0xff] & 0xff] ^
      td3[te1[(rdk[j + 3] >>  0) & 0xff] & 0xff];
  }
}

static void AES128_encrypt (const u32 *in, u32 *out, const u32 *rek)
{
  u32 in_s[4];

  in_s[0] = byte_swap_32 (in[0]);
  in_s[1] = byte_swap_32 (in[1]);
  in_s[2] = byte_swap_32 (in[2]);
  in_s[3] = byte_swap_32 (in[3]);

  u32 s0 = in_s[0] ^ rek[0];
  u32 s1 = in_s[1] ^ rek[1];
  u32 s2 = in_s[2] ^ rek[2];
  u32 s3 = in_s[3] ^ rek[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[ 4];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[ 5];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[ 6];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[ 7];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[ 8];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[ 9];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[10];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[11];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[12];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[13];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[14];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[15];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[16];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[17];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[18];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[19];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[20];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[21];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[22];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[23];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[24];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[25];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[26];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[27];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[28];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[29];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[30];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[31];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[32];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[33];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[34];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[35];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[36];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[37];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[38];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[39];

  out[0] = (te4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (te4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (te4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (te4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rek[40];

  out[1] = (te4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (te4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (te4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (te4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rek[41];

  out[2] = (te4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (te4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (te4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (te4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rek[42];

  out[3] = (te4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (te4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (te4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (te4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rek[43];

  out[0] = byte_swap_32 (out[0]);
  out[1] = byte_swap_32 (out[1]);
  out[2] = byte_swap_32 (out[2]);
  out[3] = byte_swap_32 (out[3]);
}

static void AES128_decrypt (const u32 *in, u32 *out, const u32 *rdk)
{
  u32 in_s[4];

  in_s[0] = byte_swap_32 (in[0]);
  in_s[1] = byte_swap_32 (in[1]);
  in_s[2] = byte_swap_32 (in[2]);
  in_s[3] = byte_swap_32 (in[3]);

  u32 s0 = in_s[0] ^ rdk[0];
  u32 s1 = in_s[1] ^ rdk[1];
  u32 s2 = in_s[2] ^ rdk[2];
  u32 s3 = in_s[3] ^ rdk[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[ 4];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[ 5];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[ 6];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[ 7];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[ 8];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[ 9];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[10];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[11];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[12];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[13];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[14];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[15];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[16];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[17];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[18];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[19];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[20];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[21];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[22];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[23];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[24];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[25];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[26];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[27];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[28];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[29];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[30];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[31];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[32];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[33];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[34];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[35];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[36];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[37];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[38];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[39];

  out[0] = (td4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (td4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (td4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (td4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[40];

  out[1] = (td4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (td4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (td4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (td4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[41];

  out[2] = (td4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (td4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (td4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (td4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[42];

  out[3] = (td4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (td4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (td4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (td4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[43];

  out[0] = byte_swap_32 (out[0]);
  out[1] = byte_swap_32 (out[1]);
  out[2] = byte_swap_32 (out[2]);
  out[3] = byte_swap_32 (out[3]);
}

// 256 bit

static void AES256_ExpandKey (const u32 *userkey, u32 *rek)
{
  u32 userkey_s[8];

  userkey_s[0] = byte_swap_32 (userkey[0]);
  userkey_s[1] = byte_swap_32 (userkey[1]);
  userkey_s[2] = byte_swap_32 (userkey[2]);
  userkey_s[3] = byte_swap_32 (userkey[3]);
  userkey_s[4] = byte_swap_32 (userkey[4]);
  userkey_s[5] = byte_swap_32 (userkey[5]);
  userkey_s[6] = byte_swap_32 (userkey[6]);
  userkey_s[7] = byte_swap_32 (userkey[7]);

  rek[0] = userkey_s[0];
  rek[1] = userkey_s[1];
  rek[2] = userkey_s[2];
  rek[3] = userkey_s[3];
  rek[4] = userkey_s[4];
  rek[5] = userkey_s[5];
  rek[6] = userkey_s[6];
  rek[7] = userkey_s[7];

  int i;
  int j;

  i = 0;
  j = 0;

  while (1)
  {
    u32 temp = rek[j +  7];

    rek[j +  8] = rek[j +  0]
           ^ (te2[(temp >> 16) & 0xff] & 0xff000000)
           ^ (te3[(temp >>  8) & 0xff] & 0x00ff0000)
           ^ (te0[(temp >>  0) & 0xff] & 0x0000ff00)
           ^ (te1[(temp >> 24) & 0xff] & 0x000000ff)
           ^ rcon[i];

    rek[j +  9] = rek[j +  1] ^ rek[j +  8];
    rek[j + 10] = rek[j +  2] ^ rek[j +  9];
    rek[j + 11] = rek[j +  3] ^ rek[j + 10];

    if (++i == 7) break;

    temp = rek[j + 11];

    rek[j + 12] = rek[j +  4]
           ^ (te2[(temp >> 24) & 0xff] & 0xff000000)
           ^ (te3[(temp >> 16) & 0xff] & 0x00ff0000)
           ^ (te0[(temp >>  8) & 0xff] & 0x0000ff00)
           ^ (te1[(temp >>  0) & 0xff] & 0x000000ff);

    rek[j + 13] = rek[j +  5] ^ rek[j + 12];
    rek[j + 14] = rek[j +  6] ^ rek[j + 13];
    rek[j + 15] = rek[j +  7] ^ rek[j + 14];

    j += 8;
  }
}

static void AES256_InvertKey (u32 *rdk)
{
  for (u32 i = 0, j = 56; i < j; i += 4, j -= 4)
  {
    u32 temp;

    temp = rdk[i + 0]; rdk[i + 0] = rdk[j + 0]; rdk[j + 0] = temp;
    temp = rdk[i + 1]; rdk[i + 1] = rdk[j + 1]; rdk[j + 1] = temp;
    temp = rdk[i + 2]; rdk[i + 2] = rdk[j + 2]; rdk[j + 2] = temp;
    temp = rdk[i + 3]; rdk[i + 3] = rdk[j + 3]; rdk[j + 3] = temp;
  }

  for (u32 i = 1, j = 4; i < 14; i += 1, j += 4)
  {
    rdk[j + 0] =
      td0[te1[(rdk[j + 0] >> 24) & 0xff] & 0xff] ^
      td1[te1[(rdk[j + 0] >> 16) & 0xff] & 0xff] ^
      td2[te1[(rdk[j + 0] >>  8) & 0xff] & 0xff] ^
      td3[te1[(rdk[j + 0] >>  0) & 0xff] & 0xff];

    rdk[j + 1] =
      td0[te1[(rdk[j + 1] >> 24) & 0xff] & 0xff] ^
      td1[te1[(rdk[j + 1] >> 16) & 0xff] & 0xff] ^
      td2[te1[(rdk[j + 1] >>  8) & 0xff] & 0xff] ^
      td3[te1[(rdk[j + 1] >>  0) & 0xff] & 0xff];

    rdk[j + 2] =
      td0[te1[(rdk[j + 2] >> 24) & 0xff] & 0xff] ^
      td1[te1[(rdk[j + 2] >> 16) & 0xff] & 0xff] ^
      td2[te1[(rdk[j + 2] >>  8) & 0xff] & 0xff] ^
      td3[te1[(rdk[j + 2] >>  0) & 0xff] & 0xff];

    rdk[j + 3] =
      td0[te1[(rdk[j + 3] >> 24) & 0xff] & 0xff] ^
      td1[te1[(rdk[j + 3] >> 16) & 0xff] & 0xff] ^
      td2[te1[(rdk[j + 3] >>  8) & 0xff] & 0xff] ^
      td3[te1[(rdk[j + 3] >>  0) & 0xff] & 0xff];
  }
}

static void AES256_encrypt (const u32 *in, u32 *out, const u32 *rek)
{
  u32 in_s[4];

  in_s[0] = byte_swap_32 (in[0]);
  in_s[1] = byte_swap_32 (in[1]);
  in_s[2] = byte_swap_32 (in[2]);
  in_s[3] = byte_swap_32 (in[3]);

  u32 s0 = in_s[0] ^ rek[0];
  u32 s1 = in_s[1] ^ rek[1];
  u32 s2 = in_s[2] ^ rek[2];
  u32 s3 = in_s[3] ^ rek[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[ 4];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[ 5];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[ 6];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[ 7];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[ 8];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[ 9];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[10];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[11];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[12];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[13];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[14];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[15];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[16];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[17];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[18];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[19];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[20];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[21];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[22];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[23];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[24];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[25];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[26];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[27];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[28];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[29];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[30];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[31];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[32];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[33];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[34];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[35];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[36];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[37];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[38];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[39];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[40];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[41];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[42];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[43];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[44];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[45];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[46];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[47];
  s0 = te0[t0 >> 24] ^ te1[(t1 >> 16) & 0xff] ^ te2[(t2 >>  8) & 0xff] ^ te3[t3 & 0xff] ^ rek[48];
  s1 = te0[t1 >> 24] ^ te1[(t2 >> 16) & 0xff] ^ te2[(t3 >>  8) & 0xff] ^ te3[t0 & 0xff] ^ rek[49];
  s2 = te0[t2 >> 24] ^ te1[(t3 >> 16) & 0xff] ^ te2[(t0 >>  8) & 0xff] ^ te3[t1 & 0xff] ^ rek[50];
  s3 = te0[t3 >> 24] ^ te1[(t0 >> 16) & 0xff] ^ te2[(t1 >>  8) & 0xff] ^ te3[t2 & 0xff] ^ rek[51];
  t0 = te0[s0 >> 24] ^ te1[(s1 >> 16) & 0xff] ^ te2[(s2 >>  8) & 0xff] ^ te3[s3 & 0xff] ^ rek[52];
  t1 = te0[s1 >> 24] ^ te1[(s2 >> 16) & 0xff] ^ te2[(s3 >>  8) & 0xff] ^ te3[s0 & 0xff] ^ rek[53];
  t2 = te0[s2 >> 24] ^ te1[(s3 >> 16) & 0xff] ^ te2[(s0 >>  8) & 0xff] ^ te3[s1 & 0xff] ^ rek[54];
  t3 = te0[s3 >> 24] ^ te1[(s0 >> 16) & 0xff] ^ te2[(s1 >>  8) & 0xff] ^ te3[s2 & 0xff] ^ rek[55];

  out[0] = (te4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (te4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (te4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (te4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rek[56];

  out[1] = (te4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (te4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (te4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (te4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rek[57];

  out[2] = (te4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (te4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (te4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (te4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rek[58];

  out[3] = (te4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (te4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (te4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (te4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rek[59];

  out[0] = byte_swap_32 (out[0]);
  out[1] = byte_swap_32 (out[1]);
  out[2] = byte_swap_32 (out[2]);
  out[3] = byte_swap_32 (out[3]);
}

static void AES256_decrypt (const u32 *in, u32 *out, const u32 *rdk)
{
  u32 in_s[4];

  in_s[0] = byte_swap_32 (in[0]);
  in_s[1] = byte_swap_32 (in[1]);
  in_s[2] = byte_swap_32 (in[2]);
  in_s[3] = byte_swap_32 (in[3]);

  u32 s0 = in_s[0] ^ rdk[0];
  u32 s1 = in_s[1] ^ rdk[1];
  u32 s2 = in_s[2] ^ rdk[2];
  u32 s3 = in_s[3] ^ rdk[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[ 4];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[ 5];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[ 6];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[ 7];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[ 8];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[ 9];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[10];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[11];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[12];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[13];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[14];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[15];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[16];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[17];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[18];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[19];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[20];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[21];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[22];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[23];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[24];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[25];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[26];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[27];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[28];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[29];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[30];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[31];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[32];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[33];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[34];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[35];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[36];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[37];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[38];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[39];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[40];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[41];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[42];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[43];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[44];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[45];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[46];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[47];
  s0 = td0[t0 >> 24] ^ td1[(t3 >> 16) & 0xff] ^ td2[(t2 >>  8) & 0xff] ^ td3[t1 & 0xff] ^ rdk[48];
  s1 = td0[t1 >> 24] ^ td1[(t0 >> 16) & 0xff] ^ td2[(t3 >>  8) & 0xff] ^ td3[t2 & 0xff] ^ rdk[49];
  s2 = td0[t2 >> 24] ^ td1[(t1 >> 16) & 0xff] ^ td2[(t0 >>  8) & 0xff] ^ td3[t3 & 0xff] ^ rdk[50];
  s3 = td0[t3 >> 24] ^ td1[(t2 >> 16) & 0xff] ^ td2[(t1 >>  8) & 0xff] ^ td3[t0 & 0xff] ^ rdk[51];
  t0 = td0[s0 >> 24] ^ td1[(s3 >> 16) & 0xff] ^ td2[(s2 >>  8) & 0xff] ^ td3[s1 & 0xff] ^ rdk[52];
  t1 = td0[s1 >> 24] ^ td1[(s0 >> 16) & 0xff] ^ td2[(s3 >>  8) & 0xff] ^ td3[s2 & 0xff] ^ rdk[53];
  t2 = td0[s2 >> 24] ^ td1[(s1 >> 16) & 0xff] ^ td2[(s0 >>  8) & 0xff] ^ td3[s3 & 0xff] ^ rdk[54];
  t3 = td0[s3 >> 24] ^ td1[(s2 >> 16) & 0xff] ^ td2[(s1 >>  8) & 0xff] ^ td3[s0 & 0xff] ^ rdk[55];

  out[0] = (td4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (td4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (td4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (td4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[56];

  out[1] = (td4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (td4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (td4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (td4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[57];

  out[2] = (td4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (td4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (td4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (td4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[58];

  out[3] = (td4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (td4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (td4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (td4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[59];

  out[0] = byte_swap_32 (out[0]);
  out[1] = byte_swap_32 (out[1]);
  out[2] = byte_swap_32 (out[2]);
  out[3] = byte_swap_32 (out[3]);
}

// wrappers

void AES_set_encrypt_key (const u8 *key, int keysize, AES_KEY *aes_key)
{
  aes_key->bits = keysize;

  if (aes_key->bits == 128)
  {
    AES128_ExpandKey ((const u32 *) key, aes_key->rek);
  }
  else if (aes_key->bits == 256)
  {
    AES256_ExpandKey ((const u32 *) key, aes_key->rek);
  }
}

void AES_set_decrypt_key (const u8 *key, int keysize, AES_KEY *aes_key)
{
  aes_key->bits = keysize;

  if (aes_key->bits == 128)
  {
    AES128_ExpandKey ((const u32 *) key, aes_key->rdk);

    AES128_InvertKey (aes_key->rdk);
  }
  else if (aes_key->bits == 256)
  {
    AES256_ExpandKey ((const u32 *) key, aes_key->rdk);

    AES256_InvertKey (aes_key->rdk);
  }
}

void AES_encrypt (AES_KEY *aes_key, const u8 *input, u8 *output)
{
  if (aes_key->bits == 128)
  {
    AES128_encrypt ((const u32 *) input, (u32 *) output, aes_key->rek);
  }
  else if (aes_key->bits == 256)
  {
    AES256_encrypt ((const u32 *) input, (u32 *) output, aes_key->rek);
  }
}

void AES_decrypt (AES_KEY *aes_key, const u8 *input, u8 *output)
{
  if (aes_key->bits == 128)
  {
    AES128_decrypt ((const u32 *) input, (u32 *) output, aes_key->rdk);
  }
  else if (aes_key->bits == 256)
  {
    AES256_decrypt ((const u32 *) input, (u32 *) output, aes_key->rdk);
  }
}

// helper

void AES128_decrypt_cbc (const u32 key[4], const u32 iv[4], const u32 in[16], u32 out[16])
{
  AES_KEY skey;

  AES_set_decrypt_key ((const u8 *) key, 128, &skey);

  u32 _iv[4] = { 0 };

  _iv[0] = iv[0];
  _iv[1] = iv[1];
  _iv[2] = iv[2];
  _iv[3] = iv[3];

  for (int i = 0; i < 16; i += 4)
  {
    u32 _in[4] = { 0 };
    u32 _out[4] = { 0 };

    _in[0] = in[i + 0];
    _in[1] = in[i + 1];
    _in[2] = in[i + 2];
    _in[3] = in[i + 3];

    AES_decrypt (&skey, (const u8 *) _in, (u8 *) _out);

    _out[0] ^= _iv[0];
    _out[1] ^= _iv[1];
    _out[2] ^= _iv[2];
    _out[3] ^= _iv[3];

    out[i + 0] = _out[0];
    out[i + 1] = _out[1];
    out[i + 2] = _out[2];
    out[i + 3] = _out[3];

    _iv[0] = _in[0];
    _iv[1] = _in[1];
    _iv[2] = _in[2];
    _iv[3] = _in[3];
  }
}
