/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"

#include "inc_cipher_aes.cl"

/* Fist0urs */
void u32_to_hex_lower (const u32 v, u8 hex[8])
{
  const u8 tbl[0x10] =
  {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    'a', 'b', 'c', 'd', 'e', 'f',
  };

  hex[1] = tbl[v >>  0 & 15];
  hex[0] = tbl[v >>  4 & 15];
  hex[3] = tbl[v >>  8 & 15];
  hex[2] = tbl[v >> 12 & 15];
  hex[5] = tbl[v >> 16 & 15];
  hex[4] = tbl[v >> 20 & 15];
  hex[7] = tbl[v >> 24 & 15];
  hex[6] = tbl[v >> 28 & 15];
}

int
pretty_print(char *message, void *data, int len)
{
    int g = 0;
    for (int i = 0 ; i < len; i++)
    {
        if (g == 0)
        {
            printf("%s: ", message);
            g++;
        }
        printf("%02x", ((char *)(data))[i]);
    }
    printf("\n");
    
    return 1;
    
}
/* Fist0urs_end */




void AES256_ExpandKey (u32 *userkey, u32 *rek, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  rek[0] = userkey[0];
  rek[1] = userkey[1];
  rek[2] = userkey[2];
  rek[3] = userkey[3];
  rek[4] = userkey[4];
  rek[5] = userkey[5];
  rek[6] = userkey[6];
  rek[7] = userkey[7];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0, j = 0; i < 7; i += 1, j += 8)
  {
    const u32 temp1 = rek[j + 7];

    rek[j +  8] = rek[j + 0]
                ^ (s_te2[(temp1 >> 16) & 0xff] & 0xff000000)
                ^ (s_te3[(temp1 >>  8) & 0xff] & 0x00ff0000)
                ^ (s_te0[(temp1 >>  0) & 0xff] & 0x0000ff00)
                ^ (s_te1[(temp1 >> 24) & 0xff] & 0x000000ff)
                ^ rcon[i];
    rek[j +  9] = rek[j + 1] ^ rek[j +  8];
    rek[j + 10] = rek[j + 2] ^ rek[j +  9];
    rek[j + 11] = rek[j + 3] ^ rek[j + 10];

    if (i == 6) continue;

    const u32 temp2 = rek[j + 11];

    rek[j + 12] = rek[j + 4]
                ^ (s_te2[(temp2 >> 24) & 0xff] & 0xff000000)
                ^ (s_te3[(temp2 >> 16) & 0xff] & 0x00ff0000)
                ^ (s_te0[(temp2 >>  8) & 0xff] & 0x0000ff00)
                ^ (s_te1[(temp2 >>  0) & 0xff] & 0x000000ff);
    rek[j + 13] = rek[j + 5] ^ rek[j + 12];
    rek[j + 14] = rek[j + 6] ^ rek[j + 13];
    rek[j + 15] = rek[j + 7] ^ rek[j + 14];
  }
}

void AES256_InvertKey (u32 *rdk, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0, j = 56; i < 28; i += 4, j -= 4)
  {
    u32 temp;

    temp = rdk[i + 0]; rdk[i + 0] = rdk[j + 0]; rdk[j + 0] = temp;
    temp = rdk[i + 1]; rdk[i + 1] = rdk[j + 1]; rdk[j + 1] = temp;
    temp = rdk[i + 2]; rdk[i + 2] = rdk[j + 2]; rdk[j + 2] = temp;
    temp = rdk[i + 3]; rdk[i + 3] = rdk[j + 3]; rdk[j + 3] = temp;
  }

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 1, j = 4; i < 14; i += 1, j += 4)
  {
    rdk[j + 0] =
      s_td0[s_te1[(rdk[j + 0] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 0] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 0] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 0] >>  0) & 0xff] & 0xff];

    rdk[j + 1] =
      s_td0[s_te1[(rdk[j + 1] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 1] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 1] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 1] >>  0) & 0xff] & 0xff];

    rdk[j + 2] =
      s_td0[s_te1[(rdk[j + 2] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 2] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 2] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 2] >>  0) & 0xff] & 0xff];

    rdk[j + 3] =
      s_td0[s_te1[(rdk[j + 3] >> 24) & 0xff] & 0xff] ^
      s_td1[s_te1[(rdk[j + 3] >> 16) & 0xff] & 0xff] ^
      s_td2[s_te1[(rdk[j + 3] >>  8) & 0xff] & 0xff] ^
      s_td3[s_te1[(rdk[j + 3] >>  0) & 0xff] & 0xff];
  }
}

void AES256_decrypt (const u32 *in, u32 *out, const u32 *rdk, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 t0 = in[0] ^ rdk[0];
  u32 t1 = in[1] ^ rdk[1];
  u32 t2 = in[2] ^ rdk[2];
  u32 t3 = in[3] ^ rdk[3];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 4; i < 56; i += 4)
  {
    const uchar4 x0 = as_uchar4 (t0);
    const uchar4 x1 = as_uchar4 (t1);
    const uchar4 x2 = as_uchar4 (t2);
    const uchar4 x3 = as_uchar4 (t3);

    t0 = s_td0[x0.s3] ^ s_td1[x3.s2] ^ s_td2[x2.s1] ^ s_td3[x1.s0] ^ rdk[i + 0];
    t1 = s_td0[x1.s3] ^ s_td1[x0.s2] ^ s_td2[x3.s1] ^ s_td3[x2.s0] ^ rdk[i + 1];
    t2 = s_td0[x2.s3] ^ s_td1[x1.s2] ^ s_td2[x0.s1] ^ s_td3[x3.s0] ^ rdk[i + 2];
    t3 = s_td0[x3.s3] ^ s_td1[x2.s2] ^ s_td2[x1.s1] ^ s_td3[x0.s0] ^ rdk[i + 3];
  }

  out[0] = (s_td4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[56];

  out[1] = (s_td4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[57];

  out[2] = (s_td4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[58];

  out[3] = (s_td4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rdk[59];
}

void AES256_encrypt (const u32 *in, u32 *out, const u32 *rek, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 t0 = in[0] ^ rek[0];
  u32 t1 = in[1] ^ rek[1];
  u32 t2 = in[2] ^ rek[2];
  u32 t3 = in[3] ^ rek[3];

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 4; i < 56; i += 4)
  {
    const uchar4 x0 = as_uchar4 (t0);
    const uchar4 x1 = as_uchar4 (t1);
    const uchar4 x2 = as_uchar4 (t2);
    const uchar4 x3 = as_uchar4 (t3);

    t0 = s_te0[x0.s3] ^ s_te1[x1.s2] ^ s_te2[x2.s1] ^ s_te3[x3.s0] ^ rek[i + 0];
    t1 = s_te0[x1.s3] ^ s_te1[x2.s2] ^ s_te2[x3.s1] ^ s_te3[x0.s0] ^ rek[i + 1];
    t2 = s_te0[x2.s3] ^ s_te1[x3.s2] ^ s_te2[x0.s1] ^ s_te3[x1.s0] ^ rek[i + 2];
    t3 = s_te0[x3.s3] ^ s_te1[x0.s2] ^ s_te2[x1.s1] ^ s_te3[x2.s0] ^ rek[i + 3];
  }

  out[0] = (s_te4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ rek[56];

  out[1] = (s_te4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ rek[57];

  out[2] = (s_te4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ rek[58];

  out[3] = (s_te4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ rek[59];
}

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

void md4_transform_S (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[4])
{
  u32 a = digest[0];
  u32 b = digest[1];
  u32 c = digest[2];
  u32 d = digest[3];

  MD4_STEP_S (MD4_Fo, a, b, c, d, w0[0], MD4C00, MD4S00);
  MD4_STEP_S (MD4_Fo, d, a, b, c, w0[1], MD4C00, MD4S01);
  MD4_STEP_S (MD4_Fo, c, d, a, b, w0[2], MD4C00, MD4S02);
  MD4_STEP_S (MD4_Fo, b, c, d, a, w0[3], MD4C00, MD4S03);
  MD4_STEP_S (MD4_Fo, a, b, c, d, w1[0], MD4C00, MD4S00);
  MD4_STEP_S (MD4_Fo, d, a, b, c, w1[1], MD4C00, MD4S01);
  MD4_STEP_S (MD4_Fo, c, d, a, b, w1[2], MD4C00, MD4S02);
  MD4_STEP_S (MD4_Fo, b, c, d, a, w1[3], MD4C00, MD4S03);
  MD4_STEP_S (MD4_Fo, a, b, c, d, w2[0], MD4C00, MD4S00);
  MD4_STEP_S (MD4_Fo, d, a, b, c, w2[1], MD4C00, MD4S01);
  MD4_STEP_S (MD4_Fo, c, d, a, b, w2[2], MD4C00, MD4S02);
  MD4_STEP_S (MD4_Fo, b, c, d, a, w2[3], MD4C00, MD4S03);
  MD4_STEP_S (MD4_Fo, a, b, c, d, w3[0], MD4C00, MD4S00);
  MD4_STEP_S (MD4_Fo, d, a, b, c, w3[1], MD4C00, MD4S01);
  MD4_STEP_S (MD4_Fo, c, d, a, b, w3[2], MD4C00, MD4S02);
  MD4_STEP_S (MD4_Fo, b, c, d, a, w3[3], MD4C00, MD4S03);

  MD4_STEP_S (MD4_Go, a, b, c, d, w0[0], MD4C01, MD4S10);
  MD4_STEP_S (MD4_Go, d, a, b, c, w1[0], MD4C01, MD4S11);
  MD4_STEP_S (MD4_Go, c, d, a, b, w2[0], MD4C01, MD4S12);
  MD4_STEP_S (MD4_Go, b, c, d, a, w3[0], MD4C01, MD4S13);
  MD4_STEP_S (MD4_Go, a, b, c, d, w0[1], MD4C01, MD4S10);
  MD4_STEP_S (MD4_Go, d, a, b, c, w1[1], MD4C01, MD4S11);
  MD4_STEP_S (MD4_Go, c, d, a, b, w2[1], MD4C01, MD4S12);
  MD4_STEP_S (MD4_Go, b, c, d, a, w3[1], MD4C01, MD4S13);
  MD4_STEP_S (MD4_Go, a, b, c, d, w0[2], MD4C01, MD4S10);
  MD4_STEP_S (MD4_Go, d, a, b, c, w1[2], MD4C01, MD4S11);
  MD4_STEP_S (MD4_Go, c, d, a, b, w2[2], MD4C01, MD4S12);
  MD4_STEP_S (MD4_Go, b, c, d, a, w3[2], MD4C01, MD4S13);
  MD4_STEP_S (MD4_Go, a, b, c, d, w0[3], MD4C01, MD4S10);
  MD4_STEP_S (MD4_Go, d, a, b, c, w1[3], MD4C01, MD4S11);
  MD4_STEP_S (MD4_Go, c, d, a, b, w2[3], MD4C01, MD4S12);
  MD4_STEP_S (MD4_Go, b, c, d, a, w3[3], MD4C01, MD4S13);

  MD4_STEP_S (MD4_H , a, b, c, d, w0[0], MD4C02, MD4S20);
  MD4_STEP_S (MD4_H , d, a, b, c, w2[0], MD4C02, MD4S21);
  MD4_STEP_S (MD4_H , c, d, a, b, w1[0], MD4C02, MD4S22);
  MD4_STEP_S (MD4_H , b, c, d, a, w3[0], MD4C02, MD4S23);
  MD4_STEP_S (MD4_H , a, b, c, d, w0[2], MD4C02, MD4S20);
  MD4_STEP_S (MD4_H , d, a, b, c, w2[2], MD4C02, MD4S21);
  MD4_STEP_S (MD4_H , c, d, a, b, w1[2], MD4C02, MD4S22);
  MD4_STEP_S (MD4_H , b, c, d, a, w3[2], MD4C02, MD4S23);
  MD4_STEP_S (MD4_H , a, b, c, d, w0[1], MD4C02, MD4S20);
  MD4_STEP_S (MD4_H , d, a, b, c, w2[1], MD4C02, MD4S21);
  MD4_STEP_S (MD4_H , c, d, a, b, w1[1], MD4C02, MD4S22);
  MD4_STEP_S (MD4_H , b, c, d, a, w3[1], MD4C02, MD4S23);
  MD4_STEP_S (MD4_H , a, b, c, d, w0[3], MD4C02, MD4S20);
  MD4_STEP_S (MD4_H , d, a, b, c, w2[3], MD4C02, MD4S21);
  MD4_STEP_S (MD4_H , c, d, a, b, w1[3], MD4C02, MD4S22);
  MD4_STEP_S (MD4_H , b, c, d, a, w3[3], MD4C02, MD4S23);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
}

void sha1_transform_S (const u32 w0[4], const u32 w1[4], const u32 w2[4], const u32 w3[4], u32 digest[5])
{
  u32 A = digest[0];
  u32 B = digest[1];
  u32 C = digest[2];
  u32 D = digest[3];
  u32 E = digest[4];

  u32 w0_t = w0[0];
  u32 w1_t = w0[1];
  u32 w2_t = w0[2];
  u32 w3_t = w0[3];
  u32 w4_t = w1[0];
  u32 w5_t = w1[1];
  u32 w6_t = w1[2];
  u32 w7_t = w1[3];
  u32 w8_t = w2[0];
  u32 w9_t = w2[1];
  u32 wa_t = w2[2];
  u32 wb_t = w2[3];
  u32 wc_t = w3[0];
  u32 wd_t = w3[1];
  u32 we_t = w3[2];
  u32 wf_t = w3[3];

  #undef K
  #define K SHA1C00

  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, w0_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w1_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w2_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w3_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w4_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, w5_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w6_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w7_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w8_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w9_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, wa_t);
  SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, wb_t);
  SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, wc_t);
  SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, wd_t);
  SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, we_t);
  SHA1_STEP_S (SHA1_F0o, A, B, C, D, E, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F0o, E, A, B, C, D, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F0o, D, E, A, B, C, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F0o, C, D, E, A, B, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F0o, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F2o, A, B, C, D, E, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F2o, E, A, B, C, D, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F2o, D, E, A, B, C, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F2o, C, D, E, A, B, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F2o, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, wf_t);
  w0_t = rotl32_S ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w0_t);
  w1_t = rotl32_S ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w1_t);
  w2_t = rotl32_S ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w2_t);
  w3_t = rotl32_S ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w3_t);
  w4_t = rotl32_S ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w4_t);
  w5_t = rotl32_S ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, w5_t);
  w6_t = rotl32_S ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, w6_t);
  w7_t = rotl32_S ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, w7_t);
  w8_t = rotl32_S ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, w8_t);
  w9_t = rotl32_S ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, w9_t);
  wa_t = rotl32_S ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wa_t);
  wb_t = rotl32_S ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP_S (SHA1_F1, A, B, C, D, E, wb_t);
  wc_t = rotl32_S ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP_S (SHA1_F1, E, A, B, C, D, wc_t);
  wd_t = rotl32_S ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP_S (SHA1_F1, D, E, A, B, C, wd_t);
  we_t = rotl32_S ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP_S (SHA1_F1, C, D, E, A, B, we_t);
  wf_t = rotl32_S ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP_S (SHA1_F1, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

void hmac_sha1_pad_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[5], u32 opad[5])
{
  w0[0] = w0[0] ^ 0x36363636;
  w0[1] = w0[1] ^ 0x36363636;
  w0[2] = w0[2] ^ 0x36363636;
  w0[3] = w0[3] ^ 0x36363636;
  w1[0] = w1[0] ^ 0x36363636;
  w1[1] = w1[1] ^ 0x36363636;
  w1[2] = w1[2] ^ 0x36363636;
  w1[3] = w1[3] ^ 0x36363636;
  w2[0] = w2[0] ^ 0x36363636;
  w2[1] = w2[1] ^ 0x36363636;
  w2[2] = w2[2] ^ 0x36363636;
  w2[3] = w2[3] ^ 0x36363636;
  w3[0] = w3[0] ^ 0x36363636;
  w3[1] = w3[1] ^ 0x36363636;
  w3[2] = w3[2] ^ 0x36363636;
  w3[3] = w3[3] ^ 0x36363636;

  ipad[0] = SHA1M_A;
  ipad[1] = SHA1M_B;
  ipad[2] = SHA1M_C;
  ipad[3] = SHA1M_D;
  ipad[4] = SHA1M_E;

  sha1_transform_S (w0, w1, w2, w3, ipad);

  w0[0] = w0[0] ^ 0x6a6a6a6a;
  w0[1] = w0[1] ^ 0x6a6a6a6a;
  w0[2] = w0[2] ^ 0x6a6a6a6a;
  w0[3] = w0[3] ^ 0x6a6a6a6a;
  w1[0] = w1[0] ^ 0x6a6a6a6a;
  w1[1] = w1[1] ^ 0x6a6a6a6a;
  w1[2] = w1[2] ^ 0x6a6a6a6a;
  w1[3] = w1[3] ^ 0x6a6a6a6a;
  w2[0] = w2[0] ^ 0x6a6a6a6a;
  w2[1] = w2[1] ^ 0x6a6a6a6a;
  w2[2] = w2[2] ^ 0x6a6a6a6a;
  w2[3] = w2[3] ^ 0x6a6a6a6a;
  w3[0] = w3[0] ^ 0x6a6a6a6a;
  w3[1] = w3[1] ^ 0x6a6a6a6a;
  w3[2] = w3[2] ^ 0x6a6a6a6a;
  w3[3] = w3[3] ^ 0x6a6a6a6a;

  opad[0] = SHA1M_A;
  opad[1] = SHA1M_B;
  opad[2] = SHA1M_C;
  opad[3] = SHA1M_D;
  opad[4] = SHA1M_E;

  sha1_transform_S (w0, w1, w2, w3, opad);
}

void hmac_sha1_run_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 ipad[5], u32 opad[5], u32 digest[5])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_S (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_S (w0, w1, w2, w3, digest);
}

void sha1_transform_V (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], u32x digest[5])
{
  u32x A = digest[0];
  u32x B = digest[1];
  u32x C = digest[2];
  u32x D = digest[3];
  u32x E = digest[4];

  u32x w0_t = w0[0];
  u32x w1_t = w0[1];
  u32x w2_t = w0[2];
  u32x w3_t = w0[3];
  u32x w4_t = w1[0];
  u32x w5_t = w1[1];
  u32x w6_t = w1[2];
  u32x w7_t = w1[3];
  u32x w8_t = w2[0];
  u32x w9_t = w2[1];
  u32x wa_t = w2[2];
  u32x wb_t = w2[3];
  u32x wc_t = w3[0];
  u32x wd_t = w3[1];
  u32x we_t = w3[2];
  u32x wf_t = w3[3];

  #undef K
  #define K SHA1C00

  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w0_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w1_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w2_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w3_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w4_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, w5_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, w6_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, w7_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, w8_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, w9_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wa_t);
  SHA1_STEP (SHA1_F0o, E, A, B, C, D, wb_t);
  SHA1_STEP (SHA1_F0o, D, E, A, B, C, wc_t);
  SHA1_STEP (SHA1_F0o, C, D, E, A, B, wd_t);
  SHA1_STEP (SHA1_F0o, B, C, D, E, A, we_t);
  SHA1_STEP (SHA1_F0o, A, B, C, D, E, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F0o, E, A, B, C, D, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F0o, D, E, A, B, C, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F0o, C, D, E, A, B, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F0o, B, C, D, E, A, w3_t);

  #undef K
  #define K SHA1C01

  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w7_t);

  #undef K
  #define K SHA1C02

  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F2o, A, B, C, D, E, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F2o, E, A, B, C, D, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F2o, D, E, A, B, C, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F2o, C, D, E, A, B, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F2o, B, C, D, E, A, wb_t);

  #undef K
  #define K SHA1C03

  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, wf_t);
  w0_t = rotl32 ((wd_t ^ w8_t ^ w2_t ^ w0_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w0_t);
  w1_t = rotl32 ((we_t ^ w9_t ^ w3_t ^ w1_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w1_t);
  w2_t = rotl32 ((wf_t ^ wa_t ^ w4_t ^ w2_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w2_t);
  w3_t = rotl32 ((w0_t ^ wb_t ^ w5_t ^ w3_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w3_t);
  w4_t = rotl32 ((w1_t ^ wc_t ^ w6_t ^ w4_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w4_t);
  w5_t = rotl32 ((w2_t ^ wd_t ^ w7_t ^ w5_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, w5_t);
  w6_t = rotl32 ((w3_t ^ we_t ^ w8_t ^ w6_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, w6_t);
  w7_t = rotl32 ((w4_t ^ wf_t ^ w9_t ^ w7_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, w7_t);
  w8_t = rotl32 ((w5_t ^ w0_t ^ wa_t ^ w8_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, w8_t);
  w9_t = rotl32 ((w6_t ^ w1_t ^ wb_t ^ w9_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, w9_t);
  wa_t = rotl32 ((w7_t ^ w2_t ^ wc_t ^ wa_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wa_t);
  wb_t = rotl32 ((w8_t ^ w3_t ^ wd_t ^ wb_t), 1u); SHA1_STEP (SHA1_F1, A, B, C, D, E, wb_t);
  wc_t = rotl32 ((w9_t ^ w4_t ^ we_t ^ wc_t), 1u); SHA1_STEP (SHA1_F1, E, A, B, C, D, wc_t);
  wd_t = rotl32 ((wa_t ^ w5_t ^ wf_t ^ wd_t), 1u); SHA1_STEP (SHA1_F1, D, E, A, B, C, wd_t);
  we_t = rotl32 ((wb_t ^ w6_t ^ w0_t ^ we_t), 1u); SHA1_STEP (SHA1_F1, C, D, E, A, B, we_t);
  wf_t = rotl32 ((wc_t ^ w7_t ^ w1_t ^ wf_t), 1u); SHA1_STEP (SHA1_F1, B, C, D, E, A, wf_t);

  digest[0] += A;
  digest[1] += B;
  digest[2] += C;
  digest[3] += D;
  digest[4] += E;
}

void hmac_sha1_run_V (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x ipad[5], u32x opad[5], u32x digest[5])
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_V (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_V (w0, w1, w2, w3, digest);
}

__kernel void m15300_init (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global dpapimk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global dpapimk_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w0[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];


  u32 w1[4];

  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  u32 w2[4];

  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];

  u32 w3[4];

  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  u32 pw_len = pws[gid].pw_len;

  append_0x80_4x4_S (w0, w1, w2, w3, pw_len);

  make_unicode (w1, w2, w3);
  make_unicode (w0, w0, w1);

  /**
   * main
   */

  /**
   * salt == SID
   */

  u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];
  u32 salt_buf4[4];
  u32 salt_buf5[4];

  salt_buf0[0] = esalt_bufs[digests_offset].SID[0];
  salt_buf0[1] = esalt_bufs[digests_offset].SID[1];
  salt_buf0[2] = esalt_bufs[digests_offset].SID[2];
  salt_buf0[3] = esalt_bufs[digests_offset].SID[3];
  salt_buf1[0] = esalt_bufs[digests_offset].SID[4];
  salt_buf1[1] = esalt_bufs[digests_offset].SID[5];
  salt_buf1[2] = esalt_bufs[digests_offset].SID[6];
  salt_buf1[3] = esalt_bufs[digests_offset].SID[7];
  salt_buf2[0] = esalt_bufs[digests_offset].SID[8];
  salt_buf2[1] = esalt_bufs[digests_offset].SID[9];
  salt_buf2[2] = 0;
  salt_buf2[3] = 0;   
   
  /*
  ici on va faire le hmac sha1 avec md4 et sha1
  
  */
  u32 digest_context[5];

  /* local credentials */
  if (esalt_bufs[digests_offset].context == 1)
  {
    digest_context[0] = SHA1M_A;
    digest_context[1] = SHA1M_B;
    digest_context[2] = SHA1M_C;
    digest_context[3] = SHA1M_D;
    digest_context[4] = SHA1M_E;
    
    w0[0] = swap32 (w0[0]);
    w0[1] = swap32 (w0[1]);
    w0[2] = swap32 (w0[2]);
    w0[3] = swap32 (w0[3]);
    
    w1[0] = swap32 (w1[0]);
    w1[1] = swap32 (w1[1]);
    w1[2] = swap32 (w1[2]);
    w1[3] = swap32 (w1[3]);
    
    w2[0] = swap32 (w2[0]);
    w2[1] = swap32 (w2[1]);
    w2[2] = swap32 (w2[2]);
    w2[3] = swap32 (w2[3]);

    w3[0] = swap32 (w3[0]);
    w3[1] = swap32 (w3[1]);
    w3[2] = 0;
    w3[3] = pw_len * 2 * 8;

    sha1_transform_S (w0, w1, w2, w3, digest_context);

    digest_context[0] = swap32 (digest_context[0]);
    digest_context[1] = swap32 (digest_context[1]);
    digest_context[2] = swap32 (digest_context[2]);
    digest_context[3] = swap32 (digest_context[3]);
  }
  /* domain credentials */
  else if (esalt_bufs[digests_offset].context == 2)
  {
    digest_context[0] = MD4M_A;
    digest_context[1] = MD4M_B;
    digest_context[2] = MD4M_C;
    digest_context[3] = MD4M_D;

    w3[2] = pw_len * 2 * 8;

    md4_transform_S (w0, w1, w2, w3, digest_context);

    digest_context[4] = 0;
  }

  u8 hex[8] = {0};
  u32_to_hex_lower(digest_context[0], hex);
  printf("digest_context[0]: %uld\n", digest_context[0]);
  for (int i = 0; i < 8; i++)
    printf("%c", hex[i]);
  printf("\n");

  u32_to_hex_lower(digest_context[1], hex);
  printf("digest_context[1]: %uld\n", digest_context[1]);
  for (int i = 0; i < 8; i++)
    printf("%c", hex[i]);
  printf("\n");

  u32_to_hex_lower(digest_context[2], hex);
  printf("digest_context[2]: %uld\n", digest_context[2]);
  for (int i = 0; i < 8; i++)
    printf("%c", hex[i]);
  printf("\n");

  u32_to_hex_lower(digest_context[3], hex);
  printf("digest_context[3]: %uld\n", digest_context[3]);
  for (int i = 0; i < 8; i++)
    printf("%c", hex[i]);
  printf("\n");  

  /* initialize hmac sha1 */
  
    /**
   * pads
   */

  w0[0] = swap32_S (digest_context[0]);
  w0[1] = swap32_S (digest_context[1]);
  w0[2] = swap32_S (digest_context[2]);
  w0[3] = swap32_S (digest_context[3]);
  w1[0] = swap32_S (digest_context[4]);
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

  u32 ipad[5];
  u32 opad[5];

  hmac_sha1_pad_S (w0, w1, w2, w3, ipad, opad);

  tmps[gid].ipad[0] = ipad[0];
  tmps[gid].ipad[1] = ipad[1];
  tmps[gid].ipad[2] = ipad[2];
  tmps[gid].ipad[3] = ipad[3];
  tmps[gid].ipad[4] = ipad[4];

  tmps[gid].opad[0] = opad[0];
  tmps[gid].opad[1] = opad[1];
  tmps[gid].opad[2] = opad[2];
  tmps[gid].opad[3] = opad[3];
  tmps[gid].opad[4] = opad[4];
  
  /**
   * hmac1
   */

   /* salt_buf c'est le SID là */
  w0[0] = salt_buf0[0];
  w0[1] = salt_buf0[1];
  w0[2] = salt_buf0[2];
  w0[3] = salt_buf0[3];
  w1[0] = salt_buf1[0];
  w1[1] = salt_buf1[1];
  w1[2] = salt_buf1[2];
  w1[3] = salt_buf1[3];
  w2[0] = salt_buf2[0];
  w2[1] = salt_buf2[1];
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + salt_len + 4) * 8;

  append_0x01_4x4_S (w0, w1, w2, w3, salt_len + 3);
  append_0x80_4x4_S (w0, w1, w2, w3, salt_len + 4);

  w0[0] = swap32_S (w0[0]);
  w0[1] = swap32_S (w0[1]);
  w0[2] = swap32_S (w0[2]);
  w0[3] = swap32_S (w0[3]);
  w1[0] = swap32_S (w1[0]);
  w1[1] = swap32_S (w1[1]);
  w1[2] = swap32_S (w1[2]);
  w1[3] = swap32_S (w1[3]);
  w2[0] = swap32_S (w2[0]);
  w2[1] = swap32_S (w2[1]);
  w2[2] = swap32_S (w2[2]);
  w2[3] = swap32_S (w2[3]);
  w3[0] = swap32_S (w3[0]);
  w3[1] = swap32_S (w3[1]);

  u32 digest[5];

  hmac_sha1_run_S (w0, w1, w2, w3, ipad, opad, digest);

  // tmps[gid].tmp_digest[0] = digest[0];
  // tmps[gid].tmp_digest[1] = digest[1];
  // tmps[gid].tmp_digest[2] = digest[2];
  // tmps[gid].tmp_digest[3] = digest[3];
  // tmps[gid].tmp_digest[4] = digest[4];
  // tmps[gid].tmp_digest[5] = digest[5];
  // tmps[gid].tmp_digest[6] = digest[6];
  // tmps[gid].tmp_digest[7] = digest[7];
  

  u32_to_hex_lower(digest[0], hex);
  printf("digest[0]: %uld\n", digest[0]);
  for (int i = 0; i < 8; i++)
    printf("%c", hex[i]);
  printf("\n");

  u32_to_hex_lower(digest[1], hex);
  printf("digest[1]: %uld\n", digest[1]);
  for (int i = 0; i < 8; i++)
    printf("%c", hex[i]);
  printf("\n");

  u32_to_hex_lower(digest[2], hex);
  printf("digest[2]: %uld\n", digest[2]);
  for (int i = 0; i < 8; i++)
    printf("%c", hex[i]);
  printf("\n");

  u32_to_hex_lower(digest[3], hex);
  printf("digest[3]: %uld\n", digest[3]);
  for (int i = 0; i < 8; i++)
    printf("%c", hex[i]);
  printf("\n"); 
  
}

__kernel void m15300_loop (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global dpapimk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global dpapimk_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

}

__kernel void m15300_comp (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global dpapimk_tmp_t *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global dpapimk_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 rules_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

}
