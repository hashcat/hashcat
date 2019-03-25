/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_common.h"
#include "inc_cipher_aes.h"

// 128 bit key

DECLSPEC void aes128_ExpandKey (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  ks[ 0] = ukey[0];
  ks[ 1] = ukey[1];
  ks[ 2] = ukey[2];
  ks[ 3] = ukey[3];
  ks[ 4] = ks[ 0] ^ 0x01000000
                  ^ (s_te2[(ks[ 3] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[ 3] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[ 3] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[ 3] >> 24) & 0xff] & 0x000000ff);
  ks[ 5] = ks[ 1] ^ ks[ 4];
  ks[ 6] = ks[ 2] ^ ks[ 5];
  ks[ 7] = ks[ 3] ^ ks[ 6];
  ks[ 8] = ks[ 4] ^ 0x02000000
                  ^ (s_te2[(ks[ 7] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[ 7] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[ 7] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[ 7] >> 24) & 0xff] & 0x000000ff);
  ks[ 9] = ks[ 5] ^ ks[ 8];
  ks[10] = ks[ 6] ^ ks[ 9];
  ks[11] = ks[ 7] ^ ks[10];
  ks[12] = ks[ 8] ^ 0x04000000
                  ^ (s_te2[(ks[11] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[11] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[11] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[11] >> 24) & 0xff] & 0x000000ff);
  ks[13] = ks[ 9] ^ ks[12];
  ks[14] = ks[10] ^ ks[13];
  ks[15] = ks[11] ^ ks[14];
  ks[16] = ks[12] ^ 0x08000000
                  ^ (s_te2[(ks[15] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[15] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[15] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[15] >> 24) & 0xff] & 0x000000ff);
  ks[17] = ks[13] ^ ks[16];
  ks[18] = ks[14] ^ ks[17];
  ks[19] = ks[15] ^ ks[18];
  ks[20] = ks[16] ^ 0x10000000
                  ^ (s_te2[(ks[19] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[19] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[19] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[19] >> 24) & 0xff] & 0x000000ff);
  ks[21] = ks[17] ^ ks[20];
  ks[22] = ks[18] ^ ks[21];
  ks[23] = ks[19] ^ ks[22];
  ks[24] = ks[20] ^ 0x20000000
                  ^ (s_te2[(ks[23] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[23] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[23] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[23] >> 24) & 0xff] & 0x000000ff);
  ks[25] = ks[21] ^ ks[24];
  ks[26] = ks[22] ^ ks[25];
  ks[27] = ks[23] ^ ks[26];
  ks[28] = ks[24] ^ 0x40000000
                  ^ (s_te2[(ks[27] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[27] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[27] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[27] >> 24) & 0xff] & 0x000000ff);
  ks[29] = ks[25] ^ ks[28];
  ks[30] = ks[26] ^ ks[29];
  ks[31] = ks[27] ^ ks[30];
  ks[32] = ks[28] ^ 0x80000000
                  ^ (s_te2[(ks[31] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[31] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[31] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[31] >> 24) & 0xff] & 0x000000ff);
  ks[33] = ks[29] ^ ks[32];
  ks[34] = ks[30] ^ ks[33];
  ks[35] = ks[31] ^ ks[34];
  ks[36] = ks[32] ^ 0x1b000000
                  ^ (s_te2[(ks[35] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[35] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[35] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[35] >> 24) & 0xff] & 0x000000ff);
  ks[37] = ks[33] ^ ks[36];
  ks[38] = ks[34] ^ ks[37];
  ks[39] = ks[35] ^ ks[38];
  ks[40] = ks[36] ^ 0x36000000
                  ^ (s_te2[(ks[39] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[39] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[39] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[39] >> 24) & 0xff] & 0x000000ff);
  ks[41] = ks[37] ^ ks[40];
  ks[42] = ks[38] ^ ks[41];
  ks[43] = ks[39] ^ ks[42];
}

DECLSPEC void aes128_InvertKey (u32 *ks, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 temp;

  temp = ks[ 0]; ks[ 0] = ks[40]; ks[40] = temp;
  temp = ks[ 1]; ks[ 1] = ks[41]; ks[41] = temp;
  temp = ks[ 2]; ks[ 2] = ks[42]; ks[42] = temp;
  temp = ks[ 3]; ks[ 3] = ks[43]; ks[43] = temp;
  temp = ks[ 4]; ks[ 4] = ks[36]; ks[36] = temp;
  temp = ks[ 5]; ks[ 5] = ks[37]; ks[37] = temp;
  temp = ks[ 6]; ks[ 6] = ks[38]; ks[38] = temp;
  temp = ks[ 7]; ks[ 7] = ks[39]; ks[39] = temp;
  temp = ks[ 8]; ks[ 8] = ks[32]; ks[32] = temp;
  temp = ks[ 9]; ks[ 9] = ks[33]; ks[33] = temp;
  temp = ks[10]; ks[10] = ks[34]; ks[34] = temp;
  temp = ks[11]; ks[11] = ks[35]; ks[35] = temp;
  temp = ks[12]; ks[12] = ks[28]; ks[28] = temp;
  temp = ks[13]; ks[13] = ks[29]; ks[29] = temp;
  temp = ks[14]; ks[14] = ks[30]; ks[30] = temp;
  temp = ks[15]; ks[15] = ks[31]; ks[31] = temp;
  temp = ks[16]; ks[16] = ks[24]; ks[24] = temp;
  temp = ks[17]; ks[17] = ks[25]; ks[25] = temp;
  temp = ks[18]; ks[18] = ks[26]; ks[26] = temp;
  temp = ks[19]; ks[19] = ks[27]; ks[27] = temp;

  ks[ 4] = td0[te1[(ks[ 4] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 4] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 4] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 4] >>  0) & 0xff] & 0xff];
  ks[ 5] = td0[te1[(ks[ 5] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 5] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 5] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 5] >>  0) & 0xff] & 0xff];
  ks[ 6] = td0[te1[(ks[ 6] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 6] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 6] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 6] >>  0) & 0xff] & 0xff];
  ks[ 7] = td0[te1[(ks[ 7] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 7] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 7] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 7] >>  0) & 0xff] & 0xff];
  ks[ 8] = td0[te1[(ks[ 8] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 8] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 8] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 8] >>  0) & 0xff] & 0xff];
  ks[ 9] = td0[te1[(ks[ 9] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 9] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 9] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 9] >>  0) & 0xff] & 0xff];
  ks[10] = td0[te1[(ks[10] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[10] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[10] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[10] >>  0) & 0xff] & 0xff];
  ks[11] = td0[te1[(ks[11] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[11] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[11] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[11] >>  0) & 0xff] & 0xff];
  ks[12] = td0[te1[(ks[12] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[12] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[12] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[12] >>  0) & 0xff] & 0xff];
  ks[13] = td0[te1[(ks[13] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[13] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[13] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[13] >>  0) & 0xff] & 0xff];
  ks[14] = td0[te1[(ks[14] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[14] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[14] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[14] >>  0) & 0xff] & 0xff];
  ks[15] = td0[te1[(ks[15] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[15] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[15] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[15] >>  0) & 0xff] & 0xff];
  ks[16] = td0[te1[(ks[16] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[16] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[16] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[16] >>  0) & 0xff] & 0xff];
  ks[17] = td0[te1[(ks[17] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[17] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[17] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[17] >>  0) & 0xff] & 0xff];
  ks[18] = td0[te1[(ks[18] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[18] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[18] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[18] >>  0) & 0xff] & 0xff];
  ks[19] = td0[te1[(ks[19] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[19] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[19] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[19] >>  0) & 0xff] & 0xff];
  ks[20] = td0[te1[(ks[20] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[20] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[20] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[20] >>  0) & 0xff] & 0xff];
  ks[21] = td0[te1[(ks[21] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[21] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[21] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[21] >>  0) & 0xff] & 0xff];
  ks[22] = td0[te1[(ks[22] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[22] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[22] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[22] >>  0) & 0xff] & 0xff];
  ks[23] = td0[te1[(ks[23] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[23] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[23] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[23] >>  0) & 0xff] & 0xff];
  ks[24] = td0[te1[(ks[24] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[24] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[24] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[24] >>  0) & 0xff] & 0xff];
  ks[25] = td0[te1[(ks[25] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[25] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[25] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[25] >>  0) & 0xff] & 0xff];
  ks[26] = td0[te1[(ks[26] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[26] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[26] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[26] >>  0) & 0xff] & 0xff];
  ks[27] = td0[te1[(ks[27] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[27] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[27] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[27] >>  0) & 0xff] & 0xff];
  ks[28] = td0[te1[(ks[28] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[28] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[28] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[28] >>  0) & 0xff] & 0xff];
  ks[29] = td0[te1[(ks[29] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[29] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[29] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[29] >>  0) & 0xff] & 0xff];
  ks[30] = td0[te1[(ks[30] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[30] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[30] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[30] >>  0) & 0xff] & 0xff];
  ks[31] = td0[te1[(ks[31] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[31] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[31] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[31] >>  0) & 0xff] & 0xff];
  ks[32] = td0[te1[(ks[32] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[32] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[32] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[32] >>  0) & 0xff] & 0xff];
  ks[33] = td0[te1[(ks[33] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[33] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[33] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[33] >>  0) & 0xff] & 0xff];
  ks[34] = td0[te1[(ks[34] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[34] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[34] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[34] >>  0) & 0xff] & 0xff];
  ks[35] = td0[te1[(ks[35] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[35] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[35] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[35] >>  0) & 0xff] & 0xff];
  ks[36] = td0[te1[(ks[36] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[36] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[36] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[36] >>  0) & 0xff] & 0xff];
  ks[37] = td0[te1[(ks[37] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[37] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[37] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[37] >>  0) & 0xff] & 0xff];
  ks[38] = td0[te1[(ks[38] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[38] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[38] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[38] >>  0) & 0xff] & 0xff];
  ks[39] = td0[te1[(ks[39] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[39] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[39] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[39] >>  0) & 0xff] & 0xff];
}

DECLSPEC void aes128_set_encrypt_key (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ukey_s[4];

  ukey_s[0] = hc_swap32_S (ukey[0]);
  ukey_s[1] = hc_swap32_S (ukey[1]);
  ukey_s[2] = hc_swap32_S (ukey[2]);
  ukey_s[3] = hc_swap32_S (ukey[3]);

  aes128_ExpandKey (ks, ukey_s, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void aes128_set_decrypt_key (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ukey_s[4];

  ukey_s[0] = hc_swap32_S (ukey[0]);
  ukey_s[1] = hc_swap32_S (ukey[1]);
  ukey_s[2] = hc_swap32_S (ukey[2]);
  ukey_s[3] = hc_swap32_S (ukey[3]);

  aes128_ExpandKey (ks, ukey_s, s_te0, s_te1, s_te2, s_te3, s_te4);

  aes128_InvertKey (ks, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);
}

DECLSPEC void aes128_encrypt (const u32 *ks, const u32 *in, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 in_s[4];

  in_s[0] = hc_swap32_S (in[0]);
  in_s[1] = hc_swap32_S (in[1]);
  in_s[2] = hc_swap32_S (in[2]);
  in_s[3] = hc_swap32_S (in[3]);

  u32 s0 = in_s[0] ^ ks[0];
  u32 s1 = in_s[1] ^ ks[1];
  u32 s2 = in_s[2] ^ ks[2];
  u32 s3 = in_s[3] ^ ks[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[ 4];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[ 5];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[ 6];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[ 7];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[ 8];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[ 9];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[10];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[11];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[12];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[13];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[14];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[15];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[16];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[17];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[18];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[19];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[20];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[21];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[22];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[23];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[24];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[25];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[26];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[27];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[28];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[29];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[30];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[31];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[32];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[33];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[34];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[35];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[36];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[37];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[38];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[39];

  out[0] = (s_te4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ ks[40];

  out[1] = (s_te4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ ks[41];

  out[2] = (s_te4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ ks[42];

  out[3] = (s_te4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ ks[43];

  out[0] = hc_swap32_S (out[0]);
  out[1] = hc_swap32_S (out[1]);
  out[2] = hc_swap32_S (out[2]);
  out[3] = hc_swap32_S (out[3]);
}

DECLSPEC void aes128_decrypt (const u32 *ks, const u32 *in, u32 *out, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 in_s[4];

  in_s[0] = hc_swap32_S (in[0]);
  in_s[1] = hc_swap32_S (in[1]);
  in_s[2] = hc_swap32_S (in[2]);
  in_s[3] = hc_swap32_S (in[3]);

  u32 s0 = in_s[0] ^ ks[0];
  u32 s1 = in_s[1] ^ ks[1];
  u32 s2 = in_s[2] ^ ks[2];
  u32 s3 = in_s[3] ^ ks[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[ 4];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[ 5];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[ 6];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[ 7];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[ 8];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[ 9];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[10];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[11];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[12];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[13];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[14];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[15];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[16];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[17];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[18];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[19];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[20];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[21];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[22];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[23];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[24];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[25];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[26];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[27];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[28];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[29];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[30];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[31];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[32];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[33];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[34];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[35];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[36];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[37];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[38];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[39];

  out[0] = (s_td4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ ks[40];

  out[1] = (s_td4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ ks[41];

  out[2] = (s_td4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ ks[42];

  out[3] = (s_td4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ ks[43];

  out[0] = hc_swap32_S (out[0]);
  out[1] = hc_swap32_S (out[1]);
  out[2] = hc_swap32_S (out[2]);
  out[3] = hc_swap32_S (out[3]);
}

// 256 bit key

DECLSPEC void aes256_ExpandKey (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  ks[ 0] = ukey[0];
  ks[ 1] = ukey[1];
  ks[ 2] = ukey[2];
  ks[ 3] = ukey[3];
  ks[ 4] = ukey[4];
  ks[ 5] = ukey[5];
  ks[ 6] = ukey[6];
  ks[ 7] = ukey[7];
  ks[ 8] = ks[ 0] ^ 0x01000000
                  ^ (s_te2[(ks[ 7] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[ 7] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[ 7] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[ 7] >> 24) & 0xff] & 0x000000ff);
  ks[ 9] = ks[ 1] ^ ks[ 8];
  ks[10] = ks[ 2] ^ ks[ 9];
  ks[11] = ks[ 3] ^ ks[10];
  ks[12] = ks[ 4] ^ 0
                  ^ (s_te2[(ks[11] >> 24) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[11] >> 16) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[11] >>  8) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[11] >>  0) & 0xff] & 0x000000ff);
  ks[13] = ks[ 5] ^ ks[12];
  ks[14] = ks[ 6] ^ ks[13];
  ks[15] = ks[ 7] ^ ks[14];
  ks[16] = ks[ 8] ^ 0x02000000
                  ^ (s_te2[(ks[15] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[15] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[15] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[15] >> 24) & 0xff] & 0x000000ff);
  ks[17] = ks[ 9] ^ ks[16];
  ks[18] = ks[10] ^ ks[17];
  ks[19] = ks[11] ^ ks[18];
  ks[20] = ks[12] ^ 0
                  ^ (s_te2[(ks[19] >> 24) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[19] >> 16) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[19] >>  8) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[19] >>  0) & 0xff] & 0x000000ff);
  ks[21] = ks[13] ^ ks[20];
  ks[22] = ks[14] ^ ks[21];
  ks[23] = ks[15] ^ ks[22];
  ks[24] = ks[16] ^ 0x04000000
                  ^ (s_te2[(ks[23] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[23] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[23] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[23] >> 24) & 0xff] & 0x000000ff);
  ks[25] = ks[17] ^ ks[24];
  ks[26] = ks[18] ^ ks[25];
  ks[27] = ks[19] ^ ks[26];
  ks[28] = ks[20] ^ 0
                  ^ (s_te2[(ks[27] >> 24) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[27] >> 16) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[27] >>  8) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[27] >>  0) & 0xff] & 0x000000ff);
  ks[29] = ks[21] ^ ks[28];
  ks[30] = ks[22] ^ ks[29];
  ks[31] = ks[23] ^ ks[30];
  ks[32] = ks[24] ^ 0x08000000
                  ^ (s_te2[(ks[31] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[31] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[31] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[31] >> 24) & 0xff] & 0x000000ff);
  ks[33] = ks[25] ^ ks[32];
  ks[34] = ks[26] ^ ks[33];
  ks[35] = ks[27] ^ ks[34];
  ks[36] = ks[28] ^ 0
                  ^ (s_te2[(ks[35] >> 24) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[35] >> 16) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[35] >>  8) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[35] >>  0) & 0xff] & 0x000000ff);
  ks[37] = ks[29] ^ ks[36];
  ks[38] = ks[30] ^ ks[37];
  ks[39] = ks[31] ^ ks[38];
  ks[40] = ks[32] ^ 0x10000000
                  ^ (s_te2[(ks[39] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[39] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[39] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[39] >> 24) & 0xff] & 0x000000ff);
  ks[41] = ks[33] ^ ks[40];
  ks[42] = ks[34] ^ ks[41];
  ks[43] = ks[35] ^ ks[42];
  ks[44] = ks[36] ^ 0
                  ^ (s_te2[(ks[43] >> 24) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[43] >> 16) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[43] >>  8) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[43] >>  0) & 0xff] & 0x000000ff);
  ks[45] = ks[37] ^ ks[44];
  ks[46] = ks[38] ^ ks[45];
  ks[47] = ks[39] ^ ks[46];
  ks[48] = ks[40] ^ 0x20000000
                  ^ (s_te2[(ks[47] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[47] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[47] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[47] >> 24) & 0xff] & 0x000000ff);
  ks[49] = ks[41] ^ ks[48];
  ks[50] = ks[42] ^ ks[49];
  ks[51] = ks[43] ^ ks[50];
  ks[52] = ks[44] ^ 0
                  ^ (s_te2[(ks[51] >> 24) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[51] >> 16) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[51] >>  8) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[51] >>  0) & 0xff] & 0x000000ff);
  ks[53] = ks[45] ^ ks[52];
  ks[54] = ks[46] ^ ks[53];
  ks[55] = ks[47] ^ ks[54];
  ks[56] = ks[48] ^ 0x40000000
                  ^ (s_te2[(ks[55] >> 16) & 0xff] & 0xff000000)
                  ^ (s_te3[(ks[55] >>  8) & 0xff] & 0x00ff0000)
                  ^ (s_te0[(ks[55] >>  0) & 0xff] & 0x0000ff00)
                  ^ (s_te1[(ks[55] >> 24) & 0xff] & 0x000000ff);
  ks[57] = ks[49] ^ ks[56];
  ks[58] = ks[50] ^ ks[57];
  ks[59] = ks[51] ^ ks[58];
}

DECLSPEC void aes256_InvertKey (u32 *ks, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 temp;

  temp = ks[ 0]; ks[ 0] = ks[56]; ks[56] = temp;
  temp = ks[ 1]; ks[ 1] = ks[57]; ks[57] = temp;
  temp = ks[ 2]; ks[ 2] = ks[58]; ks[58] = temp;
  temp = ks[ 3]; ks[ 3] = ks[59]; ks[59] = temp;
  temp = ks[ 4]; ks[ 4] = ks[52]; ks[52] = temp;
  temp = ks[ 5]; ks[ 5] = ks[53]; ks[53] = temp;
  temp = ks[ 6]; ks[ 6] = ks[54]; ks[54] = temp;
  temp = ks[ 7]; ks[ 7] = ks[55]; ks[55] = temp;
  temp = ks[ 8]; ks[ 8] = ks[48]; ks[48] = temp;
  temp = ks[ 9]; ks[ 9] = ks[49]; ks[49] = temp;
  temp = ks[10]; ks[10] = ks[50]; ks[50] = temp;
  temp = ks[11]; ks[11] = ks[51]; ks[51] = temp;
  temp = ks[12]; ks[12] = ks[44]; ks[44] = temp;
  temp = ks[13]; ks[13] = ks[45]; ks[45] = temp;
  temp = ks[14]; ks[14] = ks[46]; ks[46] = temp;
  temp = ks[15]; ks[15] = ks[47]; ks[47] = temp;
  temp = ks[16]; ks[16] = ks[40]; ks[40] = temp;
  temp = ks[17]; ks[17] = ks[41]; ks[41] = temp;
  temp = ks[18]; ks[18] = ks[42]; ks[42] = temp;
  temp = ks[19]; ks[19] = ks[43]; ks[43] = temp;
  temp = ks[20]; ks[20] = ks[36]; ks[36] = temp;
  temp = ks[21]; ks[21] = ks[37]; ks[37] = temp;
  temp = ks[22]; ks[22] = ks[38]; ks[38] = temp;
  temp = ks[23]; ks[23] = ks[39]; ks[39] = temp;
  temp = ks[24]; ks[24] = ks[32]; ks[32] = temp;
  temp = ks[25]; ks[25] = ks[33]; ks[33] = temp;
  temp = ks[26]; ks[26] = ks[34]; ks[34] = temp;
  temp = ks[27]; ks[27] = ks[35]; ks[35] = temp;

  ks[ 4] = td0[te1[(ks[ 4] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 4] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 4] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 4] >>  0) & 0xff] & 0xff];
  ks[ 5] = td0[te1[(ks[ 5] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 5] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 5] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 5] >>  0) & 0xff] & 0xff];
  ks[ 6] = td0[te1[(ks[ 6] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 6] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 6] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 6] >>  0) & 0xff] & 0xff];
  ks[ 7] = td0[te1[(ks[ 7] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 7] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 7] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 7] >>  0) & 0xff] & 0xff];
  ks[ 8] = td0[te1[(ks[ 8] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 8] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 8] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 8] >>  0) & 0xff] & 0xff];
  ks[ 9] = td0[te1[(ks[ 9] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[ 9] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[ 9] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[ 9] >>  0) & 0xff] & 0xff];
  ks[10] = td0[te1[(ks[10] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[10] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[10] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[10] >>  0) & 0xff] & 0xff];
  ks[11] = td0[te1[(ks[11] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[11] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[11] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[11] >>  0) & 0xff] & 0xff];
  ks[12] = td0[te1[(ks[12] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[12] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[12] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[12] >>  0) & 0xff] & 0xff];
  ks[13] = td0[te1[(ks[13] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[13] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[13] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[13] >>  0) & 0xff] & 0xff];
  ks[14] = td0[te1[(ks[14] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[14] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[14] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[14] >>  0) & 0xff] & 0xff];
  ks[15] = td0[te1[(ks[15] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[15] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[15] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[15] >>  0) & 0xff] & 0xff];
  ks[16] = td0[te1[(ks[16] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[16] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[16] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[16] >>  0) & 0xff] & 0xff];
  ks[17] = td0[te1[(ks[17] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[17] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[17] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[17] >>  0) & 0xff] & 0xff];
  ks[18] = td0[te1[(ks[18] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[18] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[18] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[18] >>  0) & 0xff] & 0xff];
  ks[19] = td0[te1[(ks[19] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[19] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[19] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[19] >>  0) & 0xff] & 0xff];
  ks[20] = td0[te1[(ks[20] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[20] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[20] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[20] >>  0) & 0xff] & 0xff];
  ks[21] = td0[te1[(ks[21] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[21] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[21] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[21] >>  0) & 0xff] & 0xff];
  ks[22] = td0[te1[(ks[22] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[22] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[22] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[22] >>  0) & 0xff] & 0xff];
  ks[23] = td0[te1[(ks[23] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[23] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[23] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[23] >>  0) & 0xff] & 0xff];
  ks[24] = td0[te1[(ks[24] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[24] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[24] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[24] >>  0) & 0xff] & 0xff];
  ks[25] = td0[te1[(ks[25] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[25] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[25] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[25] >>  0) & 0xff] & 0xff];
  ks[26] = td0[te1[(ks[26] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[26] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[26] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[26] >>  0) & 0xff] & 0xff];
  ks[27] = td0[te1[(ks[27] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[27] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[27] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[27] >>  0) & 0xff] & 0xff];
  ks[28] = td0[te1[(ks[28] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[28] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[28] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[28] >>  0) & 0xff] & 0xff];
  ks[29] = td0[te1[(ks[29] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[29] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[29] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[29] >>  0) & 0xff] & 0xff];
  ks[30] = td0[te1[(ks[30] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[30] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[30] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[30] >>  0) & 0xff] & 0xff];
  ks[31] = td0[te1[(ks[31] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[31] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[31] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[31] >>  0) & 0xff] & 0xff];
  ks[32] = td0[te1[(ks[32] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[32] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[32] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[32] >>  0) & 0xff] & 0xff];
  ks[33] = td0[te1[(ks[33] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[33] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[33] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[33] >>  0) & 0xff] & 0xff];
  ks[34] = td0[te1[(ks[34] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[34] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[34] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[34] >>  0) & 0xff] & 0xff];
  ks[35] = td0[te1[(ks[35] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[35] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[35] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[35] >>  0) & 0xff] & 0xff];
  ks[36] = td0[te1[(ks[36] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[36] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[36] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[36] >>  0) & 0xff] & 0xff];
  ks[37] = td0[te1[(ks[37] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[37] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[37] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[37] >>  0) & 0xff] & 0xff];
  ks[38] = td0[te1[(ks[38] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[38] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[38] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[38] >>  0) & 0xff] & 0xff];
  ks[39] = td0[te1[(ks[39] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[39] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[39] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[39] >>  0) & 0xff] & 0xff];
  ks[40] = td0[te1[(ks[40] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[40] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[40] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[40] >>  0) & 0xff] & 0xff];
  ks[41] = td0[te1[(ks[41] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[41] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[41] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[41] >>  0) & 0xff] & 0xff];
  ks[42] = td0[te1[(ks[42] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[42] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[42] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[42] >>  0) & 0xff] & 0xff];
  ks[43] = td0[te1[(ks[43] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[43] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[43] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[43] >>  0) & 0xff] & 0xff];
  ks[44] = td0[te1[(ks[44] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[44] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[44] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[44] >>  0) & 0xff] & 0xff];
  ks[45] = td0[te1[(ks[45] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[45] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[45] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[45] >>  0) & 0xff] & 0xff];
  ks[46] = td0[te1[(ks[46] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[46] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[46] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[46] >>  0) & 0xff] & 0xff];
  ks[47] = td0[te1[(ks[47] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[47] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[47] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[47] >>  0) & 0xff] & 0xff];
  ks[48] = td0[te1[(ks[48] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[48] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[48] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[48] >>  0) & 0xff] & 0xff];
  ks[49] = td0[te1[(ks[49] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[49] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[49] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[49] >>  0) & 0xff] & 0xff];
  ks[50] = td0[te1[(ks[50] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[50] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[50] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[50] >>  0) & 0xff] & 0xff];
  ks[51] = td0[te1[(ks[51] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[51] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[51] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[51] >>  0) & 0xff] & 0xff];
  ks[52] = td0[te1[(ks[52] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[52] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[52] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[52] >>  0) & 0xff] & 0xff];
  ks[53] = td0[te1[(ks[53] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[53] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[53] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[53] >>  0) & 0xff] & 0xff];
  ks[54] = td0[te1[(ks[54] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[54] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[54] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[54] >>  0) & 0xff] & 0xff];
  ks[55] = td0[te1[(ks[55] >> 24) & 0xff] & 0xff] ^ td1[te1[(ks[55] >> 16) & 0xff] & 0xff] ^ td2[te1[(ks[55] >>  8) & 0xff] & 0xff] ^ td3[te1[(ks[55] >>  0) & 0xff] & 0xff];
}

DECLSPEC void aes256_set_encrypt_key (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ukey_s[8];

  ukey_s[0] = hc_swap32_S (ukey[0]);
  ukey_s[1] = hc_swap32_S (ukey[1]);
  ukey_s[2] = hc_swap32_S (ukey[2]);
  ukey_s[3] = hc_swap32_S (ukey[3]);
  ukey_s[4] = hc_swap32_S (ukey[4]);
  ukey_s[5] = hc_swap32_S (ukey[5]);
  ukey_s[6] = hc_swap32_S (ukey[6]);
  ukey_s[7] = hc_swap32_S (ukey[7]);

  aes256_ExpandKey (ks, ukey_s, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void aes256_set_decrypt_key (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ukey_s[8];

  ukey_s[0] = hc_swap32_S (ukey[0]);
  ukey_s[1] = hc_swap32_S (ukey[1]);
  ukey_s[2] = hc_swap32_S (ukey[2]);
  ukey_s[3] = hc_swap32_S (ukey[3]);
  ukey_s[4] = hc_swap32_S (ukey[4]);
  ukey_s[5] = hc_swap32_S (ukey[5]);
  ukey_s[6] = hc_swap32_S (ukey[6]);
  ukey_s[7] = hc_swap32_S (ukey[7]);

  aes256_ExpandKey (ks, ukey_s, s_te0, s_te1, s_te2, s_te3, s_te4);

  aes256_InvertKey (ks, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);
}

DECLSPEC void aes256_encrypt (const u32 *ks, const u32 *in, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 in_s[4];

  in_s[0] = hc_swap32_S (in[0]);
  in_s[1] = hc_swap32_S (in[1]);
  in_s[2] = hc_swap32_S (in[2]);
  in_s[3] = hc_swap32_S (in[3]);

  u32 s0 = in_s[0] ^ ks[0];
  u32 s1 = in_s[1] ^ ks[1];
  u32 s2 = in_s[2] ^ ks[2];
  u32 s3 = in_s[3] ^ ks[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[ 4];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[ 5];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[ 6];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[ 7];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[ 8];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[ 9];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[10];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[11];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[12];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[13];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[14];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[15];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[16];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[17];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[18];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[19];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[20];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[21];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[22];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[23];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[24];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[25];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[26];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[27];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[28];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[29];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[30];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[31];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[32];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[33];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[34];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[35];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[36];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[37];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[38];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[39];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[40];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[41];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[42];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[43];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[44];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[45];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[46];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[47];
  s0 = s_te0[t0 >> 24] ^ s_te1[(t1 >> 16) & 0xff] ^ s_te2[(t2 >>  8) & 0xff] ^ s_te3[t3 & 0xff] ^ ks[48];
  s1 = s_te0[t1 >> 24] ^ s_te1[(t2 >> 16) & 0xff] ^ s_te2[(t3 >>  8) & 0xff] ^ s_te3[t0 & 0xff] ^ ks[49];
  s2 = s_te0[t2 >> 24] ^ s_te1[(t3 >> 16) & 0xff] ^ s_te2[(t0 >>  8) & 0xff] ^ s_te3[t1 & 0xff] ^ ks[50];
  s3 = s_te0[t3 >> 24] ^ s_te1[(t0 >> 16) & 0xff] ^ s_te2[(t1 >>  8) & 0xff] ^ s_te3[t2 & 0xff] ^ ks[51];
  t0 = s_te0[s0 >> 24] ^ s_te1[(s1 >> 16) & 0xff] ^ s_te2[(s2 >>  8) & 0xff] ^ s_te3[s3 & 0xff] ^ ks[52];
  t1 = s_te0[s1 >> 24] ^ s_te1[(s2 >> 16) & 0xff] ^ s_te2[(s3 >>  8) & 0xff] ^ s_te3[s0 & 0xff] ^ ks[53];
  t2 = s_te0[s2 >> 24] ^ s_te1[(s3 >> 16) & 0xff] ^ s_te2[(s0 >>  8) & 0xff] ^ s_te3[s1 & 0xff] ^ ks[54];
  t3 = s_te0[s3 >> 24] ^ s_te1[(s0 >> 16) & 0xff] ^ s_te2[(s1 >>  8) & 0xff] ^ s_te3[s2 & 0xff] ^ ks[55];

  out[0] = (s_te4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ ks[56];

  out[1] = (s_te4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ ks[57];

  out[2] = (s_te4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ ks[58];

  out[3] = (s_te4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_te4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_te4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_te4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ ks[59];

  out[0] = hc_swap32_S (out[0]);
  out[1] = hc_swap32_S (out[1]);
  out[2] = hc_swap32_S (out[2]);
  out[3] = hc_swap32_S (out[3]);
}

DECLSPEC void aes256_decrypt (const u32 *ks, const u32 *in, u32 *out, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 in_s[4];

  in_s[0] = hc_swap32_S (in[0]);
  in_s[1] = hc_swap32_S (in[1]);
  in_s[2] = hc_swap32_S (in[2]);
  in_s[3] = hc_swap32_S (in[3]);

  u32 s0 = in_s[0] ^ ks[0];
  u32 s1 = in_s[1] ^ ks[1];
  u32 s2 = in_s[2] ^ ks[2];
  u32 s3 = in_s[3] ^ ks[3];

  u32 t0;
  u32 t1;
  u32 t2;
  u32 t3;

  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[ 4];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[ 5];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[ 6];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[ 7];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[ 8];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[ 9];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[10];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[11];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[12];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[13];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[14];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[15];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[16];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[17];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[18];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[19];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[20];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[21];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[22];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[23];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[24];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[25];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[26];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[27];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[28];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[29];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[30];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[31];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[32];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[33];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[34];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[35];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[36];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[37];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[38];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[39];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[40];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[41];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[42];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[43];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[44];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[45];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[46];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[47];
  s0 = s_td0[t0 >> 24] ^ s_td1[(t3 >> 16) & 0xff] ^ s_td2[(t2 >>  8) & 0xff] ^ s_td3[t1 & 0xff] ^ ks[48];
  s1 = s_td0[t1 >> 24] ^ s_td1[(t0 >> 16) & 0xff] ^ s_td2[(t3 >>  8) & 0xff] ^ s_td3[t2 & 0xff] ^ ks[49];
  s2 = s_td0[t2 >> 24] ^ s_td1[(t1 >> 16) & 0xff] ^ s_td2[(t0 >>  8) & 0xff] ^ s_td3[t3 & 0xff] ^ ks[50];
  s3 = s_td0[t3 >> 24] ^ s_td1[(t2 >> 16) & 0xff] ^ s_td2[(t1 >>  8) & 0xff] ^ s_td3[t0 & 0xff] ^ ks[51];
  t0 = s_td0[s0 >> 24] ^ s_td1[(s3 >> 16) & 0xff] ^ s_td2[(s2 >>  8) & 0xff] ^ s_td3[s1 & 0xff] ^ ks[52];
  t1 = s_td0[s1 >> 24] ^ s_td1[(s0 >> 16) & 0xff] ^ s_td2[(s3 >>  8) & 0xff] ^ s_td3[s2 & 0xff] ^ ks[53];
  t2 = s_td0[s2 >> 24] ^ s_td1[(s1 >> 16) & 0xff] ^ s_td2[(s0 >>  8) & 0xff] ^ s_td3[s3 & 0xff] ^ ks[54];
  t3 = s_td0[s3 >> 24] ^ s_td1[(s2 >> 16) & 0xff] ^ s_td2[(s1 >>  8) & 0xff] ^ s_td3[s0 & 0xff] ^ ks[55];

  out[0] = (s_td4[(t0 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t3 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t2 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t1 >>  0) & 0xff] & 0x000000ff)
         ^ ks[56];

  out[1] = (s_td4[(t1 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t0 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t3 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t2 >>  0) & 0xff] & 0x000000ff)
         ^ ks[57];

  out[2] = (s_td4[(t2 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t1 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t0 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t3 >>  0) & 0xff] & 0x000000ff)
         ^ ks[58];

  out[3] = (s_td4[(t3 >> 24) & 0xff] & 0xff000000)
         ^ (s_td4[(t2 >> 16) & 0xff] & 0x00ff0000)
         ^ (s_td4[(t1 >>  8) & 0xff] & 0x0000ff00)
         ^ (s_td4[(t0 >>  0) & 0xff] & 0x000000ff)
         ^ ks[59];

  out[0] = hc_swap32_S (out[0]);
  out[1] = hc_swap32_S (out[1]);
  out[2] = hc_swap32_S (out[2]);
  out[3] = hc_swap32_S (out[3]);
}

// wrapper to avoid hc_swap32_S() confusion in the kernel code

DECLSPEC void AES128_set_encrypt_key (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ukey_s[4];

  ukey_s[0] = hc_swap32_S (ukey[0]);
  ukey_s[1] = hc_swap32_S (ukey[1]);
  ukey_s[2] = hc_swap32_S (ukey[2]);
  ukey_s[3] = hc_swap32_S (ukey[3]);

  aes128_set_encrypt_key (ks, ukey_s, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void AES128_set_decrypt_key (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ukey_s[4];

  ukey_s[0] = hc_swap32_S (ukey[0]);
  ukey_s[1] = hc_swap32_S (ukey[1]);
  ukey_s[2] = hc_swap32_S (ukey[2]);
  ukey_s[3] = hc_swap32_S (ukey[3]);

  aes128_set_decrypt_key (ks, ukey_s, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);
}

DECLSPEC void AES128_encrypt (const u32 *ks, const u32 *in, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 in_s[4];

  in_s[0] = hc_swap32_S (in[0]);
  in_s[1] = hc_swap32_S (in[1]);
  in_s[2] = hc_swap32_S (in[2]);
  in_s[3] = hc_swap32_S (in[3]);

  u32 out_s[4];

  aes128_encrypt (ks, in_s, out_s, s_te0, s_te1, s_te2, s_te3, s_te4);

  out[0] = hc_swap32_S (out_s[0]);
  out[1] = hc_swap32_S (out_s[1]);
  out[2] = hc_swap32_S (out_s[2]);
  out[3] = hc_swap32_S (out_s[3]);
}

DECLSPEC void AES128_decrypt (const u32 *ks, const u32 *in, u32 *out, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 in_s[4];

  in_s[0] = hc_swap32_S (in[0]);
  in_s[1] = hc_swap32_S (in[1]);
  in_s[2] = hc_swap32_S (in[2]);
  in_s[3] = hc_swap32_S (in[3]);

  u32 out_s[4];

  aes128_decrypt (ks, in_s, out_s, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] = hc_swap32_S (out_s[0]);
  out[1] = hc_swap32_S (out_s[1]);
  out[2] = hc_swap32_S (out_s[2]);
  out[3] = hc_swap32_S (out_s[3]);
}

DECLSPEC void AES256_set_encrypt_key (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ukey_s[8];

  ukey_s[0] = hc_swap32_S (ukey[0]);
  ukey_s[1] = hc_swap32_S (ukey[1]);
  ukey_s[2] = hc_swap32_S (ukey[2]);
  ukey_s[3] = hc_swap32_S (ukey[3]);
  ukey_s[4] = hc_swap32_S (ukey[4]);
  ukey_s[5] = hc_swap32_S (ukey[5]);
  ukey_s[6] = hc_swap32_S (ukey[6]);
  ukey_s[7] = hc_swap32_S (ukey[7]);

  aes256_set_encrypt_key (ks, ukey_s, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void AES256_set_decrypt_key (u32 *ks, const u32 *ukey, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ukey_s[8];

  ukey_s[0] = hc_swap32_S (ukey[0]);
  ukey_s[1] = hc_swap32_S (ukey[1]);
  ukey_s[2] = hc_swap32_S (ukey[2]);
  ukey_s[3] = hc_swap32_S (ukey[3]);
  ukey_s[4] = hc_swap32_S (ukey[4]);
  ukey_s[5] = hc_swap32_S (ukey[5]);
  ukey_s[6] = hc_swap32_S (ukey[6]);
  ukey_s[7] = hc_swap32_S (ukey[7]);

  aes256_set_decrypt_key (ks, ukey_s, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);
}

DECLSPEC void AES256_encrypt (const u32 *ks, const u32 *in, u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 in_s[4];

  in_s[0] = hc_swap32_S (in[0]);
  in_s[1] = hc_swap32_S (in[1]);
  in_s[2] = hc_swap32_S (in[2]);
  in_s[3] = hc_swap32_S (in[3]);

  u32 out_s[4];

  aes256_encrypt (ks, in_s, out_s, s_te0, s_te1, s_te2, s_te3, s_te4);

  out[0] = hc_swap32_S (out_s[0]);
  out[1] = hc_swap32_S (out_s[1]);
  out[2] = hc_swap32_S (out_s[2]);
  out[3] = hc_swap32_S (out_s[3]);
}

DECLSPEC void AES256_decrypt (const u32 *ks, const u32 *in, u32 *out, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 in_s[4];

  in_s[0] = hc_swap32_S (in[0]);
  in_s[1] = hc_swap32_S (in[1]);
  in_s[2] = hc_swap32_S (in[2]);
  in_s[3] = hc_swap32_S (in[3]);

  u32 out_s[4];

  aes256_decrypt (ks, in_s, out_s, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] = hc_swap32_S (out_s[0]);
  out[1] = hc_swap32_S (out_s[1]);
  out[2] = hc_swap32_S (out_s[2]);
  out[3] = hc_swap32_S (out_s[3]);
}
