/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha256.h"
#include "inc_luks_essiv.h"

DECLSPEC void ESSIV_sha256_init128 (u32 *key, u32 *essivhash)
{
  essivhash[0] = SHA256M_A;
  essivhash[1] = SHA256M_B;
  essivhash[2] = SHA256M_C;
  essivhash[3] = SHA256M_D;
  essivhash[4] = SHA256M_E;
  essivhash[5] = SHA256M_F;
  essivhash[6] = SHA256M_G;
  essivhash[7] = SHA256M_H;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = hc_swap32_S (key[0]);
  w0[1] = hc_swap32_S (key[1]);
  w0[2] = hc_swap32_S (key[2]);
  w0[3] = hc_swap32_S (key[3]);
  w1[0] = 0x80000000;
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
  w3[3] = 16 * 8;

  sha256_transform (w0, w1, w2, w3, essivhash);

  essivhash[0] = hc_swap32_S (essivhash[0]);
  essivhash[1] = hc_swap32_S (essivhash[1]);
  essivhash[2] = hc_swap32_S (essivhash[2]);
  essivhash[3] = hc_swap32_S (essivhash[3]);
  essivhash[4] = hc_swap32_S (essivhash[4]);
  essivhash[5] = hc_swap32_S (essivhash[5]);
  essivhash[6] = hc_swap32_S (essivhash[6]);
  essivhash[7] = hc_swap32_S (essivhash[7]);
}

DECLSPEC void ESSIV_sha256_init256 (u32 *key, u32 *essivhash)
{
  essivhash[0] = SHA256M_A;
  essivhash[1] = SHA256M_B;
  essivhash[2] = SHA256M_C;
  essivhash[3] = SHA256M_D;
  essivhash[4] = SHA256M_E;
  essivhash[5] = SHA256M_F;
  essivhash[6] = SHA256M_G;
  essivhash[7] = SHA256M_H;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = hc_swap32_S (key[0]);
  w0[1] = hc_swap32_S (key[1]);
  w0[2] = hc_swap32_S (key[2]);
  w0[3] = hc_swap32_S (key[3]);
  w1[0] = hc_swap32_S (key[4]);
  w1[1] = hc_swap32_S (key[5]);
  w1[2] = hc_swap32_S (key[6]);
  w1[3] = hc_swap32_S (key[7]);
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 32 * 8;

  sha256_transform (w0, w1, w2, w3, essivhash);

  essivhash[0] = hc_swap32_S (essivhash[0]);
  essivhash[1] = hc_swap32_S (essivhash[1]);
  essivhash[2] = hc_swap32_S (essivhash[2]);
  essivhash[3] = hc_swap32_S (essivhash[3]);
  essivhash[4] = hc_swap32_S (essivhash[4]);
  essivhash[5] = hc_swap32_S (essivhash[5]);
  essivhash[6] = hc_swap32_S (essivhash[6]);
  essivhash[7] = hc_swap32_S (essivhash[7]);
}
