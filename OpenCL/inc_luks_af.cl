/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_ripemd160.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_hash_sha512.h"
#include "inc_luks_af.h"

// diffuse functions

DECLSPEC void AF_sha1_diffuse16 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 15

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[0]);
  w0[2] = hc_swap32_S (out[1]);
  w0[3] = hc_swap32_S (out[2]);
  w1[0] = hc_swap32_S (out[3]);
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
  w3[3] = 20 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  out[0] = hc_swap32_S (digest[0]);
  out[1] = hc_swap32_S (digest[1]);
  out[2] = hc_swap32_S (digest[2]);
  out[3] = hc_swap32_S (digest[3]);
}

DECLSPEC void AF_sha1_diffuse32 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 19

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[0]);
  w0[2] = hc_swap32_S (out[1]);
  w0[3] = hc_swap32_S (out[2]);
  w1[0] = hc_swap32_S (out[3]);
  w1[1] = hc_swap32_S (out[4]);
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 24 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  out[0] = hc_swap32_S (digest[0]);
  out[1] = hc_swap32_S (digest[1]);
  out[2] = hc_swap32_S (digest[2]);
  out[3] = hc_swap32_S (digest[3]);
  out[4] = hc_swap32_S (digest[4]);

  // 20 - 31

  w0[0] = 1;
  w0[1] = hc_swap32_S (out[5]);
  w0[2] = hc_swap32_S (out[6]);
  w0[3] = hc_swap32_S (out[7]);
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

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  out[5] = hc_swap32_S (digest[0]);
  out[6] = hc_swap32_S (digest[1]);
  out[7] = hc_swap32_S (digest[2]);
}

DECLSPEC void AF_sha1_diffuse64 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 19

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[0]);
  w0[2] = hc_swap32_S (out[1]);
  w0[3] = hc_swap32_S (out[2]);
  w1[0] = hc_swap32_S (out[3]);
  w1[1] = hc_swap32_S (out[4]);
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 24 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  out[0] = hc_swap32_S (digest[0]);
  out[1] = hc_swap32_S (digest[1]);
  out[2] = hc_swap32_S (digest[2]);
  out[3] = hc_swap32_S (digest[3]);
  out[4] = hc_swap32_S (digest[4]);

  // 20 - 39

  w0[0] = 1;
  w0[1] = hc_swap32_S (out[5]);
  w0[2] = hc_swap32_S (out[6]);
  w0[3] = hc_swap32_S (out[7]);
  w1[0] = hc_swap32_S (out[8]);
  w1[1] = hc_swap32_S (out[9]);
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 24 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  out[5] = hc_swap32_S (digest[0]);
  out[6] = hc_swap32_S (digest[1]);
  out[7] = hc_swap32_S (digest[2]);
  out[8] = hc_swap32_S (digest[3]);
  out[9] = hc_swap32_S (digest[4]);

  // 40 - 59

  w0[0] = 2;
  w0[1] = hc_swap32_S (out[10]);
  w0[2] = hc_swap32_S (out[11]);
  w0[3] = hc_swap32_S (out[12]);
  w1[0] = hc_swap32_S (out[13]);
  w1[1] = hc_swap32_S (out[14]);
  w1[2] = 0x80000000;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 24 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  out[10] = hc_swap32_S (digest[0]);
  out[11] = hc_swap32_S (digest[1]);
  out[12] = hc_swap32_S (digest[2]);
  out[13] = hc_swap32_S (digest[3]);
  out[14] = hc_swap32_S (digest[4]);

  // 60 - 63

  w0[0] = 3;
  w0[1] = hc_swap32_S (out[15]);
  w0[2] = 0x80000000;
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
  w3[3] = 8 * 8;

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  out[15] = hc_swap32_S (digest[0]);
}

DECLSPEC void AF_sha256_diffuse16 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[8];

  // 0 - 15

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[0]);
  w0[2] = hc_swap32_S (out[1]);
  w0[3] = hc_swap32_S (out[2]);
  w1[0] = hc_swap32_S (out[3]);
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
  w3[3] = 20 * 8;

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, digest);

  out[0] = hc_swap32_S (digest[0]);
  out[1] = hc_swap32_S (digest[1]);
  out[2] = hc_swap32_S (digest[2]);
  out[3] = hc_swap32_S (digest[3]);
}

DECLSPEC void AF_sha256_diffuse32 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[8];

  // 0 - 31

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[0]);
  w0[2] = hc_swap32_S (out[1]);
  w0[3] = hc_swap32_S (out[2]);
  w1[0] = hc_swap32_S (out[3]);
  w1[1] = hc_swap32_S (out[4]);
  w1[2] = hc_swap32_S (out[5]);
  w1[3] = hc_swap32_S (out[6]);
  w2[0] = hc_swap32_S (out[7]);
  w2[1] = 0x80000000;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 36 * 8;

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, digest);

  out[0] = hc_swap32_S (digest[0]);
  out[1] = hc_swap32_S (digest[1]);
  out[2] = hc_swap32_S (digest[2]);
  out[3] = hc_swap32_S (digest[3]);
  out[4] = hc_swap32_S (digest[4]);
  out[5] = hc_swap32_S (digest[5]);
  out[6] = hc_swap32_S (digest[6]);
  out[7] = hc_swap32_S (digest[7]);
}

DECLSPEC void AF_sha256_diffuse64 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[8];

  // 0 - 31

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[0]);
  w0[2] = hc_swap32_S (out[1]);
  w0[3] = hc_swap32_S (out[2]);
  w1[0] = hc_swap32_S (out[3]);
  w1[1] = hc_swap32_S (out[4]);
  w1[2] = hc_swap32_S (out[5]);
  w1[3] = hc_swap32_S (out[6]);
  w2[0] = hc_swap32_S (out[7]);
  w2[1] = 0x80000000;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 36 * 8;

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, digest);

  out[0] = hc_swap32_S (digest[0]);
  out[1] = hc_swap32_S (digest[1]);
  out[2] = hc_swap32_S (digest[2]);
  out[3] = hc_swap32_S (digest[3]);
  out[4] = hc_swap32_S (digest[4]);
  out[5] = hc_swap32_S (digest[5]);
  out[6] = hc_swap32_S (digest[6]);
  out[7] = hc_swap32_S (digest[7]);

  // 32 - 63

  w0[0] = 1;
  w0[1] = hc_swap32_S (out[ 8]);
  w0[2] = hc_swap32_S (out[ 9]);
  w0[3] = hc_swap32_S (out[10]);
  w1[0] = hc_swap32_S (out[11]);
  w1[1] = hc_swap32_S (out[12]);
  w1[2] = hc_swap32_S (out[13]);
  w1[3] = hc_swap32_S (out[14]);
  w2[0] = hc_swap32_S (out[15]);
  w2[1] = 0x80000000;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 36 * 8;

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  sha256_transform (w0, w1, w2, w3, digest);

  out[ 8] = hc_swap32_S (digest[0]);
  out[ 9] = hc_swap32_S (digest[1]);
  out[10] = hc_swap32_S (digest[2]);
  out[11] = hc_swap32_S (digest[3]);
  out[12] = hc_swap32_S (digest[4]);
  out[13] = hc_swap32_S (digest[5]);
  out[14] = hc_swap32_S (digest[6]);
  out[15] = hc_swap32_S (digest[7]);
}

DECLSPEC void AF_sha512_diffuse16 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  u64 digest[8];

  // 0 - 15

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[0]);
  w0[2] = hc_swap32_S (out[1]);
  w0[3] = hc_swap32_S (out[2]);
  w1[0] = hc_swap32_S (out[3]);
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
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 20 * 8;

  digest[0] = SHA512M_A;
  digest[1] = SHA512M_B;
  digest[2] = SHA512M_C;
  digest[3] = SHA512M_D;
  digest[4] = SHA512M_E;
  digest[5] = SHA512M_F;
  digest[6] = SHA512M_G;
  digest[7] = SHA512M_H;

  sha512_transform (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  out[0] = hc_swap32_S (h32_from_64_S (digest[0]));
  out[1] = hc_swap32_S (l32_from_64_S (digest[0]));
  out[2] = hc_swap32_S (h32_from_64_S (digest[1]));
  out[3] = hc_swap32_S (l32_from_64_S (digest[1]));
}

DECLSPEC void AF_sha512_diffuse32 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  u64 digest[8];

  // 0 - 31

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[0]);
  w0[2] = hc_swap32_S (out[1]);
  w0[3] = hc_swap32_S (out[2]);
  w1[0] = hc_swap32_S (out[3]);
  w1[1] = hc_swap32_S (out[4]);
  w1[2] = hc_swap32_S (out[5]);
  w1[3] = hc_swap32_S (out[6]);
  w2[0] = hc_swap32_S (out[7]);
  w2[1] = 0x80000000;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;
  w4[0] = 0;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 36 * 8;

  digest[0] = SHA512M_A;
  digest[1] = SHA512M_B;
  digest[2] = SHA512M_C;
  digest[3] = SHA512M_D;
  digest[4] = SHA512M_E;
  digest[5] = SHA512M_F;
  digest[6] = SHA512M_G;
  digest[7] = SHA512M_H;

  sha512_transform (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  out[0] = hc_swap32_S (h32_from_64_S (digest[0]));
  out[1] = hc_swap32_S (l32_from_64_S (digest[0]));
  out[2] = hc_swap32_S (h32_from_64_S (digest[1]));
  out[3] = hc_swap32_S (l32_from_64_S (digest[1]));
  out[4] = hc_swap32_S (h32_from_64_S (digest[2]));
  out[5] = hc_swap32_S (l32_from_64_S (digest[2]));
  out[6] = hc_swap32_S (h32_from_64_S (digest[3]));
  out[7] = hc_swap32_S (l32_from_64_S (digest[3]));
}

DECLSPEC void AF_sha512_diffuse64 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  u64 digest[8];

  // 0 - 63

  w0[0] = 0;
  w0[1] = hc_swap32_S (out[ 0]);
  w0[2] = hc_swap32_S (out[ 1]);
  w0[3] = hc_swap32_S (out[ 2]);
  w1[0] = hc_swap32_S (out[ 3]);
  w1[1] = hc_swap32_S (out[ 4]);
  w1[2] = hc_swap32_S (out[ 5]);
  w1[3] = hc_swap32_S (out[ 6]);
  w2[0] = hc_swap32_S (out[ 7]);
  w2[1] = hc_swap32_S (out[ 8]);
  w2[2] = hc_swap32_S (out[ 9]);
  w2[3] = hc_swap32_S (out[10]);
  w3[0] = hc_swap32_S (out[11]);
  w3[1] = hc_swap32_S (out[12]);
  w3[2] = hc_swap32_S (out[13]);
  w3[3] = hc_swap32_S (out[14]);
  w4[0] = hc_swap32_S (out[15]);
  w4[1] = 0x80000000;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = 68 * 8;

  digest[0] = SHA512M_A;
  digest[1] = SHA512M_B;
  digest[2] = SHA512M_C;
  digest[3] = SHA512M_D;
  digest[4] = SHA512M_E;
  digest[5] = SHA512M_F;
  digest[6] = SHA512M_G;
  digest[7] = SHA512M_H;

  sha512_transform (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  out[ 0] = hc_swap32_S (h32_from_64_S (digest[0]));
  out[ 1] = hc_swap32_S (l32_from_64_S (digest[0]));
  out[ 2] = hc_swap32_S (h32_from_64_S (digest[1]));
  out[ 3] = hc_swap32_S (l32_from_64_S (digest[1]));
  out[ 4] = hc_swap32_S (h32_from_64_S (digest[2]));
  out[ 5] = hc_swap32_S (l32_from_64_S (digest[2]));
  out[ 6] = hc_swap32_S (h32_from_64_S (digest[3]));
  out[ 7] = hc_swap32_S (l32_from_64_S (digest[3]));
  out[ 8] = hc_swap32_S (h32_from_64_S (digest[4]));
  out[ 9] = hc_swap32_S (l32_from_64_S (digest[4]));
  out[10] = hc_swap32_S (h32_from_64_S (digest[5]));
  out[11] = hc_swap32_S (l32_from_64_S (digest[5]));
  out[12] = hc_swap32_S (h32_from_64_S (digest[6]));
  out[13] = hc_swap32_S (l32_from_64_S (digest[6]));
  out[14] = hc_swap32_S (h32_from_64_S (digest[7]));
  out[15] = hc_swap32_S (l32_from_64_S (digest[7]));
}

DECLSPEC void AF_ripemd160_diffuse16 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 15

  w0[0] = 0 << 24;
  w0[1] = out[0];
  w0[2] = out[1];
  w0[3] = out[2];
  w1[0] = out[3];
  w1[1] = 0x80;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 20 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  ripemd160_transform (w0, w1, w2, w3, digest);

  out[0] = digest[0];
  out[1] = digest[1];
  out[2] = digest[2];
  out[3] = digest[3];
}

DECLSPEC void AF_ripemd160_diffuse32 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 19

  w0[0] = 0 << 24;
  w0[1] = out[0];
  w0[2] = out[1];
  w0[3] = out[2];
  w1[0] = out[3];
  w1[1] = out[4];
  w1[2] = 0x80;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 24 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  ripemd160_transform (w0, w1, w2, w3, digest);

  out[0] = digest[0];
  out[1] = digest[1];
  out[2] = digest[2];
  out[3] = digest[3];
  out[4] = digest[4];

  // 20 - 31

  w0[0] = 1 << 24;
  w0[1] = out[5];
  w0[2] = out[6];
  w0[3] = out[7];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 16 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  ripemd160_transform (w0, w1, w2, w3, digest);

  out[5] = digest[0];
  out[6] = digest[1];
  out[7] = digest[2];
}

DECLSPEC void AF_ripemd160_diffuse64 (PRIVATE_AS u32 *out)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 digest[5];

  // 0 - 19

  w0[0] = 0 << 24;
  w0[1] = out[0];
  w0[2] = out[1];
  w0[3] = out[2];
  w1[0] = out[3];
  w1[1] = out[4];
  w1[2] = 0x80;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 24 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  ripemd160_transform (w0, w1, w2, w3, digest);

  out[0] = digest[0];
  out[1] = digest[1];
  out[2] = digest[2];
  out[3] = digest[3];
  out[4] = digest[4];

  // 20 - 39

  w0[0] = 1 << 24;
  w0[1] = out[5];
  w0[2] = out[6];
  w0[3] = out[7];
  w1[0] = out[8];
  w1[1] = out[9];
  w1[2] = 0x80;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 24 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  ripemd160_transform (w0, w1, w2, w3, digest);

  out[5] = digest[0];
  out[6] = digest[1];
  out[7] = digest[2];
  out[8] = digest[3];
  out[9] = digest[4];

  // 40 - 59

  w0[0] = 2 << 24;
  w0[1] = out[10];
  w0[2] = out[11];
  w0[3] = out[12];
  w1[0] = out[13];
  w1[1] = out[14];
  w1[2] = 0x80;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 24 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  ripemd160_transform (w0, w1, w2, w3, digest);

  out[10] = digest[0];
  out[11] = digest[1];
  out[12] = digest[2];
  out[13] = digest[3];
  out[14] = digest[4];

  // 60 - 63

  w0[0] = 3 << 24;
  w0[1] = out[15];
  w0[2] = 0x80;
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
  w3[2] = 8 * 8;
  w3[3] = 0;

  digest[0] = RIPEMD160M_A;
  digest[1] = RIPEMD160M_B;
  digest[2] = RIPEMD160M_C;
  digest[3] = RIPEMD160M_D;
  digest[4] = RIPEMD160M_E;

  ripemd160_transform (w0, w1, w2, w3, digest);

  out[15] = digest[0];
}
