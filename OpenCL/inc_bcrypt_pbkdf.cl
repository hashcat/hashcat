/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_sha512.h"
#include "inc_cipher_blowfish.h"
#include "inc_bcrypt_pbkdf.h"

// "OxychromaticBlowfishSwatDynamite"
CONSTANT_VK u32 c_bcrypt_magic[8] =
{
  0x4f787963, 0x68726f6d, 0x61746963, 0x426c6f77,
  0x66697368, 0x53776174, 0x44796e61, 0x6d697465
};

DECLSPEC void sha512_digest_to_words (PRIVATE_AS const u64 *h, PRIVATE_AS u32 *w)
{
  for (int i = 0; i < 8; i++)
  {
    w[(i * 2) + 0] = (u32) (h[i] >> 32);
    w[(i * 2) + 1] = (u32) (h[i] & 0xffffffff);
  }
}

// written inline because blowfish_set_key() re-initialises P and the S-boxes
// on entry, where this has to mutate the state the previous call left
DECLSPEC void bf_expand0state (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *key)
{
  for (u32 i = 0; i < 18; i++)
  {
    P[i] ^= key[i % 16];
  }

  blowfish_encrypt (P, S0, S1, S2, S3);
}

// blowfish_set_key_salt() from inc_cipher_blowfish cannot be reused: it
// hardcodes a 4-word salt, where bcrypt-pbkdf feeds a 64-byte sha2salt that the
// data stream cycles over 16 words at a time
DECLSPEC void bf_expandstate (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *data, PRIVATE_AS const u32 *key)
{
  for (u32 i = 0; i < 18; i++)
  {
    P[i] ^= key[i % 16];
  }

  u32 L0 = 0;
  u32 R0 = 0;
  u32 j  = 0;

  for (u32 i = 0; i < 18; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    P[i + 0] = L0;
    P[i + 1] = R0;
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S0, i + 0, L0);
    SET_KEY32 (S0, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S1, i + 0, L0);
    SET_KEY32 (S1, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S2, i + 0, L0);
    SET_KEY32 (S2, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S3, i + 0, L0);
    SET_KEY32 (S3, i + 1, R0);
  }
}

DECLSPEC void bcrypt_hash (PRIVATE_AS const u32 *sha2pass, PRIVATE_AS const u32 *sha2salt, PRIVATE_AS u32 *out, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  u32 P[18];

  // Blowfish_initstate

  for (u32 i = 0; i < 18; i++)
  {
    P[i] = c_pbox[i];
  }

  for (u32 i = 0; i < 256; i++)
  {
    SET_KEY32 (S0, i, c_sbox0[i]);
    SET_KEY32 (S1, i, c_sbox1[i]);
    SET_KEY32 (S2, i, c_sbox2[i]);
    SET_KEY32 (S3, i, c_sbox3[i]);
  }

  bf_expandstate (P, S0, S1, S2, S3, sha2salt, sha2pass);

  for (u32 i = 0; i < 64; i++)
  {
    bf_expand0state (P, S0, S1, S2, S3, sha2salt);
    bf_expand0state (P, S0, S1, S2, S3, sha2pass);
  }

  u32 cdata[8];

  for (u32 i = 0; i < 8; i++)
  {
    cdata[i] = c_bcrypt_magic[i];
  }

  for (u32 i = 0; i < 64; i++)
  {
    for (u32 k = 0; k < 8; k += 2)
    {
      u32 L0 = cdata[k + 0];
      u32 R0 = cdata[k + 1];

      BF_ENCRYPT (L0, R0);

      cdata[k + 0] = L0;
      cdata[k + 1] = R0;
    }
  }

  // output is little-endian

  for (u32 i = 0; i < 8; i++)
  {
    out[i] = hc_swap32_S (cdata[i]);
  }
}
