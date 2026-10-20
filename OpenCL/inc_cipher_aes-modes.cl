/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_aes.h"
#include "inc_cipher_aes-modes.h"

// The uppercase block functions in inc_cipher_aes.cl take big endian words, as used by the native
// kernels. Swap the key and every block on input and output to match that word order. The lowercase
// functions perform a second swap. The ks buffer holds up to 60 words for an AES-256 key schedule.

DECLSPEC void aes_set_encrypt_key_swap (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *key, const u32 key_len, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3)
{
  u32 ukey[8];

  for (u32 i = 0; i < (key_len / 4); i++) ukey[i] = hc_swap32_S (key[i]);

  if      (key_len == 16) AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);
  else if (key_len == 24) AES192_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);
  else                    AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);
}

DECLSPEC void aes_set_decrypt_key_swap (PRIVATE_AS u32 *ks, PRIVATE_AS const u32 *key, const u32 key_len, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3)
{
  u32 ukey[8];

  for (u32 i = 0; i < (key_len / 4); i++) ukey[i] = hc_swap32_S (key[i]);

  if      (key_len == 16) AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
  else if (key_len == 24) AES192_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
  else                    AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
}

// Process one block in big endian words using the key schedule for a key of key_len bytes.

DECLSPEC void aes_encrypt_block (PRIVATE_AS const u32 *ks, const u32 key_len, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  if      (key_len == 16) AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);
  else if (key_len == 24) AES192_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);
  else                    AES256_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);
}

DECLSPEC void aes_decrypt_block (PRIVATE_AS const u32 *ks, const u32 key_len, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  if      (key_len == 16) AES128_decrypt (ks, in, out, s_td0, s_td1, s_td2, s_td3, s_td4);
  else if (key_len == 24) AES192_decrypt (ks, in, out, s_td0, s_td1, s_td2, s_td3, s_td4);
  else                    AES256_decrypt (ks, in, out, s_td0, s_td1, s_td2, s_td3, s_td4);
}

DECLSPEC void aes_ecb_encrypt_swap (PRIVATE_AS const u32 *key, const u32 key_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ks[60];

  aes_set_encrypt_key_swap (ks, key, key_len, s_te0, s_te1, s_te2, s_te3);

  for (u32 b = 0; b < (len / 16); b++)
  {
    u32 x[4];

    for (u32 i = 0; i < 4; i++) x[i] = hc_swap32_S (in[(b * 4) + i]);

    u32 y[4];

    aes_encrypt_block (ks, key_len, x, y, s_te0, s_te1, s_te2, s_te3, s_te4);

    for (u32 i = 0; i < 4; i++) out[(b * 4) + i] = hc_swap32_S (y[i]);
  }
}

DECLSPEC void aes_ecb_decrypt_swap (PRIVATE_AS const u32 *key, const u32 key_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks[60];

  aes_set_decrypt_key_swap (ks, key, key_len, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  for (u32 b = 0; b < (len / 16); b++)
  {
    u32 x[4];

    for (u32 i = 0; i < 4; i++) x[i] = hc_swap32_S (in[(b * 4) + i]);

    u32 y[4];

    aes_decrypt_block (ks, key_len, x, y, s_td0, s_td1, s_td2, s_td3, s_td4);

    for (u32 i = 0; i < 4; i++) out[(b * 4) + i] = hc_swap32_S (y[i]);
  }
}

// CBC XORs each plaintext block with the previous ciphertext block, and the first one with the IV.

DECLSPEC void aes_cbc_encrypt_swap (PRIVATE_AS const u32 *key, const u32 key_len, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 ks[60];

  aes_set_encrypt_key_swap (ks, key, key_len, s_te0, s_te1, s_te2, s_te3);

  u32 c[4];

  for (u32 i = 0; i < 4; i++) c[i] = hc_swap32_S (iv[i]);

  for (u32 b = 0; b < (len / 16); b++)
  {
    u32 x[4];

    for (u32 i = 0; i < 4; i++) x[i] = hc_swap32_S (in[(b * 4) + i]) ^ c[i];

    aes_encrypt_block (ks, key_len, x, c, s_te0, s_te1, s_te2, s_te3, s_te4);

    for (u32 i = 0; i < 4; i++) out[(b * 4) + i] = hc_swap32_S (c[i]);
  }
}

// The in and out buffers can be the same. Save each ciphertext block for use with the next block
// before overwriting it with its plaintext.

DECLSPEC void aes_cbc_decrypt_swap (PRIVATE_AS const u32 *key, const u32 key_len, PRIVATE_AS const u32 *iv, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks[60];

  aes_set_decrypt_key_swap (ks, key, key_len, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 c[4];

  for (u32 i = 0; i < 4; i++) c[i] = hc_swap32_S (iv[i]);

  for (u32 b = 0; b < (len / 16); b++)
  {
    u32 x[4];

    for (u32 i = 0; i < 4; i++) x[i] = hc_swap32_S (in[(b * 4) + i]);

    u32 y[4];

    aes_decrypt_block (ks, key_len, x, y, s_td0, s_td1, s_td2, s_td3, s_td4);

    for (u32 i = 0; i < 4; i++) out[(b * 4) + i] = hc_swap32_S (y[i] ^ c[i]);

    for (u32 i = 0; i < 4; i++) c[i] = x[i];
  }
}

// Register A occupies in[0] and in[1], followed by the n blocks of R. Unwrapping runs the 6
// rounds of the wrap in reverse, from block n down to block 1. It decrypts A ^ t . R[i] with
// t = n * j + i, which stays below 2^32. The out buffer stores R, and a receives A. Both buffers
// remain in big endian word order.

DECLSPEC void aes_unwrap_rounds (PRIVATE_AS const u32 *kek, const u32 kek_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, PRIVATE_AS u32 *a, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 ks[60];

  aes_set_decrypt_key_swap (ks, kek, kek_len, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  const u32 n = (len / 8) - 1;

  u32 a0 = hc_swap32_S (in[0]);
  u32 a1 = hc_swap32_S (in[1]);

  for (u32 i = 0; i < (n * 2); i++) out[i] = hc_swap32_S (in[i + 2]);

  for (u32 round = 0; round < 6; round++)
  {
    const u32 j = 5 - round;

    for (u32 i = n; i >= 1; i--)
    {
      const u32 t = (n * j) + i;

      u32 x[4];

      x[0] = a0;
      x[1] = a1 ^ t;
      x[2] = out[((i - 1) * 2) + 0];
      x[3] = out[((i - 1) * 2) + 1];

      u32 y[4];

      aes_decrypt_block (ks, kek_len, x, y, s_td0, s_td1, s_td2, s_td3, s_td4);

      a0 = y[0];
      a1 = y[1];

      out[((i - 1) * 2) + 0] = y[2];
      out[((i - 1) * 2) + 1] = y[3];
    }
  }

  a[0] = a0;
  a[1] = a1;
}

DECLSPEC u32 aes_unwrap_swap (PRIVATE_AS const u32 *kek, const u32 kek_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 a[2];

  aes_unwrap_rounds (kek, kek_len, in, len, out, a, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3, s_td4);

  const u32 n = (len / 8) - 1;

  for (u32 i = 0; i < (n * 2); i++) out[i] = hc_swap32_S (out[i]);

  if (a[0] != 0xa6a6a6a6) return 0;
  if (a[1] != 0xa6a6a6a6) return 0;

  const u32 r = n * 8;

  return r;
}

DECLSPEC void aes_unwrap_iv_swap (PRIVATE_AS const u32 *kek, const u32 kek_len, PRIVATE_AS const u32 *in, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 r[16];

  u32 a[2];

  aes_unwrap_rounds (kek, kek_len, in, len, r, a, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] = hc_swap32_S (a[0]);
  out[1] = hc_swap32_S (a[1]);
}
