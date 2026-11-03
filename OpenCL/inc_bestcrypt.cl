/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_aes.h"
#include "inc_bestcrypt.h"

// What the three BestCrypt container modes share: the input of the PKCS#12 key derivation, and the
// AES-256 decryption of the first 8 blocks of a key slot.
//
// Everything here is in host byte order, so the lower case cipher helpers are the ones to call. The
// key slot arrives that way from hex_decode (), and the XTS tweak has to be in it as well, because
// the multiplication by the primitive element of GF(2 ** 128) treats the 16 byte block as a little
// endian number.

DECLSPEC void bestcrypt_salt_bytes (PRIVATE_AS u8 *out, GLOBAL_AS const u32 *salt_buf, const int salt_len)
{
  for (int i = 0; i < salt_len; i++)
  {
    out[i] = (salt_buf[i / 4] >> ((i & 3) * 8)) & 0xff;
  }
}

DECLSPEC void bestcrypt_pwd_bytes (PRIVATE_AS u8 *out, GLOBAL_AS const u32 *pw_buf, const int pw_len)
{
  // the key generator widens the password to UTF-16 and appends its terminator. Widening a byte at
  // a time is what hash-mode 24440 does with the same derivation, so a password outside ASCII does
  // not come out the way the container was written.

  for (int i = 0; i < pw_len; i++)
  {
    out[(i * 2) + 0] = 0;
    out[(i * 2) + 1] = (pw_buf[i / 4] >> ((i & 3) * 8)) & 0xff;
  }

  out[(pw_len * 2) + 0] = 0;
  out[(pw_len * 2) + 1] = 0;
}

DECLSPEC void bestcrypt_fill_be (PRIVATE_AS u32 *dst, const int dst_len, PRIVATE_AS const u8 *src, const int src_len)
{
  // the PKCS#12 fill: the source repeated to dst_len bytes, with the last copy cut short. The
  // result goes in as big endian words, which is what every hash here reads.

  for (int i = 0; i < dst_len; i += 4)
  {
    dst[i / 4] = ((u32) src[(i + 0) % src_len] << 24)
               | ((u32) src[(i + 1) % src_len] << 16)
               | ((u32) src[(i + 2) % src_len] <<  8)
               | ((u32) src[(i + 3) % src_len] <<  0);
  }
}

DECLSPEC int bestcrypt_v2 (const int pw_len)
{
  // SHA-256 takes as many whole blocks as the widened password and its terminator need. Where the
  // key generator hashes to 64 bytes it fixes the password block at one block instead, so only the
  // mode that hashes to 32 asks for this.

  const int pwd_len = (pw_len + 1) * 2;

  const int v2 = ((pwd_len + BESTCRYPT_V - 1) / BESTCRYPT_V) * BESTCRYPT_V;

  return v2;
}

DECLSPEC void bestcrypt_inc512 (PRIVATE_AS u32 *a)
{
  // a is a 512 bit big endian number, so the carry travels towards the front

  for (int i = 15; i >= 0; i--)
  {
    a[i]++;

    if (a[i] != 0) break;
  }
}

DECLSPEC void bestcrypt_add512 (PRIVATE_AS u32 *a, PRIVATE_AS const u32 *b)
{
  u32 carry = 0;

  for (int i = 15; i >= 0; i--)
  {
    const u64 sum = (u64) a[i] + (u64) b[i] + (u64) carry;

    a[i] = (u32) sum;

    carry = (u32) (sum >> 32);
  }
}

DECLSPEC int bestcrypt_kdf_input (PRIVATE_AS u32 *w, GLOBAL_AS const u32 *salt_buf, const int salt_len, GLOBAL_AS const u32 *pw_buf, const int pw_len, const int v2)
{
  // the diversifier, which is ID 1 for key material, over a whole block

  for (int i = 0; i < (BESTCRYPT_V / 4); i++) w[i] = 0x01010101;

  u8 salt_bytes[BESTCRYPT_V];

  bestcrypt_salt_bytes (salt_bytes, salt_buf, salt_len);

  bestcrypt_fill_be (&w[BESTCRYPT_V / 4], BESTCRYPT_V, salt_bytes, salt_len);

  u8 pwd_bytes[(BESTCRYPT_PW_MAX + 1) * 2];

  bestcrypt_pwd_bytes (pwd_bytes, pw_buf, pw_len);

  bestcrypt_fill_be (&w[(BESTCRYPT_V * 2) / 4], v2, pwd_bytes, (pw_len + 1) * 2);

  const int len = (BESTCRYPT_V * 2) + v2;

  return len;
}

DECLSPEC void bestcrypt_xts_mul2 (PRIVATE_AS u32 *t)
{
  const u32 c = t[3] >> 31;

  t[3] = (t[3] << 1) | (t[2] >> 31);
  t[2] = (t[2] << 1) | (t[1] >> 31);
  t[1] = (t[1] << 1) | (t[0] >> 31);
  t[0] = (t[0] << 1);

  t[0] ^= c * 0x87;
}

DECLSPEC void bestcrypt_decrypt_block (PRIVATE_AS u32 *pt, GLOBAL_AS const u32 *slot_buf, const int iv_off, const u32 mode_id, PRIVATE_AS const u32 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  // the 8 byte IV the slot carries in clear, behind the key block

  u32 iv[2];

  iv[0] = slot_buf[iv_off + 0];
  iv[1] = slot_buf[iv_off + 1];

  u32 ks[60];

  if (mode_id == BESTCRYPT_MODE_XTS)
  {
    // the tweak of the first block is that IV followed by zeros, rather than a sector number, and
    // the second half of the derived key is the one that encrypts it

    u32 t[4];

    t[0] = iv[0];
    t[1] = iv[1];
    t[2] = 0;
    t[3] = 0;

    aes256_set_encrypt_key (ks, &key[8], s_te0, s_te1, s_te2, s_te3);
    aes256_encrypt (ks, t, t, s_te0, s_te1, s_te2, s_te3, s_te4);

    aes256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    for (int i = 0; i < (BESTCRYPT_BLOCK_LEN / 4); i += 4)
    {
      u32 in[4];

      in[0] = slot_buf[i + 0] ^ t[0];
      in[1] = slot_buf[i + 1] ^ t[1];
      in[2] = slot_buf[i + 2] ^ t[2];
      in[3] = slot_buf[i + 3] ^ t[3];

      aes256_decrypt (ks, in, &pt[i], s_td0, s_td1, s_td2, s_td3, s_td4);

      pt[i + 0] ^= t[0];
      pt[i + 1] ^= t[1];
      pt[i + 2] ^= t[2];
      pt[i + 3] ^= t[3];

      bestcrypt_xts_mul2 (t);
    }

    return;
  }

  // CBC, where the 16 byte IV is the 8 byte one twice over

  aes256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 prev[4];

  prev[0] = iv[0];
  prev[1] = iv[1];
  prev[2] = iv[0];
  prev[3] = iv[1];

  for (int i = 0; i < (BESTCRYPT_BLOCK_LEN / 4); i += 4)
  {
    u32 in[4];

    in[0] = slot_buf[i + 0];
    in[1] = slot_buf[i + 1];
    in[2] = slot_buf[i + 2];
    in[3] = slot_buf[i + 3];

    aes256_decrypt (ks, in, &pt[i], s_td0, s_td1, s_td2, s_td3, s_td4);

    pt[i + 0] ^= prev[0];
    pt[i + 1] ^= prev[1];
    pt[i + 2] ^= prev[2];
    pt[i + 3] ^= prev[3];

    prev[0] = in[0];
    prev[1] = in[1];
    prev[2] = in[2];
    prev[3] = in[3];
  }
}
