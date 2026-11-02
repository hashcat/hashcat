/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_des.h"
#include "inc_krb5_des.h"

// The string-to-key of RFC 3961 6.2, shared by the DES encryption types des-cbc-crc (1),
// des-cbc-md4 (2) and des-cbc-md5 (3). Buffers are the little endian packing the DES helpers
// take, so byte i of the key sits in bits 8i of w[i / 4].

CONSTANT_VK u32a c_krb5_weak_des_keys[16][2] =
{
  { 0x01010101, 0x01010101 }, { 0x1f1f1f1f, 0x0e0e0e0e },
  { 0xe0e0e0e0, 0xf1f1f1f1 }, { 0xfefefefe, 0xfefefefe },
  { 0xfe01fe01, 0xfe01fe01 }, { 0xe01fe01f, 0xf10ef10e },
  { 0xe001e001, 0xf101f101 }, { 0xfe1ffe1f, 0xfe0efe0e },
  { 0x1f011f01, 0x0e010e01 }, { 0xfee0fee0, 0xfef1fef1 },
  { 0x01fe01fe, 0x01fe01fe }, { 0x1fe01fe0, 0x0ef10ef1 },
  { 0x01e001e0, 0x01f101f1 }, { 0x1ffe1ffe, 0x0efe0efe },
  { 0x011f011f, 0x010e010e }, { 0xe0fee0fe, 0xf1fef1fe },
};

// Reverses the low seven bits of every byte. The callers mask bit 7 off first, so reversing all
// eight bits and shifting the word down by one lands the seven bits in place without crossing a
// byte boundary.

DECLSPEC u32 krb5_des_rev7 (const u32 x)
{
  u32 r = x;

  r = ((r & 0x55555555) << 1) | ((r >> 1) & 0x55555555);
  r = ((r & 0x33333333) << 2) | ((r >> 2) & 0x33333333);
  r = ((r & 0x0f0f0f0f) << 4) | ((r >> 4) & 0x0f0f0f0f);

  return r >> 1;
}

// Gives every byte odd parity in bit 0. The fold leaves the parity of bits 1 to 7 in bit 0 of each
// byte, and bits that cross into the byte above are masked away with the result.

DECLSPEC u32 krb5_des_odd_parity (const u32 x)
{
  const u32 v = x & 0xfefefefe;

  u32 p = v;

  p ^= p >> 4;
  p ^= p >> 2;
  p ^= p >> 1;

  return v | (~p & 0x01010101);
}

DECLSPEC void krb5_des_key_correction (PRIVATE_AS u32 *k)
{
  k[0] = krb5_des_odd_parity (k[0]);
  k[1] = krb5_des_odd_parity (k[1]);

  for (u32 i = 0; i < 16; i++)
  {
    if ((k[0] == c_krb5_weak_des_keys[i][0]) && (k[1] == c_krb5_weak_des_keys[i][1]))
    {
      k[1] ^= 0xf0000000;

      break;
    }
  }
}

// Joins the password and the salt into the 256 byte buffer the string-to-key reads. The caller
// keeps the two within it: this writes 64 words whatever the lengths are.

DECLSPEC void krb5_des_build_buf (PRIVATE_AS const u32 *pw, const u32 pw_len, GLOBAL_AS const u32 *salt_buf, const u32 salt_len, PRIVATE_AS u32 *w)
{
  for (u32 i = 0; i < 64; i++) w[i] = 0;

  const u32 salt_words = (salt_len + 3) / 4;

  for (u32 i = 0; i < salt_words; i++) w[i] = salt_buf[i];

  switch_buffer_by_offset_1x64_le_S (w, pw_len);

  // the last word of the password shares its slot with the first bytes of the salt, so it is
  // masked to pw_len instead of trusting the caller to have zeroed what follows

  const u32 pw_words = pw_len / 4;

  for (u32 i = 0; i < pw_words; i++) w[i] |= pw[i];

  const u32 pw_rem = pw_len & 3;

  if (pw_rem != 0) w[pw_words] |= pw[pw_words] & ((1u << (pw_rem * 8)) - 1);
}

// w holds the password followed by the salt, zeroed beyond len, with room for len rounded up to a
// multiple of eight. out receives the eight byte key.

DECLSPEC void krb5_des_string_to_key (PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *out, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64])
{
  const u32 blocks = (len + 7) / 8;

  u32 k[2] = { 0, 0 };

  for (u32 i = 0; i < blocks; i++)
  {
    u32 b0 = w[(i * 2) + 0] & 0x7f7f7f7f;
    u32 b1 = w[(i * 2) + 1] & 0x7f7f7f7f;

    if ((i & 1) == 1)
    {
      const u32 t0 = hc_swap32_S (krb5_des_rev7 (b1));
      const u32 t1 = hc_swap32_S (krb5_des_rev7 (b0));

      b0 = t0;
      b1 = t1;
    }

    k[0] ^= b0;
    k[1] ^= b1;
  }

  k[0] <<= 1;
  k[1] <<= 1;

  krb5_des_key_correction (k);

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (k[0], k[1], Kc, Kd, s_skb);

  // the key just derived serves as both the key and the IV of the CBC-MAC

  u32 s[2];

  s[0] = k[0];
  s[1] = k[1];

  for (u32 i = 0; i < blocks; i++)
  {
    u32 data[2];

    data[0] = s[0] ^ w[(i * 2) + 0];
    data[1] = s[1] ^ w[(i * 2) + 1];

    _des_crypt_encrypt (s, data, Kc, Kd, s_SPtrans);
  }

  krb5_des_key_correction (s);

  out[0] = s[0];
  out[1] = s[1];
}
