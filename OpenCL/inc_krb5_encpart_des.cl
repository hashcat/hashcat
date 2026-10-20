/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_md5.h"
#include "inc_cipher_des.h"
#include "inc_krb5_encpart_des.h"

// Tells whether a plaintext opens with the ASN.1 header of the encrypted part it is supposed to
// be. w0 and w1 are its first two words as the DES helpers give them back, so byte i sits in bits
// 8i, and is_rep picks a reply over a ticket.
//
// An EncTicketPart is application type 3, so it opens with 0x63. A reply opens with 0x79,
// application type 25, or with 0x7a, type 26, which RFC 4120 5.4.2 asks implementations to accept
// here as well, and the six forms below are the ones m32100 tests for.
//
// m13100 tests a ticket on a second marker a block further in, which needs another block
// decrypted, so that one is left to the caller.

DECLSPEC bool krb5_des_encpart_asn1 (const u32 w0, const u32 w1, const bool is_rep)
{
  if (is_rep == true)
  {
    // the length is on one byte and under 128, on two bytes behind 0x81, or on three behind 0x82,
    // and a SEQUENCE opens right after it

    if ((w0 & 0x00ff80ff) == 0x00300079) return true;
    if ((w0 & 0x00ff80ff) == 0x0030007a) return true;
    if ((w0 & 0xff00ffff) == 0x30008179) return true;
    if ((w0 & 0xff00ffff) == 0x3000817a) return true;
    if (((w0 & 0x0000ffff) == 0x00008279) && ((w1 & 0x000000ff) == 0x00000030)) return true;
    if (((w0 & 0x0000ffff) == 0x0000827a) && ((w1 & 0x000000ff) == 0x00000030)) return true;

    return false;
  }

  if ((w0 & 0xff00ffff) == 0x30008163) return true;
  if ((w0 & 0x0000ffff) == 0x00008263) return true;

  return false;
}

// Checks an encrypted part of a Kerberos message that used des-cbc-md5 (etype 3) against a
// candidate key. RFC 3961 6.2.3 wraps it as a confounder, the MD5 of the plaintext with its own
// checksum field zeroed, and the padded message, DES-CBC encrypted under a zero IV with the long
// term key itself. checksum is the first two blocks of that ciphertext, which the hash line keeps
// apart from the rest, and edata2 is everything from byte 16 on.
//
// edata2_len is a whole number of DES blocks and at least 32 bytes, which is what the parsers
// accept: the first three blocks are read before anything is checked.

DECLSPEC bool krb5_des_encpart_check (PRIVATE_AS const u32 *key, GLOBAL_AS const u32 *checksum, GLOBAL_AS const u32 *edata2, const u32 edata2_len, const bool is_rep, SHM_TYPE u32 (*s_SPtrans)[64], SHM_TYPE u32 (*s_skb)[64])
{
  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (key[0], key[1], Kc, Kd, s_skb);

  u32 c[2];
  u32 p[2];

  // the block the header is in, chained with the one before it

  c[0] = edata2[2];
  c[1] = edata2[3];

  _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

  p[0] ^= edata2[0];
  p[1] ^= edata2[1];

  if (krb5_des_encpart_asn1 (p[0], p[1], is_rep) == false) return false;

  if (is_rep == false)
  {
    // a ticket is checked twice, the second marker a block further in

    c[0] = edata2[4];
    c[1] = edata2[5];

    _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

    p[0] ^= edata2[2];

    if (((p[0] & 0x00ffffff) != 0x00000503) && (p[0] != 0x050307a0)) return false;
  }

  // the markers hold, so the whole plaintext is worth taking the MD5 of

  md5_ctx_t ctx;

  md5_init (&ctx);

  u32 iv[2];
  u32 mac[4];
  u32 w[16];

  u32 pos = 0;

  iv[0] = 0;
  iv[1] = 0;

  const u32 plain_len = 16 + edata2_len;

  for (u32 off = 0; off < plain_len; off += 8)
  {
    if (off < 16)
    {
      c[0] = checksum[(off / 4) + 0];
      c[1] = checksum[(off / 4) + 1];
    }
    else
    {
      c[0] = edata2[((off - 16) / 4) + 0];
      c[1] = edata2[((off - 16) / 4) + 1];
    }

    _des_crypt_decrypt (p, c, Kc, Kd, s_SPtrans);

    p[0] ^= iv[0];
    p[1] ^= iv[1];

    iv[0] = c[0];
    iv[1] = c[1];

    // the checksum is covered by the MD5 that produced it, so it is held back and zeroed in place

    if (off == 8)
    {
      mac[0] = p[0];
      mac[1] = p[1];

      p[0] = 0;
      p[1] = 0;
    }
    else if (off == 16)
    {
      mac[2] = p[0];
      mac[3] = p[1];

      p[0] = 0;
      p[1] = 0;
    }

    w[pos + 0] = p[0];
    w[pos + 1] = p[1];

    pos += 2;

    if (pos == 16)
    {
      md5_update_64 (&ctx, w + 0, w + 4, w + 8, w + 12, 64);

      pos = 0;
    }
  }

  if (pos != 0)
  {
    for (u32 i = pos; i < 16; i++) w[i] = 0;

    md5_update_64 (&ctx, w + 0, w + 4, w + 8, w + 12, pos * 4);
  }

  md5_final (&ctx);

  if (mac[0] != ctx.h[0]) return false;
  if (mac[1] != ctx.h[1]) return false;
  if (mac[2] != ctx.h[2]) return false;
  if (mac[3] != ctx.h[3]) return false;

  return true;
}
