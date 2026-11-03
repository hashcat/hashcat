/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_cipher_aes.h"
#include "inc_openssl_enc.h"

// EVP_BytesToKey with one round: D1 = H (pass . salt), Dn = H (Dn-1 . pass . salt), concatenated
// until the key and the 16 byte IV are covered. The result is in big endian words, as AES takes it.

DECLSPEC void openssl_enc_bytes_to_key (PRIVATE_AS const u32 *w, const u32 pw_len, GLOBAL_AS const openssl_enc_t *esalt, PRIVATE_AS u32 *out)
{
  const u32 need = (esalt->cipher == OPENSSL_ENC_CIPHER_AES256) ? 12 : 8;

  u32 salt[2];

  salt[0] = esalt->salt[0];
  salt[1] = esalt->salt[1];

  u32 prev[16] = { 0 };

  u32 prev_len = 0;

  for (u32 have = 0; have < need; )
  {
    if (esalt->md == OPENSSL_ENC_MD_MD5)
    {
      md5_ctx_t ctx;

      md5_init (&ctx);

      if (prev_len > 0) md5_update (&ctx, prev, prev_len);

      md5_update (&ctx, w, pw_len);
      md5_update (&ctx, salt, 8);

      md5_final (&ctx);

      for (u32 i = 0; i < 4; i++)
      {
        prev[i] = ctx.h[i];

        out[have + i] = hc_swap32_S (ctx.h[i]);
      }

      prev_len = 16;

      have += 4;
    }
    else if (esalt->md == OPENSSL_ENC_MD_SHA1)
    {
      sha1_ctx_t ctx;

      sha1_init (&ctx);

      if (prev_len > 0) sha1_update (&ctx, prev, prev_len);

      sha1_update_swap (&ctx, w, pw_len);
      sha1_update_swap (&ctx, salt, 8);

      sha1_final (&ctx);

      for (u32 i = 0; i < 5; i++)
      {
        prev[i] = ctx.h[i];

        out[have + i] = ctx.h[i];
      }

      prev_len = 20;

      have += 5;
    }
    else
    {
      sha256_ctx_t ctx;

      sha256_init (&ctx);

      if (prev_len > 0) sha256_update (&ctx, prev, prev_len);

      sha256_update_swap (&ctx, w, pw_len);
      sha256_update_swap (&ctx, salt, 8);

      sha256_final (&ctx);

      for (u32 i = 0; i < 8; i++)
      {
        prev[i] = ctx.h[i];

        out[have + i] = ctx.h[i];
      }

      prev_len = 32;

      have += 8;
    }
  }
}

DECLSPEC u32 openssl_enc_byte (PRIVATE_AS const u32 *buf, const u32 pos)
{
  const u32 r = (buf[pos / 4] >> ((pos & 3) * 8)) & 0xff;

  return r;
}

DECLSPEC u32 openssl_enc_kpt_byte (GLOBAL_AS const u32 *buf, const u32 pos)
{
  const u32 r = (buf[pos / 4] >> ((pos & 3) * 8)) & 0xff;

  return r;
}

// the length of the plaintext in front of a valid PKCS#7 padding in the last block of buf, or -1

DECLSPEC int openssl_enc_pkcs_len (PRIVATE_AS const u32 *buf, const u32 len)
{
  const u32 pad = openssl_enc_byte (buf, len - 1);

  if (pad > 16) return -1;
  if (pad <  1) return -1;

  for (u32 i = len - pad; i < len; i++)
  {
    if (openssl_enc_byte (buf, i) != pad) return -1;
  }

  const int r = (int) (len - pad);

  return r;
}

DECLSPEC bool openssl_enc_has_kpt (PRIVATE_AS const u32 *buf, const u32 len, GLOBAL_AS const openssl_enc_t *esalt)
{
  const u32 kpt_len = esalt->kpt_len;

  if (kpt_len > len) return false;

  for (u32 i = 0; i <= (len - kpt_len); i++)
  {
    u32 j;

    for (j = 0; j < kpt_len; j++)
    {
      if (openssl_enc_byte (buf, i + j) != openssl_enc_kpt_byte (esalt->kpt, j)) break;
    }

    if (j == kpt_len) return true;
  }

  return false;
}

DECLSPEC bool openssl_enc_is_ascii (PRIVATE_AS const u32 *buf, const int len, const u32 pct)
{
  if (len < 0) return false;

  u32 nascii = 0;

  for (int i = 0; i < len; i++)
  {
    const u32 c = openssl_enc_byte (buf, i);

    if ((c == 0x0a) || (c == 0x0d) || ((c >= 32) && (c < 127))) nascii++;
  }

  const bool r = (nascii * 100) >= (pct * (u32) len);

  return r;
}

DECLSPEC bool openssl_enc_check (PRIVATE_AS const u32 *w, const u32 pw_len, GLOBAL_AS const openssl_enc_t *esalt, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4, SHM_TYPE u32 *s_inv0, SHM_TYPE u32 *s_inv1, SHM_TYPE u32 *s_inv2, SHM_TYPE u32 *s_inv3)
{
  u32 kd[16];

  openssl_enc_bytes_to_key (w, pw_len, esalt, kd);

  const u32 key_words = (esalt->cipher == OPENSSL_ENC_CIPHER_AES256) ? 8 : 4;

  u32 ukey[8];

  for (u32 i = 0; i < 8; i++) ukey[i] = kd[i];

  u32 iv[4];

  iv[0] = kd[key_words + 0];
  iv[1] = kd[key_words + 1];
  iv[2] = kd[key_words + 2];
  iv[3] = kd[key_words + 3];

  // the last block, chained to the IV when it is the only one

  u32 prev[4];
  u32 ct[4];

  if (esalt->inlined == 1)
  {
    prev[0] = iv[0];
    prev[1] = iv[1];
    prev[2] = iv[2];
    prev[3] = iv[3];

    ct[0] = esalt->last[0];
    ct[1] = esalt->last[1];
    ct[2] = esalt->last[2];
    ct[3] = esalt->last[3];
  }
  else
  {
    prev[0] = esalt->last[0];
    prev[1] = esalt->last[1];
    prev[2] = esalt->last[2];
    prev[3] = esalt->last[3];

    ct[0] = esalt->last[4];
    ct[1] = esalt->last[5];
    ct[2] = esalt->last[6];
    ct[3] = esalt->last[7];
  }

  // plaintext bytes are kept in little endian words from here on, the order the known plaintext
  // comes in. AES-256 decrypts the one block without expanding the whole key schedule first, and
  // that path takes and gives the block in little endian words.

  u32 ks[60];

  u32 pt[4];

  if (esalt->cipher == OPENSSL_ENC_CIPHER_AES256)
  {
    u32 ct_le[4];

    ct_le[0] = hc_swap32_S (ct[0]);
    ct_le[1] = hc_swap32_S (ct[1]);
    ct_le[2] = hc_swap32_S (ct[2]);
    ct_le[3] = hc_swap32_S (ct[3]);

    AES256_decrypt_cs (ukey, ct_le, pt, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4, s_inv0, s_inv1, s_inv2, s_inv3);
  }
  else
  {
    AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 pt_be[4];

    AES128_decrypt (ks, ct, pt_be, s_td0, s_td1, s_td2, s_td3, s_td4);

    pt[0] = hc_swap32_S (pt_be[0]);
    pt[1] = hc_swap32_S (pt_be[1]);
    pt[2] = hc_swap32_S (pt_be[2]);
    pt[3] = hc_swap32_S (pt_be[3]);
  }

  u32 tail[4];

  tail[0] = pt[0] ^ hc_swap32_S (prev[0]);
  tail[1] = pt[1] ^ hc_swap32_S (prev[1]);
  tail[2] = pt[2] ^ hc_swap32_S (prev[2]);
  tail[3] = pt[3] ^ hc_swap32_S (prev[3]);

  const int tail_len = openssl_enc_pkcs_len (tail, 16);

  if (tail_len < 0) return false;

  if (esalt->kpa == OPENSSL_ENC_KPA_NONE) return true;

  if (esalt->inlined == 1)
  {
    if (esalt->kpa == OPENSSL_ENC_KPA_TEXT)
    {
      const bool r = openssl_enc_has_kpt (tail, 16, esalt);

      return r;
    }

    const bool r = openssl_enc_is_ascii (tail, tail_len, esalt->ascii_pct);

    return r;
  }

  // only about one candidate in 256 gets this far, so the rest of the data is decrypted here

  const u32 data_len = esalt->data_len;

  if (esalt->cipher == OPENSSL_ENC_CIPHER_AES256)
  {
    AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
  }

  u32 plain[OPENSSL_ENC_DATA_MAX / 4];

  prev[0] = iv[0];
  prev[1] = iv[1];
  prev[2] = iv[2];
  prev[3] = iv[3];

  for (u32 i = 0; i < (data_len / 4); i += 4)
  {
    ct[0] = esalt->data[i + 0];
    ct[1] = esalt->data[i + 1];
    ct[2] = esalt->data[i + 2];
    ct[3] = esalt->data[i + 3];

    if (esalt->cipher == OPENSSL_ENC_CIPHER_AES256)
    {
      AES256_decrypt (ks, ct, pt, s_td0, s_td1, s_td2, s_td3, s_td4);
    }
    else
    {
      AES128_decrypt (ks, ct, pt, s_td0, s_td1, s_td2, s_td3, s_td4);
    }

    plain[i + 0] = hc_swap32_S (pt[0] ^ prev[0]);
    plain[i + 1] = hc_swap32_S (pt[1] ^ prev[1]);
    plain[i + 2] = hc_swap32_S (pt[2] ^ prev[2]);
    plain[i + 3] = hc_swap32_S (pt[3] ^ prev[3]);

    prev[0] = ct[0];
    prev[1] = ct[1];
    prev[2] = ct[2];
    prev[3] = ct[3];
  }

  if (esalt->kpa == OPENSSL_ENC_KPA_TEXT)
  {
    const bool r = openssl_enc_has_kpt (plain, data_len, esalt);

    return r;
  }

  // data that stops short of the end of the file has no padding to strip, as openssl2john keeps
  // only the first 256 bytes

  int plain_len = openssl_enc_pkcs_len (plain, data_len);

  if ((plain_len < 0) && (data_len >= OPENSSL_ENC_DATA_MAX)) plain_len = (int) data_len;

  const bool r = openssl_enc_is_ascii (plain, plain_len, esalt->ascii_pct);

  return r;
}
