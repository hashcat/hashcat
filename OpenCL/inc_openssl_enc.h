/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_OPENSSL_ENC_H
#define INC_OPENSSL_ENC_H

// "openssl enc" with AES-CBC and EVP_BytesToKey, as John the Ripper's openssl2john.py describes a
// file. The checks are shared by the attack kernels of hash-mode 2300.

#define OPENSSL_ENC_CIPHER_AES256 0
#define OPENSSL_ENC_CIPHER_AES128 1

#define OPENSSL_ENC_MD_MD5    0
#define OPENSSL_ENC_MD_SHA1   1
#define OPENSSL_ENC_MD_SHA256 2

#define OPENSSL_ENC_KPA_NONE  0
#define OPENSSL_ENC_KPA_TEXT  1
#define OPENSSL_ENC_KPA_ASCII 2

#define OPENSSL_ENC_DATA_MAX 256

typedef struct openssl_enc
{
  u32 cipher;
  u32 md;
  u32 salt[2];

  u32 inlined;
  u32 last[8];

  u32 data_len;
  u32 data[OPENSSL_ENC_DATA_MAX / 4];

  u32 kpa;
  u32 kpt_len;
  u32 kpt[64];
  u32 ascii_pct;

} openssl_enc_t;

DECLSPEC bool openssl_enc_check (PRIVATE_AS const u32 *w, const u32 pw_len, GLOBAL_AS const openssl_enc_t *esalt, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4, SHM_TYPE u32 *s_inv0, SHM_TYPE u32 *s_inv1, SHM_TYPE u32 *s_inv2, SHM_TYPE u32 *s_inv3);

#endif // INC_OPENSSL_ENC_H
