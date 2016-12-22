/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INTERFACE_H
#define _INTERFACE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

/**
 * weak hashes shutcut
 */

static const char LM_WEAK_HASH[]    = "aad3b435b51404ee";
static const char LM_MASKED_PLAIN[] = "[notfound]";

/**
 * algo specific
 */

typedef struct rar5
{
  u32 iv[4];

} rar5_t;

typedef struct pdf
{
  int  V;
  int  R;
  int  P;

  int  enc_md;

  u32  id_buf[8];
  u32  u_buf[32];
  u32  o_buf[32];

  int  id_len;
  int  o_len;
  int  u_len;

  u32  rc4key[2];
  u32  rc4data[2];

} pdf_t;

typedef struct wpa
{
  u32  pke[25];
  u32  eapol[64];
  int  eapol_size;
  int  keyver;
  u8   orig_mac1[6];
  u8   orig_mac2[6];
  u8   orig_nonce1[32];
  u8   orig_nonce2[32];
  int  essid_reuse;

} wpa_t;

typedef struct bitcoin_wallet
{
  u32 cry_master_buf[64];
  u32 ckey_buf[64];
  u32 public_key_buf[64];

  u32 cry_master_len;
  u32 ckey_len;
  u32 public_key_len;

} bitcoin_wallet_t;

typedef struct sip
{
  u32 salt_buf[30];
  u32 salt_len;

  u32 esalt_buf[38];
  u32 esalt_len;

} sip_t;

typedef struct androidfde
{
  u32 data[384];

} androidfde_t;

typedef struct ikepsk
{
  u32 nr_buf[16];
  u32 nr_len;

  u32 msg_buf[128];
  u32 msg_len;

} ikepsk_t;

typedef struct netntlm
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

typedef struct krb5pa
{
  u32 user[16];
  u32 realm[16];
  u32 salt[32];
  u32 timestamp[16];
  u32 checksum[4];

} krb5pa_t;

typedef struct krb5tgs
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[2560];
  u32 edata2_len;

} krb5tgs_t;

typedef struct keepass
{
  u32 version;
  u32 algorithm;

  /* key-file handling */
  u32 keyfile_len;
  u32 keyfile[8];

  u32 final_random_seed[8];
  u32 transf_random_seed[8];
  u32 enc_iv[4];
  u32 contents_hash[8];

  /* specific to version 1 */
  u32 contents_len;
  u32 contents[75000];

  /* specific to version 2 */
  u32 expected_bytes[8];

} keepass_t;

typedef struct tc
{
  u32 salt_buf[16];
  u32 data_buf[112];
  u32 keyfile_buf[16];
  u32 signature;

} tc_t;

typedef struct pbkdf2_md5
{
  u32 salt_buf[16];

} pbkdf2_md5_t;

typedef struct pbkdf2_sha1
{
  u32 salt_buf[16];

} pbkdf2_sha1_t;

typedef struct pbkdf2_sha256
{
  u32 salt_buf[16];

} pbkdf2_sha256_t;

typedef struct pbkdf2_sha512
{
  u32 salt_buf[32];

} pbkdf2_sha512_t;

typedef struct agilekey
{
  u8   cipher[1040];

} agilekey_t;

typedef struct rakp
{
  u32 salt_buf[128];
  u32 salt_len;

} rakp_t;

typedef struct cloudkey
{
  u32 data_len;
  u32 data_buf[512];

} cloudkey_t;

typedef struct office2007
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];

  u32 keySize;

} office2007_t;

typedef struct office2010
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2010_t;

typedef struct office2013
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2013_t;

typedef struct oldoffice01
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[4];
  u32 rc4key[2];

} oldoffice01_t;

typedef struct oldoffice34
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 rc4key[2];

} oldoffice34_t;

typedef struct pstoken
{
  u32 salt_buf[128];
  u32 salt_len;

  u32 pc_digest[5];
  u32 pc_offset;

} pstoken_t;

typedef struct zip2
{
  u32 type;
  u32 mode;
  u32 magic;
  u32 salt_len;
  u32 salt_buf[4];
  u32 verify_bytes;
  u32 compress_length;
  u32 data_len;
  u32 data_buf[2048];
  u32 auth_len;
  u32 auth_buf[4];

} zip2_t;

typedef struct win8phone
{
  u32 salt_buf[32];

} win8phone_t;

typedef struct psafe3
{
  char signature[4];
  u32  salt_buf[8];
  u32  iterations;
  u32  hash_buf[8];

} psafe3_t;

typedef struct pdf14_tmp
{
  u32 digest[4];
  u32 out[4];

} pdf14_tmp_t;

typedef struct pdf17l8_tmp
{
  union
  {
    u32 dgst32[16];
    u64  dgst64[8];
  } d;

  u32 dgst_len;
  u32 W_len;

} pdf17l8_tmp_t;

typedef struct phpass_tmp
{
  u32 digest_buf[4];

} phpass_tmp_t;

typedef struct md5crypt_tmp
{
  u32 digest_buf[4];

} md5crypt_tmp_t;

typedef struct sha512crypt_tmp
{
  u64  l_alt_result[8];

  u64  l_p_bytes[2];
  u64  l_s_bytes[2];

} sha512crypt_tmp_t;

typedef struct sha256crypt_tmp
{
  u32 alt_result[8];

  u32 p_bytes[4];
  u32 s_bytes[4];

} sha256crypt_tmp_t;

typedef struct wpa_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} wpa_tmp_t;

typedef struct bitcoin_wallet_tmp
{
  u64  dgst[8];

} bitcoin_wallet_tmp_t;

typedef struct dcc2_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[4];

} dcc2_tmp_t;

typedef struct bcrypt_tmp
{
  u32 E[18];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} bcrypt_tmp_t;

typedef struct pwsafe2_tmp
{
  u32 digest[2];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} pwsafe2_tmp_t;

typedef struct pwsafe3_tmp
{
  u32 digest_buf[8];

} pwsafe3_tmp_t;

typedef struct androidpin_tmp
{
  u32 digest_buf[5];

} androidpin_tmp_t;

typedef struct androidfde_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} androidfde_tmp_t;

typedef struct tc_tmp
{
  u32 ipad[16];
  u32 opad[16];

  u32 dgst[64];
  u32 out[64];

} tc_tmp_t;

typedef struct tc64_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

} tc64_tmp_t;

typedef struct agilekey_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} agilekey_tmp_t;

typedef struct mywallet_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst1[5];
  u32 out1[5];

  u32 dgst2[5];
  u32 out2[5];

} mywallet_tmp_t;

typedef struct sha1aix_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} sha1aix_tmp_t;

typedef struct sha256aix_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} sha256aix_tmp_t;

typedef struct sha512aix_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} sha512aix_tmp_t;

typedef struct lastpass_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} lastpass_tmp_t;

typedef struct drupal7_tmp
{
  u64  digest_buf[8];

} drupal7_tmp_t;

typedef struct lotus8_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} lotus8_tmp_t;

typedef struct office2007_tmp
{
  u32 out[5];

} office2007_tmp_t;

typedef struct office2010_tmp
{
  u32 out[5];

} office2010_tmp_t;

typedef struct office2013_tmp
{
  u64  out[8];

} office2013_tmp_t;

typedef struct saph_sha1_tmp
{
  u32 digest_buf[5];

} saph_sha1_tmp_t;

typedef struct pbkdf2_md5_tmp
{
  u32  ipad[4];
  u32  opad[4];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_md5_tmp_t;

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct pbkdf2_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} pbkdf2_sha512_tmp_t;

typedef struct ecryptfs_tmp
{
  u64  out[8];

} ecryptfs_tmp_t;

typedef struct oraclet_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} oraclet_tmp_t;

typedef struct seven_zip_tmp
{
  u32 block[16];

  u32 dgst[8];

  u32 block_len;
  u32 final_len;

} seven_zip_tmp_t;

typedef struct bsdicrypt_tmp
{
  u32 Kc[16];
  u32 Kd[16];

  u32 iv[2];

} bsdicrypt_tmp_t;

typedef struct rar3_tmp
{
  u32 dgst[17][5];

} rar3_tmp_t;

typedef struct cram_md5
{
  u32 user[16];

} cram_md5_t;

typedef struct seven_zip
{
  u32 iv_buf[4];
  u32 iv_len;

  u32 salt_buf[4];
  u32 salt_len;

  u32 crc;

  u32 data_buf[96];
  u32 data_len;

  u32 unpack_size;

} seven_zip_t;

typedef struct axcrypt_tmp
{
  u32 KEK[4];
  u32 lsb[4];
  u32 cipher[4];

} axcrypt_tmp_t;

typedef struct keepass_tmp
{
  u32 tmp_digest[8];

} keepass_tmp_t;

typedef struct struct_psafe2_hdr
{
  u32  random[2];
  u32  hash[5];
  u32  salt[5];   // unused, but makes better valid check
  u32  iv[2];     // unused, but makes better valid check

} psafe2_hdr;

typedef struct hccap
{
  char essid[36];

  u8   mac1[6];
  u8   mac2[6];
  u8   nonce1[32];
  u8   nonce2[32];

  u8   eapol[256];
  int  eapol_size;

  int  keyver;
  u8   keymic[16];

} hccap_t;

/**
 * hashtypes enums
 */

typedef enum display_len
{
  DISPLAY_LEN_MIN_0     = 32,
  DISPLAY_LEN_MAX_0     = 32,
  DISPLAY_LEN_MIN_10    = 32 + 1 + 0,
  DISPLAY_LEN_MAX_10    = 32 + 1 + 51,
  DISPLAY_LEN_MIN_10H   = 32 + 1 + 0,
  DISPLAY_LEN_MAX_10H   = 32 + 1 + 102,
  DISPLAY_LEN_MIN_20    = 32 + 1 + 0,
  DISPLAY_LEN_MAX_20    = 32 + 1 + 31,
  DISPLAY_LEN_MIN_20H   = 32 + 1 + 0,
  DISPLAY_LEN_MAX_20H   = 32 + 1 + 62,
  DISPLAY_LEN_MIN_50    = 32 + 1 + 0,
  DISPLAY_LEN_MAX_50    = 32 + 1 + 51,
  DISPLAY_LEN_MIN_50H   = 32 + 1 + 0,
  DISPLAY_LEN_MAX_50H   = 32 + 1 + 102,
  DISPLAY_LEN_MIN_100   = 40,
  DISPLAY_LEN_MAX_100   = 40,
  DISPLAY_LEN_MIN_110   = 40 + 1 + 0,
  DISPLAY_LEN_MAX_110   = 40 + 1 + 51,
  DISPLAY_LEN_MIN_110H  = 40 + 1 + 0,
  DISPLAY_LEN_MAX_110H  = 40 + 1 + 102,
  DISPLAY_LEN_MIN_120   = 40 + 1 + 0,
  DISPLAY_LEN_MAX_120   = 40 + 1 + 31,
  DISPLAY_LEN_MIN_120H  = 40 + 1 + 0,
  DISPLAY_LEN_MAX_120H  = 40 + 1 + 62,
  DISPLAY_LEN_MIN_150   = 40 + 1 + 0,
  DISPLAY_LEN_MAX_150   = 40 + 1 + 51,
  DISPLAY_LEN_MIN_150H  = 40 + 1 + 0,
  DISPLAY_LEN_MAX_150H  = 40 + 1 + 102,
  DISPLAY_LEN_MIN_200   = 16,
  DISPLAY_LEN_MAX_200   = 16,
  DISPLAY_LEN_MIN_300   = 40,
  DISPLAY_LEN_MAX_300   = 40,
  DISPLAY_LEN_MIN_400   = 34,
  DISPLAY_LEN_MAX_400   = 34,
  DISPLAY_LEN_MIN_500   = 3 + 1 + 0 + 22,
  DISPLAY_LEN_MIN_501   = 104,
  DISPLAY_LEN_MAX_500   = 3 + 1 + 8 + 22,
  DISPLAY_LEN_MAX_501   = 104,
  DISPLAY_LEN_MIN_900   = 32,
  DISPLAY_LEN_MAX_900   = 32,
  DISPLAY_LEN_MIN_910   = 32 + 1 + 0,
  DISPLAY_LEN_MAX_910   = 32 + 1 + 51,
  DISPLAY_LEN_MIN_910H  = 32 + 1 + 0,
  DISPLAY_LEN_MAX_910H  = 32 + 1 + 102,
  DISPLAY_LEN_MIN_1000  = 32,
  DISPLAY_LEN_MAX_1000  = 32,
  DISPLAY_LEN_MIN_1100  = 32 + 1 + 0,
  DISPLAY_LEN_MAX_1100  = 32 + 1 + 19,
  DISPLAY_LEN_MIN_1100H = 32 + 1 + 0,
  DISPLAY_LEN_MAX_1100H = 32 + 1 + 38,
  DISPLAY_LEN_MIN_1300  = 56,
  DISPLAY_LEN_MAX_1300  = 56,
  DISPLAY_LEN_MIN_1400  = 64,
  DISPLAY_LEN_MAX_1400  = 64,
  DISPLAY_LEN_MIN_1410  = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1410  = 64 + 1 + 51,
  DISPLAY_LEN_MIN_1410H = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1410H = 64 + 1 + 102,
  DISPLAY_LEN_MIN_1420  = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1420  = 64 + 1 + 16,
  DISPLAY_LEN_MIN_1420H = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1420H = 64 + 1 + 32,
  DISPLAY_LEN_MIN_1421  = 70,
  DISPLAY_LEN_MAX_1421  = 70,
  DISPLAY_LEN_MIN_1450  = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1450  = 64 + 1 + 51,
  DISPLAY_LEN_MIN_1450H = 64 + 1 + 0,
  DISPLAY_LEN_MAX_1450H = 64 + 1 + 102,
  DISPLAY_LEN_MIN_1500  = 13,
  DISPLAY_LEN_MAX_1500  = 13,
  DISPLAY_LEN_MIN_1600  = 29 + 0,
  DISPLAY_LEN_MAX_1600  = 29 + 8,
  DISPLAY_LEN_MIN_1700  = 128,
  DISPLAY_LEN_MAX_1700  = 128,
  DISPLAY_LEN_MIN_1710  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1710  = 128 + 1 + 51,
  DISPLAY_LEN_MIN_1710H = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1710H = 128 + 1 + 102,
  DISPLAY_LEN_MIN_1720  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1720  = 128 + 1 + 16,
  DISPLAY_LEN_MIN_1720H = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1720H = 128 + 1 + 32,
  DISPLAY_LEN_MIN_1730  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1730  = 128 + 1 + 16,
  DISPLAY_LEN_MIN_1731  = 128 + 6 + 0,
  DISPLAY_LEN_MAX_1731  = 128 + 6 + 16,
  DISPLAY_LEN_MIN_1740  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1740  = 128 + 1 + 16,
  DISPLAY_LEN_MIN_1750  = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1750  = 128 + 1 + 51,
  DISPLAY_LEN_MIN_1750H = 128 + 1 + 0,
  DISPLAY_LEN_MAX_1750H = 128 + 1 + 102,
  DISPLAY_LEN_MIN_1800  = 90 + 0,
  DISPLAY_LEN_MAX_1800  = 90 + 16,
  DISPLAY_LEN_MIN_2100  = 6 + 1 + 1 + 32 + 1 + 0,
  DISPLAY_LEN_MAX_2100  = 6 + 5 + 1 + 32 + 1 + 19,
  DISPLAY_LEN_MIN_2100H = 6 + 1 + 1 + 32 + 1 + 0,
  DISPLAY_LEN_MAX_2100H = 6 + 5 + 1 + 32 + 1 + 38,
  DISPLAY_LEN_MIN_2400  = 16,
  DISPLAY_LEN_MAX_2400  = 16,
  DISPLAY_LEN_MIN_2410  = 16 + 1 + 0,
  DISPLAY_LEN_MAX_2410  = 16 + 1 + 16,
  DISPLAY_LEN_MIN_2410H = 16 + 1 + 0,
  DISPLAY_LEN_MAX_2410H = 16 + 1 + 32,
  DISPLAY_LEN_MIN_2500  = 64 + 1 + 0,
  DISPLAY_LEN_MAX_2500  = 64 + 1 + 15,
  DISPLAY_LEN_MIN_2600  = 32,
  DISPLAY_LEN_MAX_2600  = 32,
  DISPLAY_LEN_MIN_3000  = 16,
  DISPLAY_LEN_MAX_3000  = 16,
  DISPLAY_LEN_MIN_3100  = 16 + 1 + 0,
  DISPLAY_LEN_MAX_3100  = 16 + 1 + 30,
  DISPLAY_LEN_MIN_3100H = 16 + 1 + 0,
  DISPLAY_LEN_MAX_3100H = 16 + 1 + 60,
  DISPLAY_LEN_MIN_3200  = 60,
  DISPLAY_LEN_MAX_3200  = 60,
  DISPLAY_LEN_MIN_3711  = 3 +  0 + 1 + 32,
  DISPLAY_LEN_MAX_3711  = 3 + 31 + 1 + 32,
  DISPLAY_LEN_MIN_4300  = 32,
  DISPLAY_LEN_MAX_4300  = 32,
  DISPLAY_LEN_MIN_4800  = 32 + 1 + 32 + 1 + 2,
  DISPLAY_LEN_MAX_4800  = 32 + 1 + 32 + 1 + 2,
  DISPLAY_LEN_MIN_5000  = 16,
  DISPLAY_LEN_MAX_5000  = 400,
  DISPLAY_LEN_MIN_5100  = 16,
  DISPLAY_LEN_MAX_5100  = 16,
  DISPLAY_LEN_MIN_5300  = 48,
  DISPLAY_LEN_MAX_5300  = 1024,
  DISPLAY_LEN_MIN_5400  = 56,
  DISPLAY_LEN_MAX_5400  = 1024,
  DISPLAY_LEN_MIN_5500  =  1 + 1 + 0 +  1 +  1 +  1 +  0 +  1 + 48 + 1 + 16,
  DISPLAY_LEN_MAX_5500  = 60 + 1 + 0 +  1 + 45 +  1 + 48 +  1 + 48 + 1 + 16,
  DISPLAY_LEN_MIN_5600  =  1 + 1 + 0 +  1 +  1 +  1 + 16 +  1 + 32 + 1 + 1,
  DISPLAY_LEN_MAX_5600  = 60 + 1 + 0 +  1 + 45 +  1 + 16 +  1 + 32 + 1 + 1024,
  DISPLAY_LEN_MIN_5700  = 43,
  DISPLAY_LEN_MAX_5700  = 43,
  DISPLAY_LEN_MIN_5800  = 40 + 1 + 1,
  DISPLAY_LEN_MAX_5800  = 40 + 1 + 16,
  DISPLAY_LEN_MIN_6000  = 40,
  DISPLAY_LEN_MAX_6000  = 40,
  DISPLAY_LEN_MIN_6100  = 128,
  DISPLAY_LEN_MAX_6100  = 128,
  DISPLAY_LEN_MIN_6300  =  6 + 1 + 8 + 22,
  DISPLAY_LEN_MAX_6300  =  6 + 1 + 48 + 22,
  DISPLAY_LEN_MIN_6400  =  9 + 2 + 1 + 16 + 1 + 43,
  DISPLAY_LEN_MAX_6400  =  9 + 2 + 1 + 48 + 1 + 43,
  DISPLAY_LEN_MIN_6500  =  9 + 2 + 1 + 16 + 1 + 86,
  DISPLAY_LEN_MAX_6500  =  9 + 2 + 1 + 48 + 1 + 86,
  DISPLAY_LEN_MIN_6600  =  1 + 1 + 16 + 1 + 2080,
  DISPLAY_LEN_MAX_6600  =  6 + 1 + 16 + 1 + 2080,
  DISPLAY_LEN_MIN_6700  =  7 + 2 + 1 + 16 + 1 + 27,
  DISPLAY_LEN_MAX_6700  =  7 + 2 + 1 + 48 + 1 + 27,
  DISPLAY_LEN_MIN_6800  = 32 + 1 + 1 + 1 + 0,
  DISPLAY_LEN_MAX_6800  = 32 + 1 + 5 + 1 + 32,
  DISPLAY_LEN_MIN_6900  = 64,
  DISPLAY_LEN_MAX_6900  = 64,
  DISPLAY_LEN_MIN_7100  =  4 + 2 + 1 + 64 + 1 + 128,
  DISPLAY_LEN_MAX_7100  =  4 + 5 + 1 + 64 + 1 + 128,
  DISPLAY_LEN_MIN_7200  = 19 + 1 + 1 +   1 + 128,
  DISPLAY_LEN_MAX_7200  = 19 + 5 + 1 + 224 + 128,
  DISPLAY_LEN_MIN_7300  =  64 + 1 + 40,
  DISPLAY_LEN_MAX_7300  = 512 + 1 + 40,
  DISPLAY_LEN_MIN_7400  = 47 + 0,
  DISPLAY_LEN_MAX_7400  = 47 + 16,
  DISPLAY_LEN_MIN_7500  =  1 + 6 + 1 + 2 + 1 +  0 + 1 +  0 + 1 +   0 + 1 + 72 + 32,
  DISPLAY_LEN_MAX_7500  =  1 + 6 + 1 + 2 + 1 + 64 + 1 + 64 + 1 + 128 + 1 + 72 + 32,
  DISPLAY_LEN_MIN_7700  =  1 + 1 + 16,
  DISPLAY_LEN_MAX_7700  = 40 + 1 + 16,
  DISPLAY_LEN_MIN_7800  =  1 + 1 + 40,
  DISPLAY_LEN_MAX_7800  = 40 + 1 + 40,
  DISPLAY_LEN_MIN_7900  =  3 + 1 + 8 + 43,
  DISPLAY_LEN_MAX_7900  =  3 + 1 + 8 + 43,
  DISPLAY_LEN_MIN_8000  =  2 + 4 + 16 + 64,
  DISPLAY_LEN_MAX_8000  =  2 + 4 + 16 + 64,
  DISPLAY_LEN_MIN_8100  =  1 + 8 + 40,
  DISPLAY_LEN_MAX_8100  =  1 + 8 + 40,
  DISPLAY_LEN_MIN_8200  = 64 + 1 + 32 + 1 + 1 + 1 +    1,
  DISPLAY_LEN_MAX_8200  = 64 + 1 + 32 + 1 + 8 + 1 + 2048,
  DISPLAY_LEN_MIN_8300  = 32 + 1 +  1 + 1 +  1 + 1 + 1,
  DISPLAY_LEN_MAX_8300  = 32 + 1 + 32 + 1 + 32 + 1 + 5,
  DISPLAY_LEN_MIN_8400  = 40 + 1 + 40,
  DISPLAY_LEN_MAX_8400  = 40 + 1 + 40,
  DISPLAY_LEN_MIN_8500  =  6 + 1 + 1 + 1 +  1,
  DISPLAY_LEN_MAX_8500  =  6 + 1 + 8 + 1 + 16,
  DISPLAY_LEN_MIN_8600  = 32,
  DISPLAY_LEN_MAX_8600  = 32,
  DISPLAY_LEN_MIN_8700  = 22,
  DISPLAY_LEN_MAX_8700  = 22,
  DISPLAY_LEN_MIN_8800  = 1 + 3 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 3072,
  DISPLAY_LEN_MAX_8800  = 1 + 3 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 3072,
  DISPLAY_LEN_MIN_8900  = 6 + 1 + 1 + 1 + 1 + 1 + 1 + 1 +  0 + 1 + 44,
  DISPLAY_LEN_MAX_8900  = 6 + 1 + 6 + 1 + 2 + 1 + 2 + 1 + 45 + 1 + 44,
  DISPLAY_LEN_MIN_9100  = 51,
  DISPLAY_LEN_MAX_9100  = 51,
  DISPLAY_LEN_MIN_9200  = 3 + 14 + 1 + 43,
  DISPLAY_LEN_MAX_9200  = 3 + 14 + 1 + 43,
  DISPLAY_LEN_MIN_9300  = 3 + 14 + 1 + 43,
  DISPLAY_LEN_MAX_9300  = 3 + 14 + 1 + 43,
  DISPLAY_LEN_MIN_9400  = 8 + 1 + 4 + 1 + 2 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MAX_9400  = 8 + 1 + 4 + 1 + 2 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MIN_9500  = 8 + 1 + 4 + 1 + 6 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 64,
  DISPLAY_LEN_MAX_9500  = 8 + 1 + 4 + 1 + 6 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 64,
  DISPLAY_LEN_MIN_9600  = 8 + 1 + 4 + 1 + 6 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 64,
  DISPLAY_LEN_MAX_9600  = 8 + 1 + 4 + 1 + 6 + 1 + 3 + 1 + 2 + 1 + 32 + 1 + 32 + 1 + 64,
  DISPLAY_LEN_MIN_9700  = 12 + 1 + 32 + 1 + 32 + 1 + 32,
  DISPLAY_LEN_MAX_9700  = 12 + 1 + 32 + 1 + 32 + 1 + 32,
  DISPLAY_LEN_MIN_9720  = 12 + 1 + 32 + 1 + 32 + 1 + 32 + 1 + 10,
  DISPLAY_LEN_MAX_9720  = 12 + 1 + 32 + 1 + 32 + 1 + 32 + 1 + 10,
  DISPLAY_LEN_MIN_9800  = 12 + 1 + 32 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MAX_9800  = 12 + 1 + 32 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MIN_9820  = 12 + 1 + 32 + 1 + 32 + 1 + 40 + 1 + 10,
  DISPLAY_LEN_MAX_9820  = 12 + 1 + 32 + 1 + 32 + 1 + 40 + 1 + 10,
  DISPLAY_LEN_MIN_9900  = 32,
  DISPLAY_LEN_MAX_9900  = 32,
  DISPLAY_LEN_MIN_10000 = 13 + 1 + 1 + 1 +  0 + 44,
  DISPLAY_LEN_MAX_10000 = 13 + 1 + 6 + 1 + 15 + 44,
  DISPLAY_LEN_MIN_10100 = 16 + 1 + 1 + 1 + 1 + 1 + 32,
  DISPLAY_LEN_MAX_10100 = 16 + 1 + 1 + 1 + 1 + 1 + 32,
  DISPLAY_LEN_MIN_10200 = 10 + 12 + 1 + 44,
  DISPLAY_LEN_MAX_10200 = 10 + 76 + 1 + 132,
  DISPLAY_LEN_MIN_10300 = 10 + 1 + 1 + 33,
  DISPLAY_LEN_MAX_10300 = 10 + 5 + 1 + 49,
  DISPLAY_LEN_MIN_10400 = 5 + 1 + 1 + 1 + 1 + 2 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MAX_10400 = 5 + 1 + 1 + 1 + 1 + 2 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MIN_10410 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MAX_10410 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MIN_10420 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64 + 1 + 10,
  DISPLAY_LEN_MAX_10420 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64 + 1 + 10,
  DISPLAY_LEN_MIN_10500 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MAX_10500 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 64 + 1 + 2 + 1 +  64 + 1 + 2 + 1 +  64,
  DISPLAY_LEN_MIN_10600 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 1,
  DISPLAY_LEN_MAX_10600 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 1000,
  DISPLAY_LEN_MIN_10700 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 1,
  DISPLAY_LEN_MAX_10700 = 5 + 1 + 1 + 1 + 1 + 3 + 1 + 5 + 1 + 1 + 1 + 2 + 1 + 32 + 1 + 1000,
  DISPLAY_LEN_MIN_10800 = 96,
  DISPLAY_LEN_MAX_10800 = 96,
  DISPLAY_LEN_MIN_10900 = 7 + 1 + 1 +  0 + 1 + 24,
  DISPLAY_LEN_MAX_10900 = 7 + 6 + 1 + 64 + 1 + 88,
  DISPLAY_LEN_MIN_11000 = 32 + 1 + 56,
  DISPLAY_LEN_MAX_11000 = 32 + 1 + 56,
  DISPLAY_LEN_MIN_11100 = 10 +  0 + 1 + 8 + 1 + 32,
  DISPLAY_LEN_MAX_11100 = 10 + 32 + 1 + 8 + 1 + 32,
  DISPLAY_LEN_MIN_11200 = 9 + 40 + 1 + 40,
  DISPLAY_LEN_MAX_11200 = 9 + 40 + 1 + 40,
  DISPLAY_LEN_MIN_11300 = 1 + 7 + 1 + 2 + 1 + 96 + 1 + 2 + 1 + 16 + 1 + 1 + 1 + 2 + 1 + 96 + 1 + 1 + 1 + 2,
  DISPLAY_LEN_MAX_11300 = 1 + 7 + 1 + 2 + 1 + 96 + 1 + 2 + 1 + 16 + 1 + 6 + 1 + 2 + 1 + 96 + 1 + 3 + 1 + 512,
  DISPLAY_LEN_MIN_11400 = 6 +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   1 + 1 +   0 + 1 +  1 + 1 +  0 + 1 +  0 + 1 +  0 + 1 + 3 + 1 + 32,
  DISPLAY_LEN_MAX_11400 = 6 + 512 + 1 + 512 + 1 + 116 + 1 + 116 + 1 + 246 + 1 + 245 + 1 + 246 + 1 + 245 + 1 + 50 + 1 + 50 + 1 + 50 + 1 + 50 + 1 + 3 + 1 + 32,
  DISPLAY_LEN_MIN_11500 = 8 + 1 + 8,
  DISPLAY_LEN_MAX_11500 = 8 + 1 + 8,
  DISPLAY_LEN_MIN_11600 = 1 + 2 + 1 + 1 + 1 + 1 + 1 + 1 + 1 +  0 + 1 + 1 + 1 + 32 + 1 +  1 + 1 + 1 + 1 + 1 + 1 +   2,
  DISPLAY_LEN_MAX_11600 = 1 + 2 + 1 + 1 + 1 + 2 + 1 + 1 + 1 + 64 + 1 + 1 + 1 + 32 + 1 + 10 + 1 + 3 + 1 + 3 + 1 + 768,
  DISPLAY_LEN_MIN_11700 = 64,
  DISPLAY_LEN_MAX_11700 = 64,
  DISPLAY_LEN_MIN_11800 = 128,
  DISPLAY_LEN_MAX_11800 = 128,
  DISPLAY_LEN_MIN_11900 = 3 + 1 + 1 +  0 + 1 + 12,
  DISPLAY_LEN_MAX_11900 = 3 + 6 + 1 + 64 + 1 + 88,
  DISPLAY_LEN_MIN_12000 = 4 + 1 + 1 +  0 + 1 + 16,
  DISPLAY_LEN_MAX_12000 = 4 + 6 + 1 + 64 + 1 + 88,
  DISPLAY_LEN_MIN_12100 = 6 + 1 + 1 +  0 + 1 + 16,
  DISPLAY_LEN_MAX_12100 = 6 + 6 + 1 + 64 + 1 + 88,
  DISPLAY_LEN_MIN_12200 = 1 + 8 + 1 + 1 + 1 + 1 + 1 + 16 + 1 + 16,
  DISPLAY_LEN_MAX_12200 = 1 + 8 + 1 + 1 + 1 + 1 + 1 + 16 + 1 + 16,
  DISPLAY_LEN_MIN_12300 = 160,
  DISPLAY_LEN_MAX_12300 = 160,
  DISPLAY_LEN_MIN_12400 = 1 + 4 + 4 + 11,
  DISPLAY_LEN_MAX_12400 = 1 + 4 + 4 + 11,
  DISPLAY_LEN_MIN_12500 = 6 + 1 + 1 + 1 + 16 + 1 + 32,
  DISPLAY_LEN_MAX_12500 = 6 + 1 + 1 + 1 + 16 + 1 + 32,
  DISPLAY_LEN_MIN_12600 = 64 + 1 + 64,
  DISPLAY_LEN_MAX_12600 = 64 + 1 + 64,
  DISPLAY_LEN_MIN_12700 =  1 + 10 + 1 + 1 + 1 + 64,
  DISPLAY_LEN_MAX_12700 =  1 + 10 + 1 + 5 + 1 + 20000,
  DISPLAY_LEN_MIN_12800 = 11 + 1 + 20 + 1 + 1 + 1 + 64,
  DISPLAY_LEN_MAX_12800 = 11 + 1 + 20 + 1 + 5 + 1 + 64,
  DISPLAY_LEN_MIN_12900 = 64 + 64 + 32,
  DISPLAY_LEN_MAX_12900 = 64 + 64 + 32,
  DISPLAY_LEN_MIN_13000 = 1 + 4 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 1 + 1 + 16,
  DISPLAY_LEN_MAX_13000 = 1 + 4 + 1 + 2 + 1 + 32 + 1 + 2 + 1 + 32 + 1 + 1 + 1 + 16,
  DISPLAY_LEN_MIN_13100 =  1 + 7 + 1 + 2 + 1 + 0 + 0 + 32 + 1 + 64,
  DISPLAY_LEN_MAX_13100 =  1 + 7 + 1 + 2 + 1 + 2 + 512 + 1 + 32 + 1 + 20480,
  DISPLAY_LEN_MIN_13200 =  1 + 7 + 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 48,
  DISPLAY_LEN_MAX_13200 =  1 + 7 + 1 + 1 + 1 + 1 + 50 + 1 + 32 + 1 + 48 + 1 + 20480,
  DISPLAY_LEN_MIN_13300 =  1 + 12 + 1 + 32,
  DISPLAY_LEN_MAX_13300 =  1 + 12 + 1 + 40,
  DISPLAY_LEN_MIN_13400 =  1 + 7 + 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 64 + 1 + 32 + 1 + 64 + 1 + 1 + 1 + 1,
  DISPLAY_LEN_MAX_13400 =  1 + 7 + 1 + 1 + 10 + 1 + 3 + 1 + 64 + 1 + 64 + 1 + 32 + 1 + 64 + 1 + 4 + 1 + 600000 + 1 + 2 + 1 + 64,
  DISPLAY_LEN_MIN_13500 = 40 + 1 + 32,
  DISPLAY_LEN_MAX_13500 = 40 + 1 + 1024,
  DISPLAY_LEN_MIN_13600 = 6 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 16 + 1 + 1 + 1 + 1 + 1 +    0 + 1 + 20 + 1 + 7,
  DISPLAY_LEN_MAX_13600 = 6 + 1 + 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 4 + 1 + 4 + 1 + 8192 + 1 + 20 + 1 + 7,
  DISPLAY_LEN_MIN_13800 =  64 + 1 + 256,
  DISPLAY_LEN_MAX_13800 =  64 + 1 + 256,
  DISPLAY_LEN_MIN_13900 = 40 + 1 + 9,
  DISPLAY_LEN_MAX_13900 = 40 + 1 + 9,
  DISPLAY_LEN_MIN_14000 = 16 + 1 + 16,
  DISPLAY_LEN_MAX_14000 = 16 + 1 + 16,
  DISPLAY_LEN_MIN_14100 = 16 + 1 + 16,
  DISPLAY_LEN_MAX_14100 = 16 + 1 + 16,
  DISPLAY_LEN_MIN_14400 = 40 + 1 + 20,
  DISPLAY_LEN_MAX_14400 = 40 + 1 + 20,
  DISPLAY_LEN_MIN_99999 = 1,
  DISPLAY_LEN_MAX_99999 = 55,

  DISPLAY_LEN_MIN_11    = 32 + 1 + 16,
  DISPLAY_LEN_MAX_11    = 32 + 1 + 32,
  DISPLAY_LEN_MIN_11H   = 32 + 1 + 32,
  DISPLAY_LEN_MAX_11H   = 32 + 1 + 64,
  DISPLAY_LEN_MIN_12    = 32 + 1 + 1,
  DISPLAY_LEN_MAX_12    = 32 + 1 + 32,
  DISPLAY_LEN_MIN_12H   = 32 + 1 + 2,
  DISPLAY_LEN_MAX_12H   = 32 + 1 + 64,
  DISPLAY_LEN_MIN_21    = 32 + 1 + 1,
  DISPLAY_LEN_MAX_21    = 32 + 1 + 15,
  DISPLAY_LEN_MIN_21H   = 32 + 1 + 2,
  DISPLAY_LEN_MAX_21H   = 32 + 1 + 30,
  DISPLAY_LEN_MIN_22    = 30 + 1 + 1,
  DISPLAY_LEN_MAX_22    = 30 + 1 + 28,
  DISPLAY_LEN_MIN_22H   = 30 + 1 + 2,
  DISPLAY_LEN_MAX_22H   = 30 + 1 + 56,
  DISPLAY_LEN_MIN_23    = 32 + 1 + 0,
  DISPLAY_LEN_MAX_23    = 32 + 1 + 23,
  DISPLAY_LEN_MIN_101   =  5 + 28,
  DISPLAY_LEN_MAX_101   =  5 + 28,
  DISPLAY_LEN_MIN_111   =  6 + 28 + 0,
  DISPLAY_LEN_MAX_111   =  6 + 28 + 40,
  DISPLAY_LEN_MIN_112   = 40 + 1 + 20,
  DISPLAY_LEN_MAX_112   = 40 + 1 + 20,
  DISPLAY_LEN_MIN_121   = 40 + 1 + 1,
  DISPLAY_LEN_MAX_121   = 40 + 1 + 32,
  DISPLAY_LEN_MIN_121H  = 40 + 1 + 2,
  DISPLAY_LEN_MAX_121H  = 40 + 1 + 64,
  DISPLAY_LEN_MIN_122   =  8 + 40,
  DISPLAY_LEN_MAX_122   =  8 + 40,
  DISPLAY_LEN_MIN_124   = 4 + 1 +  0 + 1 + 40,
  DISPLAY_LEN_MAX_124   = 4 + 1 + 32 + 1 + 40,
  DISPLAY_LEN_MIN_125   = 10 + 40,
  DISPLAY_LEN_MAX_125   = 10 + 40,
  DISPLAY_LEN_MIN_131   =  6 +  8 + 80,
  DISPLAY_LEN_MAX_131   =  6 +  8 + 80,
  DISPLAY_LEN_MIN_132   =  6 +  8 + 40,
  DISPLAY_LEN_MAX_132   =  6 +  8 + 40,
  DISPLAY_LEN_MIN_133   = 28,
  DISPLAY_LEN_MAX_133   = 28,
  DISPLAY_LEN_MIN_141   = 14 +  0 +  1 + 28,
  DISPLAY_LEN_MAX_141   = 14 + 44 +  1 + 28,
  DISPLAY_LEN_MIN_1441  = 14 +  0 +  1 + 43,
  DISPLAY_LEN_MAX_1441  = 14 + 24 +  1 + 43,
  DISPLAY_LEN_MIN_1711  =  9 + 86 +  0,
  DISPLAY_LEN_MAX_1711  =  9 + 86 + 68,
  DISPLAY_LEN_MIN_1722  =  8 + 128,
  DISPLAY_LEN_MAX_1722  =  8 + 128,
  DISPLAY_LEN_MIN_2611  = 32 + 1 + 0,
  DISPLAY_LEN_MAX_2611  = 32 + 1 + 23,
  DISPLAY_LEN_MIN_2611H = 32 + 1 + 0,
  DISPLAY_LEN_MIN_2612  = 6 +  0 + 1 + 32,
  DISPLAY_LEN_MAX_2611H = 32 + 1 + 46,
  DISPLAY_LEN_MAX_2612  = 6 + 46 + 1 + 32,
  DISPLAY_LEN_MIN_2711  = 32 + 1 + 23,
  DISPLAY_LEN_MAX_2711  = 32 + 1 + 31,
  DISPLAY_LEN_MIN_2711H = 32 + 1 + 46,
  DISPLAY_LEN_MAX_2711H = 32 + 1 + 62,
  DISPLAY_LEN_MIN_2811  = 32 + 1 + 0,
  DISPLAY_LEN_MAX_2811  = 32 + 1 + 31,
  DISPLAY_LEN_MIN_2811H = 32 + 1 + 0,
  DISPLAY_LEN_MAX_2811H = 32 + 1 + 62,
  DISPLAY_LEN_MIN_7600  = 40 + 1 + 32,
  DISPLAY_LEN_MAX_7600  = 40 + 1 + 32,

} display_len_t;

typedef enum hash_type
{
  HASH_TYPE_MD4                 = 1,
  HASH_TYPE_MD5                 = 2,
  HASH_TYPE_MD5H                = 3,
  HASH_TYPE_SHA1                = 4,
  HASH_TYPE_SHA224              = 5,
  HASH_TYPE_SHA256              = 6,
  HASH_TYPE_SHA384              = 7,
  HASH_TYPE_SHA512              = 8,
  HASH_TYPE_DCC2                = 9,
  HASH_TYPE_WPA                 = 10,
  HASH_TYPE_LM                  = 11,
  HASH_TYPE_DESCRYPT            = 12,
  HASH_TYPE_ORACLEH             = 13,
  HASH_TYPE_DESRACF             = 14,
  HASH_TYPE_BCRYPT              = 15,
  HASH_TYPE_KECCAK              = 16,
  HASH_TYPE_NETNTLM             = 17,
  HASH_TYPE_RIPEMD160           = 18,
  HASH_TYPE_WHIRLPOOL           = 19,
  HASH_TYPE_AES                 = 20,
  HASH_TYPE_GOST                = 21,
  HASH_TYPE_KRB5PA              = 22,
  HASH_TYPE_SAPB                = 23,
  HASH_TYPE_SAPG                = 24,
  HASH_TYPE_MYSQL               = 25,
  HASH_TYPE_LOTUS5              = 26,
  HASH_TYPE_LOTUS6              = 27,
  HASH_TYPE_ANDROIDFDE          = 28,
  HASH_TYPE_SCRYPT              = 29,
  HASH_TYPE_LOTUS8              = 30,
  HASH_TYPE_OFFICE2007          = 31,
  HASH_TYPE_OFFICE2010          = 32,
  HASH_TYPE_OFFICE2013          = 33,
  HASH_TYPE_OLDOFFICE01         = 34,
  HASH_TYPE_OLDOFFICE34         = 35,
  HASH_TYPE_SIPHASH             = 36,
  HASH_TYPE_PDFU16              = 37,
  HASH_TYPE_PDFU32              = 38,
  HASH_TYPE_PBKDF2_SHA256       = 39,
  HASH_TYPE_BITCOIN_WALLET      = 40,
  HASH_TYPE_CRC32               = 41,
  HASH_TYPE_GOST_2012SBOG_256   = 42,
  HASH_TYPE_GOST_2012SBOG_512   = 43,
  HASH_TYPE_PBKDF2_MD5          = 44,
  HASH_TYPE_PBKDF2_SHA1         = 45,
  HASH_TYPE_PBKDF2_SHA512       = 46,
  HASH_TYPE_ECRYPTFS            = 47,
  HASH_TYPE_ORACLET             = 48,
  HASH_TYPE_BSDICRYPT           = 49,
  HASH_TYPE_RAR3HP              = 50,
  HASH_TYPE_KRB5TGS             = 51,
  HASH_TYPE_STDOUT              = 52,
  HASH_TYPE_DES                 = 53,
  HASH_TYPE_PLAINTEXT           = 54,

} hash_type_t;

typedef enum kern_type
{
  KERN_TYPE_MD5                 = 0,
  KERN_TYPE_MD5_PWSLT           = 10,
  KERN_TYPE_MD5_SLTPW           = 20,
  KERN_TYPE_MD5_PWUSLT          = 30,
  KERN_TYPE_MD5_SLTPWU          = 40,
  KERN_TYPE_HMACMD5_PW          = 50,
  KERN_TYPE_HMACMD5_SLT         = 60,
  KERN_TYPE_SHA1                = 100,
  KERN_TYPE_SHA1_PWSLT          = 110,
  KERN_TYPE_SHA1_SLTPW          = 120,
  KERN_TYPE_SHA1_PWUSLT         = 130,
  KERN_TYPE_SHA1_SLTPWU         = 140,
  KERN_TYPE_HMACSHA1_PW         = 150,
  KERN_TYPE_HMACSHA1_SLT        = 160,
  KERN_TYPE_MYSQL               = 200,
  KERN_TYPE_MYSQL41             = 300,
  KERN_TYPE_PHPASS              = 400,
  KERN_TYPE_MD5CRYPT            = 500,
  KERN_TYPE_MD4                 = 900,
  KERN_TYPE_MD4_PWU             = 1000,
  KERN_TYPE_MD44_PWUSLT         = 1100,
  KERN_TYPE_SHA224              = 1300,
  KERN_TYPE_SHA256              = 1400,
  KERN_TYPE_SHA256_PWSLT        = 1410,
  KERN_TYPE_SHA256_SLTPW        = 1420,
  KERN_TYPE_SHA256_PWUSLT       = 1430,
  KERN_TYPE_SHA256_SLTPWU       = 1440,
  KERN_TYPE_HMACSHA256_PW       = 1450,
  KERN_TYPE_HMACSHA256_SLT      = 1460,
  KERN_TYPE_DESCRYPT            = 1500,
  KERN_TYPE_APR1CRYPT           = 1600,
  KERN_TYPE_SHA512              = 1700,
  KERN_TYPE_SHA512_PWSLT        = 1710,
  KERN_TYPE_SHA512_SLTPW        = 1720,
  KERN_TYPE_SHA512_PWSLTU       = 1730,
  KERN_TYPE_SHA512_SLTPWU       = 1740,
  KERN_TYPE_HMACSHA512_PW       = 1750,
  KERN_TYPE_HMACSHA512_SLT      = 1760,
  KERN_TYPE_SHA512CRYPT         = 1800,
  KERN_TYPE_STDOUT              = 2000,
  KERN_TYPE_DCC2                = 2100,
  KERN_TYPE_MD5PIX              = 2400,
  KERN_TYPE_MD5ASA              = 2410,
  KERN_TYPE_WPA                 = 2500,
  KERN_TYPE_MD55                = 2600,
  KERN_TYPE_MD55_PWSLT1         = 2610,
  KERN_TYPE_MD55_PWSLT2         = 2710,
  KERN_TYPE_MD55_SLTPW          = 2810,
  KERN_TYPE_LM                  = 3000,
  KERN_TYPE_ORACLEH             = 3100,
  KERN_TYPE_BCRYPT              = 3200,
  KERN_TYPE_MD5_SLT_MD5_PW      = 3710,
  KERN_TYPE_MD5_SLT_PW_SLT      = 3800,
  KERN_TYPE_MD5U5               = 4300,
  KERN_TYPE_MD5U5_PWSLT1        = 4310,
  KERN_TYPE_MD5_SHA1            = 4400,
  KERN_TYPE_SHA11               = 4500,
  KERN_TYPE_SHA1_MD5            = 4700,
  KERN_TYPE_MD5_CHAP            = 4800,
  KERN_TYPE_SHA1_SLT_PW_SLT     = 4900,
  KERN_TYPE_KECCAK              = 5000,
  KERN_TYPE_MD5H                = 5100,
  KERN_TYPE_PSAFE3              = 5200,
  KERN_TYPE_IKEPSK_MD5          = 5300,
  KERN_TYPE_IKEPSK_SHA1         = 5400,
  KERN_TYPE_NETNTLMv1           = 5500,
  KERN_TYPE_NETNTLMv2           = 5600,
  KERN_TYPE_ANDROIDPIN          = 5800,
  KERN_TYPE_RIPEMD160           = 6000,
  KERN_TYPE_WHIRLPOOL           = 6100,
  KERN_TYPE_TCRIPEMD160_XTS512  = 6211,
  KERN_TYPE_TCRIPEMD160_XTS1024 = 6212,
  KERN_TYPE_TCRIPEMD160_XTS1536 = 6213,
  KERN_TYPE_TCSHA512_XTS512     = 6221,
  KERN_TYPE_TCSHA512_XTS1024    = 6222,
  KERN_TYPE_TCSHA512_XTS1536    = 6223,
  KERN_TYPE_TCWHIRLPOOL_XTS512  = 6231,
  KERN_TYPE_TCWHIRLPOOL_XTS1024 = 6232,
  KERN_TYPE_TCWHIRLPOOL_XTS1536 = 6233,
  KERN_TYPE_VCSHA256_XTS512     = 13751,
  KERN_TYPE_VCSHA256_XTS1024    = 13752,
  KERN_TYPE_VCSHA256_XTS1536    = 13753,
  KERN_TYPE_MD5AIX              = 6300,
  KERN_TYPE_SHA256AIX           = 6400,
  KERN_TYPE_SHA512AIX           = 6500,
  KERN_TYPE_AGILEKEY            = 6600,
  KERN_TYPE_SHA1AIX             = 6700,
  KERN_TYPE_LASTPASS            = 6800,
  KERN_TYPE_GOST                = 6900,
  KERN_TYPE_PBKDF2_SHA512       = 7100,
  KERN_TYPE_RAKP                = 7300,
  KERN_TYPE_SHA256CRYPT         = 7400,
  KERN_TYPE_KRB5PA              = 7500,
  KERN_TYPE_SHA1_SLT_SHA1_PW    = 7600,
  KERN_TYPE_SAPB                = 7700,
  KERN_TYPE_SAPG                = 7800,
  KERN_TYPE_DRUPAL7             = 7900,
  KERN_TYPE_SYBASEASE           = 8000,
  KERN_TYPE_NETSCALER           = 8100,
  KERN_TYPE_CLOUDKEY            = 8200,
  KERN_TYPE_NSEC3               = 8300,
  KERN_TYPE_WBB3                = 8400,
  KERN_TYPE_RACF                = 8500,
  KERN_TYPE_LOTUS5              = 8600,
  KERN_TYPE_LOTUS6              = 8700,
  KERN_TYPE_ANDROIDFDE          = 8800,
  KERN_TYPE_SCRYPT              = 8900,
  KERN_TYPE_PSAFE2              = 9000,
  KERN_TYPE_LOTUS8              = 9100,
  KERN_TYPE_OFFICE2007          = 9400,
  KERN_TYPE_OFFICE2010          = 9500,
  KERN_TYPE_OFFICE2013          = 9600,
  KERN_TYPE_OLDOFFICE01         = 9700,
  KERN_TYPE_OLDOFFICE01CM1      = 9710,
  KERN_TYPE_OLDOFFICE01CM2      = 9720,
  KERN_TYPE_OLDOFFICE34         = 9800,
  KERN_TYPE_OLDOFFICE34CM1      = 9810,
  KERN_TYPE_OLDOFFICE34CM2      = 9820,
  KERN_TYPE_RADMIN2             = 9900,
  KERN_TYPE_SIPHASH             = 10100,
  KERN_TYPE_SAPH_SHA1           = 10300,
  KERN_TYPE_PDF11               = 10400,
  KERN_TYPE_PDF11CM1            = 10410,
  KERN_TYPE_PDF11CM2            = 10420,
  KERN_TYPE_PDF14               = 10500,
  KERN_TYPE_PDF17L8             = 10700,
  KERN_TYPE_SHA384              = 10800,
  KERN_TYPE_PBKDF2_SHA256       = 10900,
  KERN_TYPE_PRESTASHOP          = 11000,
  KERN_TYPE_POSTGRESQL_AUTH     = 11100,
  KERN_TYPE_MYSQL_AUTH          = 11200,
  KERN_TYPE_BITCOIN_WALLET      = 11300,
  KERN_TYPE_SIP_AUTH            = 11400,
  KERN_TYPE_CRC32               = 11500,
  KERN_TYPE_SEVEN_ZIP           = 11600,
  KERN_TYPE_GOST_2012SBOG_256   = 11700,
  KERN_TYPE_GOST_2012SBOG_512   = 11800,
  KERN_TYPE_PBKDF2_MD5          = 11900,
  KERN_TYPE_PBKDF2_SHA1         = 12000,
  KERN_TYPE_ECRYPTFS            = 12200,
  KERN_TYPE_ORACLET             = 12300,
  KERN_TYPE_BSDICRYPT           = 12400,
  KERN_TYPE_RAR3                = 12500,
  KERN_TYPE_CF10                = 12600,
  KERN_TYPE_MYWALLET            = 12700,
  KERN_TYPE_MS_DRSR             = 12800,
  KERN_TYPE_ANDROIDFDE_SAMSUNG  = 12900,
  KERN_TYPE_RAR5                = 13000,
  KERN_TYPE_KRB5TGS             = 13100,
  KERN_TYPE_AXCRYPT             = 13200,
  KERN_TYPE_SHA1_AXCRYPT        = 13300,
  KERN_TYPE_KEEPASS             = 13400,
  KERN_TYPE_PSTOKEN             = 13500,
  KERN_TYPE_ZIP2                = 13600,
  KERN_TYPE_WIN8PHONE           = 13800,
  KERN_TYPE_OPENCART            = 13900,
  KERN_TYPE_DES                 = 14000,
  KERN_TYPE_3DES                = 14100,
  KERN_TYPE_SHA1CX              = 14400,
  KERN_TYPE_PLAINTEXT           = 99999,

} kern_type_t;

/**
 * Default iteration numbers
 */

typedef enum rounds_count
{
   ROUNDS_PHPASS             = (1 << 11), // $P$B
   ROUNDS_DCC2               = 10240,
   ROUNDS_WPA2               = 4096,
   ROUNDS_BCRYPT             = (1 << 5),
   ROUNDS_PSAFE3             = 2048,
   ROUNDS_ANDROIDPIN         = 1024,
   ROUNDS_TRUECRYPT_1K       = 1000,
   ROUNDS_TRUECRYPT_2K       = 2000,
   ROUNDS_VERACRYPT_200000   = 200000,
   ROUNDS_VERACRYPT_500000   = 500000,
   ROUNDS_VERACRYPT_327661   = 327661,
   ROUNDS_VERACRYPT_655331   = 655331,
   ROUNDS_SHA1AIX            = (1 << 6),
   ROUNDS_SHA256AIX          = (1 << 6),
   ROUNDS_SHA512AIX          = (1 << 6),
   ROUNDS_MD5CRYPT           = 1000,
   ROUNDS_SHA256CRYPT        = 5000,
   ROUNDS_SHA512CRYPT        = 5000,
   ROUNDS_GRUB               = 10000,
   ROUNDS_SHA512OSX          = 35000,
   ROUNDS_AGILEKEY           = 1000,
   ROUNDS_LASTPASS           = 500,
   ROUNDS_DRUPAL7            = (1 << 14), // $S$C
   ROUNDS_CLOUDKEY           = 40000,
   ROUNDS_NSEC3              = 1,
   ROUNDS_ANDROIDFDE         = 2000,
   ROUNDS_PSAFE2             = 1000,
   ROUNDS_LOTUS8             = 5000,
   ROUNDS_CISCO8             = 20000,
   ROUNDS_OFFICE2007         = 50000,
   ROUNDS_OFFICE2010         = 100000,
   ROUNDS_OFFICE2013         = 100000,
   ROUNDS_DJANGOPBKDF2       = 20000,
   ROUNDS_SAPH_SHA1          = 1024,
   ROUNDS_PDF14              = (50 + 20),
   ROUNDS_PDF17L8            = 64,
   ROUNDS_PBKDF2_SHA256      = 1000,
   ROUNDS_BITCOIN_WALLET     = 200000,
   ROUNDS_SEVEN_ZIP          = (1 << 19),
   ROUNDS_PBKDF2_MD5         = 1000,
   ROUNDS_PBKDF2_SHA1        = 1000,
   ROUNDS_PBKDF2_SHA512      = 1000,
   ROUNDS_ECRYPTFS           = 65536,
   ROUNDS_ORACLET            = 4096,
   ROUNDS_BSDICRYPT          = 2900,
   ROUNDS_RAR3               = 262144,
   ROUNDS_MYWALLET           = 10,
   ROUNDS_MS_DRSR            = 100,
   ROUNDS_ANDROIDFDE_SAMSUNG = 4096,
   ROUNDS_RAR5               = (1 << 15),
   ROUNDS_AXCRYPT            = 10000,
   ROUNDS_KEEPASS            = 6000,
   ROUNDS_ZIP2               = 1000,
   ROUNDS_STDOUT             = 0

} rounds_count_t;

/**
 * input functions
 */

int bcrypt_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int cisco4_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int dcc_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int dcc2_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int descrypt_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int des_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int episerver_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int ipb2_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int joomla_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int postgresql_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int netscreen_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int keccak_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int lm_parse_hash                 (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md4_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5s_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5half_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5md5_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5pix_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5asa_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5apr1_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5crypt_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int mssql2000_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int mssql2005_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int netntlmv1_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int netntlmv2_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oracleh_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oracles_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oraclet_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int osc_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int arubaos_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int osx1_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int osx512_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int phpass_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha1_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha1b64_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha1b64s_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha1s_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha224_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha256_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha256s_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha384_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha512_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha512s_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha512crypt_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int smf_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int vb3_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int vb30_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int wpa_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int psafe2_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int psafe3_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int ikepsk_md5_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int ikepsk_sha1_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int androidpin_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int ripemd160_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int whirlpool_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int truecrypt_parse_hash_1k       (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int truecrypt_parse_hash_2k       (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int md5aix_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha256aix_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha512aix_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int agilekey_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha1aix_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int lastpass_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int gost_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha256crypt_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int mssql2012_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha512osx_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int episerver4_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha512grub_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha512b64s_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int hmacsha1_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int hmacsha256_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int hmacsha512_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int hmacmd5_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int krb5pa_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int krb5tgs_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sapb_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sapg_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int drupal7_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sybasease_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int mysql323_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int rakp_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int netscaler_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int chap_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int cloudkey_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int nsec3_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int wbb3_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int racf_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int lotus5_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int lotus6_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int lotus8_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int hmailserver_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int phps_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int mediawiki_b_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int peoplesoft_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int skype_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int androidfde_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int scrypt_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int juniper_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int cisco8_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int cisco9_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int office2007_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int office2010_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int office2013_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oldoffice01_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oldoffice01cm1_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oldoffice01cm2_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oldoffice34_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oldoffice34cm1_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int oldoffice34cm2_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int radmin2_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int djangosha1_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int djangopbkdf2_parse_hash       (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int siphash_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int crammd5_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int saph_sha1_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int redmine_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pdf11_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pdf11cm1_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pdf11cm2_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pdf14_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pdf17l3_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pdf17l8_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pbkdf2_sha256_parse_hash      (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int prestashop_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int postgresql_auth_parse_hash    (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int mysql_auth_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int bitcoin_wallet_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sip_auth_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int crc32_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int seven_zip_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int gost2012sbog_256_parse_hash   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int gost2012sbog_512_parse_hash   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pbkdf2_md5_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pbkdf2_sha1_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pbkdf2_sha512_parse_hash      (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int ecryptfs_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int bsdicrypt_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int rar3hp_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int rar5_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int cf10_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int mywallet_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int ms_drsr_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int androidfde_samsung_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int axcrypt_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha1axcrypt_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int keepass_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int pstoken_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int zip2_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int veracrypt_parse_hash_200000   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int veracrypt_parse_hash_500000   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int veracrypt_parse_hash_327661   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int veracrypt_parse_hash_655331   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int win8phone_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int opencart_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int plaintext_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);
int sha1cx_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED const hashconfig_t *hashconfig);

/**
 * output functions
 */

char *stroptitype (const u32 opti_type);
char *strhashtype (const u32 hash_mode);
char *strparser   (const u32 parser_status);

void to_hccap_t (hashcat_ctx_t *hashcat_ctx, hccap_t *hccap, const u32 salt_pos, const u32 digest_pos);

void wpa_essid_reuse (hashcat_ctx_t *hashcat_ctx);

int ascii_digest (hashcat_ctx_t *hashcat_ctx, char *out_buf, const size_t out_len, const u32 salt_pos, const u32 digest_pos);

int     hashconfig_init               (hashcat_ctx_t *hashcat_ctx);
void    hashconfig_destroy            (hashcat_ctx_t *hashcat_ctx);
u32     hashconfig_get_kernel_threads (hashcat_ctx_t *hashcat_ctx, const hc_device_param_t *device_param);
u32     hashconfig_get_kernel_loops   (hashcat_ctx_t *hashcat_ctx);
int     hashconfig_general_defaults   (hashcat_ctx_t *hashcat_ctx);
void    hashconfig_benchmark_defaults (hashcat_ctx_t *hashcat_ctx, salt_t *salt, void *esalt);
char   *hashconfig_benchmark_mask     (hashcat_ctx_t *hashcat_ctx);

#endif // _INTERFACE_H
