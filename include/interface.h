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
#include <inttypes.h>

/**
 * zero hashes shutcut
 */

static const char LM_ZERO_HASH[]    = "aad3b435b51404ee";
static const char LM_MASKED_PLAIN[] = "[notfound]";

/**
 * entropy check (truecrypt, veracrypt, ...)
 */

static const float MIN_SUFFICIENT_ENTROPY_FILE = 7.0f;

/**
 * algo specific
 */

// original headers from luks.h

#define LUKS_CIPHERNAME_L 32
#define LUKS_CIPHERMODE_L 32
#define LUKS_HASHSPEC_L 32
#define LUKS_DIGESTSIZE 20 // since SHA1
#define LUKS_HMACSIZE 32
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8
// Minimal number of iterations
#define LUKS_MKD_ITERATIONS_MIN  1000
#define LUKS_SLOT_ITERATIONS_MIN 1000
#define LUKS_KEY_DISABLED_OLD 0
#define LUKS_KEY_ENABLED_OLD 0xCAFE
#define LUKS_KEY_DISABLED 0x0000DEAD
#define LUKS_KEY_ENABLED  0x00AC71F3
#define LUKS_STRIPES 4000
// partition header starts with magic
#define LUKS_MAGIC {'L','U','K','S', 0xba, 0xbe};
#define LUKS_MAGIC_L 6
/* Actually we need only 37, but we don't want struct autoaligning to kick in */
#define UUID_STRING_L 40
/* Offset to keyslot area [in bytes] */
#define LUKS_ALIGN_KEYSLOTS 4096

struct luks_phdr {
  char      magic[LUKS_MAGIC_L];
  uint16_t  version;
  char      cipherName[LUKS_CIPHERNAME_L];
  char      cipherMode[LUKS_CIPHERMODE_L];
  char      hashSpec[LUKS_HASHSPEC_L];
  uint32_t  payloadOffset;
  uint32_t  keyBytes;
  char      mkDigest[LUKS_DIGESTSIZE];
  char      mkDigestSalt[LUKS_SALTSIZE];
  uint32_t  mkDigestIterations;
  char      uuid[UUID_STRING_L];
  struct {
    uint32_t active;
    /* parameters used for password processing */
    uint32_t passwordIterations;
    char     passwordSalt[LUKS_SALTSIZE];
    /* parameters used for AF store/load */
    uint32_t keyMaterialOffset;
    uint32_t stripes;
  } keyblock[LUKS_NUMKEYS];
  /* Align it to 512 sector size */
  char       _padding[432];
};

// not from original headers start with hc_

typedef enum hc_luks_hash_type
{
  HC_LUKS_HASH_TYPE_SHA1      = 1,
  HC_LUKS_HASH_TYPE_SHA256    = 2,
  HC_LUKS_HASH_TYPE_SHA512    = 3,
  HC_LUKS_HASH_TYPE_RIPEMD160 = 4,
  HC_LUKS_HASH_TYPE_WHIRLPOOL = 5,

} hc_luks_hash_type_t;

typedef enum hc_luks_key_size
{
  HC_LUKS_KEY_SIZE_128 = 128,
  HC_LUKS_KEY_SIZE_256 = 256,
  HC_LUKS_KEY_SIZE_512 = 512,

} hc_luks_key_size_t;

typedef enum hc_luks_cipher_type
{
  HC_LUKS_CIPHER_TYPE_AES     = 1,
  HC_LUKS_CIPHER_TYPE_SERPENT = 2,
  HC_LUKS_CIPHER_TYPE_TWOFISH = 3,

} hc_luks_cipher_type_t;

typedef enum hc_luks_cipher_mode
{
  HC_LUKS_CIPHER_MODE_CBC_ESSIV = 1,
  HC_LUKS_CIPHER_MODE_CBC_PLAIN = 2,
  HC_LUKS_CIPHER_MODE_XTS_PLAIN = 3,

} hc_luks_cipher_mode_t;

typedef struct luks
{
  int hash_type;    // hc_luks_hash_type_t
  int key_size;     // hc_luks_key_size_t
  int cipher_type;  // hc_luks_cipher_type_t
  int cipher_mode;  // hc_luks_cipher_mode_t

  u32 ct_buf[128];

  u32 af_src_buf[((HC_LUKS_KEY_SIZE_512 / 8) * LUKS_STRIPES) / 4];

} luks_t;

typedef struct itunes_backup
{
  u32 wpky[10];
  u32 dpsl[5];

} itunes_backup_t;

typedef struct blake2
{
  u64 h[8];
  u64 t[2];
  u64 f[2];
  u32 buflen;
  u32 outlen;

} blake2_t;

typedef struct chacha20
{
  u32 iv[2];
  u32 plain[2];
  u32 position[2];
  u32 offset;

} chacha20_t;

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

typedef struct wpa_eapol
{
  u32  pke[32];
  u32  eapol[64 + 16];
  u16  eapol_len;
  u8   message_pair;
  int  message_pair_chgd;
  u8   keyver;
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   orig_nonce_ap[32];
  u8   orig_nonce_sta[32];
  u8   essid_len;
  u8   essid[32];
  u32  keymic[4];
  u32  hash[4];
  int  nonce_compare;
  int  nonce_error_corrections;
  int  detected_le;
  int  detected_be;

} wpa_eapol_t;

typedef struct wpa_pmkid
{
  u32  pmkid[4];
  u32  pmkid_data[16];
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   essid_len;
  u32  essid_buf[16];

} wpa_pmkid_t;

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
  u32 salt_buf[32];
  u32 salt_len;

  u32 esalt_buf[256];
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
  u32 msg_len[6];

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
  u32 edata2[5120];
  u32 edata2_len;

} krb5tgs_t;

typedef struct krb5asrep
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;

} krb5asrep_t;

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

typedef struct keyboard_layout_mapping
{
  u32 src_char;
  int src_len;
  u32 dst_char;
  int dst_len;

} keyboard_layout_mapping_t;

typedef struct tc
{
  u32 salt_buf[32];
  u32 data_buf[112];
  u32 keyfile_buf[16];
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

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

typedef struct odf11_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[5];
  u32  out[5];

} odf11_tmp_t;

typedef struct odf11
{
  u32 iterations;
  u32 iv[2];
  u32 checksum[5];
  u32 encrypted_data[256];

} odf11_t;

typedef struct odf12_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} odf12_tmp_t;

typedef struct odf12
{
  u32 iterations;
  u32 iv[4];
  u32 checksum[8];
  u32 encrypted_data[256];

} odf12_t;

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

typedef struct dpapimk
{
  u32 context;

  u32 SID[32];
  u32 SID_len;
  u32 SID_offset;

  /* here only for possible
     forward compatibiliy
  */
  // u8 cipher_algo[16];
  // u8 hash_algo[16];

  u32 iv[4];
  u32 contents_len;
  u32 contents[128];

} dpapimk_t;

typedef struct jks_sha1
{
  u32 checksum[5];
  u32 iv[5];
  u32 enc_key_buf[4096];
  u32 enc_key_len;
  u32 der[5];
  u32 alias[16];

} jks_sha1_t;

typedef struct ethereum_pbkdf2
{
  u32 salt_buf[16];
  u32 ciphertext[8];

} ethereum_pbkdf2_t;

typedef struct ethereum_scrypt
{
  u32 salt_buf[16];
  u32 ciphertext[8];

} ethereum_scrypt_t;

typedef struct ethereum_presale
{
  u32 iv[4];
  u32 enc_seed[152];
  u32 enc_seed_len;

} ethereum_presale_t;

typedef struct tacacs_plus
{
  u32 session_buf[16];

  u32 ct_data_buf[64];
  u32 ct_data_len;

  u32 sequence_buf[16];

} tacacs_plus_t;

typedef struct apple_secure_notes
{
  u32 Z_PK;
  u32 ZCRYPTOITERATIONCOUNT;
  u32 ZCRYPTOSALT[16];
  u32 ZCRYPTOWRAPPEDKEY[16];

} apple_secure_notes_t;

typedef struct jwt
{
  u32 salt_buf[1024];
  u32 salt_len;

} jwt_t;

typedef struct electrum_wallet
{
  u32 salt_type;
  u32 iv[4];
  u32 encrypted[4];

} electrum_wallet_t;

typedef struct ansible_vault
{
  u32 cipher;
  u32 version;
  u32 ct_data_buf[4096];
  u32 ct_data_len;
} ansible_vault_t;

typedef struct luks_tmp
{
  u32 ipad32[8];
  u64 ipad64[8];

  u32 opad32[8];
  u64 opad64[8];

  u32 dgst32[32];
  u64 dgst64[16];

  u32 out32[32];
  u64 out64[16];

} luks_tmp_t;

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

typedef struct sha256crypt_tmp
{
  // pure version

  u32 alt_result[8];
  u32 p_bytes[64];
  u32 s_bytes[64];

} sha256crypt_tmp_t;

typedef struct sha512crypt_tmp
{
  u64 l_alt_result[8];
  u64 l_p_bytes[2];
  u64 l_s_bytes[2];

  // pure version

  u32 alt_result[16];
  u32 p_bytes[64];
  u32 s_bytes[64];

} sha512crypt_tmp_t;

typedef struct wpa_pbkdf2_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} wpa_pbkdf2_tmp_t;

typedef struct wpa_pmk_tmp
{
  u32 out[8];

} wpa_pmk_tmp_t;

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

typedef struct vc64_sbog_tmp
{
  u64  ipad_raw[8];
  u64  opad_raw[8];

  u64  ipad_hash[8];
  u64  opad_hash[8];

  u64  dgst[32];
  u64  out[32];

} vc64_sbog_tmp_t;

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

  u32 dgst[10];
  u32 out[10];

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

typedef struct pbkdf1_sha1_tmp
{
  // pbkdf1-sha1 is limited to 160 bits

  u32  ipad[5];
  u32  opad[5];

  u32  out[5];

} pbkdf1_sha1_tmp_t;

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
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

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

typedef struct seven_zip_hook_salt
{
  u32 iv_buf[4];
  u32 iv_len;

  u32 salt_buf[4];
  u32 salt_len;

  u32 crc;
  u32 crc_len;

  u8  data_type;

  u32 data_buf[81882];
  u32 data_len;

  u32 unpack_size;

  char coder_attributes[5 + 1];
  u8   coder_attributes_len;

  int aes_len; // pre-computed length of the maximal (subset of) data we need for AES-CBC

} seven_zip_hook_salt_t;

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

typedef struct dpapimk_tmp_v1
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[10];
  u32 out[10];

  u32 userKey[5];

} dpapimk_tmp_v1_t;

typedef struct dpapimk_tmp_v2
{
  u64 ipad64[8];
  u64 opad64[8];
  u64 dgst64[16];
  u64 out64[16];

  u32 userKey[8];

} dpapimk_tmp_v2_t;

typedef struct apple_secure_notes_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} apple_secure_notes_tmp_t;

typedef struct seven_zip_hook
{
  u32 ukey[8];

  u32 hook_success;

} seven_zip_hook_t;

typedef struct struct_psafe2_hdr
{
  u32  random[2];
  u32  hash[5];
  u32  salt[5];   // unused, but makes better valid check
  u32  iv[2];     // unused, but makes better valid check

} psafe2_hdr;

typedef enum
{
  MESSAGE_PAIR_M12E2 = 0,
  MESSAGE_PAIR_M14E4 = 1,
  MESSAGE_PAIR_M32E2 = 2,
  MESSAGE_PAIR_M32E3 = 3,
  MESSAGE_PAIR_M34E3 = 4,
  MESSAGE_PAIR_M34E4 = 5,

} message_pair_t;

#define HCCAPX_VERSION   4
#define HCCAPX_SIGNATURE 0x58504348 // HCPX

// this is required to force mingw to accept the packed attribute
#pragma pack(push,1)

struct hccapx
{
  u32 signature;
  u32 version;
  u8  message_pair;
  u8  essid_len;
  u8  essid[32];
  u8  keyver;
  u8  keymic[16];
  u8  mac_ap[6];
  u8  nonce_ap[32];
  u8  mac_sta[6];
  u8  nonce_sta[32];
  u16 eapol_len;
  u8  eapol[256];

} __attribute__((packed));

typedef struct hccapx hccapx_t;

#pragma pack(pop)

/**
 * hashtypes enums
 */

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
  HASH_TYPE_WPA_EAPOL           = 10,
  HASH_TYPE_LM                  = 11,
  HASH_TYPE_DESCRYPT            = 12,
  HASH_TYPE_ORACLEH             = 13,
  HASH_TYPE_DESRACF             = 14,
  HASH_TYPE_BCRYPT              = 15,
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
  HASH_TYPE_STREEBOG_256        = 42,
  HASH_TYPE_STREEBOG_512        = 43,
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
  HASH_TYPE_LUKS                = 55,
  HASH_TYPE_ITUNES_BACKUP_9     = 56,
  HASH_TYPE_ITUNES_BACKUP_10    = 57,
  HASH_TYPE_SKIP32              = 58,
  HASH_TYPE_BLAKE2B             = 59,
  HASH_TYPE_CHACHA20            = 60,
  HASH_TYPE_DPAPIMK             = 61,
  HASH_TYPE_JKS_SHA1            = 62,
  HASH_TYPE_TACACS_PLUS         = 63,
  HASH_TYPE_APPLE_SECURE_NOTES  = 64,
  HASH_TYPE_CRAM_MD5_DOVECOT    = 65,
  HASH_TYPE_JWT                 = 66,
  HASH_TYPE_ELECTRUM_WALLET     = 67,
  HASH_TYPE_WPA_PMKID_PBKDF2    = 68,
  HASH_TYPE_WPA_PMKID_PMK       = 69,
  HASH_TYPE_ANSIBLE_VAULT       = 70,
  HASH_TYPE_KRB5ASREP           = 71,
  HASH_TYPE_ODF12               = 72,
  HASH_TYPE_ODF11               = 73,

} hash_type_t;

typedef enum kern_type
{
  KERN_TYPE_MD5                     = 0,
  KERN_TYPE_MD5_PWSLT               = 10,
  KERN_TYPE_MD5_SLTPW               = 20,
  KERN_TYPE_MD5_PWUSLT              = 30,
  KERN_TYPE_MD5_SLTPWU              = 40,
  KERN_TYPE_HMACMD5_PW              = 50,
  KERN_TYPE_HMACMD5_SLT             = 60,
  KERN_TYPE_SHA1                    = 100,
  KERN_TYPE_SHA1_PWSLT              = 110,
  KERN_TYPE_SHA1_SLTPW              = 120,
  KERN_TYPE_SHA1_PWUSLT             = 130,
  KERN_TYPE_SHA1_SLTPWU             = 140,
  KERN_TYPE_HMACSHA1_PW             = 150,
  KERN_TYPE_HMACSHA1_SLT            = 160,
  KERN_TYPE_MYSQL                   = 200,
  KERN_TYPE_MYSQL41                 = 300,
  KERN_TYPE_PHPASS                  = 400,
  KERN_TYPE_MD5CRYPT                = 500,
  KERN_TYPE_BLAKE2B                 = 600,
  KERN_TYPE_MD4                     = 900,
  KERN_TYPE_MD4_PWU                 = 1000,
  KERN_TYPE_MD44_PWUSLT             = 1100,
  KERN_TYPE_SHA224                  = 1300,
  KERN_TYPE_SHA256                  = 1400,
  KERN_TYPE_SHA256_PWSLT            = 1410,
  KERN_TYPE_SHA256_SLTPW            = 1420,
  KERN_TYPE_SHA256_PWUSLT           = 1430,
  KERN_TYPE_SHA256_SLTPWU           = 1440,
  KERN_TYPE_HMACSHA256_PW           = 1450,
  KERN_TYPE_HMACSHA256_SLT          = 1460,
  KERN_TYPE_DESCRYPT                = 1500,
  KERN_TYPE_APR1CRYPT               = 1600,
  KERN_TYPE_SHA512                  = 1700,
  KERN_TYPE_SHA512_PWSLT            = 1710,
  KERN_TYPE_SHA512_SLTPW            = 1720,
  KERN_TYPE_SHA512_PWSLTU           = 1730,
  KERN_TYPE_SHA512_SLTPWU           = 1740,
  KERN_TYPE_HMACSHA512_PW           = 1750,
  KERN_TYPE_HMACSHA512_SLT          = 1760,
  KERN_TYPE_SHA512CRYPT             = 1800,
  KERN_TYPE_STDOUT                  = 2000,
  KERN_TYPE_DCC2                    = 2100,
  KERN_TYPE_MD5PIX                  = 2400,
  KERN_TYPE_MD5ASA                  = 2410,
  KERN_TYPE_WPA_EAPOL_PBKDF2        = 2500,
  KERN_TYPE_WPA_EAPOL_PMK           = 2501,
  KERN_TYPE_MD55                    = 2600,
  KERN_TYPE_MD55_PWSLT1             = 2610,
  KERN_TYPE_MD55_PWSLT2             = 2710,
  KERN_TYPE_MD55_SLTPW              = 2810,
  KERN_TYPE_LM                      = 3000,
  KERN_TYPE_ORACLEH                 = 3100,
  KERN_TYPE_BCRYPT                  = 3200,
  KERN_TYPE_MD5_SLT_MD5_PW          = 3710,
  KERN_TYPE_MD5_SLT_PW_SLT          = 3800,
  KERN_TYPE_MD55_PWSLT              = 3910,
  KERN_TYPE_MD5_SLT_MD5_SLT_PW      = 4010,
  KERN_TYPE_MD5_SLT_MD5_PW_SLT      = 4110,
  KERN_TYPE_MD5U5                   = 4300,
  KERN_TYPE_MD5U5_PWSLT1            = 4310,
  KERN_TYPE_MD5_SHA1                = 4400,
  KERN_TYPE_SHA11                   = 4500,
  KERN_TYPE_SHA1_SLT_SHA1_PW        = 4520,
  KERN_TYPE_SHA1_MD5                = 4700,
  KERN_TYPE_MD5_CHAP                = 4800,
  KERN_TYPE_SHA1_SLT_PW_SLT         = 4900,
  KERN_TYPE_MD5H                    = 5100,
  KERN_TYPE_PSAFE3                  = 5200,
  KERN_TYPE_IKEPSK_MD5              = 5300,
  KERN_TYPE_IKEPSK_SHA1             = 5400,
  KERN_TYPE_NETNTLMv1               = 5500,
  KERN_TYPE_NETNTLMv2               = 5600,
  KERN_TYPE_ANDROIDPIN              = 5800,
  KERN_TYPE_RIPEMD160               = 6000,
  KERN_TYPE_WHIRLPOOL               = 6100,
  KERN_TYPE_TCRIPEMD160_XTS512      = 6211,
  KERN_TYPE_TCRIPEMD160_XTS1024     = 6212,
  KERN_TYPE_TCRIPEMD160_XTS1536     = 6213,
  KERN_TYPE_TCSHA512_XTS512         = 6221,
  KERN_TYPE_TCSHA512_XTS1024        = 6222,
  KERN_TYPE_TCSHA512_XTS1536        = 6223,
  KERN_TYPE_TCWHIRLPOOL_XTS512      = 6231,
  KERN_TYPE_TCWHIRLPOOL_XTS1024     = 6232,
  KERN_TYPE_TCWHIRLPOOL_XTS1536     = 6233,
  KERN_TYPE_VCSHA256_XTS512         = 13751,
  KERN_TYPE_VCSHA256_XTS1024        = 13752,
  KERN_TYPE_VCSHA256_XTS1536        = 13753,
  KERN_TYPE_VCSBOG512_XTS512        = 13771,
  KERN_TYPE_VCSBOG512_XTS1024       = 13772,
  KERN_TYPE_VCSBOG512_XTS1536       = 13773,
  KERN_TYPE_MD5AIX                  = 6300,
  KERN_TYPE_SHA256AIX               = 6400,
  KERN_TYPE_SHA512AIX               = 6500,
  KERN_TYPE_AGILEKEY                = 6600,
  KERN_TYPE_SHA1AIX                 = 6700,
  KERN_TYPE_LASTPASS                = 6800,
  KERN_TYPE_GOST                    = 6900,
  KERN_TYPE_FORTIGATE               = 7000,
  KERN_TYPE_PBKDF2_SHA512           = 7100,
  KERN_TYPE_RAKP                    = 7300,
  KERN_TYPE_SHA256CRYPT             = 7400,
  KERN_TYPE_KRB5PA                  = 7500,
  KERN_TYPE_SAPB                    = 7700,
  KERN_TYPE_SAPB_MANGLED            = 7701,
  KERN_TYPE_SAPG                    = 7800,
  KERN_TYPE_SAPG_MANGLED            = 7801,
  KERN_TYPE_DRUPAL7                 = 7900,
  KERN_TYPE_SYBASEASE               = 8000,
  KERN_TYPE_NETSCALER               = 8100,
  KERN_TYPE_CLOUDKEY                = 8200,
  KERN_TYPE_NSEC3                   = 8300,
  KERN_TYPE_WBB3                    = 8400,
  KERN_TYPE_RACF                    = 8500,
  KERN_TYPE_LOTUS5                  = 8600,
  KERN_TYPE_LOTUS6                  = 8700,
  KERN_TYPE_ANDROIDFDE              = 8800,
  KERN_TYPE_SCRYPT                  = 8900,
  KERN_TYPE_PSAFE2                  = 9000,
  KERN_TYPE_LOTUS8                  = 9100,
  KERN_TYPE_OFFICE2007              = 9400,
  KERN_TYPE_OFFICE2010              = 9500,
  KERN_TYPE_OFFICE2013              = 9600,
  KERN_TYPE_OLDOFFICE01             = 9700,
  KERN_TYPE_OLDOFFICE01CM1          = 9710,
  KERN_TYPE_OLDOFFICE01CM2          = 9720,
  KERN_TYPE_OLDOFFICE34             = 9800,
  KERN_TYPE_OLDOFFICE34CM1          = 9810,
  KERN_TYPE_OLDOFFICE34CM2          = 9820,
  KERN_TYPE_RADMIN2                 = 9900,
  KERN_TYPE_SIPHASH                 = 10100,
  KERN_TYPE_SAPH_SHA1               = 10300,
  KERN_TYPE_PDF11                   = 10400,
  KERN_TYPE_PDF11CM1                = 10410,
  KERN_TYPE_PDF11CM2                = 10420,
  KERN_TYPE_PDF14                   = 10500,
  KERN_TYPE_PDF17L8                 = 10700,
  KERN_TYPE_SHA384                  = 10800,
  KERN_TYPE_PBKDF2_SHA256           = 10900,
  KERN_TYPE_PRESTASHOP              = 11000,
  KERN_TYPE_POSTGRESQL_AUTH         = 11100,
  KERN_TYPE_MYSQL_AUTH              = 11200,
  KERN_TYPE_BITCOIN_WALLET          = 11300,
  KERN_TYPE_SIP_AUTH                = 11400,
  KERN_TYPE_CRC32                   = 11500,
  KERN_TYPE_SEVEN_ZIP               = 11600,
  KERN_TYPE_STREEBOG_256            = 11700,
  KERN_TYPE_HMAC_STREEBOG_256_PW    = 11750,
  KERN_TYPE_HMAC_STREEBOG_256_SLT   = 11760,
  KERN_TYPE_STREEBOG_512            = 11800,
  KERN_TYPE_HMAC_STREEBOG_512_PW    = 11850,
  KERN_TYPE_HMAC_STREEBOG_512_SLT   = 11860,
  KERN_TYPE_PBKDF2_MD5              = 11900,
  KERN_TYPE_PBKDF2_SHA1             = 12000,
  KERN_TYPE_ECRYPTFS                = 12200,
  KERN_TYPE_ORACLET                 = 12300,
  KERN_TYPE_BSDICRYPT               = 12400,
  KERN_TYPE_RAR3                    = 12500,
  KERN_TYPE_CF10                    = 12600,
  KERN_TYPE_MYWALLET                = 12700,
  KERN_TYPE_MS_DRSR                 = 12800,
  KERN_TYPE_ANDROIDFDE_SAMSUNG      = 12900,
  KERN_TYPE_RAR5                    = 13000,
  KERN_TYPE_KRB5TGS                 = 13100,
  KERN_TYPE_AXCRYPT                 = 13200,
  KERN_TYPE_SHA1_AXCRYPT            = 13300,
  KERN_TYPE_KEEPASS                 = 13400,
  KERN_TYPE_PSTOKEN                 = 13500,
  KERN_TYPE_ZIP2                    = 13600,
  KERN_TYPE_WIN8PHONE               = 13800,
  KERN_TYPE_OPENCART                = 13900,
  KERN_TYPE_DES                     = 14000,
  KERN_TYPE_3DES                    = 14100,
  KERN_TYPE_SHA1CX                  = 14400,
  KERN_TYPE_LUKS_SHA1_AES           = 14611,
  KERN_TYPE_LUKS_SHA1_SERPENT       = 14612,
  KERN_TYPE_LUKS_SHA1_TWOFISH       = 14613,
  KERN_TYPE_LUKS_SHA256_AES         = 14621,
  KERN_TYPE_LUKS_SHA256_SERPENT     = 14622,
  KERN_TYPE_LUKS_SHA256_TWOFISH     = 14623,
  KERN_TYPE_LUKS_SHA512_AES         = 14631,
  KERN_TYPE_LUKS_SHA512_SERPENT     = 14632,
  KERN_TYPE_LUKS_SHA512_TWOFISH     = 14633,
  KERN_TYPE_LUKS_RIPEMD160_AES      = 14641,
  KERN_TYPE_LUKS_RIPEMD160_SERPENT  = 14642,
  KERN_TYPE_LUKS_RIPEMD160_TWOFISH  = 14643,
  KERN_TYPE_LUKS_WHIRLPOOL_AES      = 14651,
  KERN_TYPE_LUKS_WHIRLPOOL_SERPENT  = 14652,
  KERN_TYPE_LUKS_WHIRLPOOL_TWOFISH  = 14653,
  KERN_TYPE_ITUNES_BACKUP_9         = 14700,
  KERN_TYPE_ITUNES_BACKUP_10        = 14800,
  KERN_TYPE_SKIP32                  = 14900,
  KERN_TYPE_FILEZILLA_SERVER        = 15000,
  KERN_TYPE_NETBSD_SHA1CRYPT        = 15100,
  KERN_TYPE_DPAPIMK_V1              = 15300,
  KERN_TYPE_CHACHA20                = 15400,
  KERN_TYPE_JKS_SHA1                = 15500,
  KERN_TYPE_ETHEREUM_PBKDF2         = 15600,
  KERN_TYPE_ETHEREUM_SCRYPT         = 15700,
  KERN_TYPE_DPAPIMK_V2              = 15900,
  KERN_TYPE_TRIPCODE                = 16000,
  KERN_TYPE_TACACS_PLUS             = 16100,
  KERN_TYPE_APPLE_SECURE_NOTES      = 16200,
  KERN_TYPE_ETHEREUM_PRESALE        = 16300,
  KERN_TYPE_CRAM_MD5_DOVECOT        = 16400,
  KERN_TYPE_JWT_HS256               = 16511,
  KERN_TYPE_JWT_HS384               = 16512,
  KERN_TYPE_JWT_HS512               = 16513,
  KERN_TYPE_ELECTRUM_WALLET13       = 16600,
  KERN_TYPE_WPA_PMKID_PBKDF2        = 16800,
  KERN_TYPE_WPA_PMKID_PMK           = 16801,
  KERN_TYPE_ANSIBLE_VAULT           = 16900,
  KERN_TYPE_SHA3_224                = 17300,
  KERN_TYPE_SHA3_256                = 17400,
  KERN_TYPE_SHA3_384                = 17500,
  KERN_TYPE_SHA3_512                = 17600,
  KERN_TYPE_KECCAK_224              = 17700,
  KERN_TYPE_KECCAK_256              = 17800,
  KERN_TYPE_KECCAK_384              = 17900,
  KERN_TYPE_KECCAK_512              = 18000,
  KERN_TYPE_TOTP_HMACSHA1           = 18100,
  KERN_TYPE_KRB5ASREP               = 18200,
  KERN_TYPE_APFS                    = 18300,
  KERN_TYPE_ODF12                   = 18400,
  KERN_TYPE_SHA1_DOUBLE_MD5         = 18500,
  KERN_TYPE_ODF11                   = 18600,
  KERN_TYPE_PLAINTEXT               = 99999,

} kern_type_t;

/**
 * Default iteration numbers
 */

typedef enum rounds_count
{
   ROUNDS_PHPASS             = (1 << 11), // $P$B
   ROUNDS_DCC2               = 10240,
   ROUNDS_WPA_PBKDF2         = 4096,
   ROUNDS_WPA_PMK            = 1,
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
   ROUNDS_SHA512MACOS        = 35000,
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
   ROUNDS_LIBREOFFICE        = 100000,
   ROUNDS_OPENOFFICE         = 1024,
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
   ROUNDS_MYWALLETV2         = 5000,
   ROUNDS_MS_DRSR            = 100,
   ROUNDS_ANDROIDFDE_SAMSUNG = 4096,
   ROUNDS_RAR5               = (1 << 15),
   ROUNDS_AXCRYPT            = 10000,
   ROUNDS_KEEPASS            = 6000,
   ROUNDS_ZIP2               = 1000,
   ROUNDS_LUKS               = 163044, // this equal to jtr -test
   ROUNDS_ITUNES9_BACKUP     = 10000,
   ROUNDS_ITUNES101_BACKUP   = 10000000, // wtf, i mean, really?
   ROUNDS_ITUNES102_BACKUP   = 10000,
   ROUNDS_ATLASSIAN          = 10000,
   ROUNDS_NETBSD_SHA1CRYPT   = 20000,
   ROUNDS_DPAPIMK_V1         = 24000 - 1, // from 4000 to 24000 (possibly more)
   ROUNDS_DPAPIMK_V2         = 8000  - 1, // from 4000 to 24000 (possibly more)
   ROUNDS_ETHEREUM_PBKDF2    = 262144 - 1,
   ROUNDS_APPLE_SECURE_NOTES = 20000,
   ROUNDS_ETHEREUM_PRESALE   = 2000 - 1,
   ROUNDS_ANSIBLE_VAULT      = 10000,
   ROUNDS_STDOUT             = 0

} rounds_count_t;

/**
 * input functions
 */

int bcrypt_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int cisco4_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int dcc2_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int descrypt_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int des_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int episerver_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int postgresql_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int netscreen_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int keccak_224_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int keccak_256_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int keccak_384_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int keccak_512_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int blake2b_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int chacha20_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int lm_parse_hash                 (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md4_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md4s_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5s_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5half_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5md5_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5pix_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5asa_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5apr1_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5crypt_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int mssql2000_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int mssql2005_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int netntlmv1_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int netntlmv2_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oracleh_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oracles_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oraclet_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int osc_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int arubaos_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int macos1_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int macos512_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int phpass_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha1_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha1b64_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha1b64s_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha1s_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha224_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha256_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha256s_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha384_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha512_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha512s_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha512crypt_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int vb30_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int wpa_eapol_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int psafe2_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int psafe3_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ikepsk_md5_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ikepsk_sha1_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int androidpin_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ripemd160_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int whirlpool_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int truecrypt_parse_hash_1k       (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int truecrypt_parse_hash_2k       (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int md5aix_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha256aix_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha512aix_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int agilekey_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha1aix_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int lastpass_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int gost_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha256crypt_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int mssql2012_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha512macos_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int episerver4_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha512grub_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha512b64s_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int krb5pa_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int krb5tgs_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int krb5asrep_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sapb_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sapg_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int drupal7_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sybasease_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int mysql323_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int rakp_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int netscaler_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int chap_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int cloudkey_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int nsec3_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int wbb3_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int racf_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int lotus5_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int lotus6_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int lotus8_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int hmailserver_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int phps_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int mediawiki_b_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int peoplesoft_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int skype_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int androidfde_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int scrypt_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int juniper_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int cisco8_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int cisco9_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int office2007_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int office2010_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int office2013_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oldoffice01_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oldoffice01cm1_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oldoffice01cm2_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oldoffice34_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oldoffice34cm1_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int oldoffice34cm2_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int radmin2_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int djangosha1_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int djangopbkdf2_parse_hash       (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int siphash_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int crammd5_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int crammd5_dovecot_parse_hash    (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int saph_sha1_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int redmine_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int punbb_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pdf11_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pdf11cm1_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pdf11cm2_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pdf14_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pdf17l3_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pdf17l8_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pbkdf2_sha256_parse_hash      (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int prestashop_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int postgresql_auth_parse_hash    (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int mysql_auth_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int bitcoin_wallet_parse_hash     (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sip_auth_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int crc32_parse_hash              (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int seven_zip_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int streebog_256_parse_hash       (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int streebog_512_parse_hash       (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pbkdf2_md5_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pbkdf2_sha1_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pbkdf2_sha512_parse_hash      (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ecryptfs_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int bsdicrypt_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int rar3hp_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int rar5_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int cf10_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int mywallet_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int mywalletv2_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ms_drsr_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int androidfde_samsung_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int axcrypt_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha1axcrypt_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int keepass_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int pstoken_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int zip2_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int veracrypt_parse_hash_200000   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int veracrypt_parse_hash_500000   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int veracrypt_parse_hash_327661   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int veracrypt_parse_hash_655331   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int win8phone_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int opencart_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int plaintext_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha1cx_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int luks_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig, const int keyslot_idx);
int itunes_backup_parse_hash      (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int skip32_parse_hash             (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int fortigate_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int sha256b64s_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int filezilla_server_parse_hash   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int netbsd_sha1crypt_parse_hash   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int atlassian_parse_hash          (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int dpapimk_parse_hash            (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int jks_sha1_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ethereum_pbkdf2_parse_hash    (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ethereum_scrypt_parse_hash    (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int tripcode_parse_hash           (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int tacacs_plus_parse_hash        (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int apple_secure_notes_parse_hash (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ethereum_presale_parse_hash   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int jwt_parse_hash                (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int electrum_wallet13_parse_hash  (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int filevault2_parse_hash         (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int wpa_pmkid_pbkdf2_parse_hash   (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int wpa_pmkid_pmk_parse_hash      (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int ansible_vault_parse_hash      (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int totp_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);
int apfs_parse_hash               (u8 *input_buf, u32 input_len, hash_t *hash_buf, MAYBE_UNUSED hashconfig_t *hashconfig);

/**
 * hook functions
 */

void seven_zip_hook_func (hc_device_param_t *device_param, void *hook_salts_buf, const u32 salt_pos, const u64 pws_cnt);

/**
 * output functions
 */

const char *stroptitype (const u32 opti_type);
const char *strhashtype (const u32 hash_mode);
const char *strparser   (const u32 parser_status);

int check_old_hccap (const char *hashfile);
void to_hccapx_t (hashcat_ctx_t *hashcat_ctx, hccapx_t *hccapx, const u32 salt_pos, const u32 digest_pos);

int ascii_digest (hashcat_ctx_t *hashcat_ctx, char *out_buf, const size_t out_len, const u32 salt_pos, const u32 digest_pos);

int         hashconfig_init                   (hashcat_ctx_t *hashcat_ctx);
void        hashconfig_destroy                (hashcat_ctx_t *hashcat_ctx);
u32         hashconfig_forced_kernel_threads  (hashcat_ctx_t *hashcat_ctx);
u32         hashconfig_get_kernel_threads     (hashcat_ctx_t *hashcat_ctx, const hc_device_param_t *device_param);
u32         hashconfig_get_kernel_loops       (hashcat_ctx_t *hashcat_ctx);
int         hashconfig_general_defaults       (hashcat_ctx_t *hashcat_ctx);
int         hashconfig_get_pw_min             (hashcat_ctx_t *hashcat_ctx, const bool optimized_kernel);
int         hashconfig_get_pw_max             (hashcat_ctx_t *hashcat_ctx, const bool optimized_kernel);
int         hashconfig_get_salt_min           (hashcat_ctx_t *hashcat_ctx, const bool optimized_kernel);
int         hashconfig_get_salt_max           (hashcat_ctx_t *hashcat_ctx, const bool optimized_kernel);
void        hashconfig_benchmark_defaults     (hashcat_ctx_t *hashcat_ctx, salt_t *salt, void *esalt, void *hook_salt);
const char *hashconfig_benchmark_mask         (hashcat_ctx_t *hashcat_ctx);

#endif // _INTERFACE_H
