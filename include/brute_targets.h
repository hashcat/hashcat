#pragma once
typedef struct rar5_t_
{
  uint iv[4];

} rar5_t;

typedef struct pdf_t_
{
  int  V;
  int  R;
  int  P;

  int  enc_md;

  uint id_buf[8];
  uint u_buf[32];
  uint o_buf[32];

  int  id_len;
  int  o_len;
  int  u_len;

  uint rc4key[2];
  uint rc4data[2];

} pdf_t;

typedef struct wpa_t_
{
  uint pke[25];
  uint eapol[64];
  int  eapol_size;
  int  keyver;
  u8   orig_mac1[6];
  u8   orig_mac2[6];
  u8   orig_nonce1[32];
  u8   orig_nonce2[32];

} wpa_t;

typedef struct bitcoin_wallet_t_
{
  uint cry_master_buf[64];
  uint ckey_buf[64];
  uint public_key_buf[64];

  uint cry_master_len;
  uint ckey_len;
  uint public_key_len;

} bitcoin_wallet_t;

typedef struct sip_t_
{
  uint salt_buf[30];
  uint salt_len;

  uint esalt_buf[38];
  uint esalt_len;

} sip_t;

typedef struct androidfde_t_
{
  uint data[384];

} androidfde_t;

typedef struct ikepsk_t_
{
  uint nr_buf[16];
  uint nr_len;

  uint msg_buf[128];
  uint msg_len;

} ikepsk_t;

typedef struct netntlm_t_
{
  uint user_len;
  uint domain_len;
  uint srvchall_len;
  uint clichall_len;

  uint userdomain_buf[64];
  uint chall_buf[256];

} netntlm_t;

typedef struct krb5pa_t_
{
  uint user[16];
  uint realm[16];
  uint salt[32];
  uint timestamp[16];
  uint checksum[4];

} krb5pa_t;

typedef struct krb5tgs_t_
{
  uint account_info[512];
  uint checksum[4];
  uint edata2[2560];
  uint edata2_len;

} krb5tgs_t;

typedef struct keepass_t_
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

typedef struct tc_t_
{
  uint salt_buf[16];
  uint data_buf[112];
  uint keyfile_buf[16];
  uint signature;

} tc_t;

typedef struct pbkdf2_md5_t_
{
  uint salt_buf[16];

} pbkdf2_md5_t;

typedef struct pbkdf2_sha1_t_
{
  uint salt_buf[16];

} pbkdf2_sha1_t;

typedef struct pbkdf2_sha256_t_
{
  uint salt_buf[16];

} pbkdf2_sha256_t;

typedef struct pbkdf2_sha512_t_
{
  uint salt_buf[32];

} pbkdf2_sha512_t;

typedef struct agilekey_t_
{
  u8   cipher[1040];

} agilekey_t;

typedef struct rakp_t_
{
  uint salt_buf[128];
  uint salt_len;

} rakp_t;

typedef struct cloudkey_t_
{
  uint data_len;
  uint data_buf[512];

} cloudkey_t;

typedef struct office2007_t_
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[5];

  uint keySize;

} office2007_t;

typedef struct office2010_t_
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[8];

} office2010_t;

typedef struct office2013_t_
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[8];

} office2013_t;

typedef struct oldoffice01_t_
{
  uint version;
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[4];
  uint rc4key[2];

} oldoffice01_t;

typedef struct oldoffice34_t_
{
  uint version;
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[5];
  uint rc4key[2];

} oldoffice34_t;

typedef struct pstoken_t_
{
  u32 salt_buf[128];
  u32 salt_len;

  u32 pc_digest[5];
  u32 pc_offset;

} pstoken_t;

typedef struct zip2_t_
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

typedef struct win8phone_t_
{
  uint salt_buf[32];

} win8phone_t;

typedef struct pdf14_tmp_t_
{
  uint digest[4];
  uint out[4];

} pdf14_tmp_t;

typedef struct pdf17l8_tmp_t_
{
  union
  {
    uint dgst32[16];
    u64  dgst64[8];
  } d;

  uint dgst_len;
  uint W_len;

} pdf17l8_tmp_t;

typedef struct phpass_tmp_t_
{
  uint digest_buf[4];

} phpass_tmp_t;

typedef struct md5crypt_tmp_t_
{
  uint digest_buf[4];

} md5crypt_tmp_t;

typedef struct sha512crypt_tmp_t_
{
  u64  l_alt_result[8];

  u64  l_p_bytes[2];
  u64  l_s_bytes[2];

} sha512crypt_tmp_t;

typedef struct sha256crypt_tmp_t_
{
  uint alt_result[8];

  uint p_bytes[4];
  uint s_bytes[4];

} sha256crypt_tmp_t;

typedef struct wpa_tmp_t_
{
  uint ipad[5];
  uint opad[5];

  uint dgst[10];
  uint out[10];

} wpa_tmp_t;

typedef struct bitcoin_wallet_tmp_t_
{
  u64  dgst[8];

} bitcoin_wallet_tmp_t;

typedef struct dcc2_tmp_t_
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[4];

} dcc2_tmp_t;

typedef struct bcrypt_tmp_t_
{
  uint E[18];

  uint P[18];

  uint S0[256];
  uint S1[256];
  uint S2[256];
  uint S3[256];

} bcrypt_tmp_t;

typedef struct pwsafe2_tmp_t_
{
  uint digest[2];

  uint P[18];

  uint S0[256];
  uint S1[256];
  uint S2[256];
  uint S3[256];

} pwsafe2_tmp_t;

typedef struct pwsafe3_tmp_t_
{
  uint digest_buf[8];

} pwsafe3_tmp_t;

typedef struct androidpin_tmp_t_
{
  uint digest_buf[5];

} androidpin_tmp_t;

typedef struct androidfde_tmp_t_
{
  uint ipad[5];
  uint opad[5];

  uint dgst[10];
  uint out[10];

} androidfde_tmp_t;

typedef struct tc_tmp_t_
{
  uint ipad[16];
  uint opad[16];

  uint dgst[64];
  uint out[64];

} tc_tmp_t;

typedef struct tc64_tmp_t_
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

} tc64_tmp_t;

typedef struct agilekey_tmp_t_
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} agilekey_tmp_t;

typedef struct mywallet_tmp_t_
{
  uint ipad[5];
  uint opad[5];

  uint dgst1[5];
  uint out1[5];

  uint dgst2[5];
  uint out2[5];

} mywallet_tmp_t;

typedef struct sha1aix_tmp_t_
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} sha1aix_tmp_t;

typedef struct sha256aix_tmp_t_
{
  uint ipad[8];
  uint opad[8];

  uint dgst[8];
  uint out[8];

} sha256aix_tmp_t;

typedef struct sha512aix_tmp_t_
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} sha512aix_tmp_t;

typedef struct lastpass_tmp_t_
{
  uint ipad[8];
  uint opad[8];

  uint dgst[8];
  uint out[8];

} lastpass_tmp_t;

typedef struct drupal7_tmp_t_
{
  u64  digest_buf[8];

} drupal7_tmp_t;

typedef struct lotus8_tmp_t_
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} lotus8_tmp_t;

typedef struct office2007_tmp_t_
{
  uint out[5];

} office2007_tmp_t;

typedef struct office2010_tmp_t_
{
  uint out[5];

} office2010_tmp_t;

typedef struct office2013_tmp_t_
{
  u64  out[8];

} office2013_tmp_t;

typedef struct saph_sha1_tmp_t_
{
  uint digest_buf[5];

} saph_sha1_tmp_t;

typedef struct pbkdf2_md5_tmp_t_
{
  u32  ipad[4];
  u32  opad[4];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_md5_tmp_t;

typedef struct pbkdf2_sha1_tmp_t_
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct pbkdf2_sha256_tmp_t_
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct pbkdf2_sha512_tmp_t_
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} pbkdf2_sha512_tmp_t;

typedef struct ecryptfs_tmp_t_
{
  u64  out[8];

} ecryptfs_tmp_t;

typedef struct oraclet_tmp_t_
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} oraclet_tmp_t;

typedef struct seven_zip_tmp_t_
{
  uint block[16];

  uint dgst[8];

  uint block_len;
  uint final_len;

} seven_zip_tmp_t;

typedef struct bsdicrypt_tmp_t_
{
  uint Kc[16];
  uint Kd[16];

  uint iv[2];

} bsdicrypt_tmp_t;

typedef struct rar3_tmp_t_
{
  uint dgst[17][5];

} rar3_tmp_t;

typedef struct cram_md5_t_
{
  uint user[16];

} cram_md5_t;

typedef struct seven_zip_t_
{
  uint iv_buf[4];
  uint iv_len;

  uint salt_buf[4];
  uint salt_len;

  uint crc;

  uint data_buf[96];
  uint data_len;

  uint unpack_size;

} seven_zip_t;

typedef struct axcrypt_tmp_t_
{
  u32 KEK[4];
  u32 lsb[4];
  u32 cipher[4];

} axcrypt_tmp_t;

typedef struct keepass_tmp_t_
{
  u32 tmp_digest[8];

} keepass_tmp_t;

typedef struct psafe2_hdr_
{
  u32  random[2];
  u32  hash[5];
  u32  salt[5];   // unused, but makes better valid check
  u32  iv[2];     // unused, but makes better valid check

} psafe2_hdr;
