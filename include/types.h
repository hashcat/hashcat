/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef TYPES_H
#define TYPES_H

#ifdef _WIN
#define EOL "\r\n"
#else
#define EOL "\n"
#endif

typedef struct
{
  uint salt_buf[16];
  uint salt_buf_pc[8];

  uint salt_len;
  uint salt_iter;
  uint salt_sign[2];

  uint keccak_mdlen;
  uint truecrypt_mdlen;

  uint digests_cnt;
  uint digests_done;

  uint digests_offset;

  uint scrypt_N;
  uint scrypt_r;
  uint scrypt_p;

} salt_t;

typedef struct
{
  uint iv[4];

} rar5_t;

typedef struct
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

typedef struct
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

typedef struct
{
  uint cry_master_buf[64];
  uint ckey_buf[64];
  uint public_key_buf[64];

  uint cry_master_len;
  uint ckey_len;
  uint public_key_len;

} bitcoin_wallet_t;

typedef struct
{
  uint salt_buf[30];
  uint salt_len;

  uint esalt_buf[38];
  uint esalt_len;

} sip_t;

typedef struct
{
  uint data[384];

} androidfde_t;

typedef struct
{
  uint nr_buf[16];
  uint nr_len;

  uint msg_buf[128];
  uint msg_len;

} ikepsk_t;

typedef struct
{
  uint user_len;
  uint domain_len;
  uint srvchall_len;
  uint clichall_len;

  uint userdomain_buf[64];
  uint chall_buf[256];

} netntlm_t;

typedef struct
{
  uint user[16];
  uint realm[16];
  uint salt[32];
  uint timestamp[16];
  uint checksum[4];

} krb5pa_t;

typedef struct
{
  uint account_info[512];
  uint checksum[4];
  uint edata2[2560];
  uint edata2_len;

} krb5tgs_t;

typedef struct
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

typedef struct
{
  uint salt_buf[16];
  uint data_buf[112];
  uint keyfile_buf[16];
  uint signature;

} tc_t;

typedef struct
{
  uint salt_buf[16];

} pbkdf2_md5_t;

typedef struct
{
  uint salt_buf[16];

} pbkdf2_sha1_t;

typedef struct
{
  uint salt_buf[16];

} pbkdf2_sha256_t;

typedef struct
{
  uint salt_buf[32];

} pbkdf2_sha512_t;

typedef struct
{
  u8   cipher[1040];

} agilekey_t;

typedef struct
{
  uint salt_buf[128];
  uint salt_len;

} rakp_t;

typedef struct
{
  uint data_len;
  uint data_buf[512];

} cloudkey_t;

typedef struct
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[5];

  uint keySize;

} office2007_t;

typedef struct
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[8];

} office2010_t;

typedef struct
{
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[8];

} office2013_t;

typedef struct
{
  uint version;
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[4];
  uint rc4key[2];

} oldoffice01_t;

typedef struct
{
  uint version;
  uint encryptedVerifier[4];
  uint encryptedVerifierHash[5];
  uint rc4key[2];

} oldoffice34_t;

typedef struct
{
  u32 salt_buf[128];
  u32 salt_len;

  u32 pc_digest[5];
  u32 pc_offset;

} pstoken_t;

typedef struct
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

typedef struct
{
  uint salt_buf[32];

} win8phone_t;

typedef struct
{
  uint digest[4];
  uint out[4];

} pdf14_tmp_t;

typedef struct
{
  union
  {
    uint dgst32[16];
    u64  dgst64[8];
  } d;

  uint dgst_len;
  uint W_len;

} pdf17l8_tmp_t;

typedef struct
{
  uint digest_buf[4];

} phpass_tmp_t;

typedef struct
{
  uint digest_buf[4];

} md5crypt_tmp_t;

typedef struct
{
  u64  l_alt_result[8];

  u64  l_p_bytes[2];
  u64  l_s_bytes[2];

} sha512crypt_tmp_t;

typedef struct
{
  uint alt_result[8];

  uint p_bytes[4];
  uint s_bytes[4];

} sha256crypt_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[10];
  uint out[10];

} wpa_tmp_t;

typedef struct
{
  u64  dgst[8];

} bitcoin_wallet_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[4];

} dcc2_tmp_t;

typedef struct
{
  uint E[18];

  uint P[18];

  uint S0[256];
  uint S1[256];
  uint S2[256];
  uint S3[256];

} bcrypt_tmp_t;

typedef struct
{
  uint digest[2];

  uint P[18];

  uint S0[256];
  uint S1[256];
  uint S2[256];
  uint S3[256];

} pwsafe2_tmp_t;

typedef struct
{
  uint digest_buf[8];

} pwsafe3_tmp_t;

typedef struct
{
  uint digest_buf[5];

} androidpin_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[10];
  uint out[10];

} androidfde_tmp_t;

typedef struct
{
  uint ipad[16];
  uint opad[16];

  uint dgst[64];
  uint out[64];

} tc_tmp_t;

typedef struct
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

} tc64_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} agilekey_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst1[5];
  uint out1[5];

  uint dgst2[5];
  uint out2[5];

} mywallet_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} sha1aix_tmp_t;

typedef struct
{
  uint ipad[8];
  uint opad[8];

  uint dgst[8];
  uint out[8];

} sha256aix_tmp_t;

typedef struct
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} sha512aix_tmp_t;

typedef struct
{
  uint ipad[8];
  uint opad[8];

  uint dgst[8];
  uint out[8];

} lastpass_tmp_t;

typedef struct
{
  u64  digest_buf[8];

} drupal7_tmp_t;

typedef struct
{
  uint ipad[5];
  uint opad[5];

  uint dgst[5];
  uint out[5];

} lotus8_tmp_t;

typedef struct
{
  uint out[5];

} office2007_tmp_t;

typedef struct
{
  uint out[5];

} office2010_tmp_t;

typedef struct
{
  u64  out[8];

} office2013_tmp_t;

typedef struct
{
  uint digest_buf[5];

} saph_sha1_tmp_t;

typedef struct
{
  u32  ipad[4];
  u32  opad[4];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_md5_tmp_t;

typedef struct
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} pbkdf2_sha512_tmp_t;

typedef struct
{
  u64  out[8];

} ecryptfs_tmp_t;

typedef struct
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} oraclet_tmp_t;

typedef struct
{
  uint block[16];

  uint dgst[8];

  uint block_len;
  uint final_len;

} seven_zip_tmp_t;

typedef struct
{
  uint Kc[16];
  uint Kd[16];

  uint iv[2];

} bsdicrypt_tmp_t;

typedef struct
{
  uint dgst[17][5];

} rar3_tmp_t;

typedef struct
{
  uint user[16];

} cram_md5_t;

typedef struct
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

typedef struct
{
  u32 KEK[4];
  u32 lsb[4];
  u32 cipher[4];

} axcrypt_tmp_t;

typedef struct
{
  u32 tmp_digest[8];

} keepass_tmp_t;

typedef struct
{
  u32  random[2];
  u32  hash[5];
  u32  salt[5];   // unused, but makes better valid check
  u32  iv[2];     // unused, but makes better valid check

} psafe2_hdr;

typedef struct
{
  char *user_name;
  uint  user_len;

} user_t;

typedef struct
{
  user_t *user;
  char   *orighash;

} hashinfo_t;

typedef struct
{
  void       *digest;
  salt_t     *salt;
  void       *esalt;
  int         cracked;
  hashinfo_t *hash_info;

} hash_t;

typedef struct
{
  uint key;
  u64  val;

} hcstat_table_t;

typedef struct
{
  uint cs_buf[0x100];
  uint cs_len;

} cs_t;

typedef struct
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

typedef struct
{
  char signature[4];
  u32  salt_buf[8];
  u32  iterations;
  u32  hash_buf[8];

} psafe3_t;

typedef struct
{
  char    plain_buf[256];
  int     plain_len;

  hash_t  hash;

} pot_t;

typedef struct
{
  u64    cnt;

#ifdef _POSIX
  struct stat stat;
#endif

#ifdef _WIN
  struct __stat64 stat;
#endif

} dictstat_t;

typedef struct
{
  uint len;

  char buf[0x100];

} cpu_rule_t;

typedef struct
{
  uint cmds[0x100];

} kernel_rule_t;

typedef struct
{
  u32 i[16];

  u32 pw_len;

  u32 alignment_placeholder_1;
  u32 alignment_placeholder_2;
  u32 alignment_placeholder_3;

} pw_t;

typedef struct
{
  uint i;

} bf_t;

typedef struct
{
  uint b[32];

} bs_word_t;

typedef struct
{
  uint i[8];

  uint pw_len;

} comb_t;

typedef struct
{
  u32  version_bin;
  char cwd[256];
  u32  pid;

  u32  dictpos;
  u32  maskpos;

  u64  words_cur;

  u32  argc;
  char **argv;

} restore_data_t;

typedef struct
{
  char   *file_name;
  long   seek;
  time_t ctime;

} outfile_data_t;

typedef struct
{
  char *buf;
  u32  incr;
  u32  avail;
  u32  cnt;
  u32  pos;

} wl_data_t;

typedef struct
{
  uint bitmap_shift;
  uint collisions;

} bitmap_result_t;

#define CPT_BUF 0x20000

typedef struct
{
  uint   cracked;
  time_t timestamp;

} cpt_t;

/*
typedef struct
{
  uint plain_buf[16];
  uint plain_len;

} plain_t;
*/

typedef struct
{
  uint salt_pos;
  uint digest_pos;
  uint hash_pos;
  uint gidvid;
  uint il_pos;

} plain_t;

typedef struct
{
  uint word_buf[16];

} wordl_t;

typedef struct
{
  uint word_buf[1];

} wordr_t;

typedef struct
{
  char *device_name;
  char *alias_name;

} tuning_db_alias_t;

typedef struct
{
  char *device_name;
  int   attack_mode;
  int   hash_type;
  int   workload_profile;
  int   vector_width;
  int   kernel_accel;
  int   kernel_loops;

} tuning_db_entry_t;

typedef struct
{
  tuning_db_alias_t *alias_buf;
  int                alias_cnt;

  tuning_db_entry_t *entry_buf;
  int                entry_cnt;

} tuning_db_t;

#include "hc_device_param_t.h"

#ifdef HAVE_HWMON
typedef struct
{
  HM_ADAPTER_ADL     adl;
  HM_ADAPTER_NVML    nvml;
  HM_ADAPTER_NVAPI   nvapi;
  HM_ADAPTER_XNVCTRL xnvctrl;

  int od_version;

  int fan_get_supported;
  int fan_set_supported;

} hm_attrs_t;
#endif // HAVE_HWMON

#include "hc_global_data_t.h"

#endif

