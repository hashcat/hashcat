/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

typedef uchar  u8;
typedef ushort u16;
typedef uint   u32;
typedef ulong  u64;

static inline u32 swap32 (const u32 v)
{
  return (as_uint (as_uchar4 (v).s3210));
}

static inline u64 swap64 (const u64 v)
{
  return (as_ulong (as_uchar8 (v).s76543210));
}

#ifdef IS_AMD
static inline u32 __bfe (const u32 a, const u32 b, const u32 c)
{
  return amd_bfe (a, b, c);
}
#endif

#ifdef IS_NV
static inline u32 __byte_perm (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("prmt.b32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c));

  return r;
}

static inline u32 __bfe (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("bfe.u32 %0, %1, %2, %3;" : "=r"(r) : "r"(a), "r"(b), "r"(c));

  return r;
}

#if CUDA_ARCH >= 350

static inline u32 amd_bytealign (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(r) : "r"(b), "r"(a), "r"((c & 3) * 8));

  return r;
}

#else

static inline u32 amd_bytealign (const u32 a, const u32 b, const u32 c)
{
  return __byte_perm (b, a, (0x76543210 >> ((c & 3) * 4)) & 0xffff);
}

#endif

static inline u32 lut3_2d (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x2d;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_39 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x39;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_59 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x59;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_96 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0x96;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_e4 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xe4;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_e8 (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xe8;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

static inline u32 lut3_ca (const u32 a, const u32 b, const u32 c)
{
  u32 r;

  asm ("lop3.b32 %0, %1, %2, %3, 0xca;" : "=r" (r) : "r" (a), "r" (b), "r" (c));

  return r;
}

#endif

#define allx(r) r

/*
static u32 allx (const u32 r)
{
  return r;
}
*/

static inline u32 l32_from_64 (u64 a)
{
  const u32 r = (uint) (a);

  return r;
}

static inline u32 h32_from_64 (u64 a)
{
  a >>= 32;

  const u32 r = (uint) (a);

  return r;
}

static inline u64 hl32_to_64 (const u32 a, const u32 b)
{
  return as_ulong ((uint2) (b, a));
}

static inline u32 rotr32 (const u32 a, const u32 n)
{
  return rotate (a, 32 - n);
}

static inline u32 rotl32 (const u32 a, const u32 n)
{
  return rotate (a, n);
}

#ifdef IS_AMD

static inline u64 rotr64 (const u64 a, const u32 n)
{
  uint2 a2 = as_uint2 (a);

  uint2 t;

  t.s0 = (n >= 32) ? amd_bitalign (a2.s0, a2.s1, n - 32)
                   : amd_bitalign (a2.s1, a2.s0, n);
  t.s1 = (n >= 32) ? amd_bitalign (a2.s1, a2.s0, n - 32)
                   : amd_bitalign (a2.s0, a2.s1, n);

  return as_ulong (t);
}

static inline u64 rotl64 (const u64 a, const u32 n)
{
  return rotr64 (a, 64 - n);
}

#endif

#ifdef IS_NV

#if CUDA_ARCH >= 350

static inline u64 rotr64 (const u64 a, const u32 n)
{
  u32 il;
  u32 ir;

  asm ("mov.b64 {%0, %1}, %2;" : "=r"(il), "=r"(ir) : "l"(a));

  u32 tl;
  u32 tr;

  if (n >= 32)
  {
    asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(tl) : "r"(ir), "r"(il), "r"(n - 32));
    asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(tr) : "r"(il), "r"(ir), "r"(n - 32));
  }
  else
  {
    asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(tl) : "r"(il), "r"(ir), "r"(n));
    asm ("shf.r.wrap.b32 %0, %1, %2, %3;" : "=r"(tr) : "r"(ir), "r"(il), "r"(n));
  }

  u64 r;

  asm ("mov.b64 %0, {%1, %2};" : "=l"(r) : "r"(tl), "r"(tr));

  return r;
}

static inline u64 rotl64 (const u64 a, const u32 n)
{
  return rotr64 (a, 64 - n);
}

#else

static inline u64 rotr64 (const u64 a, const u64 n)
{
  return rotate (a, 64 - n);
}

static inline u64 rotl64 (const u64 a, const u64 n)
{
  return rotate (a, n);
}

#endif
#endif

typedef struct
{
  #if   defined _DES_
  u32  digest_buf[4];
  #elif defined _MD4_
  u32  digest_buf[4];
  #elif defined _MD5_
  u32  digest_buf[4];
  #elif defined _MD5H_
  u32  digest_buf[4];
  #elif defined _SHA1_
  u32  digest_buf[5];
  #elif defined _BCRYPT_
  u32  digest_buf[6];
  #elif defined _SHA256_
  u32  digest_buf[8];
  #elif defined _SHA384_
  u32  digest_buf[16];
  #elif defined _SHA512_
  u32  digest_buf[16];
  #elif defined _KECCAK_
  u32  digest_buf[50];
  #elif defined _RIPEMD160_
  u32  digest_buf[5];
  #elif defined _WHIRLPOOL_
  u32  digest_buf[16];
  #elif defined _GOST_
  u32  digest_buf[8];
  #elif defined _GOST2012_256_
  u32  digest_buf[8];
  #elif defined _GOST2012_512_
  u32  digest_buf[16];
  #elif defined _SAPB_
  u32  digest_buf[4];
  #elif defined _SAPG_
  u32  digest_buf[5];
  #elif defined _MYSQL323_
  u32  digest_buf[4];
  #elif defined _LOTUS5_
  u32  digest_buf[4];
  #elif defined _LOTUS6_
  u32  digest_buf[4];
  #elif defined _SCRYPT_
  u32  digest_buf[8];
  #elif defined _LOTUS8_
  u32  digest_buf[4];
  #elif defined _OFFICE2007_
  u32  digest_buf[4];
  #elif defined _OFFICE2010_
  u32  digest_buf[4];
  #elif defined _OFFICE2013_
  u32  digest_buf[4];
  #elif defined _OLDOFFICE01_
  u32  digest_buf[4];
  #elif defined _OLDOFFICE34_
  u32  digest_buf[4];
  #elif defined _SIPHASH_
  u32  digest_buf[4];
  #elif defined _PBKDF2_MD5_
  u32  digest_buf[32];
  #elif defined _PBKDF2_SHA1_
  u32  digest_buf[32];
  #elif defined _PBKDF2_SHA256_
  u32  digest_buf[32];
  #elif defined _PBKDF2_SHA512_
  u32  digest_buf[32];
  #elif defined _PDF17L8_
  u32  digest_buf[8];
  #elif defined _CRC32_
  u32  digest_buf[4];
  #elif defined _SEVEN_ZIP_
  u32  digest_buf[4];
  #elif defined _ANDROIDFDE_
  u32  digest_buf[4];
  #elif defined _DCC2_
  u32  digest_buf[4];
  #elif defined _WPA_
  u32  digest_buf[4];
  #elif defined _MD5_SHA1_
  u32  digest_buf[4];
  #elif defined _SHA1_MD5_
  u32  digest_buf[5];
  #elif defined _NETNTLMV2_
  u32  digest_buf[4];
  #elif defined _KRB5PA_
  u32  digest_buf[4];
  #elif defined _CLOUDKEY_
  u32  digest_buf[8];
  #elif defined _SCRYPT_
  u32  digest_buf[4];
  #elif defined _PSAFE2_
  u32  digest_buf[5];
  #elif defined _LOTUS8_
  u32  digest_buf[4];
  #elif defined _RAR3_
  u32  digest_buf[4];
  #elif defined _SHA256_SHA1_
  u32  digest_buf[8];
  #elif defined _MS_DRSR_
  u32  digest_buf[8];
  #endif

} digest_t;

typedef struct
{
  u32 salt_buf[16];
  u32 salt_buf_pc[8];

  u32 salt_len;
  u32 salt_iter;
  u32 salt_sign[2];

  u32 keccak_mdlen;
  u32 truecrypt_mdlen;

  u32 digests_cnt;
  u32 digests_done;

  u32 digests_offset;

  u32 scrypt_N;
  u32 scrypt_r;
  u32 scrypt_p;
  u32 scrypt_tmto;
  u32 scrypt_phy;

} salt_t;

typedef struct
{
  int V;
  int R;
  int P;

  int enc_md;

  u32 id_buf[8];
  u32 u_buf[32];
  u32 o_buf[32];

  int id_len;
  int o_len;
  int u_len;

  u32 rc4key[2];
  u32 rc4data[2];

} pdf_t;

typedef struct
{
  u32 pke[25];
  u32 eapol[64];
  int eapol_size;
  int keyver;

} wpa_t;

typedef struct
{
  u32 cry_master_buf[64];
  u32 ckey_buf[64];
  u32 public_key_buf[64];

  u32 cry_master_len;
  u32 ckey_len;
  u32 public_key_len;

} bitcoin_wallet_t;

typedef struct
{
  u32 salt_buf[30];
  u32 salt_len;

  u32 esalt_buf[38];
  u32 esalt_len;

} sip_t;

typedef struct
{
  u32 data[384];

} androidfde_t;

typedef struct
{
  u32 nr_buf[16];
  u32 nr_len;

  u32 msg_buf[128];
  u32 msg_len;

} ikepsk_t;

typedef struct
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

typedef struct
{
  u32 user[16];
  u32 realm[16];
  u32 salt[32];
  u32 timestamp[16];
  u32 checksum[4];

} krb5pa_t;

typedef struct
{
  u32 salt_buf[16];
  u32 data_buf[112];
  u32 keyfile_buf[16];

} tc_t;

typedef struct
{
  u32 salt_buf[16];

} pbkdf2_md5_t;

typedef struct
{
  u32 salt_buf[16];

} pbkdf2_sha1_t;

typedef struct
{
  u32 salt_buf[16];

} pbkdf2_sha256_t;

typedef struct
{
  u32 salt_buf[32];

} pbkdf2_sha512_t;

typedef struct
{
  u32 salt_buf[128];
  u32 salt_len;

} rakp_t;

typedef struct
{
  u32 data_len;
  u32 data_buf[512];

} cloudkey_t;

typedef struct
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];

  u32 keySize;

} office2007_t;

typedef struct
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2010_t;

typedef struct
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2013_t;

typedef struct
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[4];
  u32 rc4key[2];

} oldoffice01_t;

typedef struct
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[5];
  u32 rc4key[2];

} oldoffice34_t;

typedef struct
{
  u32 digest[4];
  u32 out[4];

} pdf14_tmp_t;

typedef struct
{
  union
  {
    u32 dgst32[16];
    u64 dgst64[8];
  };

  u32 dgst_len;
  u32 W_len;

} pdf17l8_tmp_t;

typedef struct
{
  u32 digest_buf[4];

} phpass_tmp_t;

typedef struct
{
  u32 digest_buf[4];

} md5crypt_tmp_t;

typedef struct
{
  u32 alt_result[8];

  u32 p_bytes[4];
  u32 s_bytes[4];

} sha256crypt_tmp_t;

typedef struct
{
  u64 l_alt_result[8];

  u64 l_p_bytes[2];
  u64 l_s_bytes[2];

} sha512crypt_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} wpa_tmp_t;

typedef struct
{
  u64 dgst[8];

} bitcoin_wallet_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[4];

} dcc2_tmp_t;

typedef struct
{
  u32 E[18];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} bcrypt_tmp_t;

typedef struct
{
  u32 digest[2];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} pwsafe2_tmp_t;

typedef struct
{
  u32 digest_buf[8];

} pwsafe3_tmp_t;

typedef struct
{
  u32 digest_buf[5];

} androidpin_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} androidfde_tmp_t;

typedef struct
{
  u32 ipad[16];
  u32 opad[16];

  u32 dgst[64];
  u32 out[64];

} tc_tmp_t;

typedef struct
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[32];
  u64 out[32];

} tc64_tmp_t;

typedef struct
{
  u32 ipad[4];
  u32 opad[4];

  u32 dgst[32];
  u32 out[32];

} pbkdf2_md5_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[32];
  u32 out[32];

} pbkdf2_sha1_tmp_t;

typedef struct
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[32];
  u32 out[32];

} pbkdf2_sha256_tmp_t;

typedef struct
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[16];
  u64 out[16];

} pbkdf2_sha512_tmp_t;

typedef struct
{
  u64 out[8];

} ecryptfs_tmp_t;

typedef struct
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[16];
  u64 out[16];

} oraclet_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} agilekey_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst1[5];
  u32 out1[5];

  u32 dgst2[5];
  u32 out2[5];

} mywallet_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} sha1aix_tmp_t;

typedef struct
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} sha256aix_tmp_t;

typedef struct
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[8];
  u64 out[8];

} sha512aix_tmp_t;

typedef struct
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} lastpass_tmp_t;

typedef struct
{
  u64 digest_buf[8];

} drupal7_tmp_t;

typedef struct
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} lotus8_tmp_t;

typedef struct
{
  u32 out[5];

} office2007_tmp_t;

typedef struct
{
  u32 out[5];

} office2010_tmp_t;

typedef struct
{
  u64 out[8];

} office2013_tmp_t;

typedef struct
{
  u32 digest_buf[5];

} saph_sha1_tmp_t;

typedef struct
{
  u32 block[16];

  u32 dgst[8];

  u32 block_len;
  u32 final_len;

} seven_zip_tmp_t;

typedef struct
{
  u32 Kc[16];
  u32 Kd[16];

  u32 iv[2];

} bsdicrypt_tmp_t;

typedef struct
{
  u32 dgst[17][5];

} rar3_tmp_t;

typedef struct
{
  u32 user[16];

} cram_md5_t;

typedef struct
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

typedef struct
{
  u32  key;
  u64 val;

} hcstat_table_t;

typedef struct
{
  u32 cs_buf[0x100];
  u32 cs_len;

} cs_t;

typedef struct
{
  u32 cmds[15];

} gpu_rule_t;

/*
typedef struct
{
  u32 plain_buf[16];
  u32 plailen;

} plain_t;
*/

typedef struct
{
  u32 gidvid;
  u32 il_pos;

} plain_t;

typedef struct
{
  u32 i[64];

  u32 pw_len;

  u32 alignment_placeholder_1;
  u32 alignment_placeholder_2;
  u32 alignment_placeholder_3;

} pw_t;

typedef struct
{
  u32 i;

} bf_t;

typedef struct
{
  u32 i[8];

  u32 pw_len;

} comb_t;

typedef struct
{
  u32 b[32];

} bs_word_t;

typedef struct
{
  uint4 P[64];

} scrypt_tmp_t;
