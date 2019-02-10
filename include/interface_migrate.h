
/**
 * algo specific
 */

typedef struct itunes_backup
{
  u32 wpky[10];
  u32 dpsl[5];

} itunes_backup_t;

typedef struct pbkdf2_sha256
{
  u32 salt_buf[16];

} pbkdf2_sha256_t;

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

typedef struct jks_sha1
{
  u32 checksum[5];
  u32 iv[5];
  u32 enc_key_buf[4096];
  u32 enc_key_len;
  u32 der[5];
  u32 alias[16];

} jks_sha1_t;

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

typedef struct mywallet_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} mywallet_tmp_t;

typedef struct pbkdf1_sha1_tmp
{
  // pbkdf1-sha1 is limited to 160 bits

  u32  ipad[5];
  u32  opad[5];

  u32  out[5];

} pbkdf1_sha1_tmp_t;

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

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

typedef struct cram_md5
{
  u32 user[16];

} cram_md5_t;

typedef struct axcrypt_tmp
{
  u32 KEK[4];
  u32 lsb[4];
  u32 cipher[4];

} axcrypt_tmp_t;

typedef struct apple_secure_notes_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} apple_secure_notes_tmp_t;

typedef enum kern_type
{
  KERN_TYPE_MD5_SLTPW               = 20,
  KERN_TYPE_MD5_PWUSLT              = 30,
  KERN_TYPE_HMACMD5_PW              = 50,
  KERN_TYPE_HMACMD5_SLT             = 60,
  KERN_TYPE_SHA1_SLTPW              = 120,
  KERN_TYPE_SHA1_PWUSLT             = 130,
  KERN_TYPE_SHA1_SLTPWU             = 140,
  KERN_TYPE_HMACSHA1_PW             = 150,
  KERN_TYPE_HMACSHA1_SLT            = 160,
  KERN_TYPE_SHA256_PWSLT            = 1410,
  KERN_TYPE_SHA256_SLTPW            = 1420,
  KERN_TYPE_SHA256_PWUSLT           = 1430,
  KERN_TYPE_SHA256_SLTPWU           = 1440,
  KERN_TYPE_HMACSHA256_PW           = 1450,
  KERN_TYPE_HMACSHA256_SLT          = 1460,
  KERN_TYPE_APR1CRYPT               = 1600,
  KERN_TYPE_SHA512_PWSLT            = 1710,
  KERN_TYPE_SHA512_SLTPW            = 1720,
  KERN_TYPE_SHA512_PWSLTU           = 1730,
  KERN_TYPE_SHA512_SLTPWU           = 1740,
  KERN_TYPE_HMACSHA512_PW           = 1750,
  KERN_TYPE_HMACSHA512_SLT          = 1760,
  KERN_TYPE_MD55                    = 2600,
  KERN_TYPE_MD55_PWSLT1             = 2610,
  KERN_TYPE_MD55_PWSLT2             = 2710,
  KERN_TYPE_MD55_SLTPW              = 2810,
  KERN_TYPE_MD5_SLT_MD5_PW          = 3710,
  KERN_TYPE_MD5_SLT_PW_SLT          = 3800,
  KERN_TYPE_MD5_SLT_MD5_SLT_PW      = 4010,
  KERN_TYPE_MD5_SLT_MD5_PW_SLT      = 4110,
  KERN_TYPE_MD5U5                   = 4300,
  KERN_TYPE_MD5U5_PWSLT1            = 4310,
  KERN_TYPE_MD5_SHA1                = 4400,
  KERN_TYPE_SHA11                   = 4500,
  KERN_TYPE_SHA1_SLT_SHA1_PW        = 4520,
  KERN_TYPE_SHA1_MD5                = 4700,
  KERN_TYPE_SHA1_SLT_PW_SLT         = 4900,
  KERN_TYPE_RIPEMD160               = 6000,
  KERN_TYPE_WHIRLPOOL               = 6100,
  KERN_TYPE_RADMIN2                 = 9900,
  KERN_TYPE_SIPHASH                 = 10100,
  KERN_TYPE_POSTGRESQL_AUTH         = 11100,
  KERN_TYPE_MYSQL_AUTH              = 11200,
  KERN_TYPE_STREEBOG_256            = 11700,
  KERN_TYPE_HMAC_STREEBOG_256_PW    = 11750,
  KERN_TYPE_HMAC_STREEBOG_256_SLT   = 11760,
  KERN_TYPE_STREEBOG_512            = 11800,
  KERN_TYPE_HMAC_STREEBOG_512_PW    = 11850,
  KERN_TYPE_HMAC_STREEBOG_512_SLT   = 11860,
  KERN_TYPE_ECRYPTFS                = 12200,
  KERN_TYPE_ORACLET                 = 12300,
  KERN_TYPE_MYWALLET                = 12700,
  KERN_TYPE_MS_DRSR                 = 12800,
  KERN_TYPE_ANDROIDFDE_SAMSUNG      = 12900,
  KERN_TYPE_AXCRYPT                 = 13200,
  KERN_TYPE_SHA1_AXCRYPT            = 13300,
  KERN_TYPE_ZIP2                    = 13600,
  KERN_TYPE_WIN8PHONE               = 13800,
  KERN_TYPE_OPENCART                = 13900,
  KERN_TYPE_SHA1CX                  = 14400,
  KERN_TYPE_ITUNES_BACKUP_9         = 14700,
  KERN_TYPE_ITUNES_BACKUP_10        = 14800,
  KERN_TYPE_JKS_SHA1                = 15500,
  KERN_TYPE_TACACS_PLUS             = 16100,
  KERN_TYPE_APPLE_SECURE_NOTES      = 16200,
  KERN_TYPE_ETHEREUM_PRESALE        = 16300,
  KERN_TYPE_CRAM_MD5_DOVECOT        = 16400,
  KERN_TYPE_JWT_HS256               = 16511,
  KERN_TYPE_JWT_HS384               = 16512,
  KERN_TYPE_JWT_HS512               = 16513,
  KERN_TYPE_ELECTRUM_WALLET13       = 16600,

} kern_type_t;

/**
 * Default iteration numbers
 */

typedef enum rounds_count
{
   ROUNDS_LIBREOFFICE        = 100000,
   ROUNDS_OPENOFFICE         = 1024,
   ROUNDS_ECRYPTFS           = 65536,
   ROUNDS_ORACLET            = 4096,
   ROUNDS_MYWALLET           = 10,
   ROUNDS_MYWALLETV2         = 5000,
   ROUNDS_MS_DRSR            = 100,
   ROUNDS_ANDROIDFDE_SAMSUNG = 4096,
   ROUNDS_AXCRYPT            = 10000,
   ROUNDS_KEEPASS            = 6000,
   ROUNDS_ZIP2               = 1000,
   ROUNDS_ITUNES9_BACKUP     = 10000,
   ROUNDS_ITUNES101_BACKUP   = 10000000, // wtf, i mean, really?
   ROUNDS_ITUNES102_BACKUP   = 10000,
   ROUNDS_APPLE_SECURE_NOTES = 20000,
   ROUNDS_ETHEREUM_PRESALE   = 2000 - 1,

} rounds_count_t;
