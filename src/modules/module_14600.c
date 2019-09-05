/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_16;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "LUKS";
static const u64   KERN_TYPE      = 14611; // this gets overwritten later instead of in benchmark
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_BINARY_HASHFILE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = NULL; // ST_HASH_14600  multi-hash-mode algorithm, unlikely to match self-test hash settings

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

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

// end original headers

typedef enum kern_type_luks
{
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

} kern_type_luks_t;

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

u32 module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // the module requires a lot of registers for key schedulers on _comp kernel.
  // it's possible, if using too many threads, there's not enough registers available, typically ending with misleading error message:
  // cuLaunchKernel(): out of memory

  const u32 kernel_threads_max = 64;

  return kernel_threads_max;
}

void *module_benchmark_esalt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  luks_t *luks = (luks_t *) hcmalloc (sizeof (luks_t));

  luks->key_size      = HC_LUKS_KEY_SIZE_256;
  luks->cipher_type   = HC_LUKS_CIPHER_TYPE_AES;
  luks->cipher_mode   = HC_LUKS_CIPHER_MODE_XTS_PLAIN;

  return luks;
}

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  static const int ROUNDS_LUKS = 163044; // this equal to jtr -test

  salt->salt_iter = ROUNDS_LUKS;

  return salt;
}

bool module_outfile_check_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool outfile_check_disable = true;

  return outfile_check_disable;
}

bool module_potfile_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool potfile_disable = true;

  return potfile_disable;
}

int module_hash_binary_count (MAYBE_UNUSED const hashes_t *hashes)
{
  return LUKS_NUMKEYS;
}

int module_hash_binary_parse (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, hashes_t *hashes)
{
  hash_t *hashes_buf = hashes->hashes_buf;

  int hashes_cnt = 0;

  for (int keyslot_idx = 0; keyslot_idx < LUKS_NUMKEYS; keyslot_idx++)
  {
    hash_t *hash = &hashes_buf[hashes_cnt];

    memset (hash->salt, 0, sizeof (salt_t));

    memset (hash->esalt, 0, sizeof (luks_t));

    const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hashes->hashfile, strlen (hashes->hashfile));

    if (parser_status != PARSER_OK) continue;

    hashes_cnt++;
  }

  return hashes_cnt;
}

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info)
{
  const luks_t *luks = (const luks_t *) esalt_buf;

  u64 kern_type = -1;

  if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    kern_type = KERN_TYPE_LUKS_SHA1_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    kern_type = KERN_TYPE_LUKS_SHA1_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA1) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    kern_type = KERN_TYPE_LUKS_SHA1_TWOFISH;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    kern_type = KERN_TYPE_LUKS_SHA256_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    kern_type = KERN_TYPE_LUKS_SHA256_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA256) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    kern_type = KERN_TYPE_LUKS_SHA256_TWOFISH;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    kern_type = KERN_TYPE_LUKS_SHA512_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    kern_type = KERN_TYPE_LUKS_SHA512_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_SHA512) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    kern_type = KERN_TYPE_LUKS_SHA512_TWOFISH;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    kern_type = KERN_TYPE_LUKS_RIPEMD160_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    kern_type = KERN_TYPE_LUKS_RIPEMD160_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_RIPEMD160) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    kern_type = KERN_TYPE_LUKS_RIPEMD160_TWOFISH;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_AES))
  {
    kern_type = KERN_TYPE_LUKS_WHIRLPOOL_AES;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_SERPENT))
  {
    kern_type = KERN_TYPE_LUKS_WHIRLPOOL_SERPENT;
  }
  else if ((luks->hash_type == HC_LUKS_HASH_TYPE_WHIRLPOOL) && (luks->cipher_type == HC_LUKS_CIPHER_TYPE_TWOFISH))
  {
    kern_type = KERN_TYPE_LUKS_WHIRLPOOL_TWOFISH;
  }

  return kern_type;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (luks_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (luks_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is selected
  // IOW, even in optimized kernel mode it support length 256

  const u32 pw_max = PW_MAX;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  luks_t *luks = (luks_t *) esalt_buf;

  static int keyslot_idx_sav = 0;

  const int keyslot_idx = keyslot_idx_sav;

  keyslot_idx_sav++;

  if (line_len == 0) return (PARSER_HASH_LENGTH);

  HCFILE fp;

  if (hc_fopen (&fp, (const char *) line_buf, "rb") == false) return (PARSER_HASH_FILE);

  struct luks_phdr hdr;

  const size_t nread = hc_fread (&hdr, sizeof (hdr), 1, &fp);

  if (nread != 1)
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // copy digest which we're not using ;)

  u32 *mkDigest_ptr = (u32 *) hdr.mkDigest;

  digest[0] = mkDigest_ptr[0];
  digest[1] = mkDigest_ptr[1];
  digest[2] = mkDigest_ptr[2];
  digest[3] = mkDigest_ptr[3];
  digest[4] = mkDigest_ptr[4];
  digest[5] = 0;
  digest[6] = 0;
  digest[7] = 0;

  // verify the content

  char luks_magic[6] = LUKS_MAGIC;

  if (memcmp (hdr.magic, luks_magic, LUKS_MAGIC_L) != 0)
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_MAGIC);
  }

  if (byte_swap_16 (hdr.version) != 1)
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_VERSION);
  }

  if (strcmp (hdr.cipherName, "aes") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_AES;
  }
  else if (strcmp (hdr.cipherName, "serpent") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_SERPENT;
  }
  else if (strcmp (hdr.cipherName, "twofish") == 0)
  {
    luks->cipher_type = HC_LUKS_CIPHER_TYPE_TWOFISH;
  }
  else
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_CIPHER_TYPE);
  }

  if (strcmp (hdr.cipherMode, "cbc-essiv:sha256") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_ESSIV;
  }
  else if (strcmp (hdr.cipherMode, "cbc-plain") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "cbc-plain64") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_CBC_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "xts-plain") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_XTS_PLAIN;
  }
  else if (strcmp (hdr.cipherMode, "xts-plain64") == 0)
  {
    luks->cipher_mode = HC_LUKS_CIPHER_MODE_XTS_PLAIN;
  }
  else
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_CIPHER_MODE);
  }

  if (strcmp (hdr.hashSpec, "sha1") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA1;
  }
  else if (strcmp (hdr.hashSpec, "sha256") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA256;
  }
  else if (strcmp (hdr.hashSpec, "sha512") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_SHA512;
  }
  else if (strcmp (hdr.hashSpec, "ripemd160") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_RIPEMD160;
  }
  else if (strcmp (hdr.hashSpec, "whirlpool") == 0)
  {
    luks->hash_type = HC_LUKS_HASH_TYPE_WHIRLPOOL;
  }
  else
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_HASH_TYPE);
  }

  const u32 keyBytes = byte_swap_32 (hdr.keyBytes);

  if (keyBytes == 16)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_128;
  }
  else if (keyBytes == 32)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_256;
  }
  else if (keyBytes == 64)
  {
    luks->key_size = HC_LUKS_KEY_SIZE_512;
  }
  else
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_KEY_SIZE);
  }

  // verify the selected keyslot informations

  const u32 active  = byte_swap_32 (hdr.keyblock[keyslot_idx].active);
  const u32 stripes = byte_swap_32 (hdr.keyblock[keyslot_idx].stripes);

  if (active != LUKS_KEY_ENABLED)
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_KEY_DISABLED);
  }

  if (stripes != LUKS_STRIPES)
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_KEY_STRIPES);
  }

  // configure the salt (not esalt)

  u32 *passwordSalt_ptr = (u32 *) hdr.keyblock[keyslot_idx].passwordSalt;

  salt->salt_buf[0] = passwordSalt_ptr[0];
  salt->salt_buf[1] = passwordSalt_ptr[1];
  salt->salt_buf[2] = passwordSalt_ptr[2];
  salt->salt_buf[3] = passwordSalt_ptr[3];
  salt->salt_buf[4] = passwordSalt_ptr[4];
  salt->salt_buf[5] = passwordSalt_ptr[5];
  salt->salt_buf[6] = passwordSalt_ptr[6];
  salt->salt_buf[7] = passwordSalt_ptr[7];

  salt->salt_len = LUKS_SALTSIZE;

  const u32 passwordIterations = byte_swap_32 (hdr.keyblock[keyslot_idx].passwordIterations);

  salt->salt_iter = passwordIterations - 1;

  // Load AF data for this keyslot into esalt

  const u32 keyMaterialOffset = byte_swap_32 (hdr.keyblock[keyslot_idx].keyMaterialOffset);

  const int rc_seek1 = hc_fseek (&fp, keyMaterialOffset * 512, SEEK_SET);

  if (rc_seek1 == -1)
  {
      hc_fclose (&fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  const size_t nread2 = hc_fread (luks->af_src_buf, keyBytes, stripes, &fp);

  if (nread2 != stripes)
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // finally, copy some encrypted payload data for entropy check

  const u32 payloadOffset = byte_swap_32 (hdr.payloadOffset);

  const int rc_seek2 = hc_fseek (&fp, payloadOffset * 512, SEEK_SET);

  if (rc_seek2 == -1)
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  const size_t nread3 = hc_fread (luks->ct_buf, sizeof (u32), 128, &fp);

  if (nread3 != 128)
  {
    hc_fclose (&fp);

    return (PARSER_LUKS_FILE_SIZE);
  }

  // that should be it, close the fp

  hc_fclose (&fp);

  return (PARSER_OK);
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = module_benchmark_esalt;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = module_benchmark_salt;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = module_hash_binary_count;
  module_ctx->module_hash_binary_parse        = module_hash_binary_parse;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = module_kernel_threads_max;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = module_kern_type_dynamic;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = module_outfile_check_disable;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = module_potfile_disable;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
