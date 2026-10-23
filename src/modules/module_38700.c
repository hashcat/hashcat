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
#include "parser.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "FreeBSD GELI";
static const u64   KERN_TYPE      = 38700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$geli$0$7$22$128$0$1$1000000$6766eb29e48dacb779060e57047a40f5a652810f3c20dd0eb81dbe8cd86cc7c5c5da0fa4d0336a789719894708ce9feed9529d52d9e6be9e83f1b2a998d674e0$7ed5e5f9eedd2f78f9b8665db67caedf46c45fb55c0ee8069749cd92b6d48a4d8d4d7a8d4917af1d63d8c1d4d7e1d7dce5f530b3208edc31d32c4d7156575d59332261c24fcbb0252ac9c70a2c0ae274819263d216dd2b9a7281c40a852b090bccabea718c87f0cb926444783792607803893a1d9a3fdc689dd75978ead7bd2b2392b1378a24d3794c422fd22638cde2d15dcb5cca97f41355d0b07d0cd329dcdbf7009013559d64e91fa2c7d8589e9b8aec0caa99955d03e287040f1743ec0e5da9a8d67331c7261d0127f67ddae8af8c790da48bcb34f38bda537250b62acf6082d6adfda42157c67313bfabc59ec63c5ccd897f12386baab56294658f23b53dde1c63935ac959b2f9af295a156a879e0675e1094a2bc0307d2f5a5adbe99687d221bdaccc22f119e3a9c85598711bffb58c33d415dbbdea4f0589de6c4fa722e5348d7ae3b58b52c8319a949e6b6ce640cee254c6e3f5dc39f2c73ed53e932586b01b281c66f2a77d49f20a9d08506ad55821d1adefea40536c39e87c2a8a";

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

static const char *SIGNATURE_GELI = "$geli$";

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/geli2hashcat.py to extract the hashes";
}

// The lengths of sys/geom/eli/g_eli.h. A master key slot holds the Data-Key, the IV-Key and the
// HMAC-SHA512 that the two are checked with, and md_keys says which of the two slots are in use.

#define G_ELI_SALTLEN       64
#define G_ELI_MKEYLEN      192
#define G_ELI_MAXMKEYS       2

#define G_ELI_VERSION        7

// The encryption algorithms of sys/opencrypto/cryptodev.h that a provider may name. AES-XTS is
// here because the metadata of such a provider is written with AES-CBC all the same, which is what
// g_eli_crypto_encrypt () falls back to, so the kernel never runs XTS.

#define CRYPTO_AES_CBC      11
#define CRYPTO_NULL_CBC     16
#define CRYPTO_CAMELLIA_CBC 21
#define CRYPTO_AES_XTS      22

// version and aalgo take no part in the check: md_aalgo is read only where a provider
// authenticates its data, which the master key is not covered by. They are kept so that a line
// goes back out the way it came in.

typedef struct geli
{
  u32 version;
  u32 ealgo;
  u32 keylen;
  u32 aalgo;
  u32 keys;
  u32 iterations;

  u32 mkeys[(G_ELI_MAXMKEYS * G_ELI_MKEYLEN) / 4];

} geli_t;

typedef struct pbkdf2_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} pbkdf2_sha512_tmp_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (geli_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  geli_t *geli = (geli_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  /**
   * $geli$0$<md_version>$<md_ealgo>$<md_keylen>$<md_aalgo>$<md_keys>$<md_iterations>$<md_salt>$<md_mkeys>
   *
   * The leading 0 is the version of the line itself rather than of the metadata, which is what
   * tools/geli2hashcat.py and John's geli2john.py both write.
   */

  token.token_cnt = 10;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_GELI;

  token.len[0]     = (int) strlen (SIGNATURE_GELI);
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 4;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 1;
  token.len_max[5] = 2;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '$';
  token.len_min[6] = 1;
  token.len_max[6] = 3;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[7]     = '$';
  token.len_min[7] = 1;
  token.len_max[7] = 10;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]     = '$';
  token.len[8]     = G_ELI_SALTLEN * 2;
  token.attr[8]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[9]     = '$';
  token.len[9]     = G_ELI_MAXMKEYS * G_ELI_MKEYLEN * 2;
  token.attr[9]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // the version of the line, which is the only one there has ever been

  if (hc_strtoul ((const char *) token.buf[1], NULL, 10) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  const u32 version = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (version > G_ELI_VERSION) return (PARSER_SALT_VALUE);

  geli->version = version;

  geli->aalgo = hc_strtoul ((const char *) token.buf[5], NULL, 10);

  const u32 ealgo  = hc_strtoul ((const char *) token.buf[3], NULL, 10);
  const u32 keylen = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  // the key lengths g_eli_keylen () gives back, which is what geli(8) resolves its -l option
  // through and refuses to create a provider for when it answers 0

  switch (ealgo)
  {
    case CRYPTO_AES_CBC:
    case CRYPTO_CAMELLIA_CBC:  if ((keylen != 128) && (keylen != 192) && (keylen != 256)) return (PARSER_SALT_VALUE);
                               break;
    case CRYPTO_AES_XTS:       if ((keylen != 128) && (keylen != 256)) return (PARSER_SALT_VALUE);
                               break;
    case CRYPTO_NULL_CBC:      if (keylen > (64 * 8)) return (PARSER_SALT_VALUE);
                               break;
    default:                   return (PARSER_CIPHER);
  }

  geli->ealgo  = ealgo;
  geli->keylen = keylen;

  const u32 keys = hc_strtoul ((const char *) token.buf[6], NULL, 10);

  // md_keys is a bit per slot, and a provider with none of them set holds no master key to open.
  // g_eli_mkey_decrypt () reads one bit per slot and ignores the rest, so the rest is ignored here.

  if ((keys & ((1 << G_ELI_MAXMKEYS) - 1)) == 0) return (PARSER_SALT_VALUE);

  geli->keys = keys;

  // md_iterations is an int32_t on disk. A provider whose -1 says it opens with a keyfile and no
  // passphrase is one geli2hashcat.py refuses to write out, and 0 is a provider the user asked to
  // do without PKCS#5v2.

  // read as 64 bit, because hc_strtoul () casts to u32 and a ten digit token past UINT32_MAX would
  // wrap into a value the bound below accepts

  const u64 iterations = hc_strtoull ((const char *) token.buf[7], NULL, 10);

  if (iterations > (u64) INT32_MAX) return (PARSER_SALT_ITERATION);

  geli->iterations = (u32) iterations;

  // the first PBKDF2 iteration is the init kernel's, so the loop kernel runs the rest. Without
  // PKCS#5v2 there is no loop at all, and hashcat launches it zero times.

  salt->salt_iter = (iterations > 0) ? (u32) (iterations - 1) : 0;

  const u8 *salt_pos = token.buf[8];

  for (int i = 0, j = 0; i < G_ELI_SALTLEN / 4; i += 1, j += 8)
  {
    salt->salt_buf[i] = hex_to_u32 (salt_pos + j);
  }

  salt->salt_len = G_ELI_SALTLEN;

  const u8 *mkeys_pos = token.buf[9];

  for (int i = 0, j = 0; i < (G_ELI_MAXMKEYS * G_ELI_MKEYLEN) / 4; i += 1, j += 8)
  {
    geli->mkeys[i] = hex_to_u32 (mkeys_pos + j);
  }

  // the kernel says whether a candidate opens a slot, so the digest is only what hashcat sorts and
  // deduplicates the line by. The salt is the provider's own and is random per provider, and two
  // words of each slot keep two providers apart that differ in one slot alone.

  digest[0] = geli->mkeys[0];
  digest[1] = geli->mkeys[1];
  digest[2] = geli->mkeys[(G_ELI_MKEYLEN / 4) + 0];
  digest[3] = geli->mkeys[(G_ELI_MKEYLEN / 4) + 1];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const geli_t *geli = (const geli_t *) esalt_buf;

  char *salt_hex = (char *) hcmalloc ((G_ELI_SALTLEN * 2) + 1);

  for (int i = 0; i < G_ELI_SALTLEN / 4; i++)
  {
    u32_to_hex (salt->salt_buf[i], (u8 *) salt_hex + (i * 8));
  }

  char *mkeys_hex = (char *) hcmalloc ((G_ELI_MAXMKEYS * G_ELI_MKEYLEN * 2) + 1);

  for (int i = 0; i < (G_ELI_MAXMKEYS * G_ELI_MKEYLEN) / 4; i++)
  {
    u32_to_hex (geli->mkeys[i], (u8 *) mkeys_hex + (i * 8));
  }

  const int line_len = snprintf (line_buf, line_size, "%s0$%u$%u$%u$%u$%u$%u$%s$%s",
    SIGNATURE_GELI,
    geli->version,
    geli->ealgo,
    geli->keylen,
    geli->aalgo,
    geli->keys,
    geli->iterations,
    salt_hex,
    mkeys_hex);

  hcfree (salt_hex);
  hcfree (mkeys_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_benchmark_cost           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_hints               = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hash_recipe              = MODULE_DEFAULT;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
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
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_bits                = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_length_sort              = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_register_options         = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = module_usage_notice;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
