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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PRIVATE_KEY;
static const char *HASH_NAME      = "Apple DMG (encrcdsa v3, PBKDF2-HMAC-SHA1 + AES-192 keyblob)";
static const u64   KERN_TYPE      = 90000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "po99oo";
static const char *ST_HASH        = "$dmg$3*20*20a528dfdc3dc653d5da26923cd7b07d03eda76e*192*64*17b5d1683f6cd8b076943f1397d96f2d7a966596bd4c816334f444b26c33b6dd1a2f309a375ed9c3a612b5877c75ea6c2f3053fdb4c2b9a477d6291573fcb7cd*384615";

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

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/openwall/john/blob/bleeding-jumbo/run/pem2john.py to extract the hashes";
}

#define PKCS_MIN_SALT_LEN     ( 8)
#define PKCS_MAX_SALT_LEN     (32)
#define PKCS_MIN_SALT_HEX_LEN (PKCS_MIN_SALT_LEN * 2)
#define PKCS_MAX_SALT_HEX_LEN (PKCS_MAX_SALT_LEN * 2)

#define PKCS_MIN_IV_LEN     ( 8)
#define PKCS_MAX_IV_LEN     (16)
#define PKCS_MIN_IV_HEX_LEN (PKCS_MIN_IV_LEN * 2)
#define PKCS_MAX_IV_HEX_LEN (PKCS_MAX_IV_LEN * 2)

typedef enum pkcs_cipher {
  PKCS_CIPHER_3DES        = 1,
  PKCS_CIPHER_AES_128_CBC = 2,
  PKCS_CIPHER_AES_192_CBC = 3,
  PKCS_CIPHER_AES_256_CBC = 4,
} pkcs_cipher_t;

typedef enum pkcs_cipher_block_size {
  PKCS_CIPHER_BLOCK_SIZE_3DES        =  8,
  PKCS_CIPHER_BLOCK_SIZE_AES_128_CBC = 16,
  PKCS_CIPHER_BLOCK_SIZE_AES_192_CBC = 16,
  PKCS_CIPHER_BLOCK_SIZE_AES_256_CBC = 16,
} pkcs_cipher_block_size_t;

typedef struct pkcs_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pkcs_sha1_tmp_t;

typedef struct pkcs
{
  int cipher; // pkcs_cipher_t

  u32 data_buf[16384];
  int data_len;

  u32 iv_buf[4];

} pkcs_t;

static const char *SIGNATURE_DMG = "$dmg$3";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pkcs_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pkcs_sha1_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  pkcs_t *pkcs = (pkcs_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DMG;

  token.sep[0]     = '*';   // разделитель после подписи "$dmg$3"
  token.len[0]     = 6; // "$dmg$3"
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';   // salt len (bytes)
  token.len_min[1] = 1;
  token.len_max[1] = 2;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';   // salt hex
  token.len_min[2] = 16;
  token.len_max[2] = 64;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';   // key bits (192)
  token.len_min[3] = 3;
  token.len_max[3] = 3;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';   // keyblob len (64)
  token.len_min[4] = 2;
  token.len_max[4] = 3;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';   // keyblob hex (64 bytes)
  token.len_min[5] = 128;
  token.len_max[5] = 128;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[6] = 1;     // iterations (последний токен, без sep)
  token.len_max[6] = 8;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt
  salt->salt_len = hex_decode (token.buf[2], token.len[2], (u8 *) salt->salt_buf);

  // iterations
  const u32 iter = hc_strtoul ((const char *) token.buf[6], NULL, 10);
  if (iter < 1) return (PARSER_SALT_ITERATION);
  salt->salt_iter = iter - 1;

  // keyblob -> esalt (AES-192)
  pkcs->cipher   = PKCS_CIPHER_AES_192_CBC;
  pkcs->data_len = hex_decode (token.buf[5], token.len[5], (u8 *) pkcs->data_buf);
  if (pkcs->data_len != 64) return (PARSER_HASH_LENGTH);

  // косметический digest = первые 4 слова keyblob (реальная проверка — CKIE в ядре)
  digest[0] = pkcs->data_buf[0];
  digest[1] = pkcs->data_buf[1];
  digest[2] = pkcs->data_buf[2];
  digest[3] = pkcs->data_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const pkcs_t *pkcs = (const pkcs_t *) esalt_buf;

  char salt_buf[65] = { 0 };
  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_buf);

  char data_buf[129] = { 0 };
  hex_encode ((const u8 *) pkcs->data_buf, pkcs->data_len, (u8 *) data_buf);

  const int out_len = snprintf (line_buf, line_size, "%s*%d*%s*192*%d*%s*%u",
    SIGNATURE_DMG,
    salt->salt_len,
    salt_buf,
    pkcs->data_len,
    data_buf,
    salt->salt_iter + 1);

  return out_len;
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
