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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DATABASE_SERVER;
static const char *HASH_NAME      = "MongoDB ServerKey SCRAM-SHA-1";
static const u64   KERN_TYPE      = 24100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_BASE64;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=";

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

typedef struct mongodb_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[5];
  u32  out[5];

} mongodb_sha1_tmp_t;

typedef struct mongodb_sha1
{
  u32 salt[16];
  u32 user[16];

  u32 user_len;

} mongodb_sha1_t;

static const char *SIGNATURE_MONGODB_SHA1 = "$mongodb-scram$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (mongodb_sha1_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (mongodb_sha1_tmp_t);

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

  mongodb_sha1_t *mongodb_sha1 = (mongodb_sha1_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MONGODB_SHA1;

  token.sep[0]     = '*';
  token.len_min[0] = 15;
  token.len_max[0] = 15;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 0;
  token.len_max[2] = 76; // BASE64 encoded user (57 / 3 * 4)
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 7;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len_min[4] = 24;
  token.len_max[4] = 24;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len[5]     = 28;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u8 *version_pos = token.buf[1];

  if (version_pos[0] != '0') return (PARSER_SIGNATURE_UNMATCHED);

  // user

  const u8 *user_pos = token.buf[2];
  const u32 user_len = token.len[2];

  u8 tmp_buf[100] = { 0 };

  int tmp_len = base64_decode (base64_to_int, user_pos, user_len, tmp_buf);

  if (tmp_len > 57) return (PARSER_SALT_LENGTH);

  memcpy ((char *) mongodb_sha1->user, tmp_buf, tmp_len);

  memcpy ((char *) mongodb_sha1->user + tmp_len, ":mongo:", 7);

  mongodb_sha1->user_len = tmp_len + 7;

  // iter

  const u8 *iter_pos = token.buf[3];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len != 16) return (PARSER_SALT_LENGTH);

  memcpy (mongodb_sha1->salt, tmp_buf, tmp_len);

  mongodb_sha1->salt[0] = byte_swap_32 (mongodb_sha1->salt[0]);
  mongodb_sha1->salt[1] = byte_swap_32 (mongodb_sha1->salt[1]);
  mongodb_sha1->salt[2] = byte_swap_32 (mongodb_sha1->salt[2]);
  mongodb_sha1->salt[3] = byte_swap_32 (mongodb_sha1->salt[3]);

  salt->salt_len = tmp_len;

  salt->salt_buf[0] = mongodb_sha1->salt[0];
  salt->salt_buf[1] = mongodb_sha1->salt[1];
  salt->salt_buf[2] = mongodb_sha1->salt[2];
  salt->salt_buf[3] = mongodb_sha1->salt[3];

  // hash

  const u8 *hash_pos = token.buf[5];
  const int hash_len = token.len[5];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len != 20) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  u32 *digest = (u32 *) digest_buf;

  mongodb_sha1_t *mongodb_sha1 = (mongodb_sha1_t *) esalt_buf;

  // salt

  u32 salt_buf[8] = { 0 }; // make the buffer large enough for base64_encode ()

  salt_buf[0] = byte_swap_32 (mongodb_sha1->salt[0]);
  salt_buf[1] = byte_swap_32 (mongodb_sha1->salt[1]);
  salt_buf[2] = byte_swap_32 (mongodb_sha1->salt[2]);
  salt_buf[3] = byte_swap_32 (mongodb_sha1->salt[3]);

  u8 salt_base64[32] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt_buf, 16, salt_base64);

  // digest

  u32 hash[8] = { 0 }; // make the buffer large enough for base64_encode ()

  hash[0] = byte_swap_32 (digest[0]);
  hash[1] = byte_swap_32 (digest[1]);
  hash[2] = byte_swap_32 (digest[2]);
  hash[3] = byte_swap_32 (digest[3]);
  hash[4] = byte_swap_32 (digest[4]);

  u8 dgst_base64[32] = { 0 };

  base64_encode (int_to_base64, (const u8 *) hash, 20, dgst_base64);

  // user

  u32 user_len = mongodb_sha1->user_len - 7;

  u8 user[100] = { 0 }; // actually: 64 - 7 (:mongo:)

  memcpy (user, (char *) mongodb_sha1->user, user_len);

  u8 user_base64[100] = { 0 };

  base64_encode (int_to_base64, (const u8 *) user, user_len, user_base64);

  const int line_len = snprintf (line_buf, line_size, "%s*0*%s*%u*%s*%s",
      SIGNATURE_MONGODB_SHA1,
      user_base64,
      salt->salt_iter + 1,
      salt_base64,
      dgst_base64);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
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
