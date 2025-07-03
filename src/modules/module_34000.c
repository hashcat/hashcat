/**
 * Author......: Netherlands Forensic Institute
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
static const u32   DGST_SIZE      = DGST_SIZE_8_16;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_GENERIC_KDF;
static const char *HASH_NAME      = "Argon2";
static const u64   KERN_TYPE      = 34000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_DIMY_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$argon2id$v=19$m=65536,t=3,p=1$FBMjI4RJBhIykCgol1KEJA$2ky5GAdhT1kH4kIgPN/oERE3Taiy43vNN70a3HpiKQU";

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

#include "argon2_common.c"

static const char *SIGNATURE_ARGON2D  = "$argon2d$";
static const char *SIGNATURE_ARGON2I  = "$argon2i$";
static const char *SIGNATURE_ARGON2ID = "$argon2id$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (argon2_options_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  argon2_options_t *options  = (argon2_options_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 3;
  token.signatures_buf[0] = SIGNATURE_ARGON2D;
  token.signatures_buf[1] = SIGNATURE_ARGON2I;
  token.signatures_buf[2] = SIGNATURE_ARGON2ID;

  token.len_min[0] = 9;
  token.len_max[0] = 10;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_VERIFY_SIGNATURE;

  // version
  token.len[1]     = 4;
  token.sep[1]     = '$';
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  // memoryUsageInKib
  token.len_min[2] = 3;
  token.len_max[2] = 12;
  token.sep[2]     = ',';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // iterations
  token.len_min[3] = 3;
  token.len_max[3] = 5;
  token.sep[3]     = ',';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // parallelism
  token.len_min[4] = 3;
  token.len_max[4] = 5;
  token.sep[4]     = '$';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  // salt
  token.len_min[5] = ((SALT_MIN * 8) / 6) + 0;
  token.len_max[5] = ((SALT_MAX * 8) / 6) + 3;
  token.sep[5]     = '$';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // target hash
  token.len_min[6] = ((  1 * 8) / 6) + 0;
  token.len_max[6] = ((128 * 8) / 6) + 3;
  token.sep[6]     = '$';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // signature sets argon2 typ

  const int sig_len = token.len[0];
  const u8 *sig_pos = token.buf[0];

  if      (memcmp (SIGNATURE_ARGON2D,  sig_pos, sig_len) == 0) options->type = 0;
  else if (memcmp (SIGNATURE_ARGON2I,  sig_pos, sig_len) == 0) options->type = 1;
  else if (memcmp (SIGNATURE_ARGON2ID, sig_pos, sig_len) == 0) options->type = 2;
  else
    return (PARSER_SIGNATURE_UNMATCHED);

  // argon2id config
  const u8 *ver_pos = token.buf[1];
  const u8 *mem_pos = token.buf[2];
  const u8 *it_pos  = token.buf[3];
  const u8 *par_pos = token.buf[4];

  options->version             = hc_strtoul ((const char *) ver_pos + 2, NULL, 10);
  options->memory_usage_in_kib = hc_strtoul ((const char *) mem_pos + 2, NULL, 10);
  options->iterations          = hc_strtoul ((const char *) it_pos  + 2, NULL, 10);
  options->parallelism         = hc_strtoul ((const char *) par_pos + 2, NULL, 10);

  if (options->version != 19 && options->version != 16) return (PARSER_HASH_VALUE);
  if (options->memory_usage_in_kib < 1) return (PARSER_HASH_VALUE);
  if (options->iterations < 1) return (PARSER_HASH_VALUE);
  if (options->parallelism < 1 || options->parallelism > 32) return (PARSER_HASH_VALUE);

  options->segment_length     = MAX (2, (options->memory_usage_in_kib / (ARGON2_SYNC_POINTS * options->parallelism)));
  options->lane_length        = options->segment_length * ARGON2_SYNC_POINTS;
  options->memory_block_count = options->lane_length * options->parallelism;

  // salt
  const int salt_len = token.len[5];
  const u8 *salt_pos = token.buf[5];

  salt->salt_iter = options->iterations * ARGON2_SYNC_POINTS;
  salt->salt_dimy = options->parallelism;
  salt->salt_len = base64_decode (base64_to_int, (const u8 *) salt_pos, salt_len, (u8 *) salt->salt_buf);

  // digest/ target hash
  const int digest_len = token.len[6];
  const u8 *digest_pos = token.buf[6];

  options->digest_len = base64_decode (base64_to_int, (const u8 *) digest_pos, digest_len, (u8 *) digest);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  u32 *digest = (u32 *) digest_buf;

  argon2_options_t *options  = (argon2_options_t *) esalt_buf;

  // salt
  char base64_salt[512] = { 0 };
  int len1 = base64_encode (int_to_base64, (const u8 *) salt->salt_buf, salt->salt_len, (u8 *) base64_salt);

  for (int i = len1 - 1; i >=0; i--) if (base64_salt[i] == '=') base64_salt[i] = 0;

  // digest
  char base64_digest[512] = { 0 };
  int len2 = base64_encode (int_to_base64, (const u8 *) digest, options->digest_len, (u8 *) base64_digest);

  for (int i = len2 - 1; i >=0; i--) if (base64_digest[i] == '=') base64_digest[i] = 0;

  // out

  const char *signature = NULL;

  switch (options->type)
  {
    case 0: signature = SIGNATURE_ARGON2D;  break;
    case 1: signature = SIGNATURE_ARGON2I;  break;
    case 2: signature = SIGNATURE_ARGON2ID; break;
  }

  u8 *out_buf = (u8 *) line_buf;

  const int out_len = snprintf ((char *) out_buf, line_size, "%sv=%d$m=%d,t=%d,p=%d$%s$%s",
    signature,
    options->version,
    options->memory_usage_in_kib,
    options->iterations,
    options->parallelism,
    base64_salt,
    base64_digest);

  return out_len;
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
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = argon2_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = argon2_module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = argon2_module_extra_tuningdb_block;
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
  module_ctx->module_jit_build_options        = argon2_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = argon2_module_kernel_threads_max;
  module_ctx->module_kernel_threads_min       = argon2_module_kernel_threads_min;
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
  module_ctx->module_tmp_size                 = argon2_module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}

