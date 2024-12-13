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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH_SALTED;
static const char *HASH_NAME      = "enc8 (base64 encoded MD5 with 4-byte salt)";
static const u64   KERN_TYPE      = 10;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                 | OPTI_TYPE_PRECOMPUTE_INIT
                                 | OPTI_TYPE_MEET_IN_MIDDLE
                                 | OPTI_TYPE_EARLY_SKIP
                                 | OPTI_TYPE_NOT_ITERATED
                                 | OPTI_TYPE_APPENDED_SALT
                                 | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                 | OPTS_TYPE_PT_GENERATE_LE
                                 | OPTS_TYPE_ST_ADD80
                                 | OPTS_TYPE_ST_ADDBITS14;
static const u32   SALT_TYPE      = SALT_TYPE_GENERIC;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "{enc8}D5CJdzcm8Wkn1hmHleiN9xE8wl0=";

static const char *SIGNATURE_ENC8 = "{enc8}";

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

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 1;

  // Check for {enc8} prefix
  const int signature_len = strlen (SIGNATURE_ENC8);

  if (line_len < signature_len) return (PARSER_SALT_LENGTH);

  if (strncmp (line_buf, SIGNATURE_ENC8, signature_len) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  const char *base64_str = line_buf + signature_len;
  const int base64_len = line_len - signature_len;

  if (base64_len < 16) return (PARSER_HASH_LENGTH);

  u8 tmp_buf[100] = { 0 };
  int tmp_len = base64_decode (base64_to_int, (const u8 *) base64_str, base64_len, tmp_buf);

  if (tmp_len < 20) return (PARSER_HASH_LENGTH); // 16 bytes hash + 4 bytes salt

  const u8 *hash_pos = tmp_buf;
  const u8 *salt_pos = tmp_buf + 16;  // Last 4 bytes are salt

  // Convert raw bytes to u32 values (4 bytes each)
  digest[0] = byte_swap_32 (*(u32 *)(hash_pos +  0));
  digest[1] = byte_swap_32 (*(u32 *)(hash_pos +  4));
  digest[2] = byte_swap_32 (*(u32 *)(hash_pos +  8));
  digest[3] = byte_swap_32 (*(u32 *)(hash_pos + 12));

  salt->salt_len = 4;
  memcpy (salt->salt_buf, salt_pos, salt->salt_len);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // Prepare the combined buffer (16 bytes hash + 4 bytes salt)
  u8 tmp_buf[20] = { 0 };

  // Store hash bytes directly
  u32 *tmp_ptr = (u32 *) tmp_buf;
  tmp_ptr[0] = byte_swap_32 (digest[0]);
  tmp_ptr[1] = byte_swap_32 (digest[1]);
  tmp_ptr[2] = byte_swap_32 (digest[2]);
  tmp_ptr[3] = byte_swap_32 (digest[3]);

  // Append salt
  memcpy (tmp_buf + 16, salt->salt_buf, salt->salt_len);

  // Base64 encode the combined buffer
  char *out_buf = line_buf;
  int out_len = 0;

  memcpy (out_buf, SIGNATURE_ENC8, strlen (SIGNATURE_ENC8));
  out_len += strlen (SIGNATURE_ENC8);

  out_len += base64_encode (int_to_base64, tmp_buf, 20, (u8 *) out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec             = module_attack_exec;
  module_ctx->module_benchmark_esalt         = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt     = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask          = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset       = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt          = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel        = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice       = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0               = module_dgst_pos0;
  module_ctx->module_dgst_pos1               = module_dgst_pos1;
  module_ctx->module_dgst_pos2               = module_dgst_pos2;
  module_ctx->module_dgst_pos3               = module_dgst_pos3;
  module_ctx->module_dgst_size               = module_dgst_size;
  module_ctx->module_dictstat_disable        = MODULE_DEFAULT;
  module_ctx->module_esalt_size              = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size       = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size          = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block    = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format   = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count       = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse       = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save        = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile     = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash   = MODULE_DEFAULT;
  module_ctx->module_hash_decode             = module_hash_decode;
  module_ctx->module_hash_encode_status      = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile     = MODULE_DEFAULT;
  module_ctx->module_hash_encode             = module_hash_encode;
  module_ctx->module_hash_init_selftest      = MODULE_DEFAULT;
  module_ctx->module_hash_mode               = MODULE_DEFAULT;
  module_ctx->module_hash_category           = module_hash_category;
  module_ctx->module_hash_name               = module_hash_name;
  module_ctx->module_hashes_count_min        = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max        = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable           = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size   = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init   = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term   = MODULE_DEFAULT;
  module_ctx->module_hook12                  = MODULE_DEFAULT;
  module_ctx->module_hook23                  = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size          = MODULE_DEFAULT;
  module_ctx->module_hook_size               = MODULE_DEFAULT;
  module_ctx->module_jit_build_options       = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable       = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min        = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max        = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min        = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max      = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min      = MODULE_DEFAULT;
  module_ctx->module_kern_type               = module_kern_type;
  module_ctx->module_kern_type_dynamic       = MODULE_DEFAULT;
  module_ctx->module_opti_type               = module_opti_type;
  module_ctx->module_opts_type               = module_opts_type;
  module_ctx->module_outfile_check_disable   = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp    = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check    = MODULE_DEFAULT;
  module_ctx->module_potfile_disable         = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes = MODULE_DEFAULT;
  module_ctx->module_pwdump_column           = MODULE_DEFAULT;
  module_ctx->module_pw_max                  = MODULE_DEFAULT;
  module_ctx->module_pw_min                  = MODULE_DEFAULT;
  module_ctx->module_salt_max                = MODULE_DEFAULT;
  module_ctx->module_salt_min                = MODULE_DEFAULT;
  module_ctx->module_salt_type               = module_salt_type;
  module_ctx->module_separator               = MODULE_DEFAULT;
  module_ctx->module_st_hash                 = module_st_hash;
  module_ctx->module_st_pass                 = module_st_pass;
  module_ctx->module_tmp_size                = MODULE_DEFAULT;
  module_ctx->module_unstable_warning        = MODULE_DEFAULT;
  module_ctx->module_warmup_disable          = MODULE_DEFAULT;

  return;
}
