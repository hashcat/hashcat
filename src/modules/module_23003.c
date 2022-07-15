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
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "SecureZIP AES-256";
static const u64   KERN_TYPE      = 23003;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS15
                                  | OPTS_TYPE_MAXIMUM_THREADS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$zip3$*0*1*256*0*39bff47df6152a0214d7a967*65ff418ffb3b1198cccdef0327c03750f328d6dd5287e00e4c467f33b92a6ef40a74bb11b5afad61a6c3c9b279d8bd7961e96af7b470c36fc186fd3cfe059107021c9dea0cf206692f727eeca71f18f5b0b6ee1f702b648bba01aa21c7b7f3f0f7d547838aad46868155a04214f22feef7b31d7a15e1abe6dba5e569c62ee640783bb4a54054c2c69e93ece9f1a2af9d*0*0*0*file.txt";

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

typedef struct securezip
{
  u32 data[36];
  u32 file[16];
  u32 iv[4];
  u32 iv_len;

} securezip_t;

static const char *SIGNATURE_SECUREZIP = "$zip3$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (securezip_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  securezip_t *securezip = (securezip_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt   = 11;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SECUREZIP;

  token.len_min[0]  = 6;
  token.len_max[0]  = 6;
  token.sep[0]      = '*';
  token.attr[0]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1]  = 1;
  token.len_max[1]  = 1;
  token.sep[1]      = '*';
  token.attr[1]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2]  = 1;
  token.len_max[2]  = 1;
  token.sep[2]      = '*';
  token.attr[2]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[3]  = 3;
  token.len_max[3]  = 3;
  token.sep[3]      = '*';
  token.attr[3]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4]  = 1;
  token.len_max[4]  = 1;
  token.sep[4]      = '*';
  token.attr[4]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[5]  = 0;
  token.len_max[5]  = 32;
  token.sep[5]      = '*';
  token.attr[5]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[6]  = 288;
  token.len_max[6]  = 288;
  token.sep[6]      = '*';
  token.attr[6]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[7]  = 1;
  token.len_max[7]  = 1;
  token.sep[7]      = '*';
  token.attr[7]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[8]  = 1;
  token.len_max[8]  = 1;
  token.sep[8]      = '*';
  token.attr[8]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[9]  = 1;
  token.len_max[9]  = 1;
  token.sep[9]      = '*';
  token.attr[9]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[10] = 0;
  token.len_max[10] = 64;
  token.sep[10]     = '*';
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos = token.buf[ 1];
  const u8 *type_pos    = token.buf[ 2];
  const u8 *bit_len_pos = token.buf[ 3];
  const u8 *unused1_pos = token.buf[ 4];
  const u8 *iv_pos      = token.buf[ 5];
  const u8 *data_pos    = token.buf[ 6];
  const u8 *unused2_pos = token.buf[ 7];
  const u8 *unused3_pos = token.buf[ 8];
  const u8 *unused4_pos = token.buf[ 9];
  const u8 *file_pos    = token.buf[10];

  if (version_pos[0] != '0') return (PARSER_HASH_ENCODING); // version 0
  if (type_pos[0]    != '1') return (PARSER_HASH_ENCODING); // AES

  const u32 bit_len = hc_strtoul ((const char *) bit_len_pos, NULL, 10);

  if (bit_len != 256) return (PARSER_HASH_ENCODING);

  if (unused1_pos[0] != '0') return (PARSER_HASH_ENCODING);
  if (unused2_pos[0] != '0') return (PARSER_HASH_ENCODING);
  if (unused3_pos[0] != '0') return (PARSER_HASH_ENCODING);
  if (unused4_pos[0] != '0') return (PARSER_HASH_ENCODING);

  // IV:

  u8 *iv = (u8 *) securezip->iv;

  securezip->iv_len = hex_decode (iv_pos, token.len[5], iv);

  // data:

  u32 *data = securezip->data;

  hex_decode (data_pos, token.len[6], (u8 *) data);

  // file:

  u8 *file = (u8 *) securezip->file;

  memcpy (file, file_pos, token.len[10]);

  file[63] = 0;

  // fake salt:

  salt->salt_buf[0] = iv[0];
  salt->salt_buf[1] = iv[1];
  salt->salt_buf[2] = iv[2];
  salt->salt_buf[3] = iv[3];

  salt->salt_len  = 16;

  // fake digest:

  digest[0] = data[0];
  digest[1] = data[1];
  digest[2] = data[2];
  digest[3] = data[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const securezip_t *securezip = (const securezip_t *) esalt_buf;

  // IV:

  u8 iv[33] = { 0 };

  hex_encode ((u8 *) securezip->iv, securezip->iv_len, iv);

  // data:

  u8 data[289] = { 0 };

  hex_encode ((u8 *) securezip->data, 144, data);

  // file:

  const u8 *file_ptr = (const u8 *) securezip->file;

  u8 file[65] = { 0 };

  memcpy (file, file_ptr, 64);

  int out_len = snprintf (line_buf, line_size, "%s*0*1*256*0*%s*%s*0*0*0*%s",
    SIGNATURE_SECUREZIP,
    iv,
    data,
    file
  );

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
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
