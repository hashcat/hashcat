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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "Android Backup";
static const u64   KERN_TYPE      = 18900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$ab$5*0*10000*b8900e4885ff9cad8f01ee1957a43bd633fea12491440514ae27aa83f2f5c006ec7e7fa0bce040add619919b4eb60608304b7d571a2ed87fd58c9ad6bc5fcf4c*7d254d93e16be9312fb1ccbfc6265c40cb0c5eab7b605a95a116e2383fb1cf12b688223f96221dcd2bf5410d4ca6f90e0789ee00157fa91658b42665d6b6844c*fc9f6be604d1c59ac32664ec2c5b9b30*00c4972149af3adcc235899e9d20611ea6e8de2212afcb9fcfefde7e35b691c2d0994eb47e4f9a260526ba47f4caea71af9c7fadcd5685d50126276f6acdd59966528b13ccc26036a0eaba2f2451aa64b05766d0edd03c988dcf87e2a9eec52d";

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

typedef struct android_backup_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} android_backup_tmp_t;

typedef struct android_backup
{
  u32 version;
  u32 cipher;
  u32 iter;
  u32 user_salt[16];
  u32 ck_salt[16];
  u32 user_iv[4];
  u32 masterkey_blob[24];

} android_backup_t;

static const char *SIGNATURE_ANDROID_BACKUP = "$ab$";

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // AMD Radeon Pro W5700X Compute Engine; 1.2 (Apr 22 2021 21:54:44); 11.3.1; 20E241
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == false)
    {
      return true;
    }
  }

  return false;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (android_backup_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (android_backup_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = PW_MAX;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  android_backup_t *android_backup = (android_backup_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ANDROID_BACKUP;

  // signature
  token.len[0]     = 4;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // version
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // cipher
  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // iter
  token.len_min[3] = 1;
  token.len_max[3] = 6;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // user_salt
  token.len_min[4] = 128;
  token.len_max[4] = 128;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // ck_salt
  token.len_min[5] = 128;
  token.len_max[5] = 128;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // user_iv
  token.len_min[6] = 32;
  token.len_max[6] = 32;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // masterkey_blob
  token.len_min[7] = 192;
  token.len_max[7] = 192;
  token.sep[7]     = '*';
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos         = token.buf[1];
  const u8 *cipher_pos          = token.buf[2];
  const u8 *iter_pos            = token.buf[3];
  const u8 *user_salt_pos       = token.buf[4];
  const u8 *ck_salt_pos         = token.buf[5];
  const u8 *user_iv_pos         = token.buf[6];
  const u8 *masterkey_blob_pos  = token.buf[7];

  // version

  const int version = hc_strtoul ((const char *) version_pos, NULL, 10);

  android_backup->version = version;

  // cipher

  const int cipher = hc_strtoul ((const char *) cipher_pos, NULL, 10);

  android_backup->cipher = cipher;

  // iter

  const int iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  android_backup->iter = iter;

  // user_salt

  for (int i = 0, j = 0; j < 128; i += 1, j += 8)
  {
    android_backup->user_salt[i] = hex_to_u32 ((const u8 *) user_salt_pos + j);
  }

  // ck_salt

  for (int i = 0, j = 0; j < 128; i += 1, j += 8)
  {
    android_backup->ck_salt[i] = hex_to_u32 ((const u8 *) ck_salt_pos + j);
  }

  // user_iv

  for (int i = 0, j = 0; j < 32; i += 1, j += 8)
  {
    android_backup->user_iv[i] = hex_to_u32 ((const u8 *) user_iv_pos + j);
  }

  // masterkey_blob

  for (int i = 0, j = 0; j < 192; i += 1, j += 8)
  {
    android_backup->masterkey_blob[i] = hex_to_u32 ((const u8 *) masterkey_blob_pos + j);
  }

  // make the entry unique in our databases

  salt->salt_buf[ 0] = android_backup->user_salt[ 0];
  salt->salt_buf[ 1] = android_backup->user_salt[ 1];
  salt->salt_buf[ 2] = android_backup->user_salt[ 2];
  salt->salt_buf[ 3] = android_backup->user_salt[ 3];
  salt->salt_buf[ 4] = android_backup->user_salt[ 4];
  salt->salt_buf[ 5] = android_backup->user_salt[ 5];
  salt->salt_buf[ 6] = android_backup->user_salt[ 6];
  salt->salt_buf[ 7] = android_backup->user_salt[ 7];
  salt->salt_buf[ 8] = android_backup->user_salt[ 8];
  salt->salt_buf[ 9] = android_backup->user_salt[ 9];
  salt->salt_buf[10] = android_backup->user_salt[10];
  salt->salt_buf[11] = android_backup->user_salt[11];
  salt->salt_buf[12] = android_backup->user_salt[12];
  salt->salt_buf[13] = android_backup->user_salt[13];
  salt->salt_buf[14] = android_backup->user_salt[14];
  salt->salt_buf[15] = android_backup->user_salt[15];

  salt->salt_len = 64;

  salt->salt_iter = android_backup->iter - 1;

  digest[0] = android_backup->masterkey_blob[0];
  digest[1] = android_backup->masterkey_blob[1];
  digest[2] = android_backup->masterkey_blob[2];
  digest[3] = android_backup->masterkey_blob[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const android_backup_t *android_backup = (const android_backup_t *) esalt_buf;

  int line_len = 0;

  line_len += snprintf (line_buf + line_len, line_size - line_len, "%s%u*%u*%u",
    SIGNATURE_ANDROID_BACKUP,
    android_backup->version,
    android_backup->cipher,
    android_backup->iter);

  line_buf[line_len++] = '*';

  for (int i = 0; i < 16; i++)
  {
    u32_to_hex (android_backup->user_salt[i], (u8 *) line_buf + line_len);

    line_len += 8;
  }

  line_buf[line_len++] = '*';

  for (int i = 0; i < 16; i++)
  {
    u32_to_hex (android_backup->ck_salt[i], (u8 *) line_buf + line_len);

    line_len += 8;
  }

  line_buf[line_len++] = '*';

  for (int i = 0; i < 4; i++)
  {
    u32_to_hex (android_backup->user_iv[i], (u8 *) line_buf + line_len);

    line_len += 8;
  }

  line_buf[line_len++] = '*';

  for (int i = 0; i < 24; i++)
  {
    u32_to_hex (android_backup->masterkey_blob[i], (u8 *) line_buf + line_len);

    line_len += 8;
  }

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
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
