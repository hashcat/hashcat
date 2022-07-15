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
#include "emu_inc_hash_sha256.h"

static const u32 ATTACK_EXEC   = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32 DGST_POS0     = 0;
static const u32 DGST_POS1     = 1;
static const u32 DGST_POS2     = 2;
static const u32 DGST_POS3     = 3;
static const u32 DGST_SIZE     = DGST_SIZE_4_8;
static const u32 HASH_CATEGORY = HASH_CATEGORY_DATABASE_SERVER;
static const char *HASH_NAME   = "PostgreSQL SCRAM-SHA-256";
static const u64 KERN_TYPE     = 28600;
static const u32 OPTI_TYPE     = OPTI_TYPE_ZERO_BYTE
                               | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64 OPTS_TYPE     = OPTS_TYPE_STOCK_MODULE
                               | OPTS_TYPE_PT_GENERATE_LE
                               | OPTS_TYPE_ST_BASE64;
static const u32 SALT_TYPE     = SALT_TYPE_EMBEDDED;
static const char *ST_PASS     = "hashcat";
static const char *ST_HASH     = "SCRAM-SHA-256$4096:IKfxzJ8Nq4PkLJCfgKcPmA==$"
                                 "iRw3qwTp18uaBnsTOEExbtgWdKeBMbSSnZvqD4sdqLQ=:"
                                 "hPciC1CcnBna3szR8Mf3MVc8t0W7QPbIHoMMrh4zRV0=";

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


typedef struct postgres_sha256_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} postgres_sha256_tmp_t;

typedef struct postgres_sha256
{
  u32 salt[16];
  u32 storedKey[16];

  u32 salt_len;
  u32 storedKey_len;

} postgres_sha256_t;

static const char *SIGNATURE_POSTGRES_SHA256 = "SCRAM-SHA-256";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // NVIDIA GPU
  if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // HIP
  if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // ROCM
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) &&
      (device_param->has_vperm == true))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (postgres_sha256_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (postgres_sha256_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is
  // selected IOW, even in optimized kernel mode it support length 256

  const u32 pw_max = PW_MAX;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  postgres_sha256_t *postgres_sha256 = (postgres_sha256_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt = 5;

  token.signatures_cnt = 1;
  token.signatures_buf[0] = SIGNATURE_POSTGRES_SHA256;

  token.sep[0]     = '$';
  token.len_min[0] = 13;
  token.len_max[0] = 13;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = ':';
  token.len_min[1] = 1;
  token.len_max[1] = 7;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 0;
  token.len_max[2] = 88;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = ':';
  token.len_min[3] = 44;
  token.len_max[3] = 44;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len[4]     = 44;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt
  u8 tmp_buf[100] = { 0 };

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  int tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len > 64) return (PARSER_SALT_LENGTH);

  memcpy (postgres_sha256->salt, tmp_buf, tmp_len);

  postgres_sha256->salt[ 0] = byte_swap_32 (postgres_sha256->salt[ 0]);
  postgres_sha256->salt[ 1] = byte_swap_32 (postgres_sha256->salt[ 1]);
  postgres_sha256->salt[ 2] = byte_swap_32 (postgres_sha256->salt[ 2]);
  postgres_sha256->salt[ 3] = byte_swap_32 (postgres_sha256->salt[ 3]);
  postgres_sha256->salt[ 4] = byte_swap_32 (postgres_sha256->salt[ 4]);
  postgres_sha256->salt[ 5] = byte_swap_32 (postgres_sha256->salt[ 5]);
  postgres_sha256->salt[ 6] = byte_swap_32 (postgres_sha256->salt[ 6]);
  postgres_sha256->salt[ 7] = byte_swap_32 (postgres_sha256->salt[ 7]);
  postgres_sha256->salt[ 8] = byte_swap_32 (postgres_sha256->salt[ 8]);
  postgres_sha256->salt[ 9] = byte_swap_32 (postgres_sha256->salt[ 9]);
  postgres_sha256->salt[10] = byte_swap_32 (postgres_sha256->salt[10]);
  postgres_sha256->salt[11] = byte_swap_32 (postgres_sha256->salt[11]);
  postgres_sha256->salt[12] = byte_swap_32 (postgres_sha256->salt[12]);
  postgres_sha256->salt[13] = byte_swap_32 (postgres_sha256->salt[13]);
  postgres_sha256->salt[14] = byte_swap_32 (postgres_sha256->salt[14]);
  postgres_sha256->salt[15] = byte_swap_32 (postgres_sha256->salt[15]);

  postgres_sha256->salt_len = tmp_len;
  salt->salt_len            = tmp_len;

  salt->salt_buf[ 0] = postgres_sha256->salt[ 0];
  salt->salt_buf[ 1] = postgres_sha256->salt[ 1];
  salt->salt_buf[ 2] = postgres_sha256->salt[ 2];
  salt->salt_buf[ 3] = postgres_sha256->salt[ 3];
  salt->salt_buf[ 4] = postgres_sha256->salt[ 4];
  salt->salt_buf[ 5] = postgres_sha256->salt[ 5];
  salt->salt_buf[ 6] = postgres_sha256->salt[ 6];
  salt->salt_buf[ 7] = postgres_sha256->salt[ 7];
  salt->salt_buf[ 8] = postgres_sha256->salt[ 8];
  salt->salt_buf[ 9] = postgres_sha256->salt[ 9];
  salt->salt_buf[10] = postgres_sha256->salt[10];
  salt->salt_buf[11] = postgres_sha256->salt[11];
  salt->salt_buf[12] = postgres_sha256->salt[12];
  salt->salt_buf[13] = postgres_sha256->salt[13];
  salt->salt_buf[14] = postgres_sha256->salt[14];
  salt->salt_buf[15] = postgres_sha256->salt[15];

  // stored key
  const u8 *stored_key_pos = token.buf[3];
  const int stored_key_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, stored_key_pos, stored_key_len, tmp_buf);

  memcpy (postgres_sha256->storedKey, tmp_buf, tmp_len);

  postgres_sha256->storedKey_len = tmp_len;

  // server key

  const u8 *hash_pos = token.buf[4];
  const int hash_len = token.len[4];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  u32 *digest = (u32 *) digest_buf;

  postgres_sha256_t *postgres_sha256 = (postgres_sha256_t *) esalt_buf;

  // salt

  u32 salt_buf[8] = { 0 }; // make the buffer large enough for base64_encode ()

  salt_buf[0] = byte_swap_32 (postgres_sha256->salt[0]);
  salt_buf[1] = byte_swap_32 (postgres_sha256->salt[1]);
  salt_buf[2] = byte_swap_32 (postgres_sha256->salt[2]);
  salt_buf[3] = byte_swap_32 (postgres_sha256->salt[3]);
  salt_buf[4] = byte_swap_32 (postgres_sha256->salt[4]);
  salt_buf[5] = byte_swap_32 (postgres_sha256->salt[5]);
  salt_buf[6] = byte_swap_32 (postgres_sha256->salt[6]);
  salt_buf[7] = byte_swap_32 (postgres_sha256->salt[7]);

  u8 salt_base64[64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt_buf, salt->salt_len, salt_base64);

  // server key

  u32 hash[8] = { 0 }; // make the buffer large enough for base64_encode ()

  hash[0] = byte_swap_32 (digest[0]);
  hash[1] = byte_swap_32 (digest[1]);
  hash[2] = byte_swap_32 (digest[2]);
  hash[3] = byte_swap_32 (digest[3]);
  hash[4] = byte_swap_32 (digest[4]);
  hash[5] = byte_swap_32 (digest[5]);
  hash[6] = byte_swap_32 (digest[6]);
  hash[7] = byte_swap_32 (digest[7]);

  u8 server_key_base64[64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) hash, 32, server_key_base64);

  // stored key

  u8 stored_key_bin[100] = { 0 };

  memcpy (stored_key_bin, (char *) postgres_sha256->storedKey, postgres_sha256->storedKey_len);

  u8 stored_key_base64[64] = { 0 };

  base64_encode (int_to_base64, stored_key_bin, postgres_sha256->storedKey_len, stored_key_base64);

  // print final line

  const int line_len = snprintf (line_buf, line_size, "%s$%u:%s$%s:%s",
                                 SIGNATURE_POSTGRES_SHA256,
                                 salt->salt_iter + 1,
                                 salt_base64,
                                 stored_key_base64,
                                 server_key_base64);
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
  module_ctx->module_jit_build_options        = module_jit_build_options;
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
