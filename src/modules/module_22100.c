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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "BitLocker";
static const u64   KERN_TYPE      = 22100;
static const u32   OPTI_TYPE      = OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb";

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

#define ITERATION_BITLOCKER 0x100000
#define SALT_LEN_BITLOCKER  16
#define IV_LEN_BITLOCKER    12
#define DATA_LEN_BITLOCKER  60

typedef struct bitlocker
{
  u32 type;
  u32 iv[4];
  u32 data[15];
  u32 wb_ke_pc[ITERATION_BITLOCKER][48];

} bitlocker_t;

typedef struct bitlocker_tmp
{
  u32 last_hash[8];
  u32 init_hash[8];

} bitlocker_tmp_t;

static const char *SIGNATURE_BITLOCKER = "$bitlocker$";

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
    hc_asprintf (&jit_build_options, "-D _unroll -D FORCE_DISABLE_SHM");
  }

  // AMD-GPU-PRO
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == false))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // HIP
  if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // ROCM
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == true))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (bitlocker_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bitlocker_tmp_t);

  return tmp_size;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 4096;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 4096;

  return kernel_loops_max;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings
  // The startup PIN must have a minimum length of 4 digits, and it can have a maximum length of 20 digits. By default, the minimum PIN length is 6.

  const u32 pw_min = 4;

  return pw_min;
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

  bitlocker_t *bitlocker = (bitlocker_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 9;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BITLOCKER;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 2;
  token.len_max[2] = 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 7;
  token.len_max[4] = 7;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 2;
  token.len_max[5] = 2;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '$';
  token.len_min[6] = 24;
  token.len_max[6] = 24;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '$';
  token.len_min[7] = 2;
  token.len_max[7] = 2;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]     = '$';
  token.len_min[8] = 120;
  token.len_max[8] = 120;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type

  const u8 *type_pos = token.buf[1];

  const u32 type = hc_strtoul ((const char *) type_pos, NULL, 10);

  if ((type != 0) && (type != 1)) return PARSER_SALT_VALUE;

  bitlocker->type = type;

  // salt

  const u8 *salt_len_pos = token.buf[2];

  const u32 salt_len = hc_strtoul ((const char *) salt_len_pos, NULL, 10);

  if (salt_len != SALT_LEN_BITLOCKER) return PARSER_SALT_LENGTH;

  const u8 *salt_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  salt->salt_len = SALT_LEN_BITLOCKER;

  // wb_ke_pc

  for (int i = 0; i < ITERATION_BITLOCKER; i++)
  {
    u32 tmp[64];

    tmp[ 0] = salt->salt_buf[0];
    tmp[ 1] = salt->salt_buf[1];
    tmp[ 2] = salt->salt_buf[2];
    tmp[ 3] = salt->salt_buf[3];
    tmp[ 4] = byte_swap_32 (i);
    tmp[ 5] = 0;
    tmp[ 6] = 0x80000000;
    tmp[ 7] = 0;
    tmp[ 8] = 0;
    tmp[ 9] = 0;
    tmp[10] = 0;
    tmp[11] = 0;
    tmp[12] = 0;
    tmp[13] = 0;
    tmp[14] = 0;
    tmp[15] = 88 * 8;

    #define hc_rotl32_S rotl32

    for (int j = 16; j < 64; j++)
    {
      tmp[j] = SHA256_EXPAND_S (tmp[j - 2], tmp[j - 7], tmp[j - 15], tmp[j - 16]);
    }

    for (int j = 0; j < 48; j++)
    {
      bitlocker->wb_ke_pc[i][j] = tmp[16 + j];
    }
  }

  // iter

  const u8 *iter_pos = token.buf[4];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter != ITERATION_BITLOCKER) return PARSER_SALT_VALUE;

  salt->salt_iter = ITERATION_BITLOCKER;

  // IV (nonce)

  const u8 *iv_len_pos = token.buf[5]; // aka nonce_len

  const u32 iv_len = hc_strtoul ((const char *) iv_len_pos, NULL, 10);

  if (iv_len != IV_LEN_BITLOCKER) return PARSER_SALT_LENGTH;

  const u8 *iv_pos = token.buf[6];

  u32 iv[4] = { 0 };

  iv[0] = hex_to_u32 (iv_pos +  0);
  iv[1] = hex_to_u32 (iv_pos +  8);
  iv[2] = hex_to_u32 (iv_pos + 16);

  iv[0] = byte_swap_32 (iv[0]);
  iv[1] = byte_swap_32 (iv[1]);
  iv[2] = byte_swap_32 (iv[2]);

  // prefix 0x02 and shift-right by 1 byte:

  iv[3] = (iv[2] << 24) | 0x01;         // 0x01 because we start with the VMK (skip MAC)
  iv[2] = (iv[1] << 24) | (iv[2] >> 8);
  iv[1] = (iv[0] << 24) | (iv[1] >> 8);
  iv[0] = (0x02  << 24) | (iv[0] >> 8); // 15 - strlen (iv) - 1 = 14 - 12 = 0x02

  bitlocker->iv[0] = iv[0];
  bitlocker->iv[1] = iv[1];
  bitlocker->iv[2] = iv[2];
  bitlocker->iv[3] = iv[3];

  // data and digest:

  const u8 *data_len_pos = token.buf[7];

  const u32 data_len = hc_strtoul ((const char *) data_len_pos, NULL, 10);

  if (data_len != DATA_LEN_BITLOCKER) return PARSER_SALT_LENGTH;

  const u8 *data_pos = token.buf[8];

  for (u32 i = 0, j = 0; i < DATA_LEN_BITLOCKER / 4; i += 1, j += 8)
  {
    bitlocker->data[i] = hex_to_u32 (data_pos + j);

    bitlocker->data[i] = byte_swap_32 (bitlocker->data[i]);
  }

  // fake digest:

  memcpy (digest, bitlocker->data, 16);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  bitlocker_t *bitlocker = (bitlocker_t *) esalt_buf;

  // type

  u32 type = bitlocker->type;

  // salt

  #define SALT_HEX_LEN SALT_LEN_BITLOCKER * 2 + 1

  char salt_buf[SALT_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < SALT_LEN_BITLOCKER / 4; i += 1, j += 8)
  {
    snprintf (salt_buf + j, SALT_HEX_LEN - j, "%08x", salt->salt_buf[i]);
  }

  // iv

  u32 iv[4] = { 0 };

  iv[0] = bitlocker->iv[0];
  iv[1] = bitlocker->iv[1];
  iv[2] = bitlocker->iv[2];
  iv[3] = bitlocker->iv[3];

  // remove 0x02 from start (left-shift by 1 byte):

  iv[0] = (iv[0] << 8) | (iv[1] >> 24);
  iv[1] = (iv[1] << 8) | (iv[2] >> 24);
  iv[2] = (iv[2] << 8) | (iv[3] >> 24);
  iv[3] = 0;

  #define IV_HEX_LEN IV_LEN_BITLOCKER * 2 + 1

  char iv_buf[IV_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < IV_LEN_BITLOCKER / 4; i += 1, j += 8)
  {
    snprintf (iv_buf + j, IV_HEX_LEN - j, "%08x", iv[i]);
  }

  // data

  #define DATA_HEX_LEN DATA_LEN_BITLOCKER * 2 + 1

  char data_buf[DATA_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < DATA_LEN_BITLOCKER / 4; i += 1, j += 8)
  {
    snprintf (data_buf + j, DATA_HEX_LEN - j, "%08x", bitlocker->data[i]);
  }

  // output

  int line_len = snprintf (line_buf, line_size, "$bitlocker$%i$%i$%s$%i$%i$%s$%i$%s",
    type,
    SALT_LEN_BITLOCKER,
    salt_buf,
    ITERATION_BITLOCKER,
    IV_LEN_BITLOCKER,
    iv_buf,
    DATA_LEN_BITLOCKER,
    data_buf);

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
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
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
  module_ctx->module_pw_min                   = module_pw_min;
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
