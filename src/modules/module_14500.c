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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_CIPHER_KPA;
static const char *HASH_NAME      = "Linux Kernel Crypto API (2.4)";
static const u64   KERN_TYPE      = 14541; // will be modified below
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SELF_TEST_DISABLE
                                  | OPTS_TYPE_PT_ADD80;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$cryptoapi$9$2$03000000000000000000000000000000$00000000000000000000000000000000$d1d20e91a8f2e18881dc79369d8af761";

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

static const char *SIGNATURE_CRYPTOAPI = "$cryptoapi$";

typedef enum kern_type_cryptoapi
{
  KERN_TYPE_CRYPTOAPI_SHA1_AES           = 14511, // 0
  KERN_TYPE_CRYPTOAPI_SHA1_SERPENT       = 14512, // 1
  KERN_TYPE_CRYPTOAPI_SHA1_TWOFISH       = 14513, // 2
  KERN_TYPE_CRYPTOAPI_SHA256_AES         = 14521, // 3
  KERN_TYPE_CRYPTOAPI_SHA256_SERPENT     = 14522, // 4
  KERN_TYPE_CRYPTOAPI_SHA256_TWOFISH     = 14523, // 5
  KERN_TYPE_CRYPTOAPI_SHA512_AES         = 14531, // 6
  KERN_TYPE_CRYPTOAPI_SHA512_SERPENT     = 14532, // 7
  KERN_TYPE_CRYPTOAPI_SHA512_TWOFISH     = 14533, // 8
  KERN_TYPE_CRYPTOAPI_RIPEMD160_AES      = 14541, // 9
  KERN_TYPE_CRYPTOAPI_RIPEMD160_SERPENT  = 14542, // 10
  KERN_TYPE_CRYPTOAPI_RIPEMD160_TWOFISH  = 14543, // 11
  KERN_TYPE_CRYPTOAPI_WHIRLPOOL_AES      = 14551, // 12
  KERN_TYPE_CRYPTOAPI_WHIRLPOOL_SERPENT  = 14552, // 13
  KERN_TYPE_CRYPTOAPI_WHIRLPOOL_TWOFISH  = 14553, // 14

} kern_type_cryptoapi_t;

typedef enum hc_cryptoapi_key_size
{
  HC_CRYPTOAPI_KEY_SIZE_128 = 128,
  HC_CRYPTOAPI_KEY_SIZE_192 = 192,
  HC_CRYPTOAPI_KEY_SIZE_256 = 256,

} hc_cryptoapi_key_size_t;

typedef enum hc_cryptoapi_cipher_type
{
  HC_CRYPTOAPI_CIPHER_TYPE_AES     = 1,
  HC_CRYPTOAPI_CIPHER_TYPE_SERPENT = 2,
  HC_CRYPTOAPI_CIPHER_TYPE_TWOFISH = 3,

} hc_cryptoapi_cypher_type_t;

typedef struct cryptoapi
{
  u32 kern_type;
  u32 key_size;
  u32 iv_buf[4];
  u32 pt_buf[4];

} cryptoapi_t;

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // Intel CPU
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) && (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
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
  const u64 esalt_size = (const u64) sizeof (cryptoapi_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  cryptoapi_t *cryptoapi = (cryptoapi_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CRYPTOAPI;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 2;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 16 * 2;
  token.len_max[3] = 16 * 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 16 * 2;
  token.len_max[4] = 16 * 2;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '$';
  token.len_min[5] = 16 * 2;
  token.len_max[5] = 16 * 2;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u32 type = atoi ((char *)token.buf[1]);

  if (type > 14) return (PARSER_CRYPTOAPI_KERNELTYPE);

  switch (type)
  {
    case  0: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA1_AES;          break;
    case  1: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA1_SERPENT;      break;
    case  2: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA1_TWOFISH;      break;
    case  3: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA256_AES;        break;
    case  4: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA256_SERPENT;    break;
    case  5: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA256_TWOFISH;    break;
    case  6: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA512_AES;        break;
    case  7: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA512_SERPENT;    break;
    case  8: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_SHA512_TWOFISH;    break;
    case  9: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_RIPEMD160_AES;     break;
    case 10: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_RIPEMD160_SERPENT; break;
    case 11: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_RIPEMD160_TWOFISH; break;
    case 12: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_WHIRLPOOL_AES;     break;
    case 13: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_WHIRLPOOL_SERPENT; break;
    case 14: cryptoapi->kern_type = KERN_TYPE_CRYPTOAPI_WHIRLPOOL_TWOFISH; break;
  }

  const u32 key_size = atoi ((char *)token.buf[2]);

  if (key_size > 2) return (PARSER_CRYPTOAPI_KEYSIZE);

  switch (key_size)
  {
    case 0: cryptoapi->key_size = HC_CRYPTOAPI_KEY_SIZE_128; break;
    case 1: cryptoapi->key_size = HC_CRYPTOAPI_KEY_SIZE_192; break;
    case 2: cryptoapi->key_size = HC_CRYPTOAPI_KEY_SIZE_256; break;
  }

  // IV

  const u8 *iv_pos = token.buf[3];

  cryptoapi->iv_buf[0] = hex_to_u32 (iv_pos +  0);
  cryptoapi->iv_buf[1] = hex_to_u32 (iv_pos +  8);
  cryptoapi->iv_buf[2] = hex_to_u32 (iv_pos + 16);
  cryptoapi->iv_buf[3] = hex_to_u32 (iv_pos + 24);

  // PT

  const u8 *pt_pos = token.buf[4];

  cryptoapi->pt_buf[0] = hex_to_u32 (pt_pos +  0);
  cryptoapi->pt_buf[1] = hex_to_u32 (pt_pos +  8);
  cryptoapi->pt_buf[2] = hex_to_u32 (pt_pos + 16);
  cryptoapi->pt_buf[3] = hex_to_u32 (pt_pos + 24);

  // salt_buf

  salt->salt_len  = 16;

  salt->salt_buf[0] = cryptoapi->pt_buf[0] ^ cryptoapi->iv_buf[0];
  salt->salt_buf[1] = cryptoapi->pt_buf[1] ^ cryptoapi->iv_buf[1];
  salt->salt_buf[2] = cryptoapi->pt_buf[2] ^ cryptoapi->iv_buf[2];
  salt->salt_buf[3] = cryptoapi->pt_buf[3] ^ cryptoapi->iv_buf[3];

  // hash

  const u8 *hash_pos = token.buf[5];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const cryptoapi_t *cryptoapi = (const cryptoapi_t *) esalt_buf;

  const u32 *digest = (const u32 *) digest_buf;

  u32 type = cryptoapi->kern_type;

  switch (type)
  {
    case KERN_TYPE_CRYPTOAPI_SHA1_AES:          type =  0; break;
    case KERN_TYPE_CRYPTOAPI_SHA1_SERPENT:      type =  1; break;
    case KERN_TYPE_CRYPTOAPI_SHA1_TWOFISH:      type =  2; break;
    case KERN_TYPE_CRYPTOAPI_SHA256_AES:        type =  3; break;
    case KERN_TYPE_CRYPTOAPI_SHA256_SERPENT:    type =  4; break;
    case KERN_TYPE_CRYPTOAPI_SHA256_TWOFISH:    type =  5; break;
    case KERN_TYPE_CRYPTOAPI_SHA512_AES:        type =  6; break;
    case KERN_TYPE_CRYPTOAPI_SHA512_SERPENT:    type =  7; break;
    case KERN_TYPE_CRYPTOAPI_SHA512_TWOFISH:    type =  8; break;
    case KERN_TYPE_CRYPTOAPI_RIPEMD160_AES:     type =  9; break;
    case KERN_TYPE_CRYPTOAPI_RIPEMD160_SERPENT: type = 10; break;
    case KERN_TYPE_CRYPTOAPI_RIPEMD160_TWOFISH: type = 11; break;
    case KERN_TYPE_CRYPTOAPI_WHIRLPOOL_AES:     type = 12; break;
    case KERN_TYPE_CRYPTOAPI_WHIRLPOOL_SERPENT: type = 13; break;
    case KERN_TYPE_CRYPTOAPI_WHIRLPOOL_TWOFISH: type = 14; break;
  }

  u32 key_size = cryptoapi->key_size;

  switch (key_size)
  {
    case HC_CRYPTOAPI_KEY_SIZE_128: key_size = 0; break;
    case HC_CRYPTOAPI_KEY_SIZE_192: key_size = 1; break;
    case HC_CRYPTOAPI_KEY_SIZE_256: key_size = 2; break;
  }

  u32 tmp[4];

  tmp[0] = byte_swap_32 (digest[0]);
  tmp[1] = byte_swap_32 (digest[1]);
  tmp[2] = byte_swap_32 (digest[2]);
  tmp[3] = byte_swap_32 (digest[3]);

  int out_len = snprintf (line_buf, line_size, "%s%u$%u$%08x%08x%08x%08x$%08x%08x%08x%08x$",
    SIGNATURE_CRYPTOAPI,
    type,
    key_size,
    byte_swap_32 (cryptoapi->iv_buf[0]),
    byte_swap_32 (cryptoapi->iv_buf[1]),
    byte_swap_32 (cryptoapi->iv_buf[2]),
    byte_swap_32 (cryptoapi->iv_buf[3]),
    byte_swap_32 (cryptoapi->pt_buf[0]),
    byte_swap_32 (cryptoapi->pt_buf[1]),
    byte_swap_32 (cryptoapi->pt_buf[2]),
    byte_swap_32 (cryptoapi->pt_buf[3]));

  u8 *out_buf = (u8 *) line_buf;

  u32_to_hex (tmp[0], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[1], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[2], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[3], out_buf + out_len); out_len += 8;

  return out_len;
}

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info)
{
  const cryptoapi_t *cryptoapi = (const cryptoapi_t *) esalt_buf;

  return cryptoapi->kern_type;
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
  module_ctx->module_kern_type_dynamic        = module_kern_type_dynamic;
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
