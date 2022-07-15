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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "MetaMask Wallet";
static const u64   KERN_TYPE      = 26600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat1";
static const char *ST_HASH        = "$metamask$h0c2mQBGgnhlJ4EWMhdAAZhHlFeZNVlAEwOHQHaEBhY=$q9de9oljOBLWBQRtk9Ugog==$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";

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

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct pbkdf2_sha256_aes_gcm
{
  u32 salt_buf[64];
  u32 iv_buf[4];
  u32 iv_len;
  u32 ct_buf[784];
  u32 ct_len;

} pbkdf2_sha256_aes_gcm_t;

static const char *SIGNATURE_METAMASK_WALLET = "$metamask$";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
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
  const u64 esalt_size = (const u64) sizeof (pbkdf2_sha256_aes_gcm_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha256_tmp_t);

  return tmp_size;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 8;

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

  pbkdf2_sha256_aes_gcm_t *metamask = (pbkdf2_sha256_aes_gcm_t *) esalt_buf;

  #define CT_MAX_LEN_BASE64 (((3136+16) * 8) / 6) + 3

  hc_token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_METAMASK_WALLET;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 44;
  token.len_max[1] = 44;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[2]     = '$';
  token.len_min[2] = 24;
  token.len_max[2] = 24;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = '$';
  token.len_min[3] = 64;
  token.len_max[3] = CT_MAX_LEN_BASE64;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8 tmp_buf[CT_MAX_LEN_BASE64] = { 0 };

  size_t tmp_len = 0;

  // iter

  salt->salt_iter = 10000 - 1;

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  metamask->salt_buf[0] = salt->salt_buf[0];
  metamask->salt_buf[1] = salt->salt_buf[1];
  metamask->salt_buf[2] = salt->salt_buf[2];
  metamask->salt_buf[3] = salt->salt_buf[3];
  metamask->salt_buf[4] = salt->salt_buf[4];
  metamask->salt_buf[5] = salt->salt_buf[5];
  metamask->salt_buf[6] = salt->salt_buf[6];
  metamask->salt_buf[7] = salt->salt_buf[7];

  // iv

  const u8 *iv_pos = token.buf[2];
  const int iv_len = token.len[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, iv_pos, iv_len, tmp_buf);

  if (tmp_len != 16) return (PARSER_IV_LENGTH);

  memcpy ((u8 *) metamask->iv_buf, tmp_buf, tmp_len);

  metamask->iv_buf[0] = byte_swap_32 (metamask->iv_buf[0]);
  metamask->iv_buf[1] = byte_swap_32 (metamask->iv_buf[1]);
  metamask->iv_buf[2] = byte_swap_32 (metamask->iv_buf[2]);
  metamask->iv_buf[3] = byte_swap_32 (metamask->iv_buf[3]);

  metamask->iv_len = tmp_len;

  // ciphertext

  const u8 *ct_pos = token.buf[3];
  const int ct_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, ct_pos, ct_len, tmp_buf);

  if (tmp_len <= 16) return (PARSER_CT_LENGTH);

  tmp_len -= 16;

  if (tmp_len < 30 || tmp_len > 3136) return (PARSER_CT_LENGTH);

  memcpy ((u8 *) metamask->ct_buf, tmp_buf, tmp_len);

  u32 j = tmp_len / 4;

  if ((tmp_len % 4) > 0) j++;

  for (u32 i = 0; i < j; i++) metamask->ct_buf[i] = byte_swap_32 (metamask->ct_buf[i]);

  metamask->ct_len = tmp_len;

  // tag

  u32 tag_buf[4] = { 0 };

  memcpy ((u8 *) tag_buf, tmp_buf+metamask->ct_len, 16);

  digest[0] = byte_swap_32 (tag_buf[0]);
  digest[1] = byte_swap_32 (tag_buf[1]);
  digest[2] = byte_swap_32 (tag_buf[2]);
  digest[3] = byte_swap_32 (tag_buf[3]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  pbkdf2_sha256_aes_gcm_t *metamask = (pbkdf2_sha256_aes_gcm_t *) esalt_buf;

  // salt

  #define SALT_LEN_BASE64   ((32 * 8) / 6) + 3
  #define IV_LEN_BASE64     ((16 * 8) / 6) + 3
  #define CT_MAX_LEN_BASE64 (((3136+16) * 8) / 6) + 3

  u8 salt_buf[SALT_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, (const int) salt->salt_len, salt_buf);

  // iv

  u32 tmp_iv_buf[4] = { 0 };

  tmp_iv_buf[0] = byte_swap_32 (metamask->iv_buf[0]);
  tmp_iv_buf[1] = byte_swap_32 (metamask->iv_buf[1]);
  tmp_iv_buf[2] = byte_swap_32 (metamask->iv_buf[2]);
  tmp_iv_buf[3] = byte_swap_32 (metamask->iv_buf[3]);

  u8 iv_buf[IV_LEN_BASE64+1] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp_iv_buf, (const int) metamask->iv_len, iv_buf);

  // ct

  u32 ct_len = metamask->ct_len;

  u32 j = ct_len / 4;

  if ((ct_len % 4) > 0) j++;

  u32 tmp_buf[784] = { 0 };

  for (u32 i = 0; i < j; i++) tmp_buf[i] = byte_swap_32 (metamask->ct_buf[i]);

  u32 tmp_tag[4] = { 0 };

  tmp_tag[0] = byte_swap_32 (digest[0]);
  tmp_tag[1] = byte_swap_32 (digest[1]);
  tmp_tag[2] = byte_swap_32 (digest[2]);
  tmp_tag[3] = byte_swap_32 (digest[3]);

  u8 *tmp_buf_str = (u8 *) tmp_buf;
  u8 *tmp_tag_str = (u8 *) tmp_tag;

  memcpy (tmp_buf_str+metamask->ct_len, tmp_tag_str, 16);

  u8 ct_buf[CT_MAX_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp_buf, (const int) metamask->ct_len+16, ct_buf);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf ((char *) out_buf, line_size, "%s%s$%s$%s",
    SIGNATURE_METAMASK_WALLET,
    salt_buf,
    iv_buf,
    ct_buf);

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
