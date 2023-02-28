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
// 22610 generates a decryption key based on a password-guess and uses that to AES-GCM decrypt the data decrypts
static const char *HASH_NAME      = "MetaMask Wallet (short hash, plaintext check)";
static const u64   KERN_TYPE      = 26610;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat1";
// hash generated using with python3 tools/metamask2hashcat.py --vault tools/2hashcat_tests/metamask2hashcat.json --shortdata
static const char *ST_HASH        = "$metamask-short$jfGI3TXguhb8GPnKSXFrMzRk2NCEc131Gt5G3kZr5+s=$h+BoIf2CQ5BEjaIOShFE7g==$R95fzGt4UQ0uwrcrVYnIi4UcSlWn9wlmer+//526ZDwYAp50K82F1u1oacYcdjjhuEvbZnWk/uBG00UkgLLlOw==";

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
  u32 ct_buf[784]; // TODO this can be smaller and would speedup the attack, only 64 bytes of ciphertext are allowed
  u32 ct_len;

} pbkdf2_sha256_aes_gcm_t;

static const char *SIGNATURE_METAMASK_WALLET = "$metamask-short$";

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

  #define CT_MAX_LEN_BASE64 (((3136+16) * 8) / 6) + 3 // TODO this can be smaller and would speedup the attack, only 64 bytes of ciphertext are allowed

  hc_token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_METAMASK_WALLET;

  token.len[0]     = 16;
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
  token.len_min[3] = 32;
  token.len_max[3] = 100; // TODO this can be smaller and would speedup the attack, only 64 bytes of ciphertext are allowed
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

  memcpy ((u8 *) metamask->ct_buf, tmp_buf, tmp_len);

  u32 j = tmp_len / 4;

  if ((tmp_len % 4) > 0) j++;

  for (u32 i = 0; i < j; i++) metamask->ct_buf[i] = byte_swap_32 (metamask->ct_buf[i]);

  metamask->ct_len = tmp_len;

  digest[0] =  (metamask->ct_buf[0]);
  digest[1] =  (metamask->ct_buf[1]);
  digest[2] =  (metamask->ct_buf[2]);
  digest[3] =  (metamask->ct_buf[3]);
  
  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  pbkdf2_sha256_aes_gcm_t *metamask = (pbkdf2_sha256_aes_gcm_t *) esalt_buf;

  // salt

  #define SALT_LEN_BASE64   ((32 * 8) / 6) + 3
  #define IV_LEN_BASE64     ((16 * 8) / 6) + 3
  #define CT_MAX_LEN_BASE64 (((3136+16) * 8) / 6) + 3 // TODO this can be much smaller now, probably 32 ?

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

  u32 tmp_buf[784] = { 0 }; // TODO this can be smaller and would speedup the attack, only 64 bytes of ciphertext are allowed

  for (u32 i = 0; i < j; i++) tmp_buf[i] = byte_swap_32 (metamask->ct_buf[i]);

  u8 ct_buf[CT_MAX_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp_buf, (const int) metamask->ct_len, ct_buf);

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
