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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "1Password, mobilekeychain (1Password 8)";
static const u64   KERN_TYPE      = 31800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$mobilekeychain$31800@hashcat.net$0226802599846590531367298686059042845608249051353268870564348733$fa53b7d424cdd36667dc12e585810729efc8ea9b2f8e5dd7a3ee72f7576a6788$100000$e1fea241e7b7c84535a0d53388bccbb9$dfd5f9ad6da1a72a47a3c04e03b02142b2fc301b3afff610669058527828a0e0388f5a2b0e6909813a5f9653c54f797adf0869107f4b875d4beb736cfbcec428ca19fc28346642fa32ec00f2ca4ad8dcf119af33cb247273e7b7427fd20eae8fb992779979a5e25aa465b3954794f62f4ea85355032efcd4e43ae3db6b14720d1dda963a384c37b521a92cef3494f77580edab210987ebcf2f0f7ed0220c0a4777be693e075b5f1e1302$995f3703b8ea4519f8cdc1cbded4d595";

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

typedef struct onepassword8
{
  u32 hkdf_salt_buf[8];
  u32 hkdf_key_buf[8];
  u32 tag_buf[4];

  u32 iv_buf[4];
  int iv_len;

  u32 email_buf[64];
  int email_len;

  u32 ct_buf[1024];
  int ct_len;

} onepassword8_t;

static const char *SIGNATURE_1PASSWORD8 = "$mobilekeychain$";

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

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (onepassword8_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha256_tmp_t);

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

  onepassword8_t *onepassword8 = (onepassword8_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_1PASSWORD8;

  token.len[0]     = 16;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 0;
  token.len_max[1] = 255;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len[2]     = 64;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 64;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 10;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 24;
  token.len_max[5] = 32;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len_min[6] = 16;
  token.len_max[6] = 4096;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '$';
  token.len[7]     = 32;
  token.attr[7]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // email

  const int email_len = token.len[1];
  const u8 *email_pos = token.buf[1];

  onepassword8->email_len = email_len;

  memcpy ((void *) onepassword8->email_buf, email_pos, email_len);

  u8 *ptr = (u8 *) onepassword8->email_buf;

  ptr[email_len] = 0;

  //  hkdf_salt

  //const int hkdf_salt_len = token.len[2];
  const u8 *hkdf_salt_pos = token.buf[2];

  onepassword8->hkdf_salt_buf[0] = hex_to_u32 (hkdf_salt_pos +  0);
  onepassword8->hkdf_salt_buf[1] = hex_to_u32 (hkdf_salt_pos +  8);
  onepassword8->hkdf_salt_buf[2] = hex_to_u32 (hkdf_salt_pos + 16);
  onepassword8->hkdf_salt_buf[3] = hex_to_u32 (hkdf_salt_pos + 24);
  onepassword8->hkdf_salt_buf[4] = hex_to_u32 (hkdf_salt_pos + 32);
  onepassword8->hkdf_salt_buf[5] = hex_to_u32 (hkdf_salt_pos + 40);
  onepassword8->hkdf_salt_buf[6] = hex_to_u32 (hkdf_salt_pos + 48);
  onepassword8->hkdf_salt_buf[7] = hex_to_u32 (hkdf_salt_pos + 56);

  onepassword8->hkdf_salt_buf[0] = byte_swap_32 (onepassword8->hkdf_salt_buf[0]);
  onepassword8->hkdf_salt_buf[1] = byte_swap_32 (onepassword8->hkdf_salt_buf[1]);
  onepassword8->hkdf_salt_buf[2] = byte_swap_32 (onepassword8->hkdf_salt_buf[2]);
  onepassword8->hkdf_salt_buf[3] = byte_swap_32 (onepassword8->hkdf_salt_buf[3]);
  onepassword8->hkdf_salt_buf[4] = byte_swap_32 (onepassword8->hkdf_salt_buf[4]);
  onepassword8->hkdf_salt_buf[5] = byte_swap_32 (onepassword8->hkdf_salt_buf[5]);
  onepassword8->hkdf_salt_buf[6] = byte_swap_32 (onepassword8->hkdf_salt_buf[6]);
  onepassword8->hkdf_salt_buf[7] = byte_swap_32 (onepassword8->hkdf_salt_buf[7]);

  //  hkdf_key

  //const int hkdf_key_len = token.len[3];
  const u8 *hkdf_key_pos = token.buf[3];

  onepassword8->hkdf_key_buf[0] = hex_to_u32 (hkdf_key_pos +  0);
  onepassword8->hkdf_key_buf[1] = hex_to_u32 (hkdf_key_pos +  8);
  onepassword8->hkdf_key_buf[2] = hex_to_u32 (hkdf_key_pos + 16);
  onepassword8->hkdf_key_buf[3] = hex_to_u32 (hkdf_key_pos + 24);
  onepassword8->hkdf_key_buf[4] = hex_to_u32 (hkdf_key_pos + 32);
  onepassword8->hkdf_key_buf[5] = hex_to_u32 (hkdf_key_pos + 40);
  onepassword8->hkdf_key_buf[6] = hex_to_u32 (hkdf_key_pos + 48);
  onepassword8->hkdf_key_buf[7] = hex_to_u32 (hkdf_key_pos + 56);

  onepassword8->hkdf_key_buf[0] = byte_swap_32 (onepassword8->hkdf_key_buf[0]);
  onepassword8->hkdf_key_buf[1] = byte_swap_32 (onepassword8->hkdf_key_buf[1]);
  onepassword8->hkdf_key_buf[2] = byte_swap_32 (onepassword8->hkdf_key_buf[2]);
  onepassword8->hkdf_key_buf[3] = byte_swap_32 (onepassword8->hkdf_key_buf[3]);
  onepassword8->hkdf_key_buf[4] = byte_swap_32 (onepassword8->hkdf_key_buf[4]);
  onepassword8->hkdf_key_buf[5] = byte_swap_32 (onepassword8->hkdf_key_buf[5]);
  onepassword8->hkdf_key_buf[6] = byte_swap_32 (onepassword8->hkdf_key_buf[6]);
  onepassword8->hkdf_key_buf[7] = byte_swap_32 (onepassword8->hkdf_key_buf[7]);

  // iter

  const u8 *iter_pos = token.buf[4];

  salt->salt_iter = hc_strtoul ((const char *) iter_pos, NULL, 10) - 1;

  // iv

  const int iv_len = token.len[5];
  const u8 *iv_pos = token.buf[5];

  onepassword8->iv_len = hex_decode (iv_pos, iv_len, (u8 *) onepassword8->iv_buf);

  for (int i = 0; i < 4; i++) onepassword8->iv_buf[i] = byte_swap_32 (onepassword8->iv_buf[i]);

  // ct

  const int ct_len = token.len[6];
  const u8 *ct_pos = token.buf[6];

  onepassword8->ct_len = hex_decode (ct_pos, ct_len, (u8 *) onepassword8->ct_buf);

  for (int i = 0; i < 1024; i++) onepassword8->ct_buf[i] = byte_swap_32 (onepassword8->ct_buf[i]);

  // tag

  //const int tag_len = token.len[7];
  const u8 *tag_pos = token.buf[7];

  onepassword8->tag_buf[0] = hex_to_u32 (tag_pos +  0);
  onepassword8->tag_buf[1] = hex_to_u32 (tag_pos +  8);
  onepassword8->tag_buf[2] = hex_to_u32 (tag_pos + 16);
  onepassword8->tag_buf[3] = hex_to_u32 (tag_pos + 24);

  onepassword8->tag_buf[0] = byte_swap_32 (onepassword8->tag_buf[0]);
  onepassword8->tag_buf[1] = byte_swap_32 (onepassword8->tag_buf[1]);
  onepassword8->tag_buf[2] = byte_swap_32 (onepassword8->tag_buf[2]);
  onepassword8->tag_buf[3] = byte_swap_32 (onepassword8->tag_buf[3]);

  // salt

  salt->salt_buf[0] = onepassword8->hkdf_salt_buf[0];
  salt->salt_buf[1] = onepassword8->hkdf_salt_buf[1];
  salt->salt_buf[2] = onepassword8->hkdf_salt_buf[2];
  salt->salt_buf[3] = onepassword8->hkdf_salt_buf[3];
  salt->salt_buf[4] = onepassword8->hkdf_salt_buf[4];
  salt->salt_buf[5] = onepassword8->hkdf_salt_buf[5];
  salt->salt_buf[6] = onepassword8->hkdf_salt_buf[6];
  salt->salt_buf[7] = onepassword8->hkdf_salt_buf[7];

  salt->salt_len = 32;

  // digest

  digest[0] = onepassword8->ct_buf[0];
  digest[1] = onepassword8->ct_buf[1];
  digest[2] = onepassword8->ct_buf[2];
  digest[3] = onepassword8->ct_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  //  const u32 *digest = (const u32 *) digest_buf;

  onepassword8_t *onepassword8 = (onepassword8_t *) esalt_buf;

  // iv

  u32 iv_buf[4];

  for (int i = 0; i < 4; i++) iv_buf[i] = byte_swap_32 (onepassword8->iv_buf[i]);

  u8 iv_buf8[(4 * 2 * 4) + 1];

  const int iv_len = hex_encode ((const u8 *) iv_buf, onepassword8->iv_len, iv_buf8);

  iv_buf8[iv_len] = 0;

  // ct

  u32 ct_buf[1024];

  for (int i = 0; i < 1024; i++) ct_buf[i] = byte_swap_32 (onepassword8->ct_buf[i]);

  u8 ct_buf8[(1024 * 2 * 4) + 1];

  const int ct_len = hex_encode ((const u8 *) ct_buf, onepassword8->ct_len, ct_buf8);

  ct_buf8[ct_len] = 0;

  // final

  int out_len = snprintf ((char *) line_buf, line_size, "%s%s$%08x%08x%08x%08x%08x%08x%08x%08x$%08x%08x%08x%08x%08x%08x%08x%08x$%u$%s$%s$%08x%08x%08x%08x",
    SIGNATURE_1PASSWORD8,
    (char *) onepassword8->email_buf,
    onepassword8->hkdf_salt_buf[0],
    onepassword8->hkdf_salt_buf[1],
    onepassword8->hkdf_salt_buf[2],
    onepassword8->hkdf_salt_buf[3],
    onepassword8->hkdf_salt_buf[4],
    onepassword8->hkdf_salt_buf[5],
    onepassword8->hkdf_salt_buf[6],
    onepassword8->hkdf_salt_buf[7],
    onepassword8->hkdf_key_buf[0],
    onepassword8->hkdf_key_buf[1],
    onepassword8->hkdf_key_buf[2],
    onepassword8->hkdf_key_buf[3],
    onepassword8->hkdf_key_buf[4],
    onepassword8->hkdf_key_buf[5],
    onepassword8->hkdf_key_buf[6],
    onepassword8->hkdf_key_buf[7],
    salt->salt_iter + 1,
    (char *) iv_buf8,
    (char *) ct_buf8,
    onepassword8->tag_buf[0],
    onepassword8->tag_buf[1],
    onepassword8->tag_buf[2],
    onepassword8->tag_buf[3]);

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
  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
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
