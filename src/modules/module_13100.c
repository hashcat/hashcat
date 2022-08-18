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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Kerberos 5, etype 23, TGS-REP";
static const u64   KERN_TYPE      = 13100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a";

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

typedef struct krb5tgs
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;
  u32 format;

} krb5tgs_t;

static const char *SIGNATURE_KRB5TGS = "$krb5tgs$";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  u32 native_threads = 0;

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    native_threads = 1;
  }
  else if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
  {
    #if defined (__APPLE__)

    native_threads = 32;

    #else

    if (device_param->device_local_mem_size < 49152)
    {
      native_threads = MIN (device_param->kernel_preferred_wgs_multiple, 32); // We can't just set 32, because Intel GPU need 8
    }
    else
    {
      native_threads = device_param->kernel_preferred_wgs_multiple;
    }

    #endif
  }

  hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u -D _unroll", native_threads);

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5tgs_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5tgs_t *krb5tgs = (krb5tgs_t *) esalt_buf;

  hc_token_t token;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5TGS;

  token.len[0]  = 9;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  /**
   * hc
   * format 1: $krb5tgs$23$*user$realm$spn*$checksum$edata2
   * format 2: $krb5tgs$23$checksum$edata2
   *
   * jtr
   * format 3: $krb5tgs$spn:checksum$edata2
   */

  if (line_len < (int) strlen (SIGNATURE_KRB5TGS)) return (PARSER_SALT_LENGTH);

  memset (krb5tgs, 0, sizeof (krb5tgs_t));

  token.token_cnt = 4;

  if (line_buf[token.len[0]] == '2' && line_buf[token.len[0] + 1] == '3' && line_buf[token.len[0] + 2] == '$')
  {
    if (line_buf[token.len[0] + 3] == '*')
    {
      char *account_info_start = (char *) line_buf + 12; // we want the * char included
      char *account_info_stop  = strchr ((const char *) account_info_start + 1, '*');

      if (account_info_stop == NULL) return (PARSER_SEPARATOR_UNMATCHED);

      account_info_stop++; // we want the * char included
      account_info_stop++; // we want the $ char included

      const int account_info_len = account_info_stop - account_info_start;

      token.token_cnt++;

      // etype

      token.sep[1]     = '$';
      token.len_min[1] = 2;
      token.len_max[1] = 2;
      token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                       | TOKEN_ATTR_VERIFY_DIGIT;

      // user$realm$spn

      token.len[2]     = account_info_len;
      token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

      // checksum

      token.sep[3]     = '$';
      token.len_min[3] = 32;
      token.len_max[3] = 32;
      token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                       | TOKEN_ATTR_VERIFY_HEX;

      // edata2

      token.sep[4]     = '$';
      token.len_min[4] = 64;
      token.len_max[4] = 40960;
      token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                       | TOKEN_ATTR_VERIFY_HEX;

      krb5tgs->format = 1;
    }
    else
    {
      // etype

      token.sep[1]     = '$';
      token.len_min[1] = 2;
      token.len_max[1] = 2;
      token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                       | TOKEN_ATTR_VERIFY_DIGIT;

      // checksum

      token.sep[2]     = '$';
      token.len_min[2] = 32;
      token.len_max[2] = 32;
      token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                       | TOKEN_ATTR_VERIFY_HEX;

      // edata2

      token.sep[3]     = '$';
      token.len_min[3] = 64;
      token.len_max[3] = 40960;
      token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                       | TOKEN_ATTR_VERIFY_HEX;

      krb5tgs->format = 2;
    }
  }
  else
  {
    // spn

    token.sep[1]     = ':';
    token.len_min[1] = 0;
    token.len_max[1] = 2048;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    // checksum

    token.sep[2]     = '$';
    token.len_min[2] = 32;
    token.len_max[2] = 32;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // edata2

    token.sep[3]     = '$';
    token.len_min[3] = 64;
    token.len_max[3] = 40960;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    krb5tgs->format = 3;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *checksum_pos = NULL;
  const u8 *data_pos = NULL;

  int data_len = 0;

  if (krb5tgs->format == 1)
  {
    checksum_pos = token.buf[3];

    data_pos = token.buf[4];
    data_len = token.len[4];

    memcpy (krb5tgs->account_info, token.buf[2], token.len[2]);
  }
  else if (krb5tgs->format == 2)
  {
    checksum_pos = token.buf[2];

    data_pos = token.buf[3];
    data_len = token.len[3];

    krb5tgs->account_info[0] = 0;
  }
  else if (krb5tgs->format == 3)
  {
    checksum_pos = token.buf[2];

    data_pos = token.buf[3];
    data_len = token.len[3];

    memcpy (krb5tgs->account_info, token.buf[1], token.len[1]);
  }

  if (checksum_pos == NULL || data_pos == NULL) return (PARSER_SALT_VALUE);

  krb5tgs->checksum[0] = hex_to_u32 (checksum_pos +  0);
  krb5tgs->checksum[1] = hex_to_u32 (checksum_pos +  8);
  krb5tgs->checksum[2] = hex_to_u32 (checksum_pos + 16);
  krb5tgs->checksum[3] = hex_to_u32 (checksum_pos + 24);

  u8 *edata_ptr = (u8 *) krb5tgs->edata2;

  for (int i = 0; i < data_len; i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *edata_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  krb5tgs->edata2_len = data_len / 2;

  /* this is needed for hmac_md5 */
  *edata_ptr++ = 0x80;

  salt->salt_buf[0] = krb5tgs->checksum[0];
  salt->salt_buf[1] = krb5tgs->checksum[1];
  salt->salt_buf[2] = krb5tgs->checksum[2];
  salt->salt_buf[3] = krb5tgs->checksum[3];

  salt->salt_len = 16;

  digest[0] = krb5tgs->checksum[0];
  digest[1] = krb5tgs->checksum[1];
  digest[2] = krb5tgs->checksum[2];
  digest[3] = krb5tgs->checksum[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5tgs_t *krb5tgs = (const krb5tgs_t *) esalt_buf;

  char data[5120 * 4 * 2] = { 0 };

  for (u32 i = 0, j = 0; i < krb5tgs->edata2_len; i += 1, j += 2)
  {
    u8 *ptr_edata2 = (u8 *) krb5tgs->edata2;

    sprintf (data + j, "%02x", ptr_edata2[i]);
  }

  int line_len;

  // preserve the input hash format

  if (krb5tgs->format != 3) // hc
  {
    line_len = snprintf (line_buf, line_size, "%s23$%s%08x%08x%08x%08x$%s",
      SIGNATURE_KRB5TGS,
      (char *) krb5tgs->account_info,
      byte_swap_32 (krb5tgs->checksum[0]),
      byte_swap_32 (krb5tgs->checksum[1]),
      byte_swap_32 (krb5tgs->checksum[2]),
      byte_swap_32 (krb5tgs->checksum[3]),
      data);
  }
  else // jtr
  {
    line_len = snprintf (line_buf, line_size, "%s%s:%08x%08x%08x%08x$%s",
      SIGNATURE_KRB5TGS,
      (char *) krb5tgs->account_info,
      byte_swap_32 (krb5tgs->checksum[0]),
      byte_swap_32 (krb5tgs->checksum[1]),
      byte_swap_32 (krb5tgs->checksum[2]),
      byte_swap_32 (krb5tgs->checksum[3]),
      data);
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
