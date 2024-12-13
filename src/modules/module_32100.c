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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Kerberos 5, etype 17, AS-REP";
static const u64   KERN_TYPE      = 32100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5asrep$17$user$EXAMPLE.COM$a419c4030e555734b06c2629$c09a1421f96eb126c757a4b87830381f142477d9a85b2beb3093dbfd44f38ddb6016a479537fb7b36e046315869fe79187217971ff6a12c1e0a2df3f68045e03814b21f756d8981f781803d65e8572823c88979581d93cf7d768f2efced16f3719b8d1004d9e73d798de255383476bced47d1982f16be77d0feb55a1f44f58bd013fa4caee58ac614caf0f1cf9101ec9623c5b8c2a1491b73f134f074790088fdb360b5ebce0d32a8145ed00a81ddf77188e150b92d8e8ddd0285d27f1514253e5546e6bba864b362bb1e6483b26d08fa4cc268bfbefe0f690039bcc524b774599df3680c1c3431d891bfa99514a877f964e";

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

// Struct to store the hash structure - same fields as TGS-REP type 17
typedef struct krb5asrep_17
{
  u32 user[128];
  u32 domain[128];
  u32 account_info[512];
  u32 account_info_len;

  u32 checksum[3];
  u32 edata2[5120];
  u32 edata2_len;
  u32 format;

} krb5asrep_17_t;

typedef struct krb5asrep_17_tmp
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[16];
  u32 out[16];

} krb5asrep_17_tmp_t;

static const char *SIGNATURE_KRB5ASREP = "$krb5asrep$17$";

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (krb5asrep_17_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5asrep_17_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5asrep_17_t *krb5asrep = (krb5asrep_17_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5ASREP;

  token.len[0]  = strlen (SIGNATURE_KRB5ASREP);
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  /**
   * Hashcat
   * format 1: $krb5asrep$18$user$realm$checksum$edata2
   *
   * JtR
   * format 2: $krb5asrep$18$salt$edata2$checksum
   */

  if (line_len < (int) strlen (SIGNATURE_KRB5ASREP)) return (PARSER_SALT_LENGTH);

  memset (krb5asrep, 0, sizeof (krb5asrep_17_t));

  /**
   * JtR format has the checksum at the end, so can identify it based on the
   * separator ('$') being at a fixed length from the end of the line. Checksum
   * is 24 characters in length, so then there should be a '$' at line_len - 25
   */

  if (line_buf[line_len - 25] == '$')
  {
    // JtR format
    krb5asrep->format = 2;
  }
  else
  {
    // Hashcat format
    krb5asrep->format = 1;
  }

  token.token_cnt  = 4;

  if (krb5asrep->format == 1)
  {
    token.token_cnt++;

    // user
    token.sep[1]     = '$';
    token.len_min[1] = 1;
    token.len_max[1] = 512;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    // realm
    token.sep[2]     = '$';
    token.len_min[2] = 1;
    token.len_max[2] = 512;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    // checksum
    token.sep[3]     = '$';
    // hmac-sha1 stripped to 12bytes
    token.len[3]     = 24;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // edata2
    token.sep[4]     = '$';
    token.len_min[4] = 64;
    token.len_max[4] = 40960;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }
  else
  {
    // salt
    token.sep[1]     = '$';
    token.len_min[1] = 1;
    token.len_max[1] = 512;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    // edata2
    token.sep[2]     = '$';
    token.len_min[2] = 64;
    token.len_max[2] = 40960;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // checksum
    token.sep[3]     = '$';
    // hmac-sha1 stripped to 12bytes
    token.len[3]     = 24;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }


  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos;
  const u8 *domain_pos;
  const u8 *salt_pos;
  const u8 *checksum_pos;
  const u8 *data_pos;

  int user_len;
  int domain_len;
  int data_len;
  int account_info_len;

  if (krb5asrep->format == 1)
  {
    user_pos = token.buf[1];
    user_len = token.len[1];

    memcpy (krb5asrep->user, user_pos, user_len);

    domain_pos = token.buf[2];
    domain_len = token.len[2];

    memcpy (krb5asrep->domain, domain_pos, domain_len);

    checksum_pos = token.buf[3];

    data_pos = token.buf[4];
    data_len = token.len[4];

    account_info_len = token.len[2] + token.len[1];
  }
  else
  {
    salt_pos = token.buf[1];
    account_info_len = token.len[1];

    memcpy (krb5asrep->account_info, salt_pos, account_info_len);

    /**
     * JtR format only has the final salt/account_info value (combination of
     * user and domain), rather than separate "user" and "domain" values. Since
     * user and domain won't be used for the JtR format, their values won't
     * matter, so set them both to the same value as account_info.
     */

    user_pos = token.buf[1];
    user_len = token.len[1];

    memcpy (krb5asrep->user, user_pos, user_len);

    domain_pos = token.buf[1];
    domain_len = token.len[1];

    memcpy (krb5asrep->domain, domain_pos, domain_len);

    data_pos = token.buf[2];
    data_len = token.len[2];

    checksum_pos = token.buf[3];
  }

  u8 *account_info_ptr = (u8 *) krb5asrep->account_info;

  // Domain must be uppercase
  u8 domain[128];

  if (krb5asrep->format == 1)
  {
    memcpy (domain, domain_pos, domain_len);
    uppercase (domain, domain_len);

    memcpy (account_info_ptr, domain, domain_len);
    memcpy (account_info_ptr + domain_len, user_pos, user_len);
  }

  krb5asrep->account_info_len = account_info_len;

  // hmac-sha1 is reduced to 12 bytes
  krb5asrep->checksum[0] = byte_swap_32 (hex_to_u32 (checksum_pos +  0));
  krb5asrep->checksum[1] = byte_swap_32 (hex_to_u32 (checksum_pos +  8));
  krb5asrep->checksum[2] = byte_swap_32 (hex_to_u32 (checksum_pos + 16));

  u8 *edata_ptr = (u8 *) krb5asrep->edata2;

  for (int i = 0; i < data_len; i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *edata_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  krb5asrep->edata2_len = data_len / 2;

  salt->salt_buf[0] = krb5asrep->checksum[0];
  salt->salt_buf[1] = krb5asrep->checksum[1];
  salt->salt_buf[2] = krb5asrep->checksum[2];

  salt->salt_len = 12;

  salt->salt_iter = 4096 - 1;

  digest[0] = krb5asrep->checksum[0];
  digest[1] = krb5asrep->checksum[1];
  digest[2] = krb5asrep->checksum[2];
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5asrep_17_t *krb5asrep = (const krb5asrep_17_t *) esalt_buf;

  char data[5120 * 4 * 2] = { 0 };

  for (u32 i = 0, j = 0; i < krb5asrep->edata2_len; i += 1, j += 2)
  {
    const u8 *ptr_edata2 = (const u8 *) krb5asrep->edata2;

    snprintf (data + j, 3, "%02x", ptr_edata2[i]);
  }

  int line_len = 0;

  if (krb5asrep->format == 1)
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%08x%08x%08x$%s",
      SIGNATURE_KRB5ASREP,
      (const char *) krb5asrep->user,
      (const char *) krb5asrep->domain,
      krb5asrep->checksum[0],
      krb5asrep->checksum[1],
      krb5asrep->checksum[2],
      data);
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%08x%08x%08x",
      SIGNATURE_KRB5ASREP,
      (const char *) krb5asrep->account_info,
      data,
      krb5asrep->checksum[0],
      krb5asrep->checksum[1],
      krb5asrep->checksum[2]);
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
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
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
