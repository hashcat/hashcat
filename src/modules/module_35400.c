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
#include "parser.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Kerberos 5, etype 23, AS-REP (NT)";
static const u64   KERN_TYPE      = 35400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ALWAYS_ASCII
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_AUTODETECT_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "b4b9b02e6f09a9bd760f388b67351e2b";
static const char *ST_HASH        = "$krb5asrep$23$user$realm$29a6b93ef4d76c15447b8671a5c441ae$8694eb6e61fdb1f307d2b9f09120d4c6fe12c53f97084dad533683ae6deebb28049dfe484c0b304103a05937f195b5ae08670b7dd0f951f09bcb1d34737c1a1fafeb67d0798c04e2b8a002017815e8a3d90ca5fc331ed8d3e661f273b4cade1186cd459e43fd21af749565b20ec04a1e369e96b149de37526ee680e0a7b1627d132ade71564872f867bc77556e8e8ef03e4d4494e32e5660a194d487d50a0ad0f40c9b1420acede386afa4e8357419f713bd2e0e3de3de8783536ace383f366b166a42f8c5e853901e32c57dcc258eb1198cdf0b5c43dd23815271765f7b65f513b2ad5475b1d00c11cb";

typedef struct krb5asrep
{
  u32 account_info[512];
  u32 checksum[4];
  u32 edata2[5120];
  u32 edata2_len;
  u32 format;
  u32 user[128];
  u32 realm[128];
} krb5asrep_t;

typedef struct asrep_tmp
{
  u32 nt[4];
} asrep_tmp_t;

static const char *SIGNATURE_KRB5ASREP = "$krb5asrep$";

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

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: self-test failed
        return true;
      }
    }
  }

  return false;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // We must override whatever tuningdb entry or -T value was set by the user with this
  // That's because of RC code in inc_cipher_rc4.cl has this for GPU (different on CPU):
  // #define KEY32(t,k) (((k) * 32) + ((t) & 31) + (((t) / 32) * 2048))
  // #define KEY8(t,k) (((k) & 3) + (((k) / 4) * 128) + (((t) & 31) * 4) + (((t) / 32) * 8192))

  u32 native_threads = (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU) ? 1 : 32;

  hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", native_threads);

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5asrep_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (asrep_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 32; }
u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 32; }

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5asrep_t *krb5asrep = (krb5asrep_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5ASREP;

  token.len[0]  = strlen (SIGNATURE_KRB5ASREP);
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

    /**
   * canonical (output): $krb5asrep$23$user$realm$checksum$encrypted
   * legacy:             $krb5asrep$23$user@realm:checksum$encrypted  (Impacket GetNPUsers)
   * legacy:             $krb5asrep$user@realm:checksum$encrypted     (no etype prefix)
   */

  if (line_len < (int) strlen (SIGNATURE_KRB5ASREP)) return (PARSER_SALT_LENGTH);

  memset (krb5asrep, 0, sizeof (krb5asrep_t));

  size_t parse_off = 0;

  // the three bytes that tell the two formats apart are read before they are known to be there

  if ((line_len > (token.len[0] + 2))
   && (line_buf[token.len[0]] == '2') && (line_buf[token.len[0] + 1] == '3') && (line_buf[token.len[0] + 2] == '$'))
  {
    // legacy: $krb5asrep$23$user@realm:checksum$encrypted  (Impacket GetNPUsers)
    krb5asrep->format = 1;
    parse_off += 3;
  }
  else
  {
    // legacy: $krb5asrep$user@realm:checksum$encrypted  (no etype prefix)
    krb5asrep->format = 2;
  }

  const char *account_info_start = line_buf + strlen (SIGNATURE_KRB5ASREP) + parse_off;

  const int account_info_left = line_len - (int) (account_info_start - line_buf);

  if (account_info_left < 0) return (PARSER_SALT_LENGTH);

  const char *account_info_stop = (const char *) hc_strchr_next ((const u8 *) account_info_start, account_info_left, ':');

  if (account_info_stop == NULL && krb5asrep->format == 1)
  {
    // canonical (output): $krb5asrep$23$user$realm$checksum$encrypted
    krb5asrep->format = 3;

    token.token_cnt = 6;

    token.sep[1]     = '$';
    token.len[1]     = 2;
    token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

    token.sep[2]     = '$';
    token.len_min[2] = 0;
    token.len_max[2] = 512;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[3]     = '$';
    token.len_min[3] = 0;
    token.len_max[3] = 512;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[4]     = '$';
    token.len[4]     = 32;
    token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

    token.sep[5]     = '$';
    token.len_min[5] = 64;
    token.len_max[5] = 40958;
    token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    memcpy (krb5asrep->user,  token.buf[2], token.len[2]);
    memcpy (krb5asrep->realm, token.buf[3], token.len[3]);

    const u8 *checksum_pos = token.buf[4];
    const u8 *data_pos     = token.buf[5];
    const int data_len     = token.len[5];

    krb5asrep->checksum[0] = hex_to_u32 (checksum_pos +  0);
    krb5asrep->checksum[1] = hex_to_u32 (checksum_pos +  8);
    krb5asrep->checksum[2] = hex_to_u32 (checksum_pos + 16);
    krb5asrep->checksum[3] = hex_to_u32 (checksum_pos + 24);

    u8 *edata_ptr = (u8 *) krb5asrep->edata2;

    if (data_len & 1) return (PARSER_TOKEN_LENGTH);

    for (int i = 0; (i + 1) < data_len; i += 2)
    {
      const u8 p0 = data_pos[i + 0];
      const u8 p1 = data_pos[i + 1];

      *edata_ptr++ = hex_convert (p1) << 0
                   | hex_convert (p0) << 4;
    }

    krb5asrep->edata2_len = data_len / 2;
    *edata_ptr++ = 0x80;

    salt->salt_buf[0] = krb5asrep->checksum[0];
    salt->salt_buf[1] = krb5asrep->checksum[1];
    salt->salt_buf[2] = krb5asrep->checksum[2];
    salt->salt_buf[3] = krb5asrep->checksum[3];
    salt->salt_len = 16;

    digest[0] = krb5asrep->checksum[0];
    digest[1] = krb5asrep->checksum[1];
    digest[2] = krb5asrep->checksum[2];
    digest[3] = krb5asrep->checksum[3];

    return (PARSER_OK);
  }

  if (account_info_stop == NULL) return (PARSER_SEPARATOR_UNMATCHED);

  const int account_info_len = (int) (account_info_stop - account_info_start);

  if (account_info_len >= (int) sizeof (krb5asrep->account_info)) return (PARSER_SALT_LENGTH);

  token.token_cnt  = 4;

  if (krb5asrep->format == 1)
  {
    token.token_cnt++;

    // etype
    token.sep[1]     = '$';
    token.len[1]     = 2;
    token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_DIGIT;

    // user_principal_name
    token.sep[2]     = ':';
    token.len[2]     = account_info_len;
    token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

    // checksum
    token.sep[3]     = '$';
    token.len[3]     = 32;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // edata2
    token.sep[4]     = '$';
    token.len_min[4] = 64;
    token.len_max[4] = 40958;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }
  else
  {
    // user_principal_name
    token.sep[1]     = ':';
    token.len[1]     = account_info_len;
    token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

    // checksum
    token.sep[2]     = '$';
    token.len[2]     = 32;
    token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    // edata2
    token.sep[3]     = '$';
    token.len_min[3] = 64;
    token.len_max[3] = 40958;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *checksum_pos = NULL;
  const u8 *data_pos     = NULL;

  int data_len = 0;

  if (krb5asrep->format == 1)
  {
    checksum_pos = token.buf[3];
    data_pos     = token.buf[4];
    data_len     = token.len[4];

    memcpy (krb5asrep->account_info, token.buf[2], token.len[2]);
  }
  else
  {
    checksum_pos = token.buf[2];
    data_pos     = token.buf[3];
    data_len     = token.len[3];

    memcpy (krb5asrep->account_info, token.buf[1], token.len[1]);
  }

  if (checksum_pos == NULL || data_pos == NULL) return (PARSER_SALT_VALUE);

  {
    const u8 *info = (const u8 *) krb5asrep->account_info;
    const int info_len = (int) strlen ((const char *) info);

    const u8 *at = NULL;

    for (int i = info_len - 1; i >= 0; i--)
    {
      if (info[i] == '@') { at = info + i; break; }
    }

    if (at != NULL)
    {
      const int ulen = (int) (at - info);
      const int rlen = info_len - ulen - 1;

      if (ulen > 0 && ulen < (int) sizeof (krb5asrep->user))
        memcpy (krb5asrep->user, info, ulen);
      if (rlen > 0 && rlen < (int) sizeof (krb5asrep->realm))
        memcpy (krb5asrep->realm, at + 1, rlen);
    }
  }

  krb5asrep->checksum[0] = hex_to_u32 (checksum_pos +  0);
  krb5asrep->checksum[1] = hex_to_u32 (checksum_pos +  8);
  krb5asrep->checksum[2] = hex_to_u32 (checksum_pos + 16);
  krb5asrep->checksum[3] = hex_to_u32 (checksum_pos + 24);

  u8 *edata_ptr = (u8 *) krb5asrep->edata2;

  if (data_len & 1) return (PARSER_TOKEN_LENGTH);

  // i + 1, not i: the loop reads two characters per byte, so an odd data_len read one past the
  // token, which is the next field of the line or the caller's terminator

  for (int i = 0; (i + 1) < data_len; i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *edata_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  krb5asrep->edata2_len = (u32) (data_len / 2);

  /* this is needed for hmac_md5 */
  *edata_ptr++ = 0x80;

  salt->salt_buf[0] = krb5asrep->checksum[0];
  salt->salt_buf[1] = krb5asrep->checksum[1];
  salt->salt_buf[2] = krb5asrep->checksum[2];
  salt->salt_buf[3] = krb5asrep->checksum[3];
  salt->salt_len    = 16;

  digest[0] = krb5asrep->checksum[0];
  digest[1] = krb5asrep->checksum[1];
  digest[2] = krb5asrep->checksum[2];
  digest[3] = krb5asrep->checksum[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5asrep_t *krb5asrep = (const krb5asrep_t *) esalt_buf;

  char data[5120 * 4 * 2 + 1] = { 0 };

  for (u32 i = 0, j = 0; i < krb5asrep->edata2_len; i += 1, j += 2)
  {
    const u8 *ptr_edata2 = (const u8 *) krb5asrep->edata2;

    snprintf (data + j, 3, "%02x", ptr_edata2[i]);
  }

  const int line_len = snprintf (line_buf, line_size, "%s23$%s$%s$%08x%08x%08x%08x$%s",
    SIGNATURE_KRB5ASREP,
    (const char *) krb5asrep->user,
    (const char *) krb5asrep->realm,
    byte_swap_32 (krb5asrep->checksum[0]),
    byte_swap_32 (krb5asrep->checksum[1]),
    byte_swap_32 (krb5asrep->checksum[2]),
    byte_swap_32 (krb5asrep->checksum[3]),
    data);

  return line_len;
}

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
 const char *mask = "?a?a?a?a?a?a?a?axxxxxxxxxxxxxxxx";
 return mask;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_benchmark_cost           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
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
  module_ctx->module_hash_hints               = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hash_recipe              = MODULE_DEFAULT;
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
  module_ctx->module_kern_bits                = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_length_sort              = MODULE_DEFAULT;
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
  module_ctx->module_register_options         = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
