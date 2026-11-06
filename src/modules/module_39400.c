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
static const char *HASH_NAME      = "Kerberos 5, etype 23, AS-REQ Pre-Auth (NT)";
static const u64   KERN_TYPE      = 39400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ALWAYS_ASCII
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_AUTODETECT_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "b4b9b02e6f09a9bd760f388b67351e2b";
static const char *ST_HASH        = "$krb5pa$23$user$realm$b3515d146dc326af0fd885c8079207ba$36a581548d55c65278ca30d2189c106176015a8e2c04145a6d91b736a387a9f5f8a245d3";

#include "hooks_common.c"

#define MAX_USER_LEN  511
#define MAX_REALM_LEN 511

typedef struct krb5pa
{
  u32 user[128];
  u32 realm[128];
  u32 raw_token[64];
  u32 enc_timestamp[16];
  u32 checksum[4];
  u32 enc_timestamp_len;
  u32 format;

} krb5pa_t;

typedef struct pa_tmp
{
  u32 nt[4];
} pa_tmp_t;

static const char *SIGNATURE_KRB5PA = "$krb5pa$23$";

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (pa_tmp_t);
}

static u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 32; }
static u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 32; }

static bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        return true;
      }
    }
  }

  return false;
}

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  u32 native_threads = (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU) ? 1 : 32;

  hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", native_threads);

  return jit_build_options;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (krb5pa_t);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5pa_t *krb5pa = (krb5pa_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  /**
   * format 1: $krb5pa$23$user$realm$salt$<enc><checksum>  (with salt field)
   * format 3: $krb5pa$23$user$realm$<checksum>$<enc>      (split fields, no salt)
   */

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5PA;

  // format 3: $krb5pa$23$user$realm$<32hex_checksum>$<72hex_encrypted>

  token.token_cnt  = 5;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 0;
  token.len_max[1] = MAX_USER_LEN;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len_min[2] = 0;
  token.len_max[2] = MAX_REALM_LEN;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[3]     = '$';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[4]     = 72;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  const u8 *checksum_pos;
  const u8 *timestamp_pos;

  if (rc_tokenizer == PARSER_OK)
  {
    krb5pa->format = 3;

    memcpy (krb5pa->user,  token.buf[1], token.len[1]);
    memcpy (krb5pa->realm, token.buf[2], token.len[2]);
    memset (krb5pa->raw_token, 0, sizeof (krb5pa->raw_token));

    checksum_pos  = token.buf[3];
    timestamp_pos = token.buf[4];
  }
  else
  {
    // format 1: $krb5pa$23$user$realm$salt$<72hex_enc><32hex_checksum>

    memset (&token, 0, sizeof (hc_token_t));

    token.token_cnt  = 6;

    token.signatures_cnt    = 1;
    token.signatures_buf[0] = SIGNATURE_KRB5PA;

    token.len[0]     = 11;
    token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_SIGNATURE;

    token.sep[1]     = '$';
    token.len_min[1] = 0;
    token.len_max[1] = MAX_USER_LEN;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[2]     = '$';
    token.len_min[2] = 0;
    token.len_max[2] = MAX_REALM_LEN;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[3]     = '$';
    token.len_min[3] = 0;
    token.len_max[3] = 128;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.len[4]     = 72;
    token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.len[5]     = 32;
    token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    krb5pa->format = 1;

    memcpy (krb5pa->user,  token.buf[1], token.len[1]);
    memcpy (krb5pa->realm, token.buf[2], token.len[2]);
    memcpy (krb5pa->raw_token,  token.buf[3], token.len[3]);

    timestamp_pos = token.buf[4];
    checksum_pos  = token.buf[5];
  }

  u8 *timestamp_ptr = (u8 *) krb5pa->enc_timestamp;

  for (int i = 0; i < 72; i += 2)
  {
    const u8 p0 = timestamp_pos[i + 0];
    const u8 p1 = timestamp_pos[i + 1];

    *timestamp_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  u8 *checksum_ptr = (u8 *) krb5pa->checksum;

  for (int i = 0; i < 32; i += 2)
  {
    const u8 p0 = checksum_pos[i + 0];
    const u8 p1 = checksum_pos[i + 1];

    *checksum_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;
  }

  salt->salt_buf[0] = krb5pa->enc_timestamp[0];
  salt->salt_buf[1] = krb5pa->enc_timestamp[1];
  salt->salt_buf[2] = krb5pa->enc_timestamp[2];
  salt->salt_buf[3] = krb5pa->enc_timestamp[3];
  salt->salt_buf[4] = krb5pa->enc_timestamp[4];
  salt->salt_buf[5] = krb5pa->enc_timestamp[5];
  salt->salt_buf[6] = krb5pa->enc_timestamp[6];
  salt->salt_buf[7] = krb5pa->enc_timestamp[7];
  salt->salt_buf[8] = krb5pa->enc_timestamp[8];

  salt->salt_len = 36;

  digest[0] = krb5pa->checksum[0];
  digest[1] = krb5pa->checksum[1];
  digest[2] = krb5pa->checksum[2];
  digest[3] = krb5pa->checksum[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5pa_t *krb5pa = (const krb5pa_t *) esalt_buf;

  const u8 *ptr_timestamp = (const u8 *) krb5pa->enc_timestamp;
  const u8 *ptr_checksum  = (const u8 *) krb5pa->checksum;

  char checksum_hex[64] = { 0 };
  char encrypted_hex[160] = { 0 };

  for (u32 i = 0; i < 16; i++)
  {
    snprintf (checksum_hex + i * 2, 3, "%02x", ptr_checksum[i]);
  }

  for (u32 i = 0; i < 36; i++)
  {
    snprintf (encrypted_hex + i * 2, 3, "%02x", ptr_timestamp[i]);
  }

  int line_len;

  if (krb5pa->format == 3)
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s$%s",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->realm,
      checksum_hex,
      encrypted_hex);
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s$%s%s",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->realm,
      (const char *) krb5pa->raw_token,
      encrypted_hex,
      checksum_hex);
  }

  return line_len;
}

static const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?a?a?a?a?a?a?a?axxxxxxxxxxxxxxxx";
  return mask;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
