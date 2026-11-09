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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Kerberos 5, etype 23, AS-REQ Pre-Auth";
static const u64   KERN_TYPE      = 7500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_COMBI_PURE_SWAP;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5pa$23$user$realm$salt$5cbb0c882a2b26956e81644edbdb746326f4f5f0e947144fb3095dffe4b4b03e854fc1d631323632303636373330383333353630";

#include "hooks_common.c"

#define MAX_USER_LEN  511
#define MAX_REALM_LEN 511

typedef struct krb5pa
{
  u32 user[128];
  u32 realm[128];
  u32 salt[64];
  u32 enc_timestamp[16];
  u32 checksum[4];
  u32 enc_timestamp_len;
  u32 format;

} krb5pa_t;

static const char *SIGNATURE_KRB5PA = "$krb5pa$23$";

static bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
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

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
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

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5pa_t);

  return esalt_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5pa_t *krb5pa = (krb5pa_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5PA;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  /**
   * format 1: $krb5pa$23$user$realm$salt$<enc><checksum>  (with salt field)
   * format 2: $krb5pa$23$user$realm$<enc||checksum>       (single field, no salt)
   * format 3: $krb5pa$23$user$realm$<checksum>$<enc>      (split fields, no salt)
   */

  // format 1: $krb5pa$23$user$realm$salt$<data>
  // data = encrypted timestamp (58-76 hex) + checksum (32 hex) = 90-108 hex total

  token.token_cnt  = 5;

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

  token.len_min[4] = 90;
  token.len_max[4] = 108;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  const u8 *timestamp_pos;
  const u8 *checksum_pos;
  int timestamp_hex_len;

  if (rc_tokenizer == PARSER_OK)
  {
    const int data_hex_len = token.len[4];

    if (data_hex_len % 2 != 0) return (PARSER_TOKEN_LENGTH);

    krb5pa->format = 1;

    const u8 *user_pos  = token.buf[1];
    const u8 *realm_pos = token.buf[2];
    const u8 *salt_pos  = token.buf[3];

    memcpy (krb5pa->user,  user_pos,  token.len[1]);
    memcpy (krb5pa->realm, realm_pos, token.len[2]);
    memcpy (krb5pa->salt,  salt_pos,  token.len[3]);

    timestamp_hex_len = data_hex_len - 32;
    timestamp_pos = token.buf[4];
    checksum_pos  = token.buf[4] + timestamp_hex_len;
  }

  if (rc_tokenizer != PARSER_OK)
  {
    // format 3: $krb5pa$23$user$realm$<32hex_checksum>$<58-76hex_encrypted>

    memset (&token, 0, sizeof (hc_token_t));

    token.token_cnt  = 5;

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
    token.len[3]     = 32;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.len_min[4] = 58;
    token.len_max[4] = 76;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer == PARSER_OK)
    {
      const int enc_hex_len = token.len[4];

      if (enc_hex_len % 2 != 0) return (PARSER_TOKEN_LENGTH);

      krb5pa->format = 3;

      const u8 *user_pos  = token.buf[1];
      const u8 *realm_pos = token.buf[2];

      memcpy (krb5pa->user,  user_pos,  token.len[1]);
      memcpy (krb5pa->realm, realm_pos, token.len[2]);
      memset (krb5pa->salt, 0, sizeof (krb5pa->salt));

      checksum_pos      = token.buf[3];
      timestamp_pos     = token.buf[4];
      timestamp_hex_len = enc_hex_len;
    }
  }

  if (rc_tokenizer != PARSER_OK)
  {
    // format 2: $krb5pa$23$user$realm$<90-108hex>  (encrypted||checksum, single field)

    memset (&token, 0, sizeof (hc_token_t));

    token.token_cnt  = 4;

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

    token.len_min[3] = 90;
    token.len_max[3] = 108;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    const int data_hex_len = token.len[3];

    if (data_hex_len % 2 != 0) return (PARSER_TOKEN_LENGTH);

    krb5pa->format = 2;

    const u8 *user_pos  = token.buf[1];
    const u8 *realm_pos = token.buf[2];

    memcpy (krb5pa->user,  user_pos,  token.len[1]);
    memcpy (krb5pa->realm, realm_pos, token.len[2]);
    memset (krb5pa->salt, 0, sizeof (krb5pa->salt));

    timestamp_hex_len = data_hex_len - 32;
    timestamp_pos = token.buf[3];
    checksum_pos  = token.buf[3] + timestamp_hex_len;
  }

  u8 *timestamp_ptr = (u8 *) krb5pa->enc_timestamp;

  for (int i = 0; i < timestamp_hex_len; i += 2)
  {
    const u8 p0 = timestamp_pos[i + 0];
    const u8 p1 = timestamp_pos[i + 1];

    *timestamp_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  krb5pa->enc_timestamp_len = timestamp_hex_len / 2;

  u8 *checksum_ptr = (u8 *) krb5pa->checksum;

  for (int i = 0; i < 32; i += 2)
  {
    const u8 p0 = checksum_pos[i + 0];
    const u8 p1 = checksum_pos[i + 1];

    *checksum_ptr++ = hex_convert (p1) << 0
                    | hex_convert (p0) << 4;
  }

  /**
   * copy some data to generic buffers to make sorting happy
   */

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

  for (u32 i = 0; i < krb5pa->enc_timestamp_len; i++)
  {
    snprintf (encrypted_hex + i * 2, 3, "%02x", ptr_timestamp[i]);
  }

  int line_len;

  if (krb5pa->format == 1)
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s$%s%s",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->realm,
      (const char *) krb5pa->salt,
      encrypted_hex,
      checksum_hex);
  }
  else if (krb5pa->format == 3)
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
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s%s",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->realm,
      encrypted_hex,
      checksum_hex);
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
