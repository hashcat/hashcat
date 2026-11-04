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
static const char *HASH_NAME      = "Kerberos 5, etype 3, AS-REQ Pre-Auth";
static const u64   KERN_TYPE      = 39000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5pa$3$user$realm$df8e4459369e8f512f827f8a55b552c2$4668bc8fd02db4118264d02c1c952b1018636eb1d3e0888ac5c860d9ee897b6ed71483dc0bbfa4d7";

#include "hooks_common.c"

static const char *SIGNATURE_KRB5PA = "$krb5pa$3$";

#define MAX_SALT_LEN 128

#define MAX_PW_LEN    64

#define MAX_TIMESTAMP_LEN 128

typedef struct krb5pa_3
{
  u32 user[MAX_SALT_LEN / 4];
  u32 realm[MAX_SALT_LEN / 4];

  u32 salt_buf[MAX_SALT_LEN / 4];
  u32 salt_len;

  u32 enc_timestamp[MAX_TIMESTAMP_LEN / 4];
  u32 enc_timestamp_len;
  u32 format;

} krb5pa_3_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5pa_3_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = MAX_PW_LEN;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5pa_3_t *krb5pa = (krb5pa_3_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  memset (krb5pa, 0, sizeof (krb5pa_3_t));

  /**
   * format 1: $krb5pa$3$user$realm$data
   * format 2: $krb5pa$3$user$realm$checksum$encrypted
   */

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5PA;

  const int sig_len = (int) strlen (SIGNATURE_KRB5PA);

  // format 2: $krb5pa$3$user$realm$checksum$encrypted

  token.token_cnt  = 5;

  token.len[0]     = sig_len;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = MAX_SALT_LEN - 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = MAX_SALT_LEN - 1;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[3]     = '$';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[4] = 32;
  token.len_max[4] = (MAX_TIMESTAMP_LEN - 16) * 2;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  const u8 *user_pos;
  const u8 *realm_pos;

  int user_len;
  int realm_len;
  int data_len;

  if (rc_tokenizer == PARSER_OK)
  {
    const int enc_len = token.len[4];

    if ((32 + enc_len) % 16 != 0) return (PARSER_TOKEN_LENGTH);

    krb5pa->format = 2;

    user_pos  = token.buf[1];
    realm_pos = token.buf[2];

    user_len  = token.len[1];
    realm_len = token.len[2];

    data_len  = 32 + enc_len;
  }
  else
  {
    // format 1: $krb5pa$3$user$realm$data

    memset (&token, 0, sizeof (hc_token_t));

    token.signatures_cnt    = 1;
    token.signatures_buf[0] = SIGNATURE_KRB5PA;

    token.token_cnt  = 4;

    token.len[0]     = sig_len;
    token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_SIGNATURE;

    token.sep[1]     = '$';
    token.len_min[1] = 1;
    token.len_max[1] = MAX_SALT_LEN - 1;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[2]     = '$';
    token.len_min[2] = 1;
    token.len_max[2] = MAX_SALT_LEN - 1;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.len_min[3] = 64;
    token.len_max[3] = MAX_TIMESTAMP_LEN * 2;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    krb5pa->format = 1;

    user_pos  = token.buf[1];
    realm_pos = token.buf[2];

    user_len  = token.len[1];
    realm_len = token.len[2];
    data_len  = token.len[3];
  }

  if ((user_len + realm_len) > MAX_SALT_LEN) return (PARSER_SALT_LENGTH);

  if ((data_len % 16) != 0) return (PARSER_TOKEN_LENGTH);

  memcpy (krb5pa->user,  user_pos,  user_len);
  memcpy (krb5pa->realm, realm_pos, realm_len);

  u8 *salt_ptr = (u8 *) krb5pa->salt_buf;

  memcpy (salt_ptr, realm_pos, realm_len);

  uppercase (salt_ptr, realm_len);

  memcpy (salt_ptr + realm_len, user_pos, user_len);

  krb5pa->salt_len = realm_len + user_len;

  u8 *ts_ptr = (u8 *) krb5pa->enc_timestamp;

  if (krb5pa->format == 2)
  {
    const u8 *checksum_pos  = token.buf[3];
    const u8 *encrypted_pos = token.buf[4];
    const int encrypted_len = token.len[4];

    for (int i = 0; i < 32; i += 2)
    {
      const u8 p0 = checksum_pos[i + 0];
      const u8 p1 = checksum_pos[i + 1];

      *ts_ptr++ = hex_convert (p1) << 0
                | hex_convert (p0) << 4;
    }

    for (int i = 0; i < encrypted_len; i += 2)
    {
      const u8 p0 = encrypted_pos[i + 0];
      const u8 p1 = encrypted_pos[i + 1];

      *ts_ptr++ = hex_convert (p1) << 0
                | hex_convert (p0) << 4;
    }
  }
  else
  {
    const u8 *data_pos = token.buf[3];

    for (int i = 0; i < data_len; i += 2)
    {
      const u8 p0 = data_pos[i + 0];
      const u8 p1 = data_pos[i + 1];

      *ts_ptr++ = hex_convert (p1) << 0
                | hex_convert (p0) << 4;
    }
  }

  krb5pa->enc_timestamp_len = data_len / 2;

  salt->salt_buf[0] = krb5pa->enc_timestamp[0];
  salt->salt_buf[1] = krb5pa->enc_timestamp[1];
  salt->salt_buf[2] = krb5pa->enc_timestamp[2];
  salt->salt_buf[3] = krb5pa->enc_timestamp[3];

  salt->salt_len = 16;

  digest[0] = krb5pa->enc_timestamp[0];
  digest[1] = krb5pa->enc_timestamp[1];
  digest[2] = krb5pa->enc_timestamp[2];
  digest[3] = krb5pa->enc_timestamp[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5pa_3_t *krb5pa = (const krb5pa_3_t *) esalt_buf;

  const u8 *ptr = (const u8 *) krb5pa->enc_timestamp;

  int line_len;

  if (krb5pa->format == 2)
  {
    char checksum_hex[64] = { 0 };
    char encrypted_hex[MAX_TIMESTAMP_LEN * 2 + 1];

    memset (encrypted_hex, 0, sizeof (encrypted_hex));

    for (u32 i = 0; i < 16; i++)
    {
      snprintf (checksum_hex + i * 2, 3, "%02x", ptr[i]);
    }

    for (u32 i = 16, j = 0; i < krb5pa->enc_timestamp_len; i++, j += 2)
    {
      snprintf (encrypted_hex + j, 3, "%02x", ptr[i]);
    }

    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s$%s",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->realm,
      checksum_hex,
      encrypted_hex);
  }
  else
  {
    char data[MAX_TIMESTAMP_LEN * 2 + 1];

    memset (data, 0, sizeof (data));

    for (u32 i = 0, j = 0; i < krb5pa->enc_timestamp_len; i += 1, j += 2)
    {
      snprintf (data + j, 3, "%02x", ptr[i]);
    }

    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->realm,
      data);
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
}
