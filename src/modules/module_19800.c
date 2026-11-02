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
static const char *HASH_NAME      = "Kerberos 5, etype 17, Pre-Auth";
static const u64   KERN_TYPE      = 19800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333";

#include "hooks_common.c"

typedef struct krb5pa_17
{
  u32 user[128];
  u32 domain[128];
  u32 account_info[512];
  u32 account_info_len;

  u32 checksum[3];
  u32 enc_timestamp[32];
  u32 enc_timestamp_len;

  u32 format;

} krb5pa_17_t;

typedef struct krb5pa_17_tmp
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[5];
  u32 out[5];

} krb5pa_17_tmp_t;

static const char *SIGNATURE_KRB5PA = "$krb5pa$17$";

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (krb5pa_17_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5pa_17_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5pa_17_t *krb5pa = (krb5pa_17_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5PA;

  token.len[0]  = 11;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  // assume no signature found
  if (line_len < 11) return (PARSER_SALT_LENGTH);

  // three layouts reach this parser:
  //
  //   1  $krb5pa$17$user$realm$enc_timestamp+checksum
  //   2  $krb5pa$17$user$realm$$enc_timestamp+checksum
  //   3  $krb5pa$17$user$realm$salt$enc_timestamp+checksum
  //
  // 1 is what hashcat has always written. krb5pa-sha1 always writes the salt
  // field and leaves it empty when the salt is the default, which is 2, and
  // fills it when the principal's salt is something else, which is 3. The
  // layout is taken from the field count rather than by parsing one shape and
  // retrying another, so a malformed line still reports its own error

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == '$') sep_cnt++;
  }

  krb5pa->format = (sep_cnt >= 6) ? 2 : 1;

  token.token_cnt  = 4;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 512;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 512;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (krb5pa->format == 2)
  {
    token.token_cnt  = 5;

    token.sep[3]     = '$';
    token.len_min[3] = 0;
    token.len_max[3] = 512;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[4]     = '$';
    token.len_min[4] = 104;
    token.len_max[4] = 112;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }
  else
  {
    token.sep[3]     = '$';
    token.len_min[3] = 104;
    token.len_max[3] = 112;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos;
  const u8 *domain_pos;
  const u8 *data_pos;
  const u8 *checksum_pos;

  int user_len;
  int domain_len;
  int data_len;
  int account_info_len;

  user_pos = token.buf[1];
  user_len = token.len[1];

  memcpy (krb5pa->user, user_pos, user_len);

  domain_pos = token.buf[2];
  domain_len = token.len[2];

  memcpy (krb5pa->domain, domain_pos, domain_len);

  u8 *account_info_ptr = (u8 *) krb5pa->account_info;

  if ((krb5pa->format == 2) && (token.len[3] > 0))
  {
    // the salt is given, so realm and user are carried for the encoder only

    krb5pa->format = 3;

    const u8 *salt_pos = token.buf[3];

    account_info_len = token.len[3];

    memcpy (account_info_ptr, salt_pos, account_info_len);

    data_pos = token.buf[4];
    data_len = token.len[4];
  }
  else
  {
    // uppercase(realm) + user: what AD derives for a user account. RFC 4120
    // section 4 puts the realm in verbatim, and realms are uppercase by
    // convention rather than by rule

    u8 domain[512];

    memcpy (domain, domain_pos, domain_len);
    uppercase (domain, domain_len);

    account_info_len = token.len[2] + token.len[1];

    memcpy (account_info_ptr, domain, domain_len);
    memcpy (account_info_ptr + domain_len, user_pos, user_len);

    const int data_idx = (krb5pa->format == 2) ? 4 : 3;

    data_pos = token.buf[data_idx];
    data_len = token.len[data_idx];
  }

  krb5pa->account_info_len = account_info_len;

  // Split checksum
  checksum_pos = data_pos + data_len - 24;
  data_len = data_len - 24;

  // hmac-sha1 is reduced to 12 bytes
  krb5pa->checksum[0] = byte_swap_32 (hex_to_u32 (checksum_pos +  0));
  krb5pa->checksum[1] = byte_swap_32 (hex_to_u32 (checksum_pos +  8));
  krb5pa->checksum[2] = byte_swap_32 (hex_to_u32 (checksum_pos + 16));

  u8 *edata_ptr = (u8 *) krb5pa->enc_timestamp;

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

  krb5pa->enc_timestamp_len = data_len / 2;

  salt->salt_buf[0] = krb5pa->checksum[0];
  salt->salt_buf[1] = krb5pa->checksum[1];
  salt->salt_buf[2] = krb5pa->checksum[2];

  salt->salt_len = 12;

  salt->salt_iter = 4096 - 1;

  digest[0] = krb5pa->checksum[0];
  digest[1] = krb5pa->checksum[1];
  digest[2] = krb5pa->checksum[2];
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5pa_17_t *krb5pa = (const krb5pa_17_t *) esalt_buf;

  char data[32 * 4 * 2] = { 0 };

  for (u32 i = 0, j = 0; i < krb5pa->enc_timestamp_len; i += 1, j += 2)
  {
    const u8 *ptr_enc_timestamp = (const u8 *) krb5pa->enc_timestamp;

    snprintf (data + j, 3, "%02x", ptr_enc_timestamp[i]);
  }

  int line_len;

  if (krb5pa->format == 3)
  {
    char salt_str[512 + 1] = { 0 };

    memcpy (salt_str, (const char *) krb5pa->account_info, krb5pa->account_info_len);

    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s$%s%08x%08x%08x",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->domain,
      salt_str,
      data,
      krb5pa->checksum[0],
      krb5pa->checksum[1],
      krb5pa->checksum[2]);
  }
  else if (krb5pa->format == 2)
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$$%s%08x%08x%08x",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->domain,
      data,
      krb5pa->checksum[0],
      krb5pa->checksum[1],
      krb5pa->checksum[2]);
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s%08x%08x%08x",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->domain,
      data,
      krb5pa->checksum[0],
      krb5pa->checksum[1],
      krb5pa->checksum[2]);
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
