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
static const char *HASH_NAME      = "Kerberos 5, etype 17, AS-REQ Pre-Auth";
static const u64   KERN_TYPE      = 19800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333";

#include "hooks_common.c"

#define MAX_USER_LEN  511
#define MAX_REALM_LEN 511
#define MAX_CHECKSUM_LEN 12
#define MAX_ENC_TS_LEN 128
#define MAX_KDC_SALT_LEN 1022

typedef struct krb5pa_17
{
  u32 user[128];
  u32 realm[128];
  u32 kdc_salt[256];
  u32 kdc_salt_len;

  u32 checksum[3];
  u32 enc_timestamp[MAX_ENC_TS_LEN / 4];
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

static u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (krb5pa_17_tmp_t);

  return tmp_size;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5pa_17_t);

  return esalt_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
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

  if (line_len < 11) return (PARSER_SALT_LENGTH);

  /**
   * format 1: $krb5pa$17$user$realm$enc_timestamp+checksum           (single field)
   * format 2: $krb5pa$17$user$realm$$enc_timestamp+checksum          (empty salt)
   * format 3: $krb5pa$17$user$realm$salt$enc_timestamp+checksum      (explicit salt)
   * format 4: $krb5pa$17$user$realm$checksum$enc_timestamp               (split fields)
   */

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == '$') sep_cnt++;
  }

  token.token_cnt  = 4;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = MAX_USER_LEN;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = MAX_REALM_LEN;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (sep_cnt >= 6)
  {
    // format 2/3: $krb5pa$17$user$realm$[salt]$data (data 104-112 hex)
    krb5pa->format = 2;

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
    // format 1: $krb5pa$17$user$realm$data (single field)
    krb5pa->format = 1;

    token.sep[3]     = '$';
    token.len_min[3] = 104;
    token.len_max[3] = 112;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }

  int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK)
  {
    if (sep_cnt == 6)
    {
      // format 4: $krb5pa$17$user$realm$checksum(24)$enc_timestamp(80-88)
      krb5pa->format = 4;

      token.token_cnt  = 5;

      token.sep[3]     = '$';
      token.len[3]     = 24;
      token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                       | TOKEN_ATTR_VERIFY_HEX;

      token.sep[4]     = '$';
      token.len_min[4] = 80;
      token.len_max[4] = 88;
      token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                       | TOKEN_ATTR_VERIFY_HEX;

      rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
    }

    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);
  }

  const u8 *user_pos;
  const u8 *realm_pos;
  const u8 *data_pos;
  const u8 *checksum_pos;

  int user_len;
  int realm_len;
  int data_len;
  int kdc_salt_len;

  user_pos = token.buf[1];
  user_len = token.len[1];

  memcpy (krb5pa->user, user_pos, user_len);

  realm_pos = token.buf[2];
  realm_len = token.len[2];

  memcpy (krb5pa->realm, realm_pos, realm_len);

  u8 *kdc_salt_ptr = (u8 *) krb5pa->kdc_salt;

  if ((krb5pa->format == 2) && (token.len[3] > 0))
  {
    krb5pa->format = 3;

    const u8 *salt_pos = token.buf[3];

    kdc_salt_len = token.len[3];

    memcpy (kdc_salt_ptr, salt_pos, kdc_salt_len);

    data_pos = token.buf[4];
    data_len = token.len[4];

    checksum_pos = data_pos + data_len - 24;
    data_len = data_len - 24;
  }
  else
  {
    u8 realm[512];

    memcpy (realm, realm_pos, realm_len);
    uppercase (realm, realm_len);

    kdc_salt_len = token.len[2] + token.len[1];

    memcpy (kdc_salt_ptr, realm, realm_len);
    memcpy (kdc_salt_ptr + realm_len, user_pos, user_len);

    if (krb5pa->format == 4)
    {
      checksum_pos = token.buf[3];
      data_pos = token.buf[4];
      data_len = token.len[4];
    }
    else if (krb5pa->format == 2)
    {
      data_pos = token.buf[4];
      data_len = token.len[4];

      checksum_pos = data_pos + data_len - 24;
      data_len = data_len - 24;
    }
    else
    {
      data_pos = token.buf[3];
      data_len = token.len[3];

      checksum_pos = data_pos + data_len - 24;
      data_len = data_len - 24;
    }
  }

  krb5pa->kdc_salt_len = kdc_salt_len;

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

  if (krb5pa->kdc_salt_len > 256)
  {
    salt->salt_buf[0] = krb5pa->checksum[0];
    salt->salt_buf[1] = krb5pa->checksum[1];
    salt->salt_buf[2] = krb5pa->checksum[2];

    salt->salt_len = 12;
  }
  else
  {
    const int kdc_salt_words = (krb5pa->kdc_salt_len + 3) / 4;

    for (int i = 0; i < kdc_salt_words; i++)
      salt->salt_buf[i] = krb5pa->kdc_salt[i];

    salt->salt_len = krb5pa->kdc_salt_len;
  }

  salt->salt_iter = 4096 - 1;

  digest[0] = krb5pa->checksum[0];
  digest[1] = krb5pa->checksum[1];
  digest[2] = krb5pa->checksum[2];
  digest[3] = 0;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5pa_17_t *krb5pa = (const krb5pa_17_t *) esalt_buf;

  char data[32 * 4 * 2] = { 0 };

  for (u32 i = 0, j = 0; i < krb5pa->enc_timestamp_len; i += 1, j += 2)
  {
    const u8 *ptr_enc_timestamp = (const u8 *) krb5pa->enc_timestamp;

    snprintf (data + j, 3, "%02x", ptr_enc_timestamp[i]);
  }

  int line_len;

  if (krb5pa->format == 4)
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%08x%08x%08x$%s",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->realm,
      krb5pa->checksum[0],
      krb5pa->checksum[1],
      krb5pa->checksum[2],
      data);
  }
  else if (krb5pa->format == 3)
  {
    char salt_str[512 + 1] = { 0 };

    memcpy (salt_str, (const char *) krb5pa->kdc_salt, krb5pa->kdc_salt_len);

    line_len = snprintf (line_buf, line_size, "%s%s$%s$%s$%s%08x%08x%08x",
      SIGNATURE_KRB5PA,
      (const char *) krb5pa->user,
      (const char *) krb5pa->realm,
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
      (const char *) krb5pa->realm,
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
      (const char *) krb5pa->realm,
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
  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
