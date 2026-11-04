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
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Kerberos 5, etype 1, TGS-REP";
static const u64   KERN_TYPE      = 39100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5tgs$1$user$realm$0a47b86e58028355b853b493fde21c3b$71dc52f58d538ed229fb3b0ce43e9a0e4801773037e956cff5547b558e295dbc0a89a48c7efb1b5c6fd856a37db0adea1a76fefcf8a922d4d5c288cc69e542b5de3eb02876e0e018783b3fcd5b9fe8f0b8b208928c8912a5039812078d5b100e4914875c8d8178ff41756945496d507b1a062f52c28b79f9668171a8cf3d2a3ebb97d5d6ba5a136f0d9845b14058455e681f7b067177a96c5cfc20fb78a04b8838f6b86dd52fb316e74ab1c884bdae20";

#include "hooks_common.c"

static const char *SIGNATURE_KRB5TGS = "$krb5tgs$1$";

#define MAX_SALT_LEN 128

#define MAX_PW_LEN    64

#define MAX_EDATA2_LEN 20480

typedef struct krb5tgs_1
{
  u32 account_info[512];
  u32 user[MAX_SALT_LEN / 4];
  u32 realm[MAX_SALT_LEN / 4];
  u32 format;

  u32 salt_buf[MAX_SALT_LEN / 4];
  u32 salt_len;

  u32 checksum[4];
  u32 edata2[MAX_EDATA2_LEN / 4];
  u32 edata2_len;

} krb5tgs_1_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5tgs_1_t);

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

  krb5tgs_1_t *krb5tgs = (krb5tgs_1_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  memset (krb5tgs, 0, sizeof (krb5tgs_1_t));

  /**
   * format 1: $krb5tgs$1$*user$realm$spn*$checksum$edata2  (asterisk block)
   * format 2: $krb5tgs$1$user$realm$checksum$edata2
   */

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5TGS;

  const int sig_len = (int) strlen (SIGNATURE_KRB5TGS);

  token.len[0]  = sig_len;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  if (line_len < (sig_len + 1)) return (PARSER_SALT_LENGTH);

  const u8 *user_pos  = NULL;
  const u8 *realm_pos = NULL;

  int user_len  = 0;
  int realm_len = 0;

  u32 checksum_token = 0;
  u32 data_token     = 0;

  if (line_buf[sig_len] == '*')
  {
    // format 1: $krb5tgs$1$*user$realm$spn*$checksum$edata2  (asterisk block)

    const char *account_info_start = line_buf + sig_len;

    const int account_info_left = line_len - (int) (account_info_start + 1 - line_buf);

    const char *account_info_stop = (const char *) hc_strchr_next ((const u8 *) account_info_start + 1, account_info_left, '*');

    if (account_info_stop == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    account_info_stop++;
    account_info_stop++;

    const int account_info_len = (int) (account_info_stop - account_info_start);

    if (account_info_len >= (int) sizeof (krb5tgs->account_info)) return (PARSER_SALT_LENGTH);

    token.token_cnt  = 4;

    token.len[1]     = account_info_len;
    token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

    checksum_token   = 2;
    data_token       = 3;

    token.sep[2]     = '$';
    token.len[2]     = 32;
    token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[3]     = '$';
    token.len_min[3] = 64;
    token.len_max[3] = MAX_EDATA2_LEN * 2;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    memcpy (krb5tgs->account_info, token.buf[1], token.len[1]);

    user_pos = token.buf[1] + 1;

    const int block_len = token.len[1] - 3;

    if (block_len < 1) return (PARSER_SALT_LENGTH);

    realm_pos = hc_strchr_next (user_pos, block_len, '$');

    if (realm_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    user_len = (int) (realm_pos - user_pos);

    realm_pos++;

    const u8 *spn_pos = hc_strchr_next (realm_pos, block_len - (user_len + 1), '$');

    if (spn_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    realm_len = (int) (spn_pos - realm_pos);

    krb5tgs->format = 2;
  }
  else
  {
    // format 2: $krb5tgs$1$user$realm$checksum$edata2

    token.token_cnt  = 5;

    checksum_token   = 3;
    data_token       = 4;

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

    token.sep[4]     = '$';
    token.len_min[4] = 64;
    token.len_max[4] = MAX_EDATA2_LEN * 2;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    user_pos  = token.buf[1];
    realm_pos = token.buf[2];

    user_len  = token.len[1];
    realm_len = token.len[2];

    krb5tgs->format = 1;
  }

  if ((user_len < 1) || (realm_len < 1)) return (PARSER_SALT_LENGTH);

  if ((user_len + realm_len) > MAX_SALT_LEN) return (PARSER_SALT_LENGTH);

  memcpy (krb5tgs->user,  user_pos,  user_len);
  memcpy (krb5tgs->realm, realm_pos, realm_len);

  u8 *salt_ptr = (u8 *) krb5tgs->salt_buf;

  memcpy (salt_ptr, realm_pos, realm_len);

  uppercase (salt_ptr, realm_len);

  memcpy (salt_ptr + realm_len, user_pos, user_len);

  krb5tgs->salt_len = realm_len + user_len;

  const u8 *checksum_pos = token.buf[checksum_token];

  krb5tgs->checksum[0] = hex_to_u32 (checksum_pos +  0);
  krb5tgs->checksum[1] = hex_to_u32 (checksum_pos +  8);
  krb5tgs->checksum[2] = hex_to_u32 (checksum_pos + 16);
  krb5tgs->checksum[3] = hex_to_u32 (checksum_pos + 24);

  const u8 *data_pos = token.buf[data_token];

  const int data_len = token.len[data_token];

  if ((data_len % 16) != 0) return (PARSER_TOKEN_LENGTH);

  u8 *edata_ptr = (u8 *) krb5tgs->edata2;

  for (int i = 0; i < data_len; i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *edata_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  krb5tgs->edata2_len = data_len / 2;

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
  const krb5tgs_1_t *krb5tgs = (const krb5tgs_1_t *) esalt_buf;

  char *data = (char *) hcmalloc ((MAX_EDATA2_LEN * 2) + 1);

  const u8 *ptr_edata2 = (const u8 *) krb5tgs->edata2;

  for (u32 i = 0, j = 0; i < krb5tgs->edata2_len; i += 1, j += 2)
  {
    snprintf (data + j, 3, "%02x", ptr_edata2[i]);
  }

  int line_len;

  if (krb5tgs->format == 2)
  {
    line_len = snprintf (line_buf, line_size, "%s%s%08x%08x%08x%08x$%s",
      SIGNATURE_KRB5TGS,
      (const char *) krb5tgs->account_info,
      byte_swap_32 (krb5tgs->checksum[0]),
      byte_swap_32 (krb5tgs->checksum[1]),
      byte_swap_32 (krb5tgs->checksum[2]),
      byte_swap_32 (krb5tgs->checksum[3]),
      data);
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%08x%08x%08x%08x$%s",
      SIGNATURE_KRB5TGS,
      (const char *) krb5tgs->user,
      (const char *) krb5tgs->realm,
      byte_swap_32 (krb5tgs->checksum[0]),
      byte_swap_32 (krb5tgs->checksum[1]),
      byte_swap_32 (krb5tgs->checksum[2]),
      byte_swap_32 (krb5tgs->checksum[3]),
      data);
  }

  hcfree (data);

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
