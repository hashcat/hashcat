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
static const char *HASH_NAME      = "Kerberos 5, etype 1/2/3, DB";
static const u64   KERN_TYPE      = 38400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5db$1$test$TEST.LOCAL$7f153708497ae385";

#include "hooks_common.c"

// etypes 1, 2 and 3 are des-cbc-crc, des-cbc-md4 and des-cbc-md5, and the string-to-key of
// RFC 3961 6.2 is the same function for all three, so one key serves whichever of them a domain
// stored. The three signatures are read here and the one a line carried is printed back.

static const char *SIGNATURE_KRB5DB_1 = "$krb5db$1$";
static const char *SIGNATURE_KRB5DB_2 = "$krb5db$2$";
static const char *SIGNATURE_KRB5DB_3 = "$krb5db$3$";

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/krb5db2hashcat.py to extract the hashes";
}

// the kernel assembles the password and the salt in a 256 byte buffer, so the two limits have to
// stay within it together

#define MAX_SALT_LEN 128

#define MAX_PW_LEN    64

// the salt is the realm glued to the principal, so the two are kept apart here as well to print
// the line back exactly as it came in. The encryption type is here and not in the salt because
// hashcat keeps one salt for every distinct salt and one esalt for every hash, and a dump of one
// domain holds lines of one principal under more than one type.

typedef struct krb5db_des
{
  u32 user[MAX_SALT_LEN / 4];
  u32 realm[MAX_SALT_LEN / 4];

  u32 etype;

} krb5db_des_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5db_des_t);

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

  krb5db_des_t *krb5db = (krb5db_des_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  /**
   * $krb5db$1$user$realm$hash
   * $krb5db$1$user$realm$*spn*$hash
   *
   * with 2 and 3 in place of the 1 for the other two DES encryption types
   */

  token.signatures_cnt    = 3;
  token.signatures_buf[0] = SIGNATURE_KRB5DB_1;
  token.signatures_buf[1] = SIGNATURE_KRB5DB_2;
  token.signatures_buf[2] = SIGNATURE_KRB5DB_3;

  // the three are the same length, so the fields behind them start at the same offset

  const int sig_len = (int) strlen (SIGNATURE_KRB5DB_1);

  token.len[0]  = sig_len;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  if (line_len < (sig_len + 1)) return (PARSER_SALT_LENGTH);

  // hc_strchr_next, not strchr: the field ends where the line ends, as in module_28800.c

  const char *spn_info_start = (const char *) hc_strchr_next ((const u8 *) line_buf + sig_len + 1, line_len - (sig_len + 1), '*');

  int is_spn_provided = 0;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = MAX_SALT_LEN - 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = MAX_SALT_LEN - 1;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (spn_info_start == NULL)
  {
    token.token_cnt = 4;
  }
  else
  {
    const int spn_info_left = line_len - (int) (spn_info_start + 1 - line_buf);

    const char *spn_info_stop = (const char *) hc_strchr_next ((const u8 *) spn_info_start + 1, spn_info_left, '*');

    if (spn_info_stop == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    spn_info_stop++; // we want the * char included
    spn_info_stop++; // we want the $ char included

    token.token_cnt = 5;

    token.len[3]    = (int) (spn_info_stop - spn_info_start);
    token.attr[3]   = TOKEN_ATTR_FIXED_LENGTH;

    is_spn_provided = 1;
  }

  // the service principal takes no part in the key: the salt is the realm and the principal, so
  // the field is accepted the way module_28800.c accepts it and then dropped

  token.sep[3 + is_spn_provided]  = '$';
  token.len[3 + is_spn_provided]  = 16;
  token.attr[3 + is_spn_provided] = TOKEN_ATTR_FIXED_LENGTH
                                  | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // the encryption type takes no part in the key, so the digit the signature carries is kept only
  // to write the line back out

  krb5db->etype = (u32) (token.buf[0][sig_len - 2] - '0');

  const u8 *user_pos  = token.buf[1];
  const u8 *realm_pos = token.buf[2];

  const int user_len  = token.len[1];
  const int realm_len = token.len[2];

  if ((user_len + realm_len) > MAX_SALT_LEN) return (PARSER_SALT_LENGTH);

  memcpy (krb5db->user,  user_pos,  user_len);
  memcpy (krb5db->realm, realm_pos, realm_len);

  // the Kerberos salt is the realm in upper case followed by the principal, with no separator

  u8 *salt_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_ptr, realm_pos, realm_len);

  uppercase (salt_ptr, realm_len);

  memcpy (salt_ptr + realm_len, user_pos, user_len);

  salt->salt_len = realm_len + user_len;

  // the key is read the way the kernel packs it, the first byte in the low bits of digest[0]

  const u8 *hash_pos = token.buf[3 + is_spn_provided];

  digest[0] = hex_to_u32 (hash_pos + 0);
  digest[1] = hex_to_u32 (hash_pos + 8);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const krb5db_des_t *krb5db = (const krb5db_des_t *) esalt_buf;

  u8 hash[17];

  memset (hash, 0, sizeof (hash));

  u32_to_hex (digest[0], hash + 0);
  u32_to_hex (digest[1], hash + 8);

  const int line_len = snprintf (line_buf, line_size, "$krb5db$%u$%s$%s$%s",
    krb5db->etype,
    (const char *) krb5db->user,
    (const char *) krb5db->realm,
    (const char *) hash);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_usage_notice             = module_usage_notice;
}
