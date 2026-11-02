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
static const char *HASH_NAME      = "Kerberos 5, etype 17, DB";
static const u64   KERN_TYPE      = 28800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e";

#include "hooks_common.c"

typedef struct krb5db_17
{
  u32 user[128];
  u32 domain[128];
  u32 account_info[512];
  u32 account_info_len;

} krb5db_17_t;

typedef struct krb5db_17_tmp
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[5];
  u32 out[5];

} krb5db_17_tmp_t;

static const char *SIGNATURE_KRB5DB = "$krb5db$17$";

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (krb5db_17_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5db_17_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5db_17_t *krb5db = (krb5db_17_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5DB;

  token.len[0]  = 11;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  /**
   * $krb5db$17$user$realm$hash
   * $krb5db$17$user$realm$*spn*$hash
   */

  // assume no signature found
  if (line_len < 12) return (PARSER_SALT_LENGTH);

  // hc_strchr_next, not strchr: the field ends where the line ends. strchr () ended it at the
  // first NUL instead, which is the caller's terminator where there is one and whatever follows
  // the hash on the line where the caller passed a slice of it.

  const char *spn_info_start = (const char *) hc_strchr_next ((const u8 *) line_buf + 11 + 1, line_len - (11 + 1), '*');

  int is_spn_provided = 0;

  // assume $krb5db$17$user$realm$hash
  if (spn_info_start == NULL)
  {
    token.token_cnt  = 4;

    token.sep[1]     = '$';
    token.len_min[1] = 1;
    token.len_max[1] = 512;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[2]     = '$';
    token.len_min[2] = 1;
    token.len_max[2] = 512;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[3]     = '$';
    token.len[3]     = 32;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }
  // assume $krb5db$17$user$realm$*spn*$hash
  else
  {
    // bounded for the same reason as the search above: the field ends where the line ends

    const int spn_info_left = line_len - (int) (spn_info_start + 1 - line_buf);

    const char *spn_info_stop = (const char *) hc_strchr_next ((const u8 *) spn_info_start + 1, spn_info_left, '*');

    if (spn_info_stop == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    spn_info_stop++; // we want the * $char included
    spn_info_stop++; // we want the $ char included

    const int spn_info_len = spn_info_stop - spn_info_start;

    token.token_cnt  = 5;

    token.sep[1]     = '$';
    token.len_min[1] = 1;
    token.len_max[1] = 512;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[2]     = '$';
    token.len_min[2] = 1;
    token.len_max[2] = 512;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.len[3]     = spn_info_len;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH;

    token.sep[4]     = '$';
    token.len[4]     = 32;
    token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    is_spn_provided = 1;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos;
  const u8 *domain_pos;
  const u8 *checksum_pos;

  int user_len;
  int domain_len;
  int account_info_len;

  user_pos = token.buf[1];
  user_len = token.len[1];

  memcpy (krb5db->user, user_pos, user_len);

  domain_pos = token.buf[2];
  domain_len = token.len[2];

  memcpy (krb5db->domain, domain_pos, domain_len);

  checksum_pos = token.buf[3 + is_spn_provided];

  account_info_len = token.len[2] + token.len[1];

  u8 *account_info_ptr = (u8 *) krb5db->account_info;

  // domain must be uppercase

  u8 domain[512];

  memcpy (domain, domain_pos, domain_len);
  uppercase (domain, domain_len);

  memcpy (account_info_ptr, domain, domain_len);
  memcpy (account_info_ptr + domain_len, user_pos, user_len);

  krb5db->account_info_len = account_info_len;

  // salt - copy enough of account_info for dedup (realm + user can exceed 16 bytes)

  const int ai_words = (account_info_len + 3) / 4;

  for (int i = 0; i < ai_words && i < 64; i++)
  {
    salt->salt_buf[i] = krb5db->account_info[i];
  }

  salt->salt_len = account_info_len;

  salt->salt_iter = 4096 - 1;

  // digest

  digest[0] = byte_swap_32 (hex_to_u32 (checksum_pos +  0));
  digest[1] = byte_swap_32 (hex_to_u32 (checksum_pos +  8));
  digest[2] = byte_swap_32 (hex_to_u32 (checksum_pos + 16));
  digest[3] = byte_swap_32 (hex_to_u32 (checksum_pos + 24));

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const krb5db_17_t *krb5db = (const krb5db_17_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s%s$%s$%08x%08x%08x%08x",
    SIGNATURE_KRB5DB,
    (const char *) krb5db->user,
    (const char *) krb5db->domain,
    digest[0],
    digest[1],
    digest[2],
    digest[3]);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
