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
static const char *HASH_NAME      = "Kerberos 5, etype 1, AS-REP";
static const u64   KERN_TYPE      = 39200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_COMBI_PURE_SWAP;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5asrep$1$user$realm$a8bece37ee9e682bd37952f99c5df055$5a9bac2e1d9f689f507266ca6b4ef13ee73c7129ed9437634938a2acc624d50ae038ccb4d0903601e792279f14e019175a51e6c3c17dce7ed213111d85fb82df9e299f72d1cd06d4b5cf9bd0cf7f1f92b8477f0da117f12de55d530a4a1eab3e8b9b4fcef3aafeb56fbf6916d8cce0f44a20e3b9458fb14fbfbb472fb947f86128970423d27d7149a937ed72e0984eaef795543dd198b39a7f871128daf111a47c4f4be353197842e9e1d956acc7dabf40dc1816b738d49a74ce452850e3c6018a9a31232926ac153b670a0107c6d25e52f7666e21d044cf8f3aafcf97811053";

#include "hooks_common.c"

static const char *SIGNATURE_KRB5ASREP = "$krb5asrep$1$";

#define MAX_USER_LEN  511
#define MAX_REALM_LEN 511
#define MAX_DES_SALT_LEN 128

#define MAX_PW_LEN    64

#define MAX_EDATA2_LEN 20480

typedef struct krb5asrep_1
{
  u32 user[128];
  u32 realm[128];
  u32 format;

  u32 salt_buf[MAX_DES_SALT_LEN / 4];
  u32 salt_len;

  u32 checksum[4];
  u32 edata2[MAX_EDATA2_LEN / 4];
  u32 edata2_len;

} krb5asrep_1_t;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5asrep_1_t);

  return esalt_size;
}

static u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = MAX_PW_LEN;

  return pw_max;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5asrep_1_t *krb5asrep = (krb5asrep_1_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  memset (krb5asrep, 0, sizeof (krb5asrep_1_t));

  /**
   * format 1: $krb5asrep$1$user@realm:checksum$edata2
   * format 2: $krb5asrep$1$user$realm$checksum$edata2
   */

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5ASREP;

  const int sig_len = (int) strlen (SIGNATURE_KRB5ASREP);

  token.len[0]  = sig_len;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  if (line_len < (sig_len + 1)) return (PARSER_SALT_LENGTH);

  const u8 *after_sig = (const u8 *) line_buf + sig_len;

  const int after_sig_len = line_len - sig_len;

  const u8 *colon  = hc_strchr_next (after_sig, after_sig_len, ':');
  const u8 *dollar = hc_strchr_next (after_sig, after_sig_len, '$');

  bool joined = false;

  if (colon != NULL)
  {
    if (dollar == NULL) joined = true;
    else if (colon < dollar) joined = true;
  }

  u32 checksum_token = 0;
  u32 data_token     = 0;

  if (joined == true)
  {
    token.token_cnt  = 4;

    checksum_token   = 2;
    data_token       = 3;

    token.sep[1]     = ':';
    token.len_min[1] = 3;
    token.len_max[1] = MAX_USER_LEN;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[2]     = '$';
    token.len[2]     = 32;
    token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[3]     = '$';
    token.len_min[3] = 64;
    token.len_max[3] = MAX_EDATA2_LEN * 2;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }
  else
  {
    token.token_cnt  = 5;

    checksum_token   = 3;
    data_token       = 4;

    token.sep[1]     = '$';
    token.len_min[1] = 1;
    token.len_max[1] = MAX_USER_LEN;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[2]     = '$';
    token.len_min[2] = 1;
    token.len_max[2] = MAX_REALM_LEN;
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
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos  = NULL;
  const u8 *realm_pos = NULL;

  int user_len  = 0;
  int realm_len = 0;

  if (joined == true)
  {
    const u8 *at = hc_strchr_last (token.buf[1], token.len[1], '@');

    if (at == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    user_pos  = token.buf[1];
    user_len  = (int) (at - token.buf[1]);

    realm_pos = at + 1;
    realm_len = token.len[1] - (user_len + 1);
  }
  else
  {
    user_pos  = token.buf[1];
    realm_pos = token.buf[2];

    user_len  = token.len[1];
    realm_len = token.len[2];
  }

  if ((user_len < 1) || (realm_len < 1)) return (PARSER_SALT_LENGTH);

  if ((user_len + realm_len) > MAX_DES_SALT_LEN) return (PARSER_SALT_LENGTH);

  memcpy (krb5asrep->user,  user_pos,  user_len);
  memcpy (krb5asrep->realm, realm_pos, realm_len);

  u8 *salt_ptr = (u8 *) krb5asrep->salt_buf;

  memcpy (salt_ptr, realm_pos, realm_len);

  uppercase (salt_ptr, realm_len);

  memcpy (salt_ptr + realm_len, user_pos, user_len);

  krb5asrep->salt_len = realm_len + user_len;

  if (joined == true) krb5asrep->format = 1;

  const u8 *checksum_pos = token.buf[checksum_token];

  krb5asrep->checksum[0] = hex_to_u32 (checksum_pos +  0);
  krb5asrep->checksum[1] = hex_to_u32 (checksum_pos +  8);
  krb5asrep->checksum[2] = hex_to_u32 (checksum_pos + 16);
  krb5asrep->checksum[3] = hex_to_u32 (checksum_pos + 24);

  const u8 *data_pos = token.buf[data_token];

  const int data_len = token.len[data_token];

  if ((data_len % 16) != 0) return (PARSER_TOKEN_LENGTH);

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
  salt->salt_buf[3] = krb5asrep->checksum[3];

  salt->salt_len = 16;

  digest[0] = krb5asrep->checksum[0];
  digest[1] = krb5asrep->checksum[1];
  digest[2] = krb5asrep->checksum[2];
  digest[3] = krb5asrep->checksum[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5asrep_1_t *krb5asrep = (const krb5asrep_1_t *) esalt_buf;

  char *data = (char *) hcmalloc ((MAX_EDATA2_LEN * 2) + 1);

  const u8 *ptr_edata2 = (const u8 *) krb5asrep->edata2;

  for (u32 i = 0, j = 0; i < krb5asrep->edata2_len; i += 1, j += 2)
  {
    snprintf (data + j, 3, "%02x", ptr_edata2[i]);
  }

  int line_len;

  if (krb5asrep->format == 1)
  {
    line_len = snprintf (line_buf, line_size, "%s%s@%s:%08x%08x%08x%08x$%s",
      SIGNATURE_KRB5ASREP,
      (const char *) krb5asrep->user,
      (const char *) krb5asrep->realm,
      byte_swap_32 (krb5asrep->checksum[0]),
      byte_swap_32 (krb5asrep->checksum[1]),
      byte_swap_32 (krb5asrep->checksum[2]),
      byte_swap_32 (krb5asrep->checksum[3]),
      data);
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%08x%08x%08x%08x$%s",
      SIGNATURE_KRB5ASREP,
      (const char *) krb5asrep->user,
      (const char *) krb5asrep->realm,
      byte_swap_32 (krb5asrep->checksum[0]),
      byte_swap_32 (krb5asrep->checksum[1]),
      byte_swap_32 (krb5asrep->checksum[2]),
      byte_swap_32 (krb5asrep->checksum[3]),
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
