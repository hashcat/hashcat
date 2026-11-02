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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "MS Office <= 2003 $0/$1, MD5 + RC4, collider #2";
static const u64   KERN_TYPE      = 9720;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_UTF16LE
                                  | OPTS_TYPE_SUGGEST_KG
                                  | OPTS_TYPE_AUTODETECT_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2:91b2e062b9";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/openwall/john/blob/bleeding-jumbo/run/office2john.py to extract the $oldoffice$ line, dropping the file name and colon it prints in front. This mode also needs the RC4 key appended after a colon, which the extractor does not emit: crack the $oldoffice$ line with mode 9710 first to recover the key, then append it as ':<key>'.";
}

typedef struct oldoffice01
{
  u32 version;
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[4];
  u32 rc4key[2];

} oldoffice01_t;

static const char *SIGNATURE_OLDOFFICE  = "$oldoffice$";
static const char *SIGNATURE_OLDOFFICE0 = "$oldoffice$0";
static const char *SIGNATURE_OLDOFFICE1 = "$oldoffice$1";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (oldoffice01_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 15; // https://msdn.microsoft.com/en-us/library/dd772916(v=office.12).aspx

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  oldoffice01_t *oldoffice01 = (oldoffice01_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 6;

  token.signatures_cnt    = 2;
  token.signatures_buf[0] = SIGNATURE_OLDOFFICE0;
  token.signatures_buf[1] = SIGNATURE_OLDOFFICE1;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[3]     = '*';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = ':';
  token.len[4]     = 32;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = ':';
  token.len[5]     = 10;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos               = token.buf[1];
  const u8 *osalt_pos                 = token.buf[2];
  const u8 *encryptedVerifier_pos     = token.buf[3];
  const u8 *encryptedVerifierHash_pos = token.buf[4];
  const u8 *rc4key_pos                = token.buf[5];

  // esalt

  const u32 version = *version_pos - 0x30;

  if (version != 0 && version != 1) return (PARSER_SALT_VALUE);

  oldoffice01->version = version;

  oldoffice01->encryptedVerifier[0] = hex_to_u32 (encryptedVerifier_pos +  0);
  oldoffice01->encryptedVerifier[1] = hex_to_u32 (encryptedVerifier_pos +  8);
  oldoffice01->encryptedVerifier[2] = hex_to_u32 (encryptedVerifier_pos + 16);
  oldoffice01->encryptedVerifier[3] = hex_to_u32 (encryptedVerifier_pos + 24);

  oldoffice01->encryptedVerifierHash[0] = hex_to_u32 (encryptedVerifierHash_pos +  0);
  oldoffice01->encryptedVerifierHash[1] = hex_to_u32 (encryptedVerifierHash_pos +  8);
  oldoffice01->encryptedVerifierHash[2] = hex_to_u32 (encryptedVerifierHash_pos + 16);
  oldoffice01->encryptedVerifierHash[3] = hex_to_u32 (encryptedVerifierHash_pos + 24);

  oldoffice01->rc4key[1] = 0;
  oldoffice01->rc4key[0] = 0;

  oldoffice01->rc4key[0] |= (u32) hex_convert (rc4key_pos[0]) << 28;
  oldoffice01->rc4key[0] |= (u32) hex_convert (rc4key_pos[1]) << 24;
  oldoffice01->rc4key[0] |= (u32) hex_convert (rc4key_pos[2]) << 20;
  oldoffice01->rc4key[0] |= (u32) hex_convert (rc4key_pos[3]) << 16;
  oldoffice01->rc4key[0] |= (u32) hex_convert (rc4key_pos[4]) << 12;
  oldoffice01->rc4key[0] |= (u32) hex_convert (rc4key_pos[5]) <<  8;
  oldoffice01->rc4key[0] |= (u32) hex_convert (rc4key_pos[6]) <<  4;
  oldoffice01->rc4key[0] |= (u32) hex_convert (rc4key_pos[7]) <<  0;
  oldoffice01->rc4key[1] |= (u32) hex_convert (rc4key_pos[8]) << 28;
  oldoffice01->rc4key[1] |= (u32) hex_convert (rc4key_pos[9]) << 24;

  oldoffice01->rc4key[0] = byte_swap_32 (oldoffice01->rc4key[0]);
  oldoffice01->rc4key[1] = byte_swap_32 (oldoffice01->rc4key[1]);

  // salt

  salt->salt_len = 16;

  salt->salt_buf[ 0] = hex_to_u32 (osalt_pos +  0);
  salt->salt_buf[ 1] = hex_to_u32 (osalt_pos +  8);
  salt->salt_buf[ 2] = hex_to_u32 (osalt_pos + 16);
  salt->salt_buf[ 3] = hex_to_u32 (osalt_pos + 24);

  // this is a workaround as office produces multiple documents with the same salt

  salt->salt_buf[ 4] = oldoffice01->encryptedVerifier[0];
  salt->salt_buf[ 5] = oldoffice01->encryptedVerifier[1];
  salt->salt_buf[ 6] = oldoffice01->encryptedVerifier[2];
  salt->salt_buf[ 7] = oldoffice01->encryptedVerifier[3];
  salt->salt_buf[ 8] = oldoffice01->encryptedVerifierHash[0];
  salt->salt_buf[ 9] = oldoffice01->encryptedVerifierHash[1];
  salt->salt_buf[10] = oldoffice01->encryptedVerifierHash[2];
  salt->salt_buf[11] = oldoffice01->encryptedVerifierHash[3];

  salt->salt_len += 32;

  /**
   * digest
   */

  digest[0] = oldoffice01->rc4key[0];
  digest[1] = oldoffice01->rc4key[1];
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const oldoffice01_t *oldoffice01 = (const oldoffice01_t *) esalt_buf;

  const u8 *rc4key = (const u8 *) oldoffice01->rc4key;

  const int line_len = snprintf (line_buf, line_size, "%s%u*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x:%02x%02x%02x%02x%02x",
    SIGNATURE_OLDOFFICE,
    oldoffice01->version,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]),
    byte_swap_32 (oldoffice01->encryptedVerifier[0]),
    byte_swap_32 (oldoffice01->encryptedVerifier[1]),
    byte_swap_32 (oldoffice01->encryptedVerifier[2]),
    byte_swap_32 (oldoffice01->encryptedVerifier[3]),
    byte_swap_32 (oldoffice01->encryptedVerifierHash[0]),
    byte_swap_32 (oldoffice01->encryptedVerifierHash[1]),
    byte_swap_32 (oldoffice01->encryptedVerifierHash[2]),
    byte_swap_32 (oldoffice01->encryptedVerifierHash[3]),
    rc4key[0],
    rc4key[1],
    rc4key[2],
    rc4key[3],
    rc4key[4]);

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
