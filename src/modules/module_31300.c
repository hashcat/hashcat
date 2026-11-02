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
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "MS SNTP";
static const char *HASH_RECIPE    = "md5(md4_bin(utf16le(pass)) . salt)";
static const u64   KERN_TYPE      = 31300;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS14
                                  | OPTS_TYPE_PT_UTF16LE;
static const u32   SALT_TYPE      = SALT_TYPE_GENERIC;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sntp-ms$cfc7023381cf6bb474cdcbeb0a67bdb3$907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

static const char *SIGNATURE_SNTP_MS = "$sntp-ms$";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SNTP_MS;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 32;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len[2]     = 96;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  const u8 *salt_pos = token.buf[2];

  salt->salt_buf[ 0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[ 1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[ 2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[ 3] = hex_to_u32 (salt_pos + 24);
  salt->salt_buf[ 4] = hex_to_u32 (salt_pos + 32);
  salt->salt_buf[ 5] = hex_to_u32 (salt_pos + 40);
  salt->salt_buf[ 6] = hex_to_u32 (salt_pos + 48);
  salt->salt_buf[ 7] = hex_to_u32 (salt_pos + 56);
  salt->salt_buf[ 8] = hex_to_u32 (salt_pos + 64);
  salt->salt_buf[ 9] = hex_to_u32 (salt_pos + 72);
  salt->salt_buf[10] = hex_to_u32 (salt_pos + 80);
  salt->salt_buf[11] = hex_to_u32 (salt_pos + 88);

  salt->salt_len = 48;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf (line_buf, line_size, "%s", SIGNATURE_SNTP_MS);

  u32_to_hex (digest[0], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[1], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[2], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[3], out_buf + out_len); out_len += 8;

  out_buf[out_len] = '$';

  out_len += 1;

  u32_to_hex (salt->salt_buf[ 0], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 1], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 2], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 3], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 4], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 5], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 6], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 7], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 8], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[ 9], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[10], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[11], out_buf + out_len); out_len += 8;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
