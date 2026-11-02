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
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DATABASE_SERVER;
static const char *HASH_NAME      = "MySQL caching_sha2_password challenge-response (fast auth)";
static const char *HASH_RECIPE    = "hex(xor(sha256_bin(pass), sha256_bin(sha256_bin(sha256_bin(pass)) . salt)))";
static const u64   KERN_TYPE      = 40006;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$mysqlsha2$336a0e5d214b713776503223785a39014c6d3842*1087166c986227f1ab6cfc071e7392b95a869ba94456a7429620614095b01be2";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

static const char *SIGNATURE_MYSQL_SHA2 = "$mysqlsha2$";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  // $mysqlsha2$<20 byte nonce of the server greeting>*<32 byte scramble of the client response>

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MYSQL_SHA2;

  token.len[0]     = (int) strlen (SIGNATURE_MYSQL_SHA2);
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 40;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = 64;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // the xor () result is compared in memory order

  const u8 *hash_pos = token.buf[2];

  for (u32 i = 0, j = 0; i < 8; i += 1, j += 8)
  {
    digest[i] = hex_to_u32 (&hash_pos[j]);
  }

  const u8 *salt_pos = token.buf[1];

  for (u32 i = 0, j = 0; i < 5; i += 1, j += 8)
  {
    salt->salt_buf[i] = hex_to_u32 (&salt_pos[j]);
  }

  salt->salt_len = 20;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf (line_buf, line_size, "%s", SIGNATURE_MYSQL_SHA2);

  for (u32 i = 0; i < 5; i++)
  {
    u32_to_hex (salt->salt_buf[i], &out_buf[out_len]);

    out_len += 8;
  }

  out_buf[out_len] = '*';

  out_len++;

  for (u32 i = 0; i < 8; i++)
  {
    u32_to_hex (digest[i], &out_buf[out_len]);

    out_len += 8;
  }

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
