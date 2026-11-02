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
static const u32   DGST_POS0      = 6;
static const u32   DGST_POS1      = 7;
static const u32   DGST_POS2      = 4;
static const u32   DGST_POS3      = 5;
static const u32   DGST_SIZE      = DGST_SIZE_8_25;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH;
static const char *HASH_NAME      = "SHA3-512";
static const char *HASH_RECIPE    = "sha3_512(pass)";
static const u64   KERN_TYPE      = 17600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD06;
static const u32   SALT_TYPE      = SALT_TYPE_NONE;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 1;

  token.len[0]  = 128;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];
  const int hash_len = token.len[0];

  if (hash_len != 128) return (PARSER_GLOBAL_LENGTH);

  digest[0] = hex_to_u64 (hash_pos +  0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  u64 tmp[8];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];
  tmp[4] = digest[4];
  tmp[5] = digest[5];
  tmp[6] = digest[6];
  tmp[7] = digest[7];

  u8 *out_buf = (u8 *) line_buf;

  u64_to_hex (tmp[0], out_buf +   0);
  u64_to_hex (tmp[1], out_buf +  16);
  u64_to_hex (tmp[2], out_buf +  32);
  u64_to_hex (tmp[3], out_buf +  48);
  u64_to_hex (tmp[4], out_buf +  64);
  u64_to_hex (tmp[5], out_buf +  80);
  u64_to_hex (tmp[6], out_buf +  96);
  u64_to_hex (tmp[7], out_buf + 112);

  const int out_len = 128;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
