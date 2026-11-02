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
static const u32   DGST_SIZE      = DGST_SIZE_4_16;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH;
static const char *HASH_NAME      = "SIMD-384";
static const char *HASH_RECIPE    = "simd384(pass)";
static const u64   KERN_TYPE      = 40163;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80;
static const u32   SALT_TYPE      = SALT_TYPE_NONE;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "6f6c2f83b43a3fe173ba9b58aaccee8e5e3fc2e4f191514c485acf79db9932edba23034f69530eb91a059bda05545ef9";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 1;

  token.len[0]     = 96;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[ 0] = hex_to_u32 (hash_pos +  0);
  digest[ 1] = hex_to_u32 (hash_pos +  8);
  digest[ 2] = hex_to_u32 (hash_pos + 16);
  digest[ 3] = hex_to_u32 (hash_pos + 24);
  digest[ 4] = hex_to_u32 (hash_pos + 32);
  digest[ 5] = hex_to_u32 (hash_pos + 40);
  digest[ 6] = hex_to_u32 (hash_pos + 48);
  digest[ 7] = hex_to_u32 (hash_pos + 56);
  digest[ 8] = hex_to_u32 (hash_pos + 64);
  digest[ 9] = hex_to_u32 (hash_pos + 72);
  digest[10] = hex_to_u32 (hash_pos + 80);
  digest[11] = hex_to_u32 (hash_pos + 88);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 tmp[12];

  tmp[ 0] = digest[ 0];
  tmp[ 1] = digest[ 1];
  tmp[ 2] = digest[ 2];
  tmp[ 3] = digest[ 3];
  tmp[ 4] = digest[ 4];
  tmp[ 5] = digest[ 5];
  tmp[ 6] = digest[ 6];
  tmp[ 7] = digest[ 7];
  tmp[ 8] = digest[ 8];
  tmp[ 9] = digest[ 9];
  tmp[10] = digest[10];
  tmp[11] = digest[11];

  u8 *out_buf = (u8 *) line_buf;

  u32_to_hex (tmp[ 0], out_buf +  0);
  u32_to_hex (tmp[ 1], out_buf +  8);
  u32_to_hex (tmp[ 2], out_buf + 16);
  u32_to_hex (tmp[ 3], out_buf + 24);
  u32_to_hex (tmp[ 4], out_buf + 32);
  u32_to_hex (tmp[ 5], out_buf + 40);
  u32_to_hex (tmp[ 6], out_buf + 48);
  u32_to_hex (tmp[ 7], out_buf + 56);
  u32_to_hex (tmp[ 8], out_buf + 64);
  u32_to_hex (tmp[ 9], out_buf + 72);
  u32_to_hex (tmp[10], out_buf + 80);
  u32_to_hex (tmp[11], out_buf + 88);

  const int out_len = 96;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
