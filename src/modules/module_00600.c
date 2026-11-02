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
static const u32   DGST_POS0      = 1;
static const u32   DGST_POS1      = 0;
static const u32   DGST_POS2      = 3;
static const u32   DGST_POS3      = 2;
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH;
static const char *HASH_NAME      = "BLAKE2b-512";
static const char *HASH_RECIPE    = "blake2b512(pass)";
static const u64   KERN_TYPE      = 600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_NONE;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$BLAKE2$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

static const char *SIGNATURE_BLAKE2B = "$BLAKE2$";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BLAKE2B;

  token.len[0]  = 8;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 128;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u64 (hash_pos +   0);
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

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u8 *out_buf = (u8 *) line_buf;

  int out_len = strlen (SIGNATURE_BLAKE2B);

  memcpy (out_buf, SIGNATURE_BLAKE2B, out_len);

  u64_to_hex (digest[0], out_buf + out_len); out_len += 16;
  u64_to_hex (digest[1], out_buf + out_len); out_len += 16;
  u64_to_hex (digest[2], out_buf + out_len); out_len += 16;
  u64_to_hex (digest[3], out_buf + out_len); out_len += 16;
  u64_to_hex (digest[4], out_buf + out_len); out_len += 16;
  u64_to_hex (digest[5], out_buf + out_len); out_len += 16;
  u64_to_hex (digest[6], out_buf + out_len); out_len += 16;
  u64_to_hex (digest[7], out_buf + out_len); out_len += 16;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
