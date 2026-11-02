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
#include "emu_inc_cipher_des.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_CIPHER_KPA;
static const char *HASH_NAME      = "AES-192-ECB NOKDF (PT = $salt, key = $pass)";
static const u64   KERN_TYPE      = 26402;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "2995e91b798ef51232a91579edb1d176:49869364034411376791729962721320";

#include "hooks_common.c"

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 24; // Underlaying AES-192 max

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 32;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]     = 32;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_len = 16;

  // hash

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  u32_to_hex (digest[0], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[1], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[2], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[3], out_buf + out_len); out_len += 8;

  out_buf[out_len] = hashconfig->separator;

  out_len++;

  u32_to_hex (salt->salt_buf[0], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[1], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[2], out_buf + out_len); out_len += 8;
  u32_to_hex (salt->salt_buf[3], out_buf + out_len); out_len += 8;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
}
