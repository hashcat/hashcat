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
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_APPLICATION_DATABASE;
static const char *HASH_NAME      = "XCA database password";
static const char *HASH_RECIPE    = "h = sha512_bin(salt . pass); for i = 1 to 7999 { h = sha512_bin(h) }; hex(h)";
static const u64   KERN_TYPE      = 40000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "Tcdf012ed7637ca3b9F579C6659725E28985A90E17E16072D4A371293F233323EAEB302C4A39575DEBDA03053860298920FBA3985F7E1A9B9045E56543B8D05A72BCFFB984FB3EF33";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

// XCA stores "T", 16 hex characters and the digest in uppercase hex. The salt is the first 17
// characters, the T included. A stored value without the T is XCA's older scheme, a single
// SHA-512 of a 5 character salt and the password, which is hash-mode 1720.

static const char *SIGNATURE_XCA = "T";

static const u32 XCA_ROUNDS = 8000;

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_XCA;

  token.len[0]     = 1;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 16;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = 128;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // the recipe hashes the salt as text, T and hex digits as they are stored

  const int salt_len = token.len[0] + token.len[1];

  memcpy (salt->salt_buf, line_buf, salt_len);

  salt->salt_len = salt_len;

  // the first SHA-512 runs before the loop of the recipe

  salt->salt_iter = XCA_ROUNDS - 1;

  const u8 *hash_pos = token.buf[2];

  for (u32 i = 0; i < 8; i++)
  {
    const u64 v = hex_to_u64 (&hash_pos[i * 16]);

    digest[i] = byte_swap_64 (v);
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const int line_len = snprintf (line_buf, line_size, "%s", hash_info->orighash);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
