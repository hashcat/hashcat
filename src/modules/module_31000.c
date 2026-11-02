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

static const u32   ATTACK_EXEC       = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0         = 1;
static const u32   DGST_POS1         = 0;
static const u32   DGST_POS2         = 3;
static const u32   DGST_POS3         = 2;
static const u32   DGST_SIZE         = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY     = HASH_CATEGORY_RAW_HASH;
static const char *HASH_NAME         = "BLAKE2s-256";
static const char *HASH_RECIPE       = "blake2s256(pass)";
static const u64   KERN_TYPE         = 31000;
static const u32   OPTI_TYPE         = OPTI_TYPE_ZERO_BYTE
                                     | OPTI_TYPE_USES_BITS_32
                                     | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE         = OPTS_TYPE_STOCK_MODULE
                                     | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE         = SALT_TYPE_NONE;
static const char *ST_PASS           = "hashcat";
static const char *ST_HASH           = "$BLAKE2$2c719b484789ad5f6fc1739012182169b25484af156adc91d4f64f72400e574a";

#include "hooks_common.c"

const char *module_hash_recipe       (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

static const char *SIGNATURE_BLAKE2S = "$BLAKE2$";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Only the first word changes in the loop of the optimized mask kernel. With plain rotates, the
  // compiler moves a few operations that do not depend on it out of the loop. The other kernels
  // gain nothing from plain rotates.

  if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) return jit_build_options;

  if (user_options_extra->attack_kern != ATTACK_KERN_BF) return jit_build_options;

  hc_asprintf (&jit_build_options, "-D NO_FUNNELSHIFT");

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t * salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t * hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 2;

  token.signatures_cnt = 1;
  token.signatures_buf[0] = SIGNATURE_BLAKE2S;

  token.len[0]  = 8;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 64;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t * salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t * hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u8 *out_buf = (u8 *) line_buf;

  int out_len = strlen (SIGNATURE_BLAKE2S);

  memcpy (out_buf, SIGNATURE_BLAKE2S, out_len);

  u32_to_hex (digest[0], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[1], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[2], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[3], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[4], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[5], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[6], out_buf + out_len); out_len += 8;
  u32_to_hex (digest[7], out_buf + out_len); out_len += 8;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_jit_build_options        = module_jit_build_options;
}
