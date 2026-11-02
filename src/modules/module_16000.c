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
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FORUM_SOFTWARE;
static const char *HASH_NAME      = "Tripcode";
static const u64   KERN_TYPE      = 16000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ALWAYS_ASCII;
static const u32   SALT_TYPE      = SALT_TYPE_NONE;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "pfaRCwDe0U";

#include "hooks_common.c"

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 8; // Underlaying DES max

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 1;

  token.len[0]  = 10;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  unsigned char c9 = itoa64_to_int (hash_pos[9]);

  if (c9 & 3) return (PARSER_HASH_VALUE);

  u8 add_leading_zero[12];

  add_leading_zero[0] = '.';

  memcpy (add_leading_zero + 1, line_buf, 10);

  u8 tmp_buf[100] = { 0 };

  base64_decode (itoa64_to_int, (const u8 *) add_leading_zero, 11, tmp_buf);

  memcpy (digest, tmp_buf, 8);

  DES_IP (digest[0], digest[1]);

  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u32 tmp[2];

  tmp[0] = digest[0];
  tmp[1] = digest[1];

  DES_FP (tmp[1], tmp[0]);

  char ptr_plain[32];

  base64_encode (int_to_itoa64, (const u8 *) tmp, 8, (u8 *) ptr_plain);

  ptr_plain[11] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s", ptr_plain + 1);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
}
