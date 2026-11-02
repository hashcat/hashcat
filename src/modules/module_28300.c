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
static const u32   DGST_POS0      = 3;
static const u32   DGST_POS1      = 4;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_MESSAGING;
static const char *HASH_NAME      = "Teamspeak 3 (channel hash)";
static const u64   KERN_TYPE      = 28300;
static const u32   OPTI_TYPE      = OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$teamspeak$3$E0aV0IQ29EDyxRfkFoQflUGJ6zo=$mRgDUkNpd0IwUEcTJQBmE0NHYwdDEhFzQ0VgMRcFJUIRYnaHBwNXRZJwk2ZUaURzdXkVYiUROERmI0hYYGFYCDiIJCeIU3N5EhRVcZFnSIRCJlkUFkY4YFMDcheYeTl4RYZEdpKGJYhxAIQJEYGYEA==";

#include "hooks_common.c"

static const char *SIGNATURE_TEAMSPEAK = "$teamspeak$";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_TEAMSPEAK;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 28;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = '$';
  token.len[3]     = 152;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /*
   * version
   */

  if (token.buf[1][0] != '3') return (PARSER_SIGNATURE_UNMATCHED);

  /*
   * hash
   */

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  u8 tmp_buf[128];

  const int decoded_hash_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (decoded_hash_len != 20) return (PARSER_HASH_LENGTH);

  const u32 *ptr = (const u32 *) tmp_buf;

  digest[0] = byte_swap_32 (ptr[0]);
  digest[1] = byte_swap_32 (ptr[1]);
  digest[2] = byte_swap_32 (ptr[2]);
  digest[3] = byte_swap_32 (ptr[3]);
  digest[4] = byte_swap_32 (ptr[4]);

  /*
   * salt
   */

  const u8 *salt_pos = token.buf[3];
  const int salt_len = token.len[3];

  memcpy (salt->salt_buf, salt_pos, salt_len);

  for (int i = 0; i < 38; i++) // 152 / 4 = 38 -- we use the salt as it is
  {
    salt->salt_buf[i] = byte_swap_32 (salt->salt_buf[i]);
  }

  salt->salt_len = salt_len;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  char tmp_buf[128];

  // digest

  u32 tmp_digest[5];

  tmp_digest[0] = digest[0];
  tmp_digest[1] = digest[1];
  tmp_digest[2] = digest[2];
  tmp_digest[3] = digest[3];
  tmp_digest[4] = digest[4];

  tmp_digest[0] = byte_swap_32 (tmp_digest[0]);
  tmp_digest[1] = byte_swap_32 (tmp_digest[1]);
  tmp_digest[2] = byte_swap_32 (tmp_digest[2]);
  tmp_digest[3] = byte_swap_32 (tmp_digest[3]);
  tmp_digest[4] = byte_swap_32 (tmp_digest[4]);

  const int encoded_hash_len = base64_encode (int_to_base64, (const u8 *) tmp_digest, 20, (u8 *) tmp_buf);

  tmp_buf[encoded_hash_len] = 0;

  // salt

  u32 tmp_salt[64] = { 0 };

  for (int i = 0; i < 38; i++) // see decoder
  {
    tmp_salt[i] = byte_swap_32 (salt->salt_buf[i]);
  }

  const int line_len = snprintf (line_buf, line_size, "%s%u$%s$%s", SIGNATURE_TEAMSPEAK, 3, tmp_buf, (char *) tmp_salt);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
}
