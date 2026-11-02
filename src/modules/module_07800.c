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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_EAS;
static const char *HASH_NAME      = "SAP CODVN F/G (PASSCODE)";
static const u64   KERN_TYPE      = 7800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_ST_ADD80
                                  | OPTS_TYPE_ST_UPPER;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "604020408266$32837BA7B97672BA4E5AC74767A4E6E1AE802651";

#include "hooks_common.c"

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  const u32 pw_max = (optimized_kernel == false) ? 40 : hashconfig->pw_max; // https://www.daniel-berlin.de/security/sap-sec/password-hash-algorithms/

  return pw_max;
}

u32 module_combined_len_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // the optimized kernels keep password and salt in one buffer

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  const u32 combined_len_max = (optimized_kernel == true) ? 55 : 0;

  return combined_len_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  // a user name may contain a $, so it ends at the last one

  token.sep[0]     = '$';
  token.len_min[0] = 1;
  token.len_max[0] = 40;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_SEPARATOR_FARTHEST;

  token.len[1]     = 40;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * salt
   */

  const u8 *salt_pos = token.buf[0];

  // exports pad the user name with spaces, which SAP does not hash

  int salt_len = token.len[0];

  while ((salt_len > 0) && (salt_pos[salt_len - 1] == ' ')) salt_len--;

  if (salt_len == 0) return (PARSER_SALT_LENGTH);

  // SAP user names cannot be longer than 12 characters. UTF-8 stores a non-ASCII one in more than
  // one byte, and a byte of the form 10xxxxxx continues a character rather than starting one.

  int user_len = 0;

  for (int i = 0; i < salt_len; i++)
  {
    if ((salt_pos[i] & 0xc0) == 0x80) continue;

    user_len++;
  }

  if (user_len > 12) return (PARSER_SALT_LENGTH);

  // SAP user name cannot start with ! or ?
  if (salt_pos[0] == '!' || salt_pos[0] == '?') return (PARSER_SALT_VALUE);

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  /**
   * hash
   */

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (&hash_pos[ 0]);
  digest[1] = hex_to_u32 (&hash_pos[ 8]);
  digest[2] = hex_to_u32 (&hash_pos[16]);
  digest[3] = hex_to_u32 (&hash_pos[24]);
  digest[4] = hex_to_u32 (&hash_pos[32]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  char tmp_salt[(SALT_MAX * 2) + 1];

  const int salt_len = generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, (u8 *) tmp_salt);

  tmp_salt[salt_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s$%08X%08X%08X%08X%08X",
    tmp_salt,
    digest[0],
    digest[1],
    digest[2],
    digest[3],
    digest[4]);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_combined_len_max         = module_combined_len_max;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
}
