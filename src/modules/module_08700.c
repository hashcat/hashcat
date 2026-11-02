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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_EAS;
static const char *HASH_NAME      = "Lotus Notes/Domino 6";
static const u64   KERN_TYPE      = 8700;
static const u32   OPTI_TYPE      = OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "(GDJ0nDZI8l8RJzlRbemg)";

#include "hooks_common.c"

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = 32;

  if (optimized_kernel == true)
  {

  }
  else
  {
    pw_max = 64; // https://www.ibm.com/support/knowledgecenter/en/SSKTWP_8.5.3/com.ibm.notes85.client.doc/fram_limits_of_notes_r.html
  }

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 4;

  token.len[0]  = 1;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[1]  = 1;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[2]  = 19;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_BASE64A;

  token.len[3]  = 1;
  token.attr[3] = TOKEN_ATTR_FIXED_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  if (token.buf[0][0] != '(') return (PARSER_SIGNATURE_UNMATCHED);
  if (token.buf[1][0] != 'G') return (PARSER_SIGNATURE_UNMATCHED);
  if (token.buf[3][0] != ')') return (PARSER_SIGNATURE_UNMATCHED);

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  u8 tmp_buf[120] = { 0 };

  base64_decode (lotus64_to_int, hash_pos, hash_len, tmp_buf);

  tmp_buf[3] += -4; // dont ask!

  // salt

  memcpy (salt->salt_buf, tmp_buf, 5);

  salt->salt_len = 5;

  memcpy (digest, tmp_buf + 5, 9);

  // yes, only 9 byte are needed to crack, but 10 to display

  salt->salt_buf_pc[7] = hash_pos[18];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  char buf[16] = { 0 };

  memcpy (buf + 0, salt->salt_buf, 5);
  memcpy (buf + 5, digest_buf, 9);

  buf[3] -= -4;

  char tmp_buf[20];

  base64_encode (int_to_lotus64, (const u8 *) buf, 14, (u8 *) tmp_buf);

  tmp_buf[18] = salt->salt_buf_pc[7];
  tmp_buf[19] = 0;

  const int line_len = snprintf (line_buf, line_size, "(G%s)", tmp_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
}
