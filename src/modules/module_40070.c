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
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_GENERIC_KDF;
static const char *HASH_NAME      = "PBKDF1-SHA1";
static const char *HASH_RECIPE    = "h = sha1_bin(pass . salt); for i = 1 to iter { h = sha1_bin(h) }; hex(h)";
static const u64   KERN_TYPE      = 40070;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "PBKDF1:sha1:1000:cGVuZ3VpbmtlZXBlcg==:J4BrIhXDUHNQ9lPPrWKn4V7Of9Y=";

typedef struct pbkdf1_sha1_tmp
{
  u32 digest_buf[5];
} pbkdf1_sha1_tmp;

static const char *SIGNATURE_PBKDF1 = "PBKDF1";
static const char *SIGNATURE_SHA1 = "sha1";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf1_sha1_tmp);
  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 2;
  token.signatures_buf[0] = SIGNATURE_PBKDF1;
  token.signatures_buf[1] = SIGNATURE_SHA1;

  // Signature
  token.sep[0]     = ':';
  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // Primitive "sha1"
  token.sep[1]     = ':';
  token.len[1]     = 4;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // Iterations
  token.sep[2]     = ':';
  token.attr[2]    = TOKEN_ATTR_VERIFY_DIGIT;

  // Salt
  token.sep[3]     = ':';
  token.len_min[3] = SALT_MIN;
  token.len_max[3] = SALT_MAX;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // Hash
  token.sep[4]     = ':';
  token.len[4]     = 28;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iterations

  const u8 *iter_pos = token.buf[2];

  const int iter = strtol ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // base64 decode salt

  const u8 *salt_pos = token.buf[3];
  const int salt_len = token.len[3];

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  u8 tmp_buf[1000];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  salt->salt_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (salt->salt_len > 255) return (PARSER_SALT_LENGTH);

  memcpy (salt_buf_ptr, tmp_buf, salt_len);

  // base64 decode hash

  const u8 *hash_pos = token.buf[4];
  const int hash_len = token.len[4];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

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

  // hash

  u32 tmp[5];

  tmp[0] = byte_swap_32 (digest[0]);
  tmp[1] = byte_swap_32 (digest[1]);
  tmp[2] = byte_swap_32 (digest[2]);
  tmp[3] = byte_swap_32 (digest[3]);
  tmp[4] = byte_swap_32 (digest[4]);

  char tmp_buf[64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp, 20, (u8 *) tmp_buf);

  char salt_buf[500] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_buf);

  // output

  const int line_len = snprintf (line_buf, line_size, "%s:%s:%u:%s:%s", SIGNATURE_PBKDF1, SIGNATURE_SHA1, salt->salt_iter + 1, (const char *) salt_buf, tmp_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
