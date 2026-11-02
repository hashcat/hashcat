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
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_EAS;
static const char *HASH_NAME      = "SAP CODVN H (PWDSALTEDHASH) iSSHA-256";
static const char *HASH_RECIPE    = "h = sha256_bin(pass . salt); for i = 1 to iter { h = sha256_bin(pass . h) }; hex(h)";
static const u64   KERN_TYPE      = 40081;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "{x-isSHA256, 3000}56SL4GZltN0YPoXeGfu6BzTjFYmY4QS723iBHVbRnXg1Njc4OTAxMjM0NTY=";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

typedef struct saph_sha256_tmp
{
  u32 digest_buf[8];

} saph_sha256_tmp_t;

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (saph_sha256_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 40; // https://www.daniel-berlin.de/security/sap-sec/password-hash-algorithms/

  return pw_max;
}

static const char *SIGNATURE_SAPH_SHA256 = "{x-isSHA256, ";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SAPH_SHA256;

  token.len[0]     = 13;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '}';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 48;
  token.len_max[2] = 88;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1)
  {
    return (PARSER_SALT_ITERATION);
  }

  iter--; // first iteration is special

  salt->salt_iter = iter;

  // decode

  const u8 *base64_pos = token.buf[2];
  const int base64_len = token.len[2];

  u8 tmp_buf[256] = { 0 };

  const u32 decoded_len = base64_decode (base64_to_int, base64_pos, base64_len, tmp_buf);

  if (decoded_len < 36) return (PARSER_SALT_LENGTH);

  // copy the salt

  const u32 salt_len = decoded_len - 32;

  if (salt_len > 32) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf + 32, salt_len);

  salt->salt_len = salt_len;

  // set digest

  u32 *digest_ptr = (u32 *) tmp_buf;

  digest[0] = byte_swap_32 (digest_ptr[0]);
  digest[1] = byte_swap_32 (digest_ptr[1]);
  digest[2] = byte_swap_32 (digest_ptr[2]);
  digest[3] = byte_swap_32 (digest_ptr[3]);
  digest[4] = byte_swap_32 (digest_ptr[4]);
  digest[5] = byte_swap_32 (digest_ptr[5]);
  digest[6] = byte_swap_32 (digest_ptr[6]);
  digest[7] = byte_swap_32 (digest_ptr[7]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u32 tmp[8];

  tmp[0] = byte_swap_32 (digest[0]);
  tmp[1] = byte_swap_32 (digest[1]);
  tmp[2] = byte_swap_32 (digest[2]);
  tmp[3] = byte_swap_32 (digest[3]);
  tmp[4] = byte_swap_32 (digest[4]);
  tmp[5] = byte_swap_32 (digest[5]);
  tmp[6] = byte_swap_32 (digest[6]);
  tmp[7] = byte_swap_32 (digest[7]);

  char tmp_buf[256];

  memcpy (tmp_buf +  0, tmp, 32);
  memcpy (tmp_buf + 32, salt->salt_buf, salt->salt_len);

  const u32 tmp_len = 32 + salt->salt_len;

  // base64 encode it

  char base64_encoded[256] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp_buf, tmp_len, (u8 *) base64_encoded);

  const int line_len = snprintf (line_buf, line_size, "%s%u}%s", SIGNATURE_SAPH_SHA256, salt->salt_iter + 1, base64_encoded);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
