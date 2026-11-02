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
static const u32   DGST_SIZE      = DGST_SIZE_4_64;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FRAMEWORK;
static const char *HASH_NAME      = "Python passlib pbkdf2-sha256";
static const u64   KERN_TYPE      = 40024;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *HASH_RECIPE    = "pbkdf2_sha256(pass, salt, iter, 32)";
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A";

static const u32   HASH_LEN_RAW   = 32;
static const u32   HASH_LEN_B64   = 43;

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

typedef struct pbkdf2_sha256
{
  u32 salt_buf[64];

} pbkdf2_sha256_t;

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

static const char *SIGNATURE_PASSLIB_PBKDF2_SHA256 = "pbkdf2-sha256";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pbkdf2_sha256_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha256_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PASSLIB_PBKDF2_SHA256;

  // the hash starts with a $
  token.sep[0]     = '$';
  token.len[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[1]     = '$';
  token.len[1]     = 13;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // iterations in decimal representation
  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 8;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt in alternate base64 representation
  token.sep[3]     = '$';
  token.len_min[3] = SALT_MIN;
  token.len_max[3] = SALT_MAX;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  // payload in alternate base64 representation
  token.sep[4]     = '$';
  token.len[4]     = HASH_LEN_B64;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter
  const u8 *iter_pos = token.buf[2];
  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // base64 decode salt
  const u8 *salt_pos = token.buf[3];
  const int salt_len = token.len[3];

  u8 tmp_buf[256] = { 0 };

  const size_t salt_len_decoded = base64_decode (ab64_to_int, salt_pos, salt_len, tmp_buf);

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha256->salt_buf;
  memcpy (salt_buf_ptr, tmp_buf, salt_len_decoded);
  memcpy (salt->salt_buf, salt_buf_ptr, salt_len_decoded);

  salt->salt_len = salt_len_decoded;

  // base64 decode hash
  const u8 *hash_pos = token.buf[4];
  const int hash_len = token.len[4];

  base64_decode (ab64_to_int, hash_pos, hash_len, tmp_buf);
  memcpy (digest, tmp_buf, HASH_LEN_RAW);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const pbkdf2_sha256_t *pbkdf2_sha256 = (const pbkdf2_sha256_t *) esalt_buf;

  // hash
  u32 tmp[9];

  tmp[0] = byte_swap_32 (digest[0]);
  tmp[1] = byte_swap_32 (digest[1]);
  tmp[2] = byte_swap_32 (digest[2]);
  tmp[3] = byte_swap_32 (digest[3]);
  tmp[4] = byte_swap_32 (digest[4]);
  tmp[5] = byte_swap_32 (digest[5]);
  tmp[6] = byte_swap_32 (digest[6]);
  tmp[7] = byte_swap_32 (digest[7]);
  tmp[8] = 0;

  char salt_enc[257] = { 0 };
  char hash_enc[128] = { 0 };

  const size_t salt_len_enc = base64_encode (int_to_ab64, (const u8 *) pbkdf2_sha256->salt_buf, salt->salt_len, (u8 *) salt_enc);
  const size_t hash_len_enc = base64_encode (int_to_ab64, (const u8 *) tmp, HASH_LEN_RAW, (u8 *) hash_enc);

  // remove padding =
  for (size_t i = 0; i < salt_len_enc; i++)
  {
    if (salt_enc[i] == '=')
    {
      salt_enc[i] = '\0';
    }
  }

  for (size_t i = 0; i < hash_len_enc; i++)
  {
    if (hash_enc[i] == '=')
    {
      hash_enc[i] = '\0';
    }
  }

  // output
  const int line_len = snprintf (line_buf, line_size, "$%s$%u$%s$%s", SIGNATURE_PASSLIB_PBKDF2_SHA256, salt->salt_iter + 1, salt_enc, hash_enc);
  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
