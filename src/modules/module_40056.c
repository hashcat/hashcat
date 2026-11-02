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
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_16;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FRAMEWORK;
static const char *HASH_NAME      = "Flask Session Cookie ($salt.$salt.$pass)";
static const char *HASH_RECIPE    = "hmac_sha1(hmac_sha1_bin(pass, \"cookie-session\"), salt)";
static const u64   KERN_TYPE      = 40056;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "eyJ1c2VybmFtZSI6ImFkbWluIn0.YjdgRQ.1OTlf1PD0H9wXsu_qS0aywAJVD8";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_iter = 1;
  salt->salt_len  = 34;

  return salt;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.sep[0]     = '.';
  token.len_min[0] =  0;
  token.len_max[0] = 120;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64C;

  token.sep[1]     = '.';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64C;

  token.sep[2]     = '.';
  token.len_min[2] = 20;
  token.len_max[2] = 27;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64C;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const int salt1_len = token.len[0];
  const int salt2_len = token.len[1];
  const u8 *hash_pos  = token.buf[2];
  const int hash_len  = token.len[2];
  const int salt_len  = salt1_len + 1 + salt2_len;

  // salt_len covers token 0, the '.' and token 1, so the decode has to start
  // at the beginning of the line. Starting it at token 1 instead read
  // salt1_len + 1 bytes past the end of the salt and, on a long enough first
  // token, off the end of the line entirely.
  const bool parse_rc = generic_salt_decode (hashconfig, (const u8 *) line_buf, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, line_buf, salt_len);

  // salt_buf is u32[64] and salt_len counts bytes, so indexing it directly wrote element 77 of 64
  // for a salt this token is allowed to be. The terminator belongs at byte salt_len.

  ((u8 *) salt->salt_buf)[salt_len] = 0;

  u8 tmp_buf[100] = { 0 };

  const int decoded_len = base64_decode (base64url_to_int, hash_pos, hash_len, tmp_buf);

  if (decoded_len != 20) return (PARSER_HASH_LENGTH);

  memcpy (digest_buf, tmp_buf, 20);

  u32 *digest = (u32 *) digest_buf;

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest32 = (const u32 *) digest_buf;

  char ptr_plain[128];

  u32 tmp[5];

  tmp[0] = byte_swap_32 (digest32[0]);
  tmp[1] = byte_swap_32 (digest32[1]);
  tmp[2] = byte_swap_32 (digest32[2]);
  tmp[3] = byte_swap_32 (digest32[3]);
  tmp[4] = byte_swap_32 (digest32[4]);

  base64_encode (int_to_base64url, (const u8 *) tmp, 20, (u8 *) ptr_plain);

  ptr_plain[27] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s.%s", (const char *) salt->salt_buf, (const char *) ptr_plain);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_salt           = module_benchmark_salt;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
