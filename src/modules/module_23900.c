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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "BestCrypt v3 Volume Encryption";
static const u64   KERN_TYPE      = 23900;
static const bool  LENGTH_SORT    = true;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$bcve$3$08$234b8182cee7098b$35c12ef76a1e88175c4c222da3558310a0075bc7a06ecf46746d149c02a81fb8a97637d1103d2e13ddd5deaf982889594b18c12d7ca18a54875c5da4a47f90ae615ab94b8e3ed9e3c793d872a1b5ac35cfdb66c221d6d0853e9ff2e0f4435b43";

#include "hooks_common.c"

bool        module_length_sort    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return LENGTH_SORT;     }

typedef struct bestcrypt_tmp
{
  u32 salt_pw_buf[33];
  u32 out[8];

} bestcrypt_tmp_t;

typedef struct bestcrypt
{
  u32 data[24];

} bestcrypt_t;

static const char *SIGNATURE_BESTCRYPT  = "$bcve$";

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bestcrypt_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (bestcrypt_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is selected
  // IOW, even in optimized kernel mode it support length 56

  const u32 pw_max = 56;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  bestcrypt_t *bestcrypt = (bestcrypt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BESTCRYPT;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 2;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 16;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[4]     = 192;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *format_type_pos = token.buf[1];

  if (format_type_pos[0] != '3') return (PARSER_SALT_VALUE);

  const u8 *crypto_type_pos = token.buf[2];

  if (crypto_type_pos[0] != '0') return (PARSER_SALT_VALUE);
  if (crypto_type_pos[1] != '8') return (PARSER_SALT_VALUE);

  salt->salt_iter = 1;

  // salt

  const u8 *salt_pos = token.buf[3];
  const int salt_len = token.len[3];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  // data

  const u8 *data_pos = token.buf[4];
  const int data_len = token.len[4];

  hex_decode (data_pos, data_len, (u8 *) bestcrypt->data);

  // fake digest

  digest[0] = bestcrypt->data[16]; // the encrypted checksum
  digest[1] = bestcrypt->data[17];
  digest[2] = bestcrypt->data[18];
  digest[3] = bestcrypt->data[19];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const bestcrypt_t *bestcrypt = (const bestcrypt_t *) esalt_buf;

  // salt

  u32 tmp_salt[4] = { 0 };

  tmp_salt[0] = byte_swap_32 (salt->salt_buf[0]);
  tmp_salt[1] = byte_swap_32 (salt->salt_buf[1]);

  char salt_hex[17] = { 0 };

  generic_salt_encode (hashconfig, (const u8 *) tmp_salt, (const int) salt->salt_len, (u8 *) salt_hex);

  // data

  u8 data_hex[193] = { 0 };

  hex_encode ((const u8 *) bestcrypt->data, 96, data_hex);

  int out_len = snprintf (line_buf, line_size, "%s3$08$%s$%s",
    SIGNATURE_BESTCRYPT,
    salt_hex,
    data_hex
  );

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_length_sort              = module_length_sort;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
