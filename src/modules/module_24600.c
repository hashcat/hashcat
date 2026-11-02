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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_APPLICATION_DATABASE;
static const char *HASH_NAME      = "SQLCipher";
static const u64   KERN_TYPE      = 24610;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SELF_TEST_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "SQLCIPHER*1*64000*25548249195677404156261816261456*85b5e156e1cf1e0be5e9f4217186817b*33435c230bbc7989bbd027630e3f47cd";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/sqlcipher2hashcat.pl to extract the hashes";
}

typedef struct sqlcipher_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} sqlcipher_sha1_tmp_t;

typedef struct sqlcipher_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[8];
  u32  out[8];

} sqlcipher_sha256_tmp_t;

typedef struct sqlcipher_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} sqlcipher_sha512_tmp_t;

typedef struct sqlcipher
{
  u32 iv_buf[4];
  u32 data_buf[4];

  u32 type;

} sqlcipher_t;

typedef enum kern_type_sqlcipher
{
  KERN_TYPE_SQLCIPHER_SHA1   = 24610,
  KERN_TYPE_SQLCIPHER_SHA256 = 24620,
  KERN_TYPE_SQLCIPHER_SHA512 = 24630,

} kern_type_sqlcipher_t;

static const char *SIGNATURE_SQLCIPHER = "SQLCIPHER";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (sqlcipher_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (sqlcipher_sha512_tmp_t); // we just select the largest

  return tmp_size;
}

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info)
{
  const sqlcipher_t *sqlcipher = (const sqlcipher_t *) esalt_buf;

  u64 kern_type = -1;

  if (sqlcipher->type == 1)
  {
    kern_type = KERN_TYPE_SQLCIPHER_SHA1;
  }
  else if (sqlcipher->type == 2)
  {
    kern_type = KERN_TYPE_SQLCIPHER_SHA256;
  }
  else if (sqlcipher->type == 3)
  {
    kern_type = KERN_TYPE_SQLCIPHER_SHA512;
  }
  else
  {
    return (PARSER_HASH_LENGTH);
  }

  return kern_type;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  sqlcipher_t *sqlcipher = (sqlcipher_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SQLCIPHER;

  token.sep[0]     = '*';
  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len[4]     = 32;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '*';
  token.len[5]     = 32;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type

  const u8 *type_pos = token.buf[1];

  const int type = hc_strtoul ((const char *) type_pos, NULL, 10);

  if ((type != 1) && (type != 2) && (type != 3)) return (PARSER_SIGNATURE_UNMATCHED);

  sqlcipher->type = type;

  // cipher

  const u8 *iter_pos = token.buf[2];

  int iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt buffer

  const u8 *salt_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_len = 16;

  // IV buffer

  const u8 *iv_pos = token.buf[4];

  sqlcipher->iv_buf[0] = hex_to_u32 (iv_pos +  0);
  sqlcipher->iv_buf[1] = hex_to_u32 (iv_pos +  8);
  sqlcipher->iv_buf[2] = hex_to_u32 (iv_pos + 16);
  sqlcipher->iv_buf[3] = hex_to_u32 (iv_pos + 24);

  // data buffer

  const u8 *data_pos = token.buf[5];

  sqlcipher->data_buf[0] = hex_to_u32 (data_pos +  0);
  sqlcipher->data_buf[1] = hex_to_u32 (data_pos +  8);
  sqlcipher->data_buf[2] = hex_to_u32 (data_pos + 16);
  sqlcipher->data_buf[3] = hex_to_u32 (data_pos + 24);

  // hash

  digest[0] = sqlcipher->data_buf[0];
  digest[1] = sqlcipher->data_buf[1];
  digest[2] = sqlcipher->data_buf[2];
  digest[3] = sqlcipher->data_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const sqlcipher_t *sqlcipher = (const sqlcipher_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  const int out_len = snprintf ((char *) out_buf, line_size, "%s*%d*%d*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x",
    SIGNATURE_SQLCIPHER,
    sqlcipher->type,
    salt->salt_iter + 1,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]),
    byte_swap_32 (sqlcipher->iv_buf[0]),
    byte_swap_32 (sqlcipher->iv_buf[1]),
    byte_swap_32 (sqlcipher->iv_buf[2]),
    byte_swap_32 (sqlcipher->iv_buf[3]),
    byte_swap_32 (sqlcipher->data_buf[0]),
    byte_swap_32 (sqlcipher->data_buf[1]),
    byte_swap_32 (sqlcipher->data_buf[2]),
    byte_swap_32 (sqlcipher->data_buf[3]));

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kern_type_dynamic        = module_kern_type_dynamic;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
