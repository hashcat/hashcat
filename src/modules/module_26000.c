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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "Mozilla key3.db";
static const u64   KERN_TYPE      = 26000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_MAXIMUM_THREADS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$mozilla$*3DES*b735d19e6cadb5136376a98c2369f22819d08c79*2b36961682200a877f7d5550975b614acc9fefe3*f03f3575fd5bdbc9e32232316eab7623";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/mozilla2hashcat.py to extract the hashes";
}

typedef struct mozilla_3des
{
  u32 ct_buf[4];

} mozilla_3des_t;

static const char *SIGNATURE_MOZILLA      = "$mozilla$";
static const char *SIGNATURE_MOZILLA_3DES = "3DES";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (mozilla_3des_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  mozilla_3des_t *mozilla_3des = (mozilla_3des_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 2;
  token.signatures_buf[0] = SIGNATURE_MOZILLA;
  token.signatures_buf[1] = SIGNATURE_MOZILLA_3DES;

  token.sep[0]     = '*';
  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 4;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[2]     = '*';
  token.len[2]     = 40;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len[3]     = 40;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len[4]     = 32;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // global salt buffer + entry salt buffer combined
  // this also requires us to copy to local variables in kernel

  const u8 *global_salt_pos = token.buf[2];
  const u8 *entry_salt_pos  = token.buf[3];

  salt->salt_buf[ 0] = hex_to_u32 (global_salt_pos +  0);
  salt->salt_buf[ 1] = hex_to_u32 (global_salt_pos +  8);
  salt->salt_buf[ 2] = hex_to_u32 (global_salt_pos + 16);
  salt->salt_buf[ 3] = hex_to_u32 (global_salt_pos + 24);
  salt->salt_buf[ 4] = hex_to_u32 (global_salt_pos + 32);
  salt->salt_buf[ 5] = 0;
  salt->salt_buf[ 6] = 0;
  salt->salt_buf[ 7] = 0;
  salt->salt_buf[ 8] = hex_to_u32 (entry_salt_pos +  0);
  salt->salt_buf[ 9] = hex_to_u32 (entry_salt_pos +  8);
  salt->salt_buf[10] = hex_to_u32 (entry_salt_pos + 16);
  salt->salt_buf[11] = hex_to_u32 (entry_salt_pos + 24);
  salt->salt_buf[12] = hex_to_u32 (entry_salt_pos + 32);
  salt->salt_buf[13] = 0;
  salt->salt_buf[14] = 0;
  salt->salt_buf[15] = 0;

  salt->salt_len = 64;

  // CT buffer

  const u8 *ct_pos = token.buf[4];

  mozilla_3des->ct_buf[0] = hex_to_u32 (ct_pos +  0);
  mozilla_3des->ct_buf[1] = hex_to_u32 (ct_pos +  8);
  mozilla_3des->ct_buf[2] = hex_to_u32 (ct_pos + 16);
  mozilla_3des->ct_buf[3] = hex_to_u32 (ct_pos + 24);

  // make salt sorter happy: the kernel checks the ct of the first hash of a salt only, so entries
  // with the same two salts must not share one. The ct goes after the words the kernel reads.

  salt->salt_buf[16] = mozilla_3des->ct_buf[0];
  salt->salt_buf[17] = mozilla_3des->ct_buf[1];
  salt->salt_buf[18] = mozilla_3des->ct_buf[2];
  salt->salt_buf[19] = mozilla_3des->ct_buf[3];

  salt->salt_len += 16;

  // hash

  digest[0] = mozilla_3des->ct_buf[0];
  digest[1] = mozilla_3des->ct_buf[1];
  digest[2] = mozilla_3des->ct_buf[2];
  digest[3] = mozilla_3des->ct_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const mozilla_3des_t *mozilla_3des = (const mozilla_3des_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  const int out_len = snprintf ((char *) out_buf, line_size, "%s*%s*%08x%08x%08x%08x%08x*%08x%08x%08x%08x%08x*%08x%08x%08x%08x",
    SIGNATURE_MOZILLA,
    SIGNATURE_MOZILLA_3DES,
    byte_swap_32 (salt->salt_buf[ 0]),
    byte_swap_32 (salt->salt_buf[ 1]),
    byte_swap_32 (salt->salt_buf[ 2]),
    byte_swap_32 (salt->salt_buf[ 3]),
    byte_swap_32 (salt->salt_buf[ 4]),
    byte_swap_32 (salt->salt_buf[ 8]),
    byte_swap_32 (salt->salt_buf[ 9]),
    byte_swap_32 (salt->salt_buf[10]),
    byte_swap_32 (salt->salt_buf[11]),
    byte_swap_32 (salt->salt_buf[12]),
    byte_swap_32 (mozilla_3des->ct_buf[0]),
    byte_swap_32 (mozilla_3des->ct_buf[1]),
    byte_swap_32 (mozilla_3des->ct_buf[2]),
    byte_swap_32 (mozilla_3des->ct_buf[3]));

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_usage_notice             = module_usage_notice;
}
