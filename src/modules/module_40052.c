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
static const u32   DGST_SIZE      = DGST_SIZE_4_32;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_MESSAGING;
static const char *HASH_NAME      = "XMPP SCRAM PBKDF2-SHA1";
static const char *HASH_RECIPE    = "sha1(hmac_sha1_bin(pbkdf2_sha1_bin(pass, salt, iter, 20), \"Client Key\"))";
static const u64   KERN_TYPE      = 40052;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$xmpp-scram$0$4096$45$353835323736323530353932363531393630313632353634313335323434323038393931323138373138343134$6d5b543b985dc6c0645da3c83d114fce121aa51d";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

typedef struct xmpp_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} xmpp_tmp_t;

static const char *SIGNATURE_XMPP = "xmpp-scram";

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (xmpp_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_XMPP;

  token.sep[0]     = '$';
  token.len[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[1]     = '$';
  token.len[1]     = 10;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[2]     = '$';
  token.len[2]     = 1;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 8;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 8;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 0;
  token.len_max[5] = 512;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len[6]     = 40;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type

  if (token.buf[2][0] != '0') return (PARSER_SIGNATURE_UNMATCHED);

  // iter

  const u8 *iter_pos = token.buf[3];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt buffer

  const u8 *salt_pos = token.buf[5];
  const int salt_len = token.len[5];

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  // salt length

  const u8 *salt_len_pos = token.buf[4];

  const u32 salt_len_verify = hc_strtoul ((const char *) salt_len_pos, NULL, 10);

  if (salt_len_verify != salt->salt_len) return (PARSER_SALT_LENGTH);

  // hash

  const u8 *hash_pos = token.buf[6];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

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

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf ((char *) out_buf, line_size, "$%s$0$%d$%d$", SIGNATURE_XMPP, salt->salt_iter + 1, salt->salt_len);

  out_len += hex_encode ((const u8 *) salt->salt_buf, (const int) salt->salt_len, out_buf + out_len);

  out_buf[out_len] = '$';

  out_len += 1;

  u32 tmp[5];

  tmp[0] = byte_swap_32 (digest[0]);
  tmp[1] = byte_swap_32 (digest[1]);
  tmp[2] = byte_swap_32 (digest[2]);
  tmp[3] = byte_swap_32 (digest[3]);
  tmp[4] = byte_swap_32 (digest[4]);

  out_len += hex_encode ((const u8 *) tmp, 20, out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
