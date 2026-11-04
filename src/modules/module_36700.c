/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Cardano Daedalus Wallet (Byron era, spending password)";
static const u64   KERN_TYPE      = 36700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "TryGu3ssMe";
static const char *ST_HASH        = "$cardano$2$16384$8$1$582024d30367feda5ece6185c0b1eeb70af43746ce7c48c3a7cf09afcdf01f636df7$6379785ebb2033411f194070c7a925ae367e932a9b7f1e0248c14eec7a561699";

#include "hooks_common.c"

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode cracks the spending password of a Byron era Daedalus wallet, from the log2(N)|r|p|salt|hash string that its secret.key stores beside each encrypted key. The salt and the hash are base64 in that string and hex in the hash line. It does not read john's $cardano$1$ line, which carries the encrypted key instead and needs an ed25519 point multiplication that hashcat does not have yet";
}

static const char *SIGNATURE_CARDANO = "$cardano$2$";

static const u32 SCRYPT_THREADS = 32;

#include "scrypt_common.c"

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CARDANO;

  token.len[0]     = 11;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 7;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 3;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 3;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // the salt of the sample in issue 3013 is 34 bytes, because cardano-sl stored it CBOR wrapped as
  // well, so the length is read from the line rather than fixed

  token.sep[4]     = '$';
  token.len_min[4] = 16;
  token.len_max[4] = 128;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '$';
  token.len[5]     = 64;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // scrypt settings

  salt->scrypt_N = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  salt->scrypt_r = hc_strtoul ((const char *) token.buf[2], NULL, 10);
  salt->scrypt_p = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if (salt->scrypt_N < 1) return (PARSER_SALT_VALUE);
  if (salt->scrypt_r < 1) return (PARSER_SALT_VALUE);
  if (salt->scrypt_p < 1) return (PARSER_SALT_VALUE);

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  // salt

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  if (salt_len & 1) return (PARSER_SALT_LENGTH);

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  // the stored hash, which the scrypt output is compared with. scrypt_pbkdf2_body_pp swaps its
  // own output, so the result is in host byte order and the stored bytes go in as they are.

  const u8 *hash_pos = token.buf[5];
  const int hash_len = token.len[5];

  hex_decode (hash_pos, hash_len, (u8 *) digest);

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  char salt_hex[(128 / 2 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_hex);

  char hash_hex[(32 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) digest, 32, (u8 *) hash_hex);

  const int line_len = snprintf (line_buf, line_size, "%s%u$%u$%u$%s$%s",
    SIGNATURE_CARDANO,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    salt_hex,
    hash_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = scrypt_module_benchmark_cost;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = scrypt_module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = scrypt_module_jit_build_options;
  module_ctx->module_kernel_accel_max         = scrypt_module_kernel_accel_max;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
  module_ctx->module_tune_variants            = scrypt_module_tune_variants;
  module_ctx->module_usage_notice             = module_usage_notice;
}
