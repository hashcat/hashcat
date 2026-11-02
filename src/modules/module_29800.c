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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Bisq .wallet (scrypt)";
static const u64   KERN_TYPE      = 27700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat1";
static const char *ST_HASH        = "$bisq$3*32768*8*6*31d838af87f99cb8*5cfb7bf3228d9e865881156e17b1866589ffa6b757011e25d1319083595236d2";

#include "hooks_common.c"

u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/bisq2hashcat.py to extract the hashes";
}

static const char *SIGNATURE_BISQ = "$bisq$";

static const u32 SCRYPT_THREADS = 16;

#include "scrypt_common.c"

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 8;

  return pw_min;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BISQ;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 10;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len[4]     = 1;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';
  token.len[5]     = 16;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[6]     = 64;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u8 *version_pos = token.buf[1];

  if (version_pos[0] != (u8) '3') return (PARSER_SIGNATURE_UNMATCHED);

  // scrypt settings

  const u8 *scrypt_n_pos = token.buf[2];

  const u32 scrypt_n = hc_strtoul ((const char *) scrypt_n_pos, NULL, 10);

  const u8 *scrypt_r_pos = token.buf[3];

  const u32 scrypt_r = hc_strtoul ((const char *) scrypt_r_pos, NULL, 10);

  const u8 *scrypt_p_pos = token.buf[4];

  const u32 scrypt_p = hc_strtoul ((const char *) scrypt_p_pos, NULL, 10);

  salt->scrypt_N = scrypt_n;
  salt->scrypt_r = scrypt_r;
  salt->scrypt_p = scrypt_p;

  salt->salt_iter    = salt->scrypt_N;
  if (salt->scrypt_p < 1) return (PARSER_SALT_VALUE);

  salt->salt_repeats = salt->scrypt_p - 1;

  // salt

  const u8 *salt_pos = token.buf[5];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]); // swap the salt (only the salt)
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  // IV

  const u8 *blob_pos = token.buf[6];

  salt->salt_buf[2] = hex_to_u32 (blob_pos +  0);
  salt->salt_buf[3] = hex_to_u32 (blob_pos +  8);
  salt->salt_buf[4] = hex_to_u32 (blob_pos + 16);
  salt->salt_buf[5] = hex_to_u32 (blob_pos + 24);

  // data

  salt->salt_buf[6] = hex_to_u32 (blob_pos + 32);
  salt->salt_buf[7] = hex_to_u32 (blob_pos + 40);
  salt->salt_buf[8] = hex_to_u32 (blob_pos + 48);
  salt->salt_buf[9] = hex_to_u32 (blob_pos + 56);

  salt->salt_len = 40;

  // fake digest:

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const int line_len = snprintf (line_buf, line_size, "%s%u*%u*%u*%u*%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
    SIGNATURE_BISQ,
    3,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    salt->salt_buf[0],
    salt->salt_buf[1],
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]),
    byte_swap_32 (salt->salt_buf[4]),
    byte_swap_32 (salt->salt_buf[5]),
    byte_swap_32 (salt->salt_buf[6]),
    byte_swap_32 (salt->salt_buf[7]),
    byte_swap_32 (salt->salt_buf[8]),
    byte_swap_32 (salt->salt_buf[9]));

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
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
