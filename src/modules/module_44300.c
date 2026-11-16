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

#include "emu_inc_hash_base58.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Bitcoin BIP38 Private Key (no EC multiply)";
static const u64   KERN_TYPE      = 44300;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "6PYWpAH8W1hiFNRSPh7zWc1oD6LbAhk2JqdQMBfn57JDCABLnnsghkwzL8";

#include "hooks_common.c"

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode cracks a BIP38 encrypted private key made without EC multiply, the 58 character string that starts with 6PR or 6PY. The password is checked against the addresshash of the key's Bitcoin mainnet P2PKH address, so a testnet key, or a key of another coin that uses the BIP38 format with its own address version, does not crack";
}

static const u32 SCRYPT_THREADS = 4;

#include "scrypt_common.c"

// An encrypted key is 0x01 0x42, a flag byte, the addresshash and the two encrypted halves of the
// private key, with a base58check checksum. That is always 43 bytes and 58 base58 digits.

#define BIP38_BIN_LEN 43
#define BIP38_B58_LEN 58

#define BIP38_FLAG_COMPRESSED 0x20

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 1;

  token.len[0]    = BIP38_B58_LEN;
  token.attr[0]   = TOKEN_ATTR_FIXED_LENGTH
                  | TOKEN_ATTR_VERIFY_BASE58;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8 bin[BIP38_BIN_LEN];

  u32 bin_len = BIP38_BIN_LEN;

  if (b58dec (bin, &bin_len, (const u8 *) line_buf, line_len) == false) return (PARSER_HASH_LENGTH);

  if (bin_len != BIP38_BIN_LEN) return (PARSER_HASH_LENGTH);

  if (b58check (bin, BIP38_BIN_LEN) == false) return (PARSER_HASH_ENCODING);

  // 0x01 0x43 is the EC multiply form, which this mode does not cover

  if (bin[0] != 0x01) return (PARSER_SIGNATURE_UNMATCHED);
  if (bin[1] != 0x42) return (PARSER_SIGNATURE_UNMATCHED);

  const u32 flag = bin[2];

  if ((flag & ~BIP38_FLAG_COMPRESSED) != 0xc0) return (PARSER_HASH_VALUE);

  // The addresshash is the whole scrypt salt. The encrypted halves and the flag follow it in
  // salt_buf, outside salt_len, so that two keys sharing an addresshash stay two salts.

  u8 *salt_ptr = (u8 *) salt->salt_buf;

  for (u32 i = 0; i < 36; i++) salt_ptr[i] = bin[3 + i];

  salt->salt_buf[9] = flag;

  salt->salt_len = 4;

  salt->scrypt_N = 16384;
  salt->scrypt_r = 8;
  salt->scrypt_p = 8;

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  digest[0] = byte_swap_32 (salt->salt_buf[0]);
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u8 *salt_ptr = (const u8 *) salt->salt_buf;

  u8 data[BIP38_BIN_LEN - 5];

  data[0] = 0x42;
  data[1] = (u8) salt->salt_buf[9];

  for (u32 i = 0; i < 36; i++) data[2 + i] = salt_ptr[i];

  u8 b58[BIP38_B58_LEN + 8];

  u32 b58_len = sizeof (b58);

  if (b58check_enc (b58, &b58_len, 0x01, data, sizeof (data)) == false) return -1;

  const int line_len = snprintf (line_buf, line_size, "%s", (char *) b58);

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
