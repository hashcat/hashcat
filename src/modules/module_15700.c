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
static const char *HASH_NAME      = "Ethereum Wallet, SCRYPT";
static const u64   KERN_TYPE      = 15700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_ST_HEX;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$ethereum$s*262144*8*1*3134313837333434333838303231333633373433323633373534333136363537*73da7f80ec3bd4f2a128c3a815cfb4d576ecb1a9b47024c902e62ea926f7795b*910e0f8dc1f7ba41959e1089bb769f3e919109591913cc33ba03953d7a905efd";

#include "hooks_common.c"

u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

typedef struct ethereum_scrypt
{
  u32 salt_buf[16];
  u32 ciphertext[8];

} ethereum_scrypt_t;

static const char *SIGNATURE_ETHEREUM_SCRYPT = "$ethereum$s";

static const u32 SCRYPT_THREADS = 4;

#include "scrypt_common.c"

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (ethereum_scrypt_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  ethereum_scrypt_t *ethereum_scrypt = (ethereum_scrypt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ETHEREUM_SCRYPT;

  token.sep[0]     = '*';
  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 6;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len[4]     = 64;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '*';
  token.len[5]     = 64;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '*';
  token.len[6]     = 64;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // scrypt settings

  const u8 *scryptN_pos = token.buf[1];
  const u8 *scryptr_pos = token.buf[2];
  const u8 *scryptp_pos = token.buf[3];

  const u32 scrypt_N = hc_strtoul ((const char *) scryptN_pos, NULL, 10);
  const u32 scrypt_r = hc_strtoul ((const char *) scryptr_pos, NULL, 10);
  const u32 scrypt_p = hc_strtoul ((const char *) scryptp_pos, NULL, 10);

  salt->scrypt_N = scrypt_N;
  salt->scrypt_r = scrypt_r;
  salt->scrypt_p = scrypt_p;

  salt->salt_iter    = salt->scrypt_N;
  if (salt->scrypt_p < 1) return (PARSER_SALT_VALUE);

  salt->salt_repeats = salt->scrypt_p - 1;

  if (salt->scrypt_N % 1024) return (PARSER_SALT_VALUE); // we set loop count to 1024 fixed

  // salt

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  ethereum_scrypt->salt_buf[0] = salt->salt_buf[0];
  ethereum_scrypt->salt_buf[1] = salt->salt_buf[1];
  ethereum_scrypt->salt_buf[2] = salt->salt_buf[2];
  ethereum_scrypt->salt_buf[3] = salt->salt_buf[3];
  ethereum_scrypt->salt_buf[4] = salt->salt_buf[4];
  ethereum_scrypt->salt_buf[5] = salt->salt_buf[5];
  ethereum_scrypt->salt_buf[6] = salt->salt_buf[6];
  ethereum_scrypt->salt_buf[7] = salt->salt_buf[7];

  // ciphertext

  const u8 *ciphertext_pos = token.buf[5];

  ethereum_scrypt->ciphertext[0] = hex_to_u32 (&ciphertext_pos[ 0]);
  ethereum_scrypt->ciphertext[1] = hex_to_u32 (&ciphertext_pos[ 8]);
  ethereum_scrypt->ciphertext[2] = hex_to_u32 (&ciphertext_pos[16]);
  ethereum_scrypt->ciphertext[3] = hex_to_u32 (&ciphertext_pos[24]);
  ethereum_scrypt->ciphertext[4] = hex_to_u32 (&ciphertext_pos[32]);
  ethereum_scrypt->ciphertext[5] = hex_to_u32 (&ciphertext_pos[40]);
  ethereum_scrypt->ciphertext[6] = hex_to_u32 (&ciphertext_pos[48]);
  ethereum_scrypt->ciphertext[7] = hex_to_u32 (&ciphertext_pos[56]);

  // hash

  const u8 *hash_pos = token.buf[6];

  digest[0] = hex_to_u32 (&hash_pos[ 0]);
  digest[1] = hex_to_u32 (&hash_pos[ 8]);
  digest[2] = hex_to_u32 (&hash_pos[16]);
  digest[3] = hex_to_u32 (&hash_pos[24]);
  digest[4] = hex_to_u32 (&hash_pos[32]);
  digest[5] = hex_to_u32 (&hash_pos[40]);
  digest[6] = hex_to_u32 (&hash_pos[48]);
  digest[7] = hex_to_u32 (&hash_pos[56]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  char tmp_salt[(SALT_MAX * 2) + 1];

  const int salt_len = generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, (u8 *) tmp_salt);

  tmp_salt[salt_len] = 0;

  const ethereum_scrypt_t *ethereum_scrypt = (const ethereum_scrypt_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s*%u*%u*%u*%s*%08x%08x%08x%08x%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
    SIGNATURE_ETHEREUM_SCRYPT,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    (char *) tmp_salt,
    byte_swap_32 (ethereum_scrypt->ciphertext[0]),
    byte_swap_32 (ethereum_scrypt->ciphertext[1]),
    byte_swap_32 (ethereum_scrypt->ciphertext[2]),
    byte_swap_32 (ethereum_scrypt->ciphertext[3]),
    byte_swap_32 (ethereum_scrypt->ciphertext[4]),
    byte_swap_32 (ethereum_scrypt->ciphertext[5]),
    byte_swap_32 (ethereum_scrypt->ciphertext[6]),
    byte_swap_32 (ethereum_scrypt->ciphertext[7]),
    byte_swap_32 (digest[0]),
    byte_swap_32 (digest[1]),
    byte_swap_32 (digest[2]),
    byte_swap_32 (digest[3]),
    byte_swap_32 (digest[4]),
    byte_swap_32 (digest[5]),
    byte_swap_32 (digest[6]),
    byte_swap_32 (digest[7])
  );

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = scrypt_module_benchmark_cost;
  module_ctx->module_esalt_size               = module_esalt_size;
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
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
}
