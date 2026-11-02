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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "BestCrypt v4 Volume Encryption";
static const u64   KERN_TYPE      = 24000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_ST_HEX;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$bcve$4$08$323631353538333233323034363039393534383233393530$9f7892b8324b1d8cd36b5f2f8705b407131261620a89370db8369046646f5f82b96780453948db53b04928ae0cc47066f13454b34e31b58ea44ce943bcba14fcbd87f17205a31a896df182629ceea164d87e9e29127e8d865ca0bee52f832723";

#include "hooks_common.c"

u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

typedef struct bestcrypt_scrypt
{
  u32 salt_buf[24];
  u32 ciphertext[96];
  u32 version;

} bestcrypt_scrypt_t;

static const char *SIGNATURE_BESTCRYPT_SCRYPT = "$bcve$";

static const u32 SCRYPT_THREADS = 16;

#include "scrypt_common.c"

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (bestcrypt_scrypt_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  bestcrypt_scrypt_t *bestcrypt_scrypt = (bestcrypt_scrypt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BESTCRYPT_SCRYPT;

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
  token.len[3]     = 48;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[4]     = 192;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *format_type_pos = token.buf[1];

  if (format_type_pos[0] != '4') return (PARSER_SALT_VALUE);

  const u8 *crypto_type_pos = token.buf[2];

  bestcrypt_scrypt->version = crypto_type_pos[1];

  // scrypt settings

  const u32 scrypt_N = 32768;
  const u32 scrypt_r = 16;
  const u32 scrypt_p = 1;

  salt->scrypt_N = scrypt_N;
  salt->scrypt_r = scrypt_r;
  salt->scrypt_p = scrypt_p;

  // salt

  const u8 *salt_pos = token.buf[3];
  const int salt_len = token.len[3];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  bestcrypt_scrypt->salt_buf[0] = salt->salt_buf[0];
  bestcrypt_scrypt->salt_buf[1] = salt->salt_buf[1];

  bestcrypt_scrypt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  bestcrypt_scrypt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);

  salt->salt_iter    = salt->scrypt_N;
  if (salt->scrypt_p < 1) return (PARSER_SALT_VALUE);

  salt->salt_repeats = salt->scrypt_p - 1;

  // ciphertext

  const u8 *ciphertext_pos = token.buf[4];
  const int ciphertext_len = token.len[4];

  hex_decode (ciphertext_pos, ciphertext_len, (u8 *) bestcrypt_scrypt->ciphertext);

  digest[0] = bestcrypt_scrypt->ciphertext[16];
  digest[1] = bestcrypt_scrypt->ciphertext[17];
  digest[2] = bestcrypt_scrypt->ciphertext[18];
  digest[3] = bestcrypt_scrypt->ciphertext[19];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  char tmp_salt[(SALT_MAX * 2) + 1];

  const int salt_len = generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, (u8 *) tmp_salt);

  tmp_salt[salt_len] = 0;

  bestcrypt_scrypt_t *bestcrypt_scrypt = (bestcrypt_scrypt_t *) esalt_buf;

  u8 data_hex[193] = { 0 };

  hex_encode ((u8 *) bestcrypt_scrypt->ciphertext, 96, data_hex);

  const int line_len = snprintf (line_buf, line_size, "%s4$0%c$%s$%s",
    SIGNATURE_BESTCRYPT_SCRYPT,
    bestcrypt_scrypt->version,
    (char *) tmp_salt,
    data_hex
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
