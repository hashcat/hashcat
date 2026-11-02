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
static const u32   DGST_SIZE      = DGST_SIZE_8_2;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_CHECKSUM;
static const char *HASH_NAME      = "MurmurHash64A";
static const u64   KERN_TYPE      = 34200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG
                                  | OPTS_TYPE_MAXIMUM_THREADS
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "ef3014941bf1102d:837163b2348dfae1";

#include "hooks_common.c"

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = PW_MAX;

  if (optimized_kernel == true)
  {
    // The a0 and a1 kernels load 32 bytes of the word. Brute force hashes 64 of the candidate.

    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      pw_max = 64;
    }
    else
    {
      pw_max = 32;
    }
  }

  return pw_max;
}

u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_max = 8;

  return salt_max;
}

u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_min = 8;

  return salt_min;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 16;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[1]     = hashconfig->separator;
  token.len[1]     = 16;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // Digest

  // 16 chars (hash hex string, big endian)
  const u8 *hash_pos = token.buf[0];

  // Convert to little endian u64
  digest[0] = ((hex_to_u64 (&hash_pos[0])));
  digest[1] = 0;

  digest[0] = byte_swap_64 (digest[0]);

  // Seed

  // 16 chars (salt hex string, big endian)
  const u8 *salt_pos = token.buf[1];

  u64 temp_salt = hex_to_u64 (&salt_pos[0]); // Convert hex to u64
  temp_salt = byte_swap_64 (temp_salt); // Byte swap to little endian

  // Split into two u32s for salt_buf
  salt->salt_buf[0] = (u32) (temp_salt & 0xffffffff); // lo 32 bits
  salt->salt_buf[1] = (u32) (temp_salt >> 32); // hi 32 bits

  salt->salt_len = 8;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  const u64 *salt_b = (const u64 *) salt->salt_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  // Write hash as big endian hex
  u64_to_hex (byte_swap_64 (digest[0]), out_buf + out_len); out_len += 16;

  out_buf[out_len] = (u8) hashconfig->separator;

  out_len += 1;

  // Write salt as big endian hex
  u64_to_hex (byte_swap_64 (salt_b[0]), out_buf + out_len); out_len += 16;

  // len should be 33 (16 + 1 + 16)
  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
}
