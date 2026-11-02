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
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Electrum Wallet (Salt-Type 1-3)";
static const u64   KERN_TYPE      = 16600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS15;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$electrum$1*44358283104603165383613672586868*c43a6632d9f59364f74c395a03d8c2ea";

#include "hooks_common.c"

typedef struct electrum_wallet
{
  u32 iv[4];
  u32 encrypted[4];
  u32 salt_type;

} electrum_wallet_t;

static const char *SIGNATURE_ELECTRUM_WALLET = "$electrum$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (electrum_wallet_t);

  return esalt_size;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // On Metal this kernel runs faster when the backend builds it at the size optimization level.

  if (device_param->is_metal == true) hc_asprintf (&jit_build_options, "-D METAL_OPT_SIZE");

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  electrum_wallet_t *electrum_wallet = (electrum_wallet_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ELECTRUM_WALLET;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt_type

  const u8 *salt_type_pos = token.buf[1];

  const u32 salt_type = hc_strtoul ((const char *) salt_type_pos, NULL, 10);

  if ((salt_type == 1) || (salt_type == 2) || (salt_type == 3))
  {
    // all ok
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  electrum_wallet->salt_type = salt_type;

  // iv

  const u8 *iv_pos = token.buf[2];

  electrum_wallet->iv[0] = hex_to_u32 (&iv_pos[ 0]);
  electrum_wallet->iv[1] = hex_to_u32 (&iv_pos[ 8]);
  electrum_wallet->iv[2] = hex_to_u32 (&iv_pos[16]);
  electrum_wallet->iv[3] = hex_to_u32 (&iv_pos[24]);

  // encrypted

  const u8 *encrypted_pos = token.buf[3];

  electrum_wallet->encrypted[0] = hex_to_u32 (&encrypted_pos[ 0]);
  electrum_wallet->encrypted[1] = hex_to_u32 (&encrypted_pos[ 8]);
  electrum_wallet->encrypted[2] = hex_to_u32 (&encrypted_pos[16]);
  electrum_wallet->encrypted[3] = hex_to_u32 (&encrypted_pos[24]);

  // salt fake

  salt->salt_buf[0] = electrum_wallet->iv[0];
  salt->salt_buf[1] = electrum_wallet->iv[1];
  salt->salt_buf[2] = electrum_wallet->iv[2];
  salt->salt_buf[3] = electrum_wallet->iv[3];
  salt->salt_buf[4] = electrum_wallet->encrypted[0];
  salt->salt_buf[5] = electrum_wallet->encrypted[1];
  salt->salt_buf[6] = electrum_wallet->encrypted[2];
  salt->salt_buf[7] = electrum_wallet->encrypted[3];

  salt->salt_len = 32;

  // hash fake

  digest[0] = electrum_wallet->iv[0];
  digest[1] = electrum_wallet->iv[1];
  digest[2] = electrum_wallet->iv[2];
  digest[3] = electrum_wallet->iv[3];
  digest[4] = electrum_wallet->encrypted[0];
  digest[5] = electrum_wallet->encrypted[1];
  digest[6] = electrum_wallet->encrypted[2];
  digest[7] = electrum_wallet->encrypted[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const electrum_wallet_t *electrum_wallet = (const electrum_wallet_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s%u*%08x%08x%08x%08x*%08x%08x%08x%08x",
    SIGNATURE_ELECTRUM_WALLET,
    electrum_wallet->salt_type,
    byte_swap_32 (electrum_wallet->iv[0]),
    byte_swap_32 (electrum_wallet->iv[1]),
    byte_swap_32 (electrum_wallet->iv[2]),
    byte_swap_32 (electrum_wallet->iv[3]),
    byte_swap_32 (electrum_wallet->encrypted[0]),
    byte_swap_32 (electrum_wallet->encrypted[1]),
    byte_swap_32 (electrum_wallet->encrypted[2]),
    byte_swap_32 (electrum_wallet->encrypted[3]));

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
}
