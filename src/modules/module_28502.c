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

#include "emu_inc_hash_base58.h"

static const u32   ATTACK_EXEC       = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0         = 0;
static const u32   DGST_POS1         = 1;
static const u32   DGST_POS2         = 2;
static const u32   DGST_POS3         = 3;
static const u32   DGST_SIZE         = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY     = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME         = "Bitcoin WIF private key (P2PKH), uncompressed";
static const u64   KERN_TYPE         = 28502;
static const u32   OPTI_TYPE         = OPTI_TYPE_NOT_SALTED;
static const u64   OPTS_TYPE         = OPTS_TYPE_STOCK_MODULE
                                     | OPTS_TYPE_PT_BASE58
                                     | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE         = SALT_TYPE_NONE;
static const char *ST_PASS           = "5KcL859EUnBDtVG76134U6DZWnVmpE996emJnWmTLRW2hashcat";
static const char *ST_HASH           = "1L9nr4GX4Zmd7gDL1UT75QPUqxSgNTvdHb";
static const char *BENCHMARK_MASK    = "?1?1?1?1?1?1?1EUnBDtVG76134U6DZWnVmpE996emJnWmTLRW2hashcat";
static const char *BENCHMARK_CHARSET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

#include "hooks_common.c"

const char *module_benchmark_mask    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BENCHMARK_MASK;  }
const char *module_benchmark_charset (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BENCHMARK_CHARSET;  }

#define PUBKEY_MAXLEN 64 // our max is actually always 25 (21 + 4)
#define WIF_LEN       51

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: self-test failed
        return true;
      }
    }
  }

  return false;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return WIF_LEN;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return WIF_LEN;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u8 *digest = (u8 *) digest_buf;

  u8 pubkey[PUBKEY_MAXLEN];

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 1;

  token.len_min[0] = 26;
  token.len_max[0] = 34;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE58;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u32 pubkey_len = PUBKEY_MAXLEN;

  bool res = b58dec (pubkey, &pubkey_len, (const u8 *) line_buf, line_len);

  if (res == false) return (PARSER_HASH_LENGTH);

  // for now we support only P2PKH addresses

  if (pubkey_len != 25) return (PARSER_HASH_LENGTH); // most likely wrong Bitcoin address type

  u32 l = PUBKEY_MAXLEN - pubkey_len;

  if (pubkey[l] != 0) return (PARSER_HASH_VALUE); // wrong Bitcoin address type

  // check if pubkey has correct sha256 sum included

  u32 npubkey[16] = { 0 };

  u8 *npubkey_ptr = (u8 *) npubkey;

  for (u32 i = 0, j = PUBKEY_MAXLEN - pubkey_len; i < pubkey_len; i++, j++)
  {
    npubkey_ptr[i] = pubkey[j];
  }

  // if (b58check   (npubkey_ptr, pubkey_len) == false) return (PARSER_HASH_ENCODING);
  // if (b58check64 (npubkey,     pubkey_len) == false) return (PARSER_HASH_ENCODING);

  if (b58check_25 (npubkey) == false) return (PARSER_HASH_ENCODING);

  for (u32 i = 0; i < 20; i++) // DGST_SIZE
  {
    digest[i] = pubkey[PUBKEY_MAXLEN - pubkey_len + i + 1];
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u8 *digest = (const u8 *) digest_buf;

  u8 buf[64] = { 0 };

  u32 len = 64;

  b58check_enc (buf, &len, 0, digest, 20);

  return snprintf (line_buf, line_size, "%s", buf);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_benchmark_charset        = module_benchmark_charset;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
