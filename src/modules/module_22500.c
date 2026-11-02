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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "MultiBit Classic .key (MD5)";
static const u64   KERN_TYPE      = 22500;
static const u32   OPTI_TYPE      = OPTI_TYPE_EARLY_SKIP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de";

#include "hooks_common.c"

static const char *SIGNATURE_MULTIBIT = "$multibit$";

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm22500_s04' pipeline, Compilation failed
        return true;
      }
    }
  }

  return false;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = PW_MAX;

  if (optimized_kernel == true)
  {
    pw_max = 31; // 55 - 8 (salt) - 16 (key1/key2)
  }

  return pw_max;
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

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MULTIBIT;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 16;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len[3]     = 64;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u8 *version_pos = token.buf[1];

  const u32 version = hc_strtoul ((const char *) version_pos, NULL, 10);

  if (version != 1) return PARSER_SALT_VALUE;

  // salt

  const u8 *salt_pos = token.buf[2];

  salt->salt_buf[0] = hex_to_u32 (salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos + 8);

  // data

  const u8 *data_pos = token.buf[3];

  salt->salt_buf[2] = hex_to_u32 (data_pos +  0);
  salt->salt_buf[3] = hex_to_u32 (data_pos +  8);
  salt->salt_buf[4] = hex_to_u32 (data_pos + 16);
  salt->salt_buf[5] = hex_to_u32 (data_pos + 24);
  salt->salt_buf[6] = hex_to_u32 (data_pos + 32);
  salt->salt_buf[7] = hex_to_u32 (data_pos + 40);
  salt->salt_buf[8] = hex_to_u32 (data_pos + 48);
  salt->salt_buf[9] = hex_to_u32 (data_pos + 56);

  salt->salt_len = 40; // 8 + 32;

  // fake hash

  digest[0] = salt->salt_buf[2];
  digest[1] = salt->salt_buf[3];
  digest[2] = salt->salt_buf[4];
  digest[3] = salt->salt_buf[5];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  int line_len = snprintf (line_buf, line_size, "%s%i*%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
    SIGNATURE_MULTIBIT,
    1,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
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

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
