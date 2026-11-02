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
static const u32   DGST_POS0      = 14;
static const u32   DGST_POS1      = 15;
static const u32   DGST_POS2      = 6;
static const u32   DGST_POS3      = 7;
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Citrix NetScaler (SHA512)";
static const char *HASH_RECIPE    = "sha512(salt . pass . \"\\0\")";
static const u64   KERN_TYPE      = 22200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_PREPENDED_SALT
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "2f9282ade42ce148175dc3b4d8b5916dae5211eee49886c3f7cc768f6b9f2eb982a5ac2f2672a0223999bfd15349093278adf12f6276e8b61dacf5572b3f93d0b4fa886ce";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // the optimized kernels hash the 8 byte salt, the password and the trailing zero in one block

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  const u32 pw_max = (optimized_kernel == true) ? MIN (hashconfig->pw_max, 46) : hashconfig->pw_max; // 55 - 8 - 1

  return pw_max;
}

static const char *SIGNATURE_NETSCALER = "2";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // HIP
  if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // ROCM
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == true))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_NETSCALER;

  token.len[0]  = 1;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 8;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH;

  token.len[2]  = 128;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  memcpy (salt->salt_buf, salt_pos, salt_len);

  // Optimized kernels need big endian salt words. Recipe kernels read the original bytes.

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
    salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  }

  salt->salt_len = salt_len;

  // hash

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= SHA512M_A;
    digest[1] -= SHA512M_B;
    digest[2] -= SHA512M_C;
    digest[3] -= SHA512M_D;
    digest[4] -= SHA512M_E;
    digest[5] -= SHA512M_F;
    digest[6] -= SHA512M_G;
    digest[7] -= SHA512M_H;
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u64 tmp[8];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];
  tmp[4] = digest[4];
  tmp[5] = digest[5];
  tmp[6] = digest[6];
  tmp[7] = digest[7];

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    tmp[0] += SHA512M_A;
    tmp[1] += SHA512M_B;
    tmp[2] += SHA512M_C;
    tmp[3] += SHA512M_D;
    tmp[4] += SHA512M_E;
    tmp[5] += SHA512M_F;
    tmp[6] += SHA512M_G;
    tmp[7] += SHA512M_H;
  }

  tmp[0] = byte_swap_64 (tmp[0]);
  tmp[1] = byte_swap_64 (tmp[1]);
  tmp[2] = byte_swap_64 (tmp[2]);
  tmp[3] = byte_swap_64 (tmp[3]);
  tmp[4] = byte_swap_64 (tmp[4]);
  tmp[5] = byte_swap_64 (tmp[5]);
  tmp[6] = byte_swap_64 (tmp[6]);
  tmp[7] = byte_swap_64 (tmp[7]);

  u32 tmp_salt[2];

  tmp_salt[0] = salt->salt_buf[0];
  tmp_salt[1] = salt->salt_buf[1];

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    tmp_salt[0] = byte_swap_32 (tmp_salt[0]);
    tmp_salt[1] = byte_swap_32 (tmp_salt[1]);
  }

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  out_buf[0] = '2'; out_len += 1;

  memcpy (out_buf + out_len, tmp_salt, 8); out_len += 8;

  u64_to_hex (tmp[0], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[1], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[2], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[3], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[4], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[5], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[6], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[7], out_buf + out_len); out_len += 16;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_pw_max                   = module_pw_max;
}
