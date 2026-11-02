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
static const u32   DGST_POS0      = 6;
static const u32   DGST_POS1      = 7;
static const u32   DGST_POS2      = 4;
static const u32   DGST_POS3      = 5;
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH_SALTED;
static const char *HASH_NAME      = "sha384($salt.$pass)";
static const char *HASH_RECIPE    = "sha384(salt . pass)";
static const u64   KERN_TYPE      = 10820;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_PREPENDED_SALT
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS15;
static const u32   SALT_TYPE      = SALT_TYPE_GENERIC;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "63f63d7f82d4a4cb6b9ff37a6bc7c5ec39faaf9c9078551f5cbf7960e76ded87b643d37ac53c45bc544325e7ff83a1f2:93362";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    // Metal
    if (device_param->is_metal == true)
    {
      hc_asprintf (&jit_build_options, "-D _unroll");
    }

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

u32 module_combined_len_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // the optimized kernels keep password and salt in one buffer

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  const u32 combined_len_max = (optimized_kernel == true) ? 55 : 0;

  return combined_len_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 96;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u64 (hash_pos +  0);
  digest[1] = hex_to_u64 (hash_pos + 16);
  digest[2] = hex_to_u64 (hash_pos + 32);
  digest[3] = hex_to_u64 (hash_pos + 48);
  digest[4] = hex_to_u64 (hash_pos + 64);
  digest[5] = hex_to_u64 (hash_pos + 80);
  digest[6] = 0;
  digest[7] = 0;

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = 0;
  digest[7] = 0;

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= SHA384M_A;
    digest[1] -= SHA384M_B;
    digest[2] -= SHA384M_C;
    digest[3] -= SHA384M_D;
    digest[4] -= SHA384M_E;
    digest[5] -= SHA384M_F;
    digest[6] -= 0;
    digest[7] -= 0;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

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
  tmp[6] = 0;
  tmp[7] = 0;

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    tmp[0] += SHA384M_A;
    tmp[1] += SHA384M_B;
    tmp[2] += SHA384M_C;
    tmp[3] += SHA384M_D;
    tmp[4] += SHA384M_E;
    tmp[5] += SHA384M_F;
    tmp[6] += 0;
    tmp[7] += 0;
  }

  tmp[0] = byte_swap_64 (tmp[0]);
  tmp[1] = byte_swap_64 (tmp[1]);
  tmp[2] = byte_swap_64 (tmp[2]);
  tmp[3] = byte_swap_64 (tmp[3]);
  tmp[4] = byte_swap_64 (tmp[4]);
  tmp[5] = byte_swap_64 (tmp[5]);
  tmp[6] = 0;
  tmp[7] = 0;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  u64_to_hex (tmp[0], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[1], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[2], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[3], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[4], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[5], out_buf + out_len); out_len += 16;

  out_buf[out_len] = hashconfig->separator;

  out_len += 1;

  out_len += generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_combined_len_max         = module_combined_len_max;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_jit_build_options        = module_jit_build_options;
}
