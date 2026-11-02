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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "RAR3-hp";
static const u64   KERN_TYPE      = 12500;
static const bool  LENGTH_SORT    = true;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_POST_AMP_UTF16LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317";

#include "hooks_common.c"

bool        module_length_sort    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return LENGTH_SORT;     }

typedef struct rar3_tmp
{
  u32 dgst[5];

  u32 w[66]; // 256 byte pass + 8 byte salt

  u32 iv[4];

} rar3_tmp_t;

typedef struct rar3_tmp_optimized
{
  u32 dgst[17][5];

} rar3_tmp_optimized_t;

static const int   ROUNDS_RAR3    = 262144;
static const char *SIGNATURE_RAR3 = "$RAR3$";

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
    {
      // Intel Iris
      return true;
    }
  }

  return false;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u64 tmp_size = (u64) sizeof (rar3_tmp_t);

  if (optimized_kernel == true)
  {
    tmp_size = (u64) sizeof (rar3_tmp_optimized_t);
  }

  return tmp_size;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = ROUNDS_RAR3 / 16;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = ROUNDS_RAR3 / 16;

  return kernel_loops_max;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = 128;

  if (optimized_kernel == true)
  {
    pw_max = 20;
  }

  return pw_max;
}

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?l?l?l?l?l";

  return mask;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_RAR3;

  token.sep[0]     = '*';
  token.len[0]     = 6;
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
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *type_pos    = token.buf[1];
  const u8 *salt_pos    = token.buf[2];
  const u8 *crypted_pos = token.buf[3];

  if (type_pos[0] != '0') return (PARSER_SIGNATURE_UNMATCHED);

  /**
   * copy data
   */

  salt->salt_buf[0] = hex_to_u32 (salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos + 8);
  salt->salt_buf[2] = hex_to_u32 (crypted_pos +  0);
  salt->salt_buf[3] = hex_to_u32 (crypted_pos +  8);
  salt->salt_buf[4] = hex_to_u32 (crypted_pos + 16);
  salt->salt_buf[5] = hex_to_u32 (crypted_pos + 24);

  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);
  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);
  salt->salt_buf[5] = byte_swap_32 (salt->salt_buf[5]);

  salt->salt_len  = 24;
  salt->salt_iter = ROUNDS_RAR3;

  // there's no hash for rar3. the data which is in crypted_pos is some encrypted data and
  // if it matches the value \xc4\x3d\x7b\x00\x40\x07\x00 after decrypt we know that we successfully cracked it.

  digest[0] = 0xc43d7b00;
  digest[1] = 0x40070000;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  return snprintf (line_buf, line_size, "%s*0*%08x%08x*%08x%08x%08x%08x",
      SIGNATURE_RAR3,
      byte_swap_32 (salt->salt_buf[0]),
      byte_swap_32 (salt->salt_buf[1]),
      salt->salt_buf[2],
      salt->salt_buf[3],
      salt->salt_buf[4],
      salt->salt_buf[5]);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_length_sort              = module_length_sort;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
