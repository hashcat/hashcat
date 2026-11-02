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
static const u32   DGST_SIZE      = DGST_SIZE_4_6;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "bcrypt $2*$, Blowfish (Unix)";
static const u64   KERN_TYPE      = 3200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DYNAMIC_SHARED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou";

#include "hooks_common.c"

typedef struct bcrypt_tmp
{
  u32 E[18];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} bcrypt_tmp_t;

#include "blowfish_common.c"

static const char *SIGNATURE_BCRYPT1 = "$2a$";
static const char *SIGNATURE_BCRYPT2 = "$2b$";
static const char *SIGNATURE_BCRYPT3 = "$2x$";
static const char *SIGNATURE_BCRYPT4 = "$2y$";

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 32;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 32;

  return kernel_loops_max;
}

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

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bcrypt_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 4;
  token.signatures_buf[0] = SIGNATURE_BCRYPT1;
  token.signatures_buf[1] = SIGNATURE_BCRYPT2;
  token.signatures_buf[2] = SIGNATURE_BCRYPT3;
  token.signatures_buf[3] = SIGNATURE_BCRYPT4;

  token.len[0]     = 4;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 2;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len[2]     = 22;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  token.len[3]     = 31;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *iter_pos = token.buf[1];
  const u8 *salt_pos = token.buf[2];
  const u8 *hash_pos = token.buf[3];

  const int salt_len = token.len[2];
  const int hash_len = token.len[3];

  salt->salt_len  = 16;

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter > 31) return (PARSER_SALT_ITERATION);

  salt->salt_iter = 1u << iter;

  memcpy ((char *) salt->salt_sign, line_buf, 6);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  u8 tmp_buf[100];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (bf64_to_int, salt_pos, salt_len, tmp_buf);

  memcpy (salt_buf_ptr, tmp_buf, 16);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (bf64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 24);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);

  digest[5] &= ~0xffu; // its just 23 not 24 !

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u32 tmp_digest[6];

  tmp_digest[0] = byte_swap_32 (digest[0]);
  tmp_digest[1] = byte_swap_32 (digest[1]);
  tmp_digest[2] = byte_swap_32 (digest[2]);
  tmp_digest[3] = byte_swap_32 (digest[3]);
  tmp_digest[4] = byte_swap_32 (digest[4]);
  tmp_digest[5] = byte_swap_32 (digest[5]);

  u32 tmp_salt[4];

  tmp_salt[0] = byte_swap_32 (salt->salt_buf[0]);
  tmp_salt[1] = byte_swap_32 (salt->salt_buf[1]);
  tmp_salt[2] = byte_swap_32 (salt->salt_buf[2]);
  tmp_salt[3] = byte_swap_32 (salt->salt_buf[3]);

  char tmp_buf[64];

  base64_encode (int_to_bf64, (const u8 *) tmp_salt,   16, (u8 *) tmp_buf +  0);
  base64_encode (int_to_bf64, (const u8 *) tmp_digest, 23, (u8 *) tmp_buf + 22);

  tmp_buf[22 + 31] = 0; // base64_encode wants to pad

  return snprintf (line_buf, line_size, "%s$%s", (const char *) salt->salt_sign, tmp_buf);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = blowfish_module_benchmark_cost;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = blowfish_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = blowfish_module_jit_cache_disable;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_pw_max                   = blowfish_module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
