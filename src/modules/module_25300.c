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
static const u32   DGST_POS0      = 14;
static const u32   DGST_POS1      = 15;
static const u32   DGST_POS2      = 6;
static const u32   DGST_POS3      = 7;
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "MS Office 2016 - SheetProtection";
static const u64   KERN_TYPE      = 25300;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$office$2016$0$100000$876MLoKTq42+/DLp415iZQ==$TNDvpvYyvlSUy97UOLKNhXynhUDDA7H8kLql0ISH5SxcP6hbthdjaTo4Z3/MU0dcR2SAd+AduYb3TB5CLZ8+ow==";

#include "hooks_common.c"

typedef struct office2016
{
  u32 salt_buf[24 + 1];

} office2016_t;

typedef struct office2016_tmp
{
  u64 out[8];

} office2016_tmp_t;

static const char *SIGNATURE_OFFICE2016_SHEETPROTECTION = "$office$2016$0$";

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm25300_init' pipeline, Compilation failed
        return true;
      }
    }
  }

  return false;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // NVIDIA GPU
  if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
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

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (office2016_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (office2016_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  office2016_t *office2016 = (office2016_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OFFICE2016_SHEETPROTECTION;

  token.len[0]     = 15;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 6;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 24;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = '$';
  token.len[3]     = 88;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *spinCount_pos = token.buf[1];

  const u32 spinCount =  hc_strtoul ((const char *) spinCount_pos, NULL, 10);

  if (spinCount != 100000) return (PARSER_SALT_VALUE);

  /**
   * salt
   */

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  memcpy (office2016->salt_buf, salt_pos, salt_len);

  u8 tmp_buf[256];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  int tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len != 16) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  salt->salt_len  = tmp_len;
  salt->salt_iter = spinCount;

  /**
   * digest
   */

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len != 64) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, tmp_len);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  const office2016_t *office2016 = (const office2016_t *) esalt_buf;

  const u32 spinCount = salt->salt_iter;

  // hash

  u64 tmp[8];

  tmp[0] = byte_swap_64 (digest[0]);
  tmp[1] = byte_swap_64 (digest[1]);
  tmp[2] = byte_swap_64 (digest[2]);
  tmp[3] = byte_swap_64 (digest[3]);
  tmp[4] = byte_swap_64 (digest[4]);
  tmp[5] = byte_swap_64 (digest[5]);
  tmp[6] = byte_swap_64 (digest[6]);
  tmp[7] = byte_swap_64 (digest[7]);

  char hash_enc[256];

  memset (hash_enc, 0, sizeof (hash_enc));

  base64_encode (int_to_base64, (const u8 *) tmp, 64, (u8 *) hash_enc);

  // output

  const int line_len = snprintf (line_buf, line_size, "%s%u$%s$%s", SIGNATURE_OFFICE2016_SHEETPROTECTION, spinCount, (const char *) office2016->salt_buf, hash_enc);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
