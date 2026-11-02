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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Blockchain, My Wallet, Second Password (SHA256)";
static const char *HASH_RECIPE    = "h = sha256_bin(salt . pass); for i = 1 to iter { h = sha256_bin(h) }; hex(h)";
static const u64   KERN_TYPE      = 40040;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "YnM6WYERjJfhxwepT7zV6odWoEUz1X4esYQb4bQ3KZ7bbZAyOTc1MDM3OTc1NjMyODA0ECcAAD3vFoc=";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

typedef struct bsp_tmp
{
  u32 hash[8];

} bsp_tmp_t;

typedef struct bsp
{
  char signature[3];
  u32  digest[8];
  u32  salt[4];
  u32  iter;
  u32  crc32;

} bsp_t;

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // Intel CPU
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) && (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
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

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bsp_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (bsp_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  bsp_t *bsp = (bsp_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 1;

  token.len[0]     = 80;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8 tmp_buf[64];

  const int tmp_len = base64_decode (base64_to_int, token.buf[0], token.len[0], (u8 *) tmp_buf);

  if (tmp_len != 59) return (PARSER_HASH_LENGTH);

  memcpy ((char *) &bsp->signature, tmp_buf  +  0,  3);
  memcpy ((char *) &bsp->digest,    tmp_buf  +  3, 32);
  memcpy ((char *) &bsp->salt,      tmp_buf  + 35, 16);
  memcpy ((char *) &bsp->iter,      tmp_buf  + 51,  4);
  memcpy ((char *) &bsp->crc32,     tmp_buf  + 55,  4);

  // version

  if (bsp->signature[0] != 'b') return (PARSER_SIGNATURE_UNMATCHED);
  if (bsp->signature[1] != 's') return (PARSER_SIGNATURE_UNMATCHED);
  if (bsp->signature[2] != ':') return (PARSER_SIGNATURE_UNMATCHED);

  // digest

  digest[0] = byte_swap_32 (bsp->digest[0]);
  digest[1] = byte_swap_32 (bsp->digest[1]);
  digest[2] = byte_swap_32 (bsp->digest[2]);
  digest[3] = byte_swap_32 (bsp->digest[3]);

  // salt

  const u8 *ptr = (const u8 *) bsp->salt;

  u8 *uuid = (u8 *) salt->salt_buf;

  int uuid_len = 0;

  u8_to_hex (ptr[ 0], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[ 1], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[ 2], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[ 3], uuid + uuid_len); uuid_len += 2;

  uuid[uuid_len] = '-'; uuid_len += 1;

  u8_to_hex (ptr[ 4], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[ 5], uuid + uuid_len); uuid_len += 2;

  uuid[uuid_len] = '-'; uuid_len += 1;

  u8_to_hex (ptr[ 6], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[ 7], uuid + uuid_len); uuid_len += 2;

  uuid[uuid_len] = '-'; uuid_len += 1;

  u8_to_hex (ptr[ 8], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[ 9], uuid + uuid_len); uuid_len += 2;

  uuid[uuid_len] = '-'; uuid_len += 1;

  u8_to_hex (ptr[10], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[11], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[12], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[13], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[14], uuid + uuid_len); uuid_len += 2;
  u8_to_hex (ptr[15], uuid + uuid_len); uuid_len += 2;

  uuid[uuid_len] = 0;

  salt->salt_len = 36;

  if (bsp->iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = bsp->iter - 1;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const bsp_t *bsp = (const bsp_t *) esalt_buf;

  u8 tmp_buf[64];

  memcpy (tmp_buf +  0, &bsp->signature,  3);
  memcpy (tmp_buf +  3, &bsp->digest,    32);
  memcpy (tmp_buf + 35, &bsp->salt,      16);
  memcpy (tmp_buf + 51, &bsp->iter,       4);
  memcpy (tmp_buf + 55, &bsp->crc32,      4);

  return base64_encode (int_to_base64, (const u8 *) tmp_buf, 59, (u8 *) line_buf);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
