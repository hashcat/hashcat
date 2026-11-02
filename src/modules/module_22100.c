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
#include "emu_inc_hash_sha256.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "BitLocker";
static const u64   KERN_TYPE      = 22100;
static const u32   OPTI_TYPE      = OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/bitlocker2hashcat.py to extract the hashes";
}

#define ITERATION_BITLOCKER 0x100000
#define SALT_LEN_BITLOCKER  16
#define IV_LEN_BITLOCKER    12
#define DATA_LEN_BITLOCKER  60

typedef struct bitlocker
{
  u32 type;
  u32 iv[4];
  u32 data[15];
  u32 wb_ke_pc[ITERATION_BITLOCKER][48];

} bitlocker_t;

typedef struct bitlocker_tmp
{
  u32 last_hash[8];
  u32 init_hash[8];

} bitlocker_tmp_t;

static const char *SIGNATURE_BITLOCKER = "$bitlocker$";

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

  // AMD-GPU-PRO
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == false))
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
  const u64 esalt_size = (const u64) sizeof (bitlocker_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bitlocker_tmp_t);

  return tmp_size;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 1024;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 1024;

  return kernel_loops_max;
}

u32 module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_max = 512;

  return kernel_threads_max;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // https://docs.microsoft.com/en-us/windows/security/information-protection/bitlocker/bitlocker-group-policy-settings
  // The startup PIN must have a minimum length of 4 digits, and it can have a maximum length of 20 digits. By default, the minimum PIN length is 6.

  const u32 pw_min = 6;

  return pw_min;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  bitlocker_t *bitlocker = (bitlocker_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 9;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BITLOCKER;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 2;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len[4]     = 7;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len[5]     = 2;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '$';
  token.len[6]     = 24;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '$';
  token.len[7]     = 2;
  token.attr[7]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]     = '$';
  token.len[8]     = 120;
  token.attr[8]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type

  const u8 *type_pos = token.buf[1];

  const u32 type = hc_strtoul ((const char *) type_pos, NULL, 10);

  if ((type != 0) && (type != 1)) return PARSER_SALT_VALUE;

  bitlocker->type = type;

  // salt

  const u8 *salt_len_pos = token.buf[2];

  const u32 salt_len = hc_strtoul ((const char *) salt_len_pos, NULL, 10);

  if (salt_len != SALT_LEN_BITLOCKER) return PARSER_SALT_LENGTH;

  const u8 *salt_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  salt->salt_len = SALT_LEN_BITLOCKER;

  // wb_ke_pc

  for (int i = 0; i < ITERATION_BITLOCKER; i++)
  {
    u32 tmp[64];

    tmp[ 0] = salt->salt_buf[0];
    tmp[ 1] = salt->salt_buf[1];
    tmp[ 2] = salt->salt_buf[2];
    tmp[ 3] = salt->salt_buf[3];
    tmp[ 4] = byte_swap_32 (i);
    tmp[ 5] = 0;
    tmp[ 6] = 0x80000000;
    tmp[ 7] = 0;
    tmp[ 8] = 0;
    tmp[ 9] = 0;
    tmp[10] = 0;
    tmp[11] = 0;
    tmp[12] = 0;
    tmp[13] = 0;
    tmp[14] = 0;
    tmp[15] = 88 * 8;

    #define hc_rotl32_S rotl32

    for (int j = 16; j < 64; j++)
    {
      tmp[j] = SHA256_EXPAND_S (tmp[j - 2], tmp[j - 7], tmp[j - 15], tmp[j - 16]);
    }

    for (int j = 0; j < 48; j++)
    {
      bitlocker->wb_ke_pc[i][j] = tmp[16 + j];
    }
  }

  // iter

  const u8 *iter_pos = token.buf[4];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter != ITERATION_BITLOCKER) return PARSER_SALT_VALUE;

  salt->salt_iter = ITERATION_BITLOCKER;

  // IV (nonce)

  const u8 *iv_len_pos = token.buf[5]; // aka nonce_len

  const u32 iv_len = hc_strtoul ((const char *) iv_len_pos, NULL, 10);

  if (iv_len != IV_LEN_BITLOCKER) return PARSER_SALT_LENGTH;

  const u8 *iv_pos = token.buf[6];

  u32 iv[4] = { 0 };

  iv[0] = hex_to_u32 (iv_pos +  0);
  iv[1] = hex_to_u32 (iv_pos +  8);
  iv[2] = hex_to_u32 (iv_pos + 16);

  iv[0] = byte_swap_32 (iv[0]);
  iv[1] = byte_swap_32 (iv[1]);
  iv[2] = byte_swap_32 (iv[2]);

  // prefix 0x02 and shift-right by 1 byte:

  iv[3] = (iv[2] << 24) | 0x01;         // 0x01 because we start with the VMK (skip MAC)
  iv[2] = (iv[1] << 24) | (iv[2] >> 8);
  iv[1] = (iv[0] << 24) | (iv[1] >> 8);
  iv[0] = (0x02  << 24) | (iv[0] >> 8); // 15 - strlen (iv) - 1 = 14 - 12 = 0x02

  bitlocker->iv[0] = iv[0];
  bitlocker->iv[1] = iv[1];
  bitlocker->iv[2] = iv[2];
  bitlocker->iv[3] = iv[3];

  // data and digest:

  const u8 *data_len_pos = token.buf[7];

  const u32 data_len = hc_strtoul ((const char *) data_len_pos, NULL, 10);

  if (data_len != DATA_LEN_BITLOCKER) return PARSER_SALT_LENGTH;

  const u8 *data_pos = token.buf[8];

  for (u32 i = 0, j = 0; i < DATA_LEN_BITLOCKER / 4; i += 1, j += 8)
  {
    bitlocker->data[i] = hex_to_u32 (data_pos + j);

    bitlocker->data[i] = byte_swap_32 (bitlocker->data[i]);
  }

  // fake digest:

  memcpy (digest, bitlocker->data, 16);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const bitlocker_t *bitlocker = (const bitlocker_t *) esalt_buf;

  // type

  u32 type = bitlocker->type;

  // salt

  #define SALT_HEX_LEN SALT_LEN_BITLOCKER * 2 + 1

  char salt_buf[SALT_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < SALT_LEN_BITLOCKER / 4; i += 1, j += 8)
  {
    snprintf (salt_buf + j, SALT_HEX_LEN - j, "%08x", salt->salt_buf[i]);
  }

  // iv

  u32 iv[4] = { 0 };

  iv[0] = bitlocker->iv[0];
  iv[1] = bitlocker->iv[1];
  iv[2] = bitlocker->iv[2];
  iv[3] = bitlocker->iv[3];

  // remove 0x02 from start (left-shift by 1 byte):

  iv[0] = (iv[0] << 8) | (iv[1] >> 24);
  iv[1] = (iv[1] << 8) | (iv[2] >> 24);
  iv[2] = (iv[2] << 8) | (iv[3] >> 24);
  iv[3] = 0;

  #define IV_HEX_LEN IV_LEN_BITLOCKER * 2 + 1

  char iv_buf[IV_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < IV_LEN_BITLOCKER / 4; i += 1, j += 8)
  {
    snprintf (iv_buf + j, IV_HEX_LEN - j, "%08x", iv[i]);
  }

  // data

  #define DATA_HEX_LEN DATA_LEN_BITLOCKER * 2 + 1

  char data_buf[DATA_HEX_LEN] = { 0 };

  for (u32 i = 0, j = 0; i < DATA_LEN_BITLOCKER / 4; i += 1, j += 8)
  {
    snprintf (data_buf + j, DATA_HEX_LEN - j, "%08x", bitlocker->data[i]);
  }

  // output

  int line_len = snprintf (line_buf, line_size, "$bitlocker$%i$%i$%s$%i$%i$%s$%i$%s",
    type,
    SALT_LEN_BITLOCKER,
    salt_buf,
    ITERATION_BITLOCKER,
    IV_LEN_BITLOCKER,
    iv_buf,
    DATA_LEN_BITLOCKER,
    data_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = module_kernel_threads_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
