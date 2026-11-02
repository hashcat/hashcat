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
static const char *HASH_NAME      = "Terra Station Wallet (AES256-CBC(PBKDF2($pass)))";
static const u64   KERN_TYPE      = 29600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "67445496c838e96c1424a8dae4b146f0fc247c8c34ef33feffeb1e4412018512wZGtBMeN84XZE2LoOKwTGvA4Ee4m7PR1lDGIdWUV6OSUZKRiKFx9tlrnZLt8r8OfOzbwUS2a2Uo+nrrP6F85fh4eHstwPJw0KwzHWB8br58=";

#include "hooks_common.c"

static const u32 ROUNDS_PBKDF_SHA_TERRA = 100;

typedef struct pbkdf_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf_sha1_tmp_t;

typedef struct terra
{
  u32 salt_buf[8];
  u32 ct[16]; // 16 * 4 = 64 bytes (we have extra 16 bytes in digest: 64 + 16 = 80)
  u32 iv[4];

} terra_t;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm29600_init' pipeline, timeout reached
        return true;
      }
    }
  }

  return false;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (terra_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf_sha1_tmp_t);

  return tmp_size;
}

u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_min = 16;

  return salt_min;
}

u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_max = 16;

  return salt_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  terra_t *terra = (terra_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  // salt
  token.len[0]  = 32;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  // iv
  token.len[1]  = 32;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  // ciphertext
  token.len[2]  = 108;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt
  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  // Populating salt buf even though it's unused - we use esalt below
  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // Set the loop rounds - 1 round is done in the init function
  salt->salt_iter = ROUNDS_PBKDF_SHA_TERRA - 1;

  // Unhex the salt into the esalt buffer
  if (salt_len != 32) return (PARSER_HASH_LENGTH);

  terra->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  terra->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  terra->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  terra->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  // store IV
  const u8 *iv_pos = token.buf[1];
  const int iv_len = token.len[1];

  if (iv_len != 32) return (PARSER_SALT_LENGTH);

  terra->iv[0] = hex_to_u32 (iv_pos +  0);
  terra->iv[1] = hex_to_u32 (iv_pos +  8);
  terra->iv[2] = hex_to_u32 (iv_pos + 16);
  terra->iv[3] = hex_to_u32 (iv_pos + 24);

  // Base64 decode the ciphertext
  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  u8  tmp_buf[512];
  int tmp_len;

  tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len != 0x50) return (PARSER_HASH_LENGTH);

  u32 *whole_digest = (u32 *) tmp_buf;

  // Penultimate block, i.e. IV, xored with a whole padding block
  terra->ct[0] = byte_swap_32 (whole_digest[0xc] ^ 0x10101010);
  terra->ct[1] = byte_swap_32 (whole_digest[0xd] ^ 0x10101010);
  terra->ct[2] = byte_swap_32 (whole_digest[0xe] ^ 0x10101010);
  terra->ct[3] = byte_swap_32 (whole_digest[0xf] ^ 0x10101010);

  for (int i = 4; i < 16; i++)
  {
    terra->ct[i] = whole_digest[i - 4];
  }

  // Last block
  digest[0] = byte_swap_32 (whole_digest[0x10]);
  digest[1] = byte_swap_32 (whole_digest[0x11]);
  digest[2] = byte_swap_32 (whole_digest[0x12]);
  digest[3] = byte_swap_32 (whole_digest[0x13]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const terra_t *terra = (const terra_t *) esalt_buf;

  // salt:

  char salt_hex[32 + 1] = { 0 };

  hex_encode ((const u8 *) terra->salt_buf, 16, (u8 *) salt_hex); // or use: generic_salt_encode ()

  salt_hex[32] = 0;

  // iv:

  char iv_hex[32 + 1] = { 0 };

  hex_encode ((const u8 *) terra->iv, 16, (u8 *) iv_hex);

  iv_hex[32] = 0;

  // data:

  u32 data[16 + 4] = { 0 }; // total: 80 bytes

  for (int i = 4; i < 16; i++)
  {
    data[i - 4] = terra->ct[i];
  }

  data[0xc] = byte_swap_32 (terra->ct[0] ^ 0x10101010);
  data[0xd] = byte_swap_32 (terra->ct[1] ^ 0x10101010);
  data[0xe] = byte_swap_32 (terra->ct[2] ^ 0x10101010);
  data[0xf] = byte_swap_32 (terra->ct[3] ^ 0x10101010);

  data[ 16] = byte_swap_32 (digest[0]);
  data[ 17] = byte_swap_32 (digest[1]);
  data[ 18] = byte_swap_32 (digest[2]);
  data[ 19] = byte_swap_32 (digest[3]);

  char data_b64[108 + 1] = { 0 };

  base64_encode (int_to_base64, (u8 *) data, 80, (u8 *) data_b64);

  data_b64[108] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s%s%s", salt_hex, iv_hex, data_b64);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
