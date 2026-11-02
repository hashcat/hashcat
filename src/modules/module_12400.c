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
#include "emu_inc_cipher_des.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "BSDi Crypt, Extended DES";
static const u64   KERN_TYPE      = 12400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MAXIMUM_THREADS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "_GW..8841inaTltazRsQ";

#include "hooks_common.c"

typedef struct bsdicrypt_tmp
{
  u32 Kc[16];
  u32 Kd[16];

  u32 iv[2];

} bsdicrypt_tmp_t;

static const char *SIGNATURE_BSDICRYPT = "_";

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

  return jit_build_options;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bsdicrypt_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BSDICRYPT;

  token.len[0]     = 1;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 4;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  token.len[2]     = 4;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  token.len[3]     = 11;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iteration count

  const u8 *iter_pos = token.buf[1];

  salt->salt_iter = itoa64_to_int (iter_pos[0])
                  | itoa64_to_int (iter_pos[1]) <<  6
                  | itoa64_to_int (iter_pos[2]) << 12
                  | itoa64_to_int (iter_pos[3]) << 18;

  // set salt

  const u8 *salt_pos = token.buf[2];

  salt->salt_buf[0] = itoa64_to_int (salt_pos[0])
                    | itoa64_to_int (salt_pos[1]) <<  6
                    | itoa64_to_int (salt_pos[2]) << 12
                    | itoa64_to_int (salt_pos[3]) << 18;

  salt->salt_len = 4;

  // hash

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  unsigned char c19 = itoa64_to_int (hash_pos[10]);

  if (c19 & 3) return (PARSER_HASH_VALUE);

  u8 tmp_buf[100] = { 0 };

  base64_decode (itoa64_to_int, hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 8);

  DES_IP (digest[0], digest[1]);

  digest[0] = rotr32 (digest[0], 31);
  digest[1] = rotr32 (digest[1], 31);
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // encode iteration count

  char salt_iter[5];

  salt_iter[0] = int_to_itoa64 ((salt->salt_iter      ) & 0x3f);
  salt_iter[1] = int_to_itoa64 ((salt->salt_iter >>  6) & 0x3f);
  salt_iter[2] = int_to_itoa64 ((salt->salt_iter >> 12) & 0x3f);
  salt_iter[3] = int_to_itoa64 ((salt->salt_iter >> 18) & 0x3f);
  salt_iter[4] = 0;

  // encode salt

  char ptr_salt[5];

  ptr_salt[0] = int_to_itoa64 ((salt->salt_buf[0]      ) & 0x3f);
  ptr_salt[1] = int_to_itoa64 ((salt->salt_buf[0] >>  6) & 0x3f);
  ptr_salt[2] = int_to_itoa64 ((salt->salt_buf[0] >> 12) & 0x3f);
  ptr_salt[3] = int_to_itoa64 ((salt->salt_buf[0] >> 18) & 0x3f);
  ptr_salt[4] = 0;

  // encode digest

  u32 tmp[2];

  tmp[0] = rotl32 (digest[0], 31);
  tmp[1] = rotl32 (digest[1], 31);

  DES_FP (tmp[1], tmp[0]);

  char ptr_plain[12];

  base64_encode (int_to_itoa64, (const u8 *) tmp, 8, (u8 *) ptr_plain);

  ptr_plain[11] = 0;

  // fill the resulting buffer

  const int line_len = snprintf (line_buf, line_size, "_%s%s%s", salt_iter, ptr_salt, ptr_plain);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
