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
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FRAMEWORK;
static const char *HASH_NAME      = "Web2py pbkdf2-sha512";
static const char *HASH_RECIPE    = "pbkdf2_sha512(pass, salt, iter, 20)";
static const u64   KERN_TYPE      = 40050;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "pbkdf2(1000,20,sha512)$744943$c5f8cdef76e3327c908d8d96d4abdb3d8caba14c";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

static const char *SIGNATURE_WEB2PY_START = "pbkdf2";
static const char *SIGNATURE_WEB2PY_STOP  = "20,sha512)";

typedef struct web2py_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} web2py_sha512_tmp_t;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "AMD Radeon", 10) == 0)
      {
        // AMD Radeon Pro W5700X, Metal.Version.: 261.13, compiler hangs
        return true;
      }
    }
  }

  return false;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (web2py_sha512_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 2;
  token.signatures_buf[0] = SIGNATURE_WEB2PY_START;
  token.signatures_buf[1] = SIGNATURE_WEB2PY_STOP;

  token.sep[0]     = '(';
  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = ',';
  token.len_min[1] = 1;
  token.len_max[1] = 8;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 10;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[3]     = '$';
  token.len_min[3] = SALT_MIN;
  token.len_max[3] = SALT_MAX;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len[4]     = 40;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[3];
  const int salt_len = token.len[3];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  const u32 iter = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // hash

  hex_decode (token.buf[4], 40, (u8 *) digest);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf ((char *) out_buf, line_size, "%s(%d,%s$", SIGNATURE_WEB2PY_START, salt->salt_iter + 1, SIGNATURE_WEB2PY_STOP);

  out_len += generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, out_buf + out_len);

  out_buf[out_len] = '$';

  out_len += 1;

  u64 tmp[3];

  tmp[0] = byte_swap_64 (digest[0]);
  tmp[1] = byte_swap_64 (digest[1]);
  tmp[2] = byte_swap_64 (digest[2]);

  out_len += hex_encode ((const u8 *) tmp, 20, out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
