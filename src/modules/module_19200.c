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
#include "emu_inc_hash_sha512.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "QNX /etc/shadow (SHA512)";
static const u64   KERN_TYPE      = 19200;
static const bool  LENGTH_SORT    = true;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159";

#include "hooks_common.c"

bool        module_length_sort    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return LENGTH_SORT;     }

typedef struct qnx_sha512_tmp
{
  sha512_ctx_t sha512_ctx;

  u32 sav; // to trigger sha512 bug

} qnx_sha512_tmp_t;

static const int ROUNDS_QNX = 1000;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_INTEL_SDK) && (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU))
  {
    if (strncmp (device_param->device_name, "AMD EPYC", 8) == 0)
    {
      // works on Linux: AMD EPYC 7642 48-Core Processor, OpenCL 2.1 (Build 0)
      return false;
    }

    return true;
  }

  return false;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (qnx_sha512_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.sep[0]     = '@';
  token.len[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[1]     = '@';
  token.len_min[1] = 1;
  token.len_max[1] = 8;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '@';
  token.len_min[2] = 32;
  token.len_max[2] = 128;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '@';
  token.len_min[3] = 8;
  token.len_max[3] = 16;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // check hash type

  if (token.buf[1][0] != 'S') return (PARSER_SIGNATURE_UNMATCHED);

  // check iter

  u32 iter = ROUNDS_QNX;

  if (token.len[1] > 1)
  {
    if (token.buf[1][1] != ',') return (PARSER_SEPARATOR_UNMATCHED);

    iter = hc_strtoul ((const char *) token.buf[1] + 2, NULL, 10);
  }

  // iter++; the additional round is added in the init kernel

  salt->salt_iter = iter;

  // digest

  if (token.len[2] != 128) return (PARSER_HASH_LENGTH);

  digest[0] = hex_to_u64 (token.buf[2] +   0);
  digest[1] = hex_to_u64 (token.buf[2] +  16);
  digest[2] = hex_to_u64 (token.buf[2] +  32);
  digest[3] = hex_to_u64 (token.buf[2] +  48);
  digest[4] = hex_to_u64 (token.buf[2] +  64);
  digest[5] = hex_to_u64 (token.buf[2] +  80);
  digest[6] = hex_to_u64 (token.buf[2] +  96);
  digest[7] = hex_to_u64 (token.buf[2] + 112);

  // salt

  if ((token.len[3] == 8) || (token.len[3] == 16))
  {
    memcpy (salt->salt_buf, token.buf[3], token.len[3]);

    salt->salt_len = token.len[3];
  }
  else
  {
    return (PARSER_SALT_LENGTH);
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  int line_len = 0;

  const int iter = salt->salt_iter;

  if (iter == ROUNDS_QNX)
  {
    line_buf[line_len++] = '@';
    line_buf[line_len++] = 'S';
    line_buf[line_len++] = '@';
  }
  else
  {
    line_buf[line_len++] = '@';
    line_buf[line_len++] = 'S';
    line_buf[line_len++] = ',';

    line_len += snprintf (line_buf + line_len, line_size - line_len, "%d", iter);

    line_buf[line_len++] = '@';
  }

  u64_to_hex (digest[0], (u8 *) line_buf + line_len); line_len += 16;
  u64_to_hex (digest[1], (u8 *) line_buf + line_len); line_len += 16;
  u64_to_hex (digest[2], (u8 *) line_buf + line_len); line_len += 16;
  u64_to_hex (digest[3], (u8 *) line_buf + line_len); line_len += 16;
  u64_to_hex (digest[4], (u8 *) line_buf + line_len); line_len += 16;
  u64_to_hex (digest[5], (u8 *) line_buf + line_len); line_len += 16;
  u64_to_hex (digest[6], (u8 *) line_buf + line_len); line_len += 16;
  u64_to_hex (digest[7], (u8 *) line_buf + line_len); line_len += 16;

  line_buf[line_len++] = '@';

  memcpy (line_buf + line_len, salt->salt_buf, salt->salt_len);

  line_len += salt->salt_len;

  line_buf[line_len] = 0;

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_length_sort              = module_length_sort;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
