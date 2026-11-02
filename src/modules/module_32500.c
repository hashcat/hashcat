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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Dogechain.info Wallet";
static const u64   KERN_TYPE      = 32500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$dogechain$0*5000*EEmAkgiMlVrToRhu2suq91R5Frf+VQCvNzv9lj6OwRWIf/3IM31wqhJM7gGQpinXH9kqHkuQ2DMZxspgA7QFAddsUWvZxGdNAkaeKy90EAsTLIuDQnH3plfBQfmL6j5NPaH7Nr7kF1PdvM0pbUw6XHySBYkD/rPHNM6n58NRK4xfO4VVMykeX3+m2LaVyv5s269r/op38svRPT0YFGpRcanY6/U1BeSrvG2IXii1BKXXAcVEN4GFmyEQRWKI0uZE+3M0atf7UEPD4K9tmEKosqdsF4MFLiBtfI4eq0+926ijoezDmUPvHIiyQZ9CH2jZ*6jOgqW/GxL9He1afQiINIg==";

#include "hooks_common.c"

static const char *SIGNATURE_DOGECHAIN = "$dogechain$0";

typedef struct payload
{
  u32 pl_buf[64];
  u32 pl_len;

} payload_t;

typedef struct doge_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} doge_tmp_t;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm32500_init' pipeline, timeout reached
        return true;
      }
    }
  }

  return false;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (payload_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (doge_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  payload_t *payload = (payload_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DOGECHAIN;

  // sig
  token.sep[0]     = '*';
  token.len_min[0] = 12;
  token.len_max[0] = 12;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH //VERIFY NOT FIXED
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // iter
  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 10;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // payload
  token.sep[2]     = '*';
  token.len_min[2] = 320;
  token.len_max[2] = 320;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A; //verify is b64

  // salt
  token.sep[3]     = '*';
  token.len_min[3] = 24;
  token.len_max[3] = 24;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A; //verify is b64

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // Our parsing

  // esalt for payload

  const u8 *data_pos = token.buf[2];
  const int data_len = token.len[2];

  u8 tmp_buf[256]  = { 0 };

  int tmp_len = base64_decode (base64_to_int, data_pos, data_len, tmp_buf);

  memcpy (payload->pl_buf, tmp_buf, tmp_len);

  payload->pl_len = tmp_len;

  // salt

  const u8 *salt_pos = token.buf[3];
  const int salt_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  // iter

  const u8 *iter_pos = token.buf[1];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // digest

  digest[0] = 0;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  //const u32 *digest = (const u32 *) digest_buf;

  const payload_t *payload = (const payload_t *) esalt_buf;

  // payload

  u8 payload_base64[512] = { 0 };

  base64_encode (int_to_base64, (const u8 *) payload->pl_buf, payload->pl_len, payload_base64);

  // salt

  u8 salt_base64[32] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, salt->salt_len, salt_base64);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf ((char *) out_buf, line_size, "%s*%u*%s*%s",
    SIGNATURE_DOGECHAIN,
    salt->salt_iter + 1,
    payload_base64,
    salt_base64);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
