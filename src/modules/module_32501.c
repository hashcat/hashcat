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
static const char *HASH_NAME      = "Dogechain.info Wallet (AES-GCM)";
static const u64   KERN_TYPE      = 32501;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$dogechain$1*5000*bF98K2vULFQ/eh8kqwKU3hST7DYFTMQKvnJrL5iGxTDlLvkKEmo0KrB5qB6YMkGcdet2xHVEcuEUuPiM9r6MIHGsBaQ49oSJX6gucGnlszzFBDpFu5XnOO96s4NMmdwF52n85xG1tHEtRwYMyIOHvOYzxTs3I6WTxbkE0XRCLGlOyVmSQf9EWzw9fAXm6FJ2qD3jpAXIoKGiL3GTrkoJL0SWbccTn+OereIIQIB6ZCirmXYd//eJR1DYomSyzmKTpyZMv3uLzq4QXlYG2muuvjqEd5qnJU5GaNA9qpsdpT+RntKI0w==*qrvM3e4AESIzRFVmd4iZ/w==";

#include "hooks_common.c"

static const char *SIGNATURE_DOGECHAIN_GCM = "$dogechain$1";

typedef struct doge_gcm
{
  u32 iv_buf[4];
  u32 ct_buf[256];
  u32 ct_len;

} doge_gcm_t;

typedef struct doge_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} doge_tmp_t;

static bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: timeout creating the KDF init pipeline, observed on the identical init of -m 32500
        return true;
      }
    }
  }

  return false;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (doge_gcm_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (doge_tmp_t);

  return tmp_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  doge_gcm_t *doge = (doge_gcm_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DOGECHAIN_GCM;

  // sig
  token.sep[0]     = '*';
  token.len_min[0] = 12;
  token.len_max[0] = 12;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // iter
  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 10;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // payload: iv (12) + tag (16) + ct (16..1024)
  token.sep[2]     = '*';
  token.len_min[2] = 60;
  token.len_max[2] = 1404;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // salt
  token.sep[3]     = '*';
  token.len_min[3] = 24;
  token.len_max[3] = 24;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // payload

  const u8 *data_pos = token.buf[2];
  const int data_len = token.len[2];

  u8 tmp_buf[1404] = { 0 };

  int tmp_len = base64_decode (base64_to_int, data_pos, data_len, tmp_buf);

  if (tmp_len < 12 + 16 + 16) return (PARSER_CT_LENGTH);

  const int ct_len = tmp_len - 12 - 16;

  if (ct_len > 1024) return (PARSER_CT_LENGTH);

  // iv

  memcpy ((u8 *) doge->iv_buf, tmp_buf, 12);

  doge->iv_buf[0] = byte_swap_32 (doge->iv_buf[0]);
  doge->iv_buf[1] = byte_swap_32 (doge->iv_buf[1]);
  doge->iv_buf[2] = byte_swap_32 (doge->iv_buf[2]);
  doge->iv_buf[3] = 0;

  // tag

  u32 tag_buf[4] = { 0 };

  memcpy ((u8 *) tag_buf, tmp_buf + 12, 16);

  digest[0] = byte_swap_32 (tag_buf[0]);
  digest[1] = byte_swap_32 (tag_buf[1]);
  digest[2] = byte_swap_32 (tag_buf[2]);
  digest[3] = byte_swap_32 (tag_buf[3]);

  // ct

  memcpy ((u8 *) doge->ct_buf, tmp_buf + 28, ct_len);

  const int ct_w32 = (ct_len + 3) / 4;

  for (int i = 0; i < ct_w32; i++) doge->ct_buf[i] = byte_swap_32 (doge->ct_buf[i]);

  doge->ct_len = ct_len;

  // salt

  const u8 *salt_pos = token.buf[3];
  const int salt_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len != 16) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  // iter

  const u8 *iter_pos = token.buf[1];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const doge_gcm_t *doge = (const doge_gcm_t *) esalt_buf;

  // payload: iv + tag + ct

  u8 payload[12 + 16 + 1024] = { 0 };

  u32 iv_buf[4];

  iv_buf[0] = byte_swap_32 (doge->iv_buf[0]);
  iv_buf[1] = byte_swap_32 (doge->iv_buf[1]);
  iv_buf[2] = byte_swap_32 (doge->iv_buf[2]);
  iv_buf[3] = 0;

  memcpy (payload, iv_buf, 12);

  u32 tag_buf[4];

  tag_buf[0] = byte_swap_32 (digest[0]);
  tag_buf[1] = byte_swap_32 (digest[1]);
  tag_buf[2] = byte_swap_32 (digest[2]);
  tag_buf[3] = byte_swap_32 (digest[3]);

  memcpy (payload + 12, tag_buf, 16);

  for (int i = 0; i < 256; i++)
  {
    payload[28 + i * 4 + 0] = (doge->ct_buf[i] >> 24) & 0xff;
    payload[28 + i * 4 + 1] = (doge->ct_buf[i] >> 16) & 0xff;
    payload[28 + i * 4 + 2] = (doge->ct_buf[i] >>  8) & 0xff;
    payload[28 + i * 4 + 3] = (doge->ct_buf[i] >>  0) & 0xff;
  }

  u8 payload_base64[1404 + 4] = { 0 };

  base64_encode (int_to_base64, payload, 28 + doge->ct_len, payload_base64);

  // salt

  u8 salt_base64[32] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, salt->salt_len, salt_base64);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf ((char *) out_buf, line_size, "%s*%u*%s*%s",
    SIGNATURE_DOGECHAIN_GCM,
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
