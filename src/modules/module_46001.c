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
static const char *HASH_NAME      = "Phantom Wallet (PBKDF2-HMAC-SHA256 + XSalsa20-Poly1305)";
static const u64   KERN_TYPE      = 46001;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ITERATION_OVERRIDE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "PhantomTest1!";
// generated with tools/test_modules/m46001.py
static const char *ST_HASH        = "$phantom$p*10000*Dx4tPEtaaXiHlqW0w9Lh8A==*+Pf29fTz8vHw7+7t7Ovq6ejn5uXk4+Lh*KOgDlXq//jOK4n5cQ2P3+jU2h3IGxnAZY3StYXHN+cZ+4ixroBn0qP6EujCV4FJe";


#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/phantom2hashcat.py to extract the hashes";
}

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct phantom_pbkdf2
{
  u32 salt_buf[16];  // up to 64 bytes
  u32 nonce[6];      // 24 bytes
  u32 box[144];      // secretbox output: tag(16) || ct, up to 576 bytes
  u32 box_len;

} phantom_pbkdf2_t;

static const char *SIGNATURE_PHANTOM_PBKDF2 = "$phantom$p";

#define SALT_LEN_MAX        64
#define SALT_LEN_MAX_BASE64 (((SALT_LEN_MAX * 8) / 6) + 4)
#define NONCE_LEN_BASE64    (((24 * 8) / 6) + 4)
#define BOX_LEN_MAX         576
#define BOX_LEN_MAX_BASE64  (((BOX_LEN_MAX * 8) / 6) + 4)

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
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

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (phantom_pbkdf2_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha256_tmp_t);

  return tmp_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  phantom_pbkdf2_t *ph = (phantom_pbkdf2_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PHANTOM_PBKDF2;

  token.sep[0]     = '*';
  token.len[0]     = 10; // strlen("$phantom$p")
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // iterations
  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 9;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt (16 bytes -> 24 base64 chars, but accept what the vault carries)
  token.sep[2]     = '*';
  token.len_min[2] = 4;
  token.len_max[2] = SALT_LEN_MAX_BASE64;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // nonce (24 bytes -> 32 base64 chars)
  token.sep[3]     = '*';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // box (tag || ct, 48 bytes for a 32-byte secret -> 64 base64 chars)
  token.sep[4]     = '*';
  token.len_min[4] = 24;
  token.len_max[4] = BOX_LEN_MAX_BASE64;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iterations

  const u32 iter = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  u8 tmp[800];

  // salt - raw into salt_t and esalt

  const int salt_len = base64_decode (base64_to_int, token.buf[2], token.len[2], tmp);

  if (salt_len < 1 || salt_len > SALT_LEN_MAX) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp, salt_len);

  salt->salt_len = salt_len;

  memcpy ((u8 *) ph->salt_buf, tmp, salt_len);

  // nonce (24 bytes) - raw; comp's xsalsa20 reads it as a byte string

  const int nonce_len = base64_decode (base64_to_int, token.buf[3], token.len[3], tmp);

  if (nonce_len != 24) return (PARSER_IV_LENGTH);

  memcpy ((u8 *) ph->nonce, tmp, nonce_len);

  // box: tag(16) || ct, the way NaCl secretbox lays it out; the tag rides in
  // the digest, LE-packed (same convention as the computed MAC in comp)

  const int box_len = base64_decode (base64_to_int, token.buf[4], token.len[4], tmp);

  if (box_len < 22 || box_len > BOX_LEN_MAX) return (PARSER_CT_LENGTH);

  memcpy ((u8 *) ph->box, tmp, box_len);

  ph->box_len = box_len;

  digest[0] = (u32) tmp[0]  | ((u32) tmp[1]  << 8) | ((u32) tmp[2]  << 16) | ((u32) tmp[3]  << 24);
  digest[1] = (u32) tmp[4]  | ((u32) tmp[5]  << 8) | ((u32) tmp[6]  << 16) | ((u32) tmp[7]  << 24);
  digest[2] = (u32) tmp[8]  | ((u32) tmp[9]  << 8) | ((u32) tmp[10] << 16) | ((u32) tmp[11] << 24);
  digest[3] = (u32) tmp[12] | ((u32) tmp[13] << 8) | ((u32) tmp[14] << 16) | ((u32) tmp[15] << 24);

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const phantom_pbkdf2_t *ph = (const phantom_pbkdf2_t *) esalt_buf;

  u8 salt_buf[SALT_LEN_MAX_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, (const int) salt->salt_len, salt_buf);

  u8 nonce_buf[NONCE_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) ph->nonce, 24, nonce_buf);

  u8 box_buf[BOX_LEN_MAX_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) ph->box, (const int) ph->box_len, box_buf);

  return snprintf (line_buf, line_size, "%s*%u*%s*%s*%s",
    SIGNATURE_PHANTOM_PBKDF2,
    salt->salt_iter + 1,
    salt_buf,
    nonce_buf,
    box_buf);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
