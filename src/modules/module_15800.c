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
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "xchain-crypto Keystore (THORChain, THORSwap)";
static const u64   KERN_TYPE      = 15800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$xchain$*1024*000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f*3ce156b0a3960af99263a7ab09f420f6d556427b905edee06ce4563ea049d39ef11eaac4f3420dc6f7a367751cd69a19fe9337bf6181457a00ec238f1d0f0a2838f8b584513738a82e071e*97ac65d0d9fc3ec6c4895c00fbb4920af4b936a1b338af33eed30ff15b3b1d52";

#include "hooks_common.c"

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

// The payload is the wallet's BIP39 recovery phrase, so its length follows the phrase. 24 of the
// longest words with their separators come to 215 bytes, which is what the cap allows for.

#define XCHAIN_CT_MAX 256

typedef struct xchain
{
  u32 salt_buf[16];

  u32 ciphertext[XCHAIN_CT_MAX / 4];
  u32 ciphertext_len;

} xchain_t;

static const char *SIGNATURE_XCHAIN = "$xchain$";

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
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

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (xchain_t);

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

  xchain_t *xchain = (xchain_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_XCHAIN;

  token.sep[0]     = '*';
  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 0;
  token.len_max[2] = 64;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 2;
  token.len_max[3] = XCHAIN_CT_MAX * 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len[4]     = 64;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  xchain->salt_buf[0] = salt->salt_buf[0];
  xchain->salt_buf[1] = salt->salt_buf[1];
  xchain->salt_buf[2] = salt->salt_buf[2];
  xchain->salt_buf[3] = salt->salt_buf[3];
  xchain->salt_buf[4] = salt->salt_buf[4];
  xchain->salt_buf[5] = salt->salt_buf[5];
  xchain->salt_buf[6] = salt->salt_buf[6];
  xchain->salt_buf[7] = salt->salt_buf[7];

  // ciphertext

  const u8 *ciphertext_pos = token.buf[3];
  const int ciphertext_len = token.len[3];

  if ((ciphertext_len % 2) != 0) return (PARSER_CT_LENGTH);

  xchain->ciphertext_len = ciphertext_len / 2;

  u8 *ciphertext_ptr = (u8 *) xchain->ciphertext;

  for (int i = 0, j = 0; j < ciphertext_len; i += 1, j += 2)
  {
    ciphertext_ptr[i] = hex_to_u8 (&ciphertext_pos[j]);
  }

  // hash

  const u8 *hash_pos = token.buf[4];

  digest[0] = hex_to_u32 (&hash_pos[ 0]);
  digest[1] = hex_to_u32 (&hash_pos[ 8]);
  digest[2] = hex_to_u32 (&hash_pos[16]);
  digest[3] = hex_to_u32 (&hash_pos[24]);
  digest[4] = hex_to_u32 (&hash_pos[32]);
  digest[5] = hex_to_u32 (&hash_pos[40]);
  digest[6] = hex_to_u32 (&hash_pos[48]);
  digest[7] = hex_to_u32 (&hash_pos[56]);

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const xchain_t *xchain = (const xchain_t *) esalt_buf;

  char *tmp_salt = (char *) hcmalloc ((salt->salt_len * 2) + 1);

  const int salt_len = generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, (u8 *) tmp_salt);

  tmp_salt[salt_len] = 0;

  const u32 ciphertext_len = xchain->ciphertext_len;

  const u8 *ciphertext_ptr = (const u8 *) xchain->ciphertext;

  char tmp_ciphertext[(XCHAIN_CT_MAX * 2) + 1];

  for (u32 i = 0; i < ciphertext_len; i++)
  {
    u8_to_hex (ciphertext_ptr[i], (u8 *) &tmp_ciphertext[i * 2]);
  }

  tmp_ciphertext[ciphertext_len * 2] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s*%u*%s*%s*%08x%08x%08x%08x%08x%08x%08x%08x",
    SIGNATURE_XCHAIN,
    salt->salt_iter + 1,
    tmp_salt,
    tmp_ciphertext,
    byte_swap_32 (digest[0]),
    byte_swap_32 (digest[1]),
    byte_swap_32 (digest[2]),
    byte_swap_32 (digest[3]),
    byte_swap_32 (digest[4]),
    byte_swap_32 (digest[5]),
    byte_swap_32 (digest[6]),
    byte_swap_32 (digest[7])
  );

  hcfree (tmp_salt);

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
}
