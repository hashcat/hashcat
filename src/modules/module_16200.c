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
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // originally DGST_SIZE_4_;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "Apple Secure Notes";
static const u64   KERN_TYPE      = 16200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/securenotes2hashcat.pl to extract the hashes";
}

typedef struct apple_secure_notes
{
  u32 Z_PK;
  u32 ZCRYPTOITERATIONCOUNT;
  u32 ZCRYPTOSALT[16];
  u32 ZCRYPTOWRAPPEDKEY[16];

} apple_secure_notes_t;

typedef struct apple_secure_notes_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} apple_secure_notes_tmp_t;

static const char *SIGNATURE_APPLE_SECURE_NOTES = "$ASN$";

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
  const u64 esalt_size = (const u64) sizeof (apple_secure_notes_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (apple_secure_notes_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  apple_secure_notes_t *apple_secure_notes = (apple_secure_notes_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_APPLE_SECURE_NOTES;

  token.sep[0]     = '*';
  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 10;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len[4]     = 48;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * parse line
   */

  // Z_PK

  const u8 *Z_PK_pos = token.buf[1];

  const u32 Z_PK = hc_strtoul ((const char *) Z_PK_pos, NULL, 10);

  apple_secure_notes->Z_PK = Z_PK;

  // ZCRYPTOITERATIONCOUNT

  const u8 *ZCRYPTOITERATIONCOUNT_pos = token.buf[2];

  const u32 ZCRYPTOITERATIONCOUNT = hc_strtoul ((const char *) ZCRYPTOITERATIONCOUNT_pos, NULL, 10);

  apple_secure_notes->ZCRYPTOITERATIONCOUNT = ZCRYPTOITERATIONCOUNT;

  // ZCRYPTOSALT

  const u8 *ZCRYPTOSALT_pos = token.buf[3];

  apple_secure_notes->ZCRYPTOSALT[ 0] = hex_to_u32 (&ZCRYPTOSALT_pos[ 0]);
  apple_secure_notes->ZCRYPTOSALT[ 1] = hex_to_u32 (&ZCRYPTOSALT_pos[ 8]);
  apple_secure_notes->ZCRYPTOSALT[ 2] = hex_to_u32 (&ZCRYPTOSALT_pos[16]);
  apple_secure_notes->ZCRYPTOSALT[ 3] = hex_to_u32 (&ZCRYPTOSALT_pos[24]);
  apple_secure_notes->ZCRYPTOSALT[ 4] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 5] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 6] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 7] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 8] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 9] = 0;
  apple_secure_notes->ZCRYPTOSALT[10] = 0;
  apple_secure_notes->ZCRYPTOSALT[11] = 0;
  apple_secure_notes->ZCRYPTOSALT[12] = 0;
  apple_secure_notes->ZCRYPTOSALT[13] = 0;
  apple_secure_notes->ZCRYPTOSALT[14] = 0;
  apple_secure_notes->ZCRYPTOSALT[15] = 0;

  // ZCRYPTOWRAPPEDKEY

  const u8 *ZCRYPTOWRAPPEDKEY_pos = token.buf[4];

  apple_secure_notes->ZCRYPTOWRAPPEDKEY[0] = hex_to_u32 (&ZCRYPTOWRAPPEDKEY_pos[ 0]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[1] = hex_to_u32 (&ZCRYPTOWRAPPEDKEY_pos[ 8]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[2] = hex_to_u32 (&ZCRYPTOWRAPPEDKEY_pos[16]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[3] = hex_to_u32 (&ZCRYPTOWRAPPEDKEY_pos[24]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[4] = hex_to_u32 (&ZCRYPTOWRAPPEDKEY_pos[32]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[5] = hex_to_u32 (&ZCRYPTOWRAPPEDKEY_pos[40]);

  // fake salt

  salt->salt_buf[0] = apple_secure_notes->ZCRYPTOSALT[0];
  salt->salt_buf[1] = apple_secure_notes->ZCRYPTOSALT[1];
  salt->salt_buf[2] = apple_secure_notes->ZCRYPTOSALT[2];
  salt->salt_buf[3] = apple_secure_notes->ZCRYPTOSALT[3];
  salt->salt_buf[4] = apple_secure_notes->Z_PK;

  if (apple_secure_notes->ZCRYPTOITERATIONCOUNT < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = apple_secure_notes->ZCRYPTOITERATIONCOUNT - 1;
  salt->salt_len  = 20;

  // fake hash

  digest[0] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[0];
  digest[1] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[1];
  digest[2] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[2];
  digest[3] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const apple_secure_notes_t *apple_secure_notes = (const apple_secure_notes_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x",
    SIGNATURE_APPLE_SECURE_NOTES,
    apple_secure_notes->Z_PK,
    apple_secure_notes->ZCRYPTOITERATIONCOUNT,
    byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[0]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[1]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[2]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[3]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[0]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[1]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[2]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[3]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[4]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[5]));

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
  module_ctx->module_usage_notice             = module_usage_notice;
}
