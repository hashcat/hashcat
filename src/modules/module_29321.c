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
#include "path.h"
#include "parser.h"
#include "memory.h"
#include "cpu_crc32.h"
#include "keyboard_layout.h"
#include "truecrypt_veracrypt_common.c"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_32;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "TrueCrypt SHA512 + XTS 512 bit";
static const u64   KERN_TYPE      = 6221; // old kernel used here
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP
                                  | OPTI_TYPE_USES_BITS_64;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$truecrypt$5ebff6b4050aaa3374f9946166a9c4134dd3ec0df1176da2fb103909d20e8b3c9b95cbbd6d1a7ad05411a1443ad6254e059e924d78bab6a0463e71cf7c3109b7$ef4e837bf6d7a548dd8333c451b59d1132098f44c6ff19c6cb921b1de3bd0aa675e0478a05f90204d46a5d6ff598bfa40370ac8795928a6d2e0f1347696e3cfa329738170fe54298981d84f40c63d1a338c5db62679338e849124a28a79a8e505bb89a4673f0457b2737a00b908116310281b5b2eb66c6fda5599196b313d51ef26201335d715c18f6b128454a5601671e619bdcce8e54acb47d498c4161614a05063bff5497a4a3d99bff1fce2a163727af2fe9ae7512461b9dcebf3a4f1031d6235d8ce09b734294d0cedc04eafc6295f212b1b080e7b9745580d0dd18e99cfd95afef982762d5aabeaa2d3a928dcf36322cc06b07fd719c88e0b9a2625a94a77502d4bd40a85ba138cbd0cf9561aa395dc552801f68cce16e5484a672aa5b78665dc531ab1e3e728185929dc443b7f4c8a5cb687c6589bb3f4ddc2a8639d959b839b0813d50e7711b761622c3693a92e540e4f932c6c89bf4e1bff1d69151848c3d01b2f6aba52b58e5b393f6cd58ff0d2e040b1205b042b5a28d5b12cb0cc95fa32f1bcdebd4c82d889a5d87c45dcfd34e80b19bf7be35696e0fa0cbd9338b314de24c1ee7bbc0a3b6824f86af2aa5d127d21444985ff566e921431938f6";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return USAGE_NOTICE_TRUECRYPT;
}

#define TC_SALT_LEN     (             64)
#define TC_SALT_HEX_LEN (TC_SALT_LEN * 2)

#define TC_DATA_LEN     (            448)
#define TC_DATA_HEX_LEN (TC_DATA_LEN * 2)

typedef struct tc64_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

} tc64_tmp_t;

typedef struct tc
{
  u32 data_buf[TC_DATA_LEN / 4];
  u32 keyfile_buf16[16];
  u32 keyfile_buf32[32];
  u32 keyfile_enabled;
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

} tc_t;

static const int   ROUNDS_TRUECRYPT_1K         = 1000;
static const float MIN_SUFFICIENT_ENTROPY_FILE = 7.0f;
static const char *SIGNATURE_TRUECRYPT         = "$truecrypt$";

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    // self-test failed
    if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
    {
      return true;
    }
  }

  return false;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (tc_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (tc64_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is selected
  // IOW, even in optimized kernel mode it support length 64

  const u32 pw_max = 64;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  tc_t *tc = (tc_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_TRUECRYPT;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = TC_SALT_HEX_LEN;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len[2]     = TC_DATA_HEX_LEN;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];

  salt->salt_len = hex_decode (salt_pos, TC_SALT_HEX_LEN, (u8 *) salt->salt_buf);

  // iter

  salt->salt_iter = ROUNDS_TRUECRYPT_1K - 1;

  // data

  const u8 *data_pos = token.buf[2];

  hex_decode (data_pos, TC_DATA_HEX_LEN, (u8 *) tc->data_buf);

  // entropy

  const float entropy = get_entropy ((const u8 *) tc->data_buf, TC_DATA_LEN);

  if (entropy < MIN_SUFFICIENT_ENTROPY_FILE) return (PARSER_INSUFFICIENT_ENTROPY);

  // signature

  tc->signature = 0x45555254; // "TRUE"

  // fake digest

  memcpy (digest, tc->data_buf, TC_DATA_LEN / 4);

  return (PARSER_OK);
}

int module_hash_decode_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  tc_t *tc = (tc_t *) esalt_buf;

  // keyfiles

  const char *truecrypt_keyfiles = module_option_str (user_options, OPTION_TRUECRYPT_KEYFILES);

  if (truecrypt_keyfiles)
  {
    char *keyfiles = hcstrdup (truecrypt_keyfiles);

    char *saveptr = NULL;

    char *keyfile = strtok_r (keyfiles, ",", &saveptr);

    while (keyfile)
    {
      if (hc_path_read (keyfile))
      {
        cpu_crc32 (keyfile, (u8 *) tc->keyfile_buf16,  64);
        cpu_crc32 (keyfile, (u8 *) tc->keyfile_buf32, 128);
      }

      keyfile = strtok_r ((char *) NULL, ",", &saveptr);
    }

    hcfree (keyfiles);

    tc->keyfile_enabled = 1;
  }

  // keyboard layout mapping

  const char *keyboard_layout_mapping = module_option_str (user_options, OPTION_KEYBOARD_LAYOUT_MAPPING);

  if (keyboard_layout_mapping)
  {
    if (hc_path_read (keyboard_layout_mapping))
    {
      initialize_keyboard_layout_mapping (keyboard_layout_mapping, tc->keyboard_layout_mapping_buf, &tc->keyboard_layout_mapping_cnt);
    }
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const tc_t *tc = (const tc_t *) esalt_buf;

  // salt

  char salt_buf[TC_SALT_HEX_LEN + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, TC_SALT_LEN, (u8 *) salt_buf);

  // data

  char data_buf[TC_DATA_HEX_LEN + 1] = { 0 };

  hex_encode ((const u8 *) tc->data_buf, TC_DATA_LEN, (u8 *) data_buf);

  // output

  int line_len = snprintf (line_buf, line_size, "%s%s$%s",
    SIGNATURE_TRUECRYPT,
    salt_buf,
    data_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode_postprocess  = module_hash_decode_postprocess;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_register_options         = truecrypt_module_register_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = module_usage_notice;
}
