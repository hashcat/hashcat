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
static const char *HASH_NAME      = "VeraCrypt SHA512 + XTS 1536 bit";
static const u64   KERN_TYPE      = 13723; // old kernel used here
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_KEYBOARD_MAPPING
                                  | OPTS_TYPE_COPY_TMPS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_EXTENDED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$veracrypt$d44f26d1742260f88023d825729cc5a64cf8475d887632a2fb4a84af27af138cfadc4bcbb122f6ba68339ae8427d1f72c0c4aeef041291492ae0a7d8677d8da4$3227ae2a26d9a433076b44458b14f52766cf0e4baeb473a789180660d62e42bbea7c042379a5a74e259463e1c18381fa13aee27141264be381de71c12f8f704913f211c45fda0295e963d90fc35272e907858c0522601f6e7a73b43ff222663f149a485fc6c464e5f3b7cc0b6508f30621385365ca8a4e0bff4061f64f5fbdb11f70f19d77e56fa6ff015ad76ecaaccd759d30da05d2a6fbf00ac9673ac3c23efd339313c2a99511e928f976bf9b2664d97685498d5931af2d453edc6fb1129e324eaba64264711fbe21d0d202b3659106e8100634f09c38cd15b1b3acba79d7f31d31fe23c166392e300db09f10550c83187566dc0fdf768b872555851b34e3c15ad7e7438a72e6126c895cf1204987df4b42cb7bc2fe03c5777867d269378c6e496df2a1a3457b907f7143a139d800868ad95e2901723c6ebb991054b4e991c67fe4c17702d9829d9dc1fe8bf4a956460721c858e31dbcbe56850a4ed31558c6ee89ba2cba2ef4bde77fed11848f9f92e0add54964a683c3686dbab4695ebc42554da922a08c6fff32cac936ea447e771aa74a689eb269ffef677294ef297600dfd73bbbb734d2968e38a98b4a8a77ff0eec8246d93b542e3521a3eb636101";

#include "hooks_common.c"

u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return USAGE_NOTICE_VERACRYPT;
}

#define VC_SALT_LEN     (             64)
#define VC_SALT_HEX_LEN (VC_SALT_LEN * 2)

#define VC_DATA_LEN     (            448)
#define VC_DATA_HEX_LEN (VC_DATA_LEN * 2)

typedef struct vc64_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

  u64 pim_key[32];
  int pim; // marker for cracked
  int pim_check; // marker for _extended kernel

} vc64_tmp_t;

typedef struct vc
{
  u32 data_buf[VC_DATA_LEN / 4];
  u32 keyfile_buf16[16];
  u32 keyfile_buf32[32];
  u32 keyfile_enabled;
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

  int pim_multi; // 2048 for boot (not SHA-512 or Whirlpool), 1000 for others
  int pim_start;
  int pim_stop;

} vc_t;

static const int   ROUNDS_VERACRYPT_500000     = 500000;
static const float MIN_SUFFICIENT_ENTROPY_FILE = 7.0f;
static const char *SIGNATURE_VERACRYPT         = "$veracrypt$";

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm13723_loop' pipeline, timeout reached
        return true;
      }
    }
    else
    {
      if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD)
      {
        // AMD Radeon Pro W5700X Compute Engine; 1.2 (Apr 22 2021 21:54:44); 11.3.1; 20E241
        return true;
      }
    }
  }

  return false;
}

int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const void *tmps, const u32 *src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 *dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  const vc64_tmp_t *vc64_tmp = (const vc64_tmp_t *) tmps;

  if (vc64_tmp->pim == 0)
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s", (const char *) src_buf);
  }
  else
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s   (PIM=%d)", (const char *) src_buf, vc64_tmp->pim - 15);
  }
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (vc_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (vc64_tmp_t);

  return tmp_size;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 250;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 1000; // lowest PIM multiplier

  return kernel_loops_max;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is selected
  // IOW, even in optimized kernel mode it support length 64

  const u32 pw_max = 128;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  vc_t *vc = (vc_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_VERACRYPT;

  token.len[0]     = 11;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = VC_SALT_HEX_LEN;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len[2]     = VC_DATA_HEX_LEN;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];

  salt->salt_len = hex_decode (salt_pos, VC_SALT_HEX_LEN, (u8 *) salt->salt_buf);

  // iter

  salt->salt_iter = ROUNDS_VERACRYPT_500000 - 1;

  // data

  const u8 *data_pos = token.buf[2];

  hex_decode (data_pos, VC_DATA_HEX_LEN, (u8 *) vc->data_buf);

  // entropy

  const float entropy = get_entropy ((const u8 *) vc->data_buf, VC_DATA_LEN);

  if (entropy < MIN_SUFFICIENT_ENTROPY_FILE) return (PARSER_INSUFFICIENT_ENTROPY);

  // pim

  vc->pim_multi = 1000;
  vc->pim_start = 0;
  vc->pim_stop  = 0;

  // signature

  vc->signature = 0x41524556; // "VERA"

  // fake digest

  memcpy (digest, vc->data_buf, VC_DATA_LEN / 4);

  return (PARSER_OK);
}

int module_hash_decode_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  vc_t *vc = (vc_t *) esalt_buf;

  // keyfiles

  const char *veracrypt_keyfiles = module_option_str (user_options, OPTION_VERACRYPT_KEYFILES);

  if (veracrypt_keyfiles)
  {
    char *keyfiles = hcstrdup (veracrypt_keyfiles);

    char *saveptr = NULL;

    char *keyfile = strtok_r (keyfiles, ",", &saveptr);

    while (keyfile)
    {
      if (hc_path_read (keyfile))
      {
        cpu_crc32 (keyfile, (u8 *) vc->keyfile_buf16,  64);
        cpu_crc32 (keyfile, (u8 *) vc->keyfile_buf32, 128);
      }

      keyfile = strtok_r ((char *) NULL, ",", &saveptr);
    }

    hcfree (keyfiles);

    vc->keyfile_enabled = 1;
  }

  // keyboard layout mapping

  const char *keyboard_layout_mapping = module_option_str (user_options, OPTION_KEYBOARD_LAYOUT_MAPPING);

  if (keyboard_layout_mapping)
  {
    if (hc_path_read (keyboard_layout_mapping))
    {
      initialize_keyboard_layout_mapping (keyboard_layout_mapping, vc->keyboard_layout_mapping_buf, &vc->keyboard_layout_mapping_cnt);
    }
  }

  // veracrypt PIM

  if ((module_option_given (user_options, OPTION_VERACRYPT_PIM_START) == true) && (module_option_given (user_options, OPTION_VERACRYPT_PIM_STOP) == true))
  {
    vc->pim_start = 15 + module_option_u32 (user_options, OPTION_VERACRYPT_PIM_START);
    vc->pim_stop  = 15 + module_option_u32 (user_options, OPTION_VERACRYPT_PIM_STOP);

    salt->salt_iter = vc->pim_stop * 1000 - 1;
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const vc_t *vc = (const vc_t *) esalt_buf;

  // salt

  char salt_buf[VC_SALT_HEX_LEN + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, VC_SALT_LEN, (u8 *) salt_buf);

  // data

  char data_buf[VC_DATA_HEX_LEN + 1] = { 0 };

  hex_encode ((const u8 *) vc->data_buf, VC_DATA_LEN, (u8 *) data_buf);

  // output

  int line_len = snprintf (line_buf, line_size, "%s%s$%s",
    SIGNATURE_VERACRYPT,
    salt_buf,
    data_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_build_plain_postprocess  = module_build_plain_postprocess;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode_postprocess  = module_hash_decode_postprocess;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_register_options         = veracrypt_keyboard_module_register_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = module_usage_notice;
}
