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
static const char *HASH_NAME      = "VeraCrypt Streebog-512 + XTS 512 bit + boot-mode";
static const u64   KERN_TYPE      = 13771; // old kernel used here
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
static const char *ST_HASH        = "$veracrypt$2bfe4a72e13388a9ce074bbe0711a48d62f123df85b09e0350771edc4a0e4f397038a49b900275c9158145a96b52f95e92f927b3f963c7eadb71a07518d64323$1041c457d2794d0aa505f794153b52b24441271185d386833fbabf0e880c51b544f583d0db2ab6a926ddd3cdd0b68a61d7f5fe3f0ac6aa06ca676a868f373d35073605cf9d521ff55862b5005213a881a7b9025afc3409fa34dc86496620835df072fecd5b501f15e08113835c510d9f0bfd09d2ef1ac0e7bd01f0523d74a54fe984eb497cb960cce5bb154e024dc0c6c61a61e20a45a8f8ef319c63ca9646fbe00930302a5910891a1bc84bd936c926ca535b3b40c9e0ab255363b24a28bb8216d3d32244a725774e6ebbd73d6d3f2a2adcbc28d5341679cbb747efd56db1a09ce80b24640583ffc6f7ca5bd60d59114afcc78601184ba8feadb8d472f86c32bebf70e8158aa56f9db3b3200ef432aa7b370aa4ba408ef11b70d6806f1a21aaa3b629fa06f71dac0ae3e0ce95c7e5b550fc8c46017e151cbbcdf64b3b62b1b846a08925a217227286acfdad35b28407d589bec9578c2a4e9a4320f4a78e1e590fdf53c0a20fe0a1bb6c7d693abcd0e991c449e569477980d4b8972d21e4abc917d897e48ca427c954c3a3e0c8465ef40de51ffc9188047c043224c4a18638f1d91cd88c36623a1d880f18fd0d6ca0b3bbfa7d5d795acfb63576e2c2d83772e8";

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

typedef struct vc64_sbog_tmp
{
  u64  ipad_raw[8];
  u64  opad_raw[8];

  u64  ipad_hash[8];
  u64  opad_hash[8];

  u64  dgst[32];
  u64  out[32];

  u64 pim_key[32];
  int pim; // marker for cracked
  int pim_check; // marker for _extended kernel

} vc64_sbog_tmp_t;

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

static const int   ROUNDS_VERACRYPT_200000     = 200000;
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
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm13771_loop' pipeline, timeout reached
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
  const vc_t *vc = (const vc_t *) hashes->esalts_buf;

  u32 tmp_buf[64] = { 0 };

  memcpy (tmp_buf, src_buf, src_len);

  execute_keyboard_layout_mapping (tmp_buf, src_len, vc->keyboard_layout_mapping_buf, vc->keyboard_layout_mapping_cnt);

  const vc64_sbog_tmp_t *vc64_sbog_tmp = (const vc64_sbog_tmp_t *) tmps;

  if (vc64_sbog_tmp->pim == 0)
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s", (char *) tmp_buf);
  }
  else
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s   (PIM=%d)", (char *) tmp_buf, vc64_sbog_tmp->pim);
  }
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (vc_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (vc64_sbog_tmp_t);

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

  salt->salt_iter = ROUNDS_VERACRYPT_200000 - 1;

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
    vc->pim_start = module_option_u32 (user_options, OPTION_VERACRYPT_PIM_START);
    vc->pim_stop  = module_option_u32 (user_options, OPTION_VERACRYPT_PIM_STOP);

    salt->salt_iter = vc->pim_stop * 2048 - 1;
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
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_register_options         = veracrypt_keyboard_module_register_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = module_usage_notice;
}
