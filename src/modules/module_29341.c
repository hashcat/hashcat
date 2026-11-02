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
static const char *HASH_NAME      = "TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode";
static const u64   KERN_TYPE      = 6211; // old kernel used here
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_KEYBOARD_MAPPING;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$truecrypt$2b5da9924119fde5270f712ba3c3e4974460416e8465f222149499908c2fca0a4753b581f26625d11c4d3f49bdeb1c95bc3e17629d7e19ffb66175e5feab90a4$fd670194f95d578266f3f54e61b82dc00efc2bb4438e19c3f6d7a92825a7625d88ec6286ab4e1761749edc83dad4340fd167544f09913fd6b03775013ff232fc4dad6f726ef82ad4bd1c5227a7796d7db35a912beeda5b0cdd798bc34d3ac24403c87dc672a983687dd64f920c991840a56105a6311797eed9976014909700366420673f6455242c71151ac75903a353538ec24b4feb967e2b46886395cf3e934e83a6a58ef2c0180273a0c33ba2bd870b1d84afb03d5558dc17bc7fb586404ad9a7e506ed859540110c6ad73f0f1d2be47829bc666e1838ec3f1dc1f610206241ce07fbf2542ecef9348b37aa460815794ca582709697cbf0c90c3dae4cb9dd97b29d3c7d82bd8d0c81d708e74c7007468c6c55a40fd4f803a4f5a75818d7da0d1ef333b8622e7de516fa62a6fa2b8d6d5d23653dfcedffec771456ee204e5c85ee88defbe195462fbe8ce0e2a5a455dab66478b877ec37dfa66f19ab5201c56cd707ba7bee1b10360965d3868c1fdf91dda124b1b0994fee75848083d19369735905bd2864b496c6e35ecf96f6dd4728570a45746bcf8d7d0ec0b9b0b112b28fdc53efcfa7d0558c132cd683a742d62b34304d9f991029c8aedc3d8767da8c";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return USAGE_NOTICE_TRUECRYPT;
}

#define TC_SALT_LEN     (             64)
#define TC_SALT_HEX_LEN (TC_SALT_LEN * 2)

#define TC_DATA_LEN     (            448)
#define TC_DATA_HEX_LEN (TC_DATA_LEN * 2)

typedef struct tc_tmp
{
  u32 ipad[16];
  u32 opad[16];

  u32 dgst[64];
  u32 out[64];

} tc_tmp_t;

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

int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const void *tmps, const u32 *src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 *dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  const tc_t *tc = (const tc_t *) hashes->esalts_buf;

  if (src_len < (int) dst_sz)
  {
    memcpy (dst_buf, src_buf, src_len);
  }

  return execute_keyboard_layout_mapping (dst_buf, src_len, tc->keyboard_layout_mapping_buf, tc->keyboard_layout_mapping_cnt);
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (tc_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (tc_tmp_t);

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

  module_ctx->module_build_plain_postprocess  = module_build_plain_postprocess;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode_postprocess  = module_hash_decode_postprocess;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_register_options         = truecrypt_keyboard_module_register_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
