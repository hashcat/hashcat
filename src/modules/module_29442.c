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
static const char *HASH_NAME      = "VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode";
static const u64   KERN_TYPE      = 13712; // old kernel used here
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_KEYBOARD_MAPPING
                                  | OPTS_TYPE_COPY_TMPS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_EXTENDED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$veracrypt$a3c0fa44ec59bf7a3eed64bf70b8a60623664503eeb972eb51fa25ee921d813f8e45d3e1ab1c0088a62482bb78c6e07308d2308d3d66831505b0cb02fe214fba$c8a51cf9be2ada3c46045afa7df810f2e7b57792150de63b111a9aa78d70e25d832b3d6901aa455b32da240ff68380d66da27f4f7ccc5fadc6b3ff68e27b6d5c48e6512865e3b9fbe2a64a55454cfc333d7850603ecf8e1cf19abaaf8c1581a6fa14c5091ebe70e6338081d72d6a95b542764f3865946edc8e626e166cc2e0f6260032f8decdd98f9a82aa2b065a41e9b42ce8c33d3f935706431d19888bd5b2bd4d34d9bceb8596b15994f247169ee7f8cd34b6955362b60f37a4167c7b63bab8af65e7c592e9ba4535c255b4b3d93b302aa017ea335af20f9d9696f1eb37770ca87b0245d29887cc4611a3a43d11170219c509814eb1fc122a189c08394f22309dd48a996cbfc70cf67f76b6b19e46407a12ef001b2c360501dbd63d1c9f85132204709204992078318920b32aac917bb98d8eeefb60abef47571404d069a6df7881f8e7815c18789f23561d7d33f47e1aa97fb4a60bac0332b0e742a9b0498e5641401567615fd6dbd0fcfff07aebce0d543f2c498486f15f38dcf1dd55d7144d3fc51bf1f491798b183a84f3f49a72944c8054cdab915e19dc376ae3fa681d4afcd7b13f425e96340a696a4f11929b2e769ba207c5bf2c2976a3834c499d";

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

typedef struct vc_tmp
{
  u32 ipad[16];
  u32 opad[16];

  u32 dgst[64];
  u32 out[64];

  u32 pim_key[64];
  int pim; // marker for cracked
  int pim_check; // marker for _extended kernel

} vc_tmp_t;

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

static const int   ROUNDS_VERACRYPT_327661     = 327661;
static const float MIN_SUFFICIENT_ENTROPY_FILE = 7.0f;
static const char *SIGNATURE_VERACRYPT         = "$veracrypt$";

int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const void *tmps, const u32 *src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 *dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  const vc_t *vc = (const vc_t *) hashes->esalts_buf;

  u32 tmp_buf[64] = { 0 };

  memcpy (tmp_buf, src_buf, src_len);

  execute_keyboard_layout_mapping (tmp_buf, src_len, vc->keyboard_layout_mapping_buf, vc->keyboard_layout_mapping_cnt);

  const vc_tmp_t *vc_tmp = (const vc_tmp_t *) tmps;

  if (vc_tmp->pim == 0)
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s", (char *) tmp_buf);
  }
  else
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s   (PIM=%d)", (char *) tmp_buf, vc_tmp->pim);
  }
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (vc_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (vc_tmp_t);

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

  salt->salt_iter = ROUNDS_VERACRYPT_327661 - 1;

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
  module_ctx->module_usage_notice             = module_usage_notice;
}
