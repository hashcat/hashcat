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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "KDE KWallet < 4.13 (SHA-1, Blowfish)";
static const u64   KERN_TYPE      = 36410;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DYNAMIC_SHARED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$kwallet$88$45975b748f882d01c2bf498e329f20000810fcf38c4803e0985006270fabde065b41363475a9753a54687fae112c326915658aad6901b32dff0f62b96346dd4e";

#include "hooks_common.c"

typedef struct kwallet_legacy_tmp
{
  u32 dgst[4][5];

  u32 nblocks;
  u32 pw_len;

} kwallet_legacy_tmp_t;

typedef struct kwallet
{
  u32 ct[16];
  u32 ct_len;

} kwallet_t;

static const char *SIGNATURE_KWALLET = "$kwallet$";

// 2000 SHA-1 per 16 byte password chunk, the first one runs in the init kernel

#define ROUNDS_KWALLET_LEGACY 2000

#define KWALLET_CT_KEEP     64
#define KWALLET_CT_KEEP_HEX (KWALLET_CT_KEEP * 2)

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This is the wallet format written before KWallet 4.13, use -m 36400 for a newer one. You can use https://github.com/openwall/john/blob/bleeding-jumbo/run/kwallet2john.py to extract the hash. Only the first 64 byte of the ciphertext field are used, so a hash line from a large wallet can be cut down to that: keep the '$kwallet$<length>$' prefix as it is and shorten the hex that follows to 128 characters.";
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // the comp kernel keeps the blowfish sboxes in shared memory, one set per thread,
  // so the local size it can run at follows from how much shared memory the device has

  bool use_dynamic = false;

  if (device_param->is_cuda == true)
  {
    use_dynamic = true;
  }

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u", 1);
  }
  else
  {
    u32 overhead = 0;

    if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
    {
      if (device_param->is_opencl == true)
      {
        overhead = 1;
      }
    }

    if (user_options->kernel_threads_chgd == true)
    {
      u32 fixed_local_size = user_options->kernel_threads;

      if (use_dynamic == true)
      {
        if ((fixed_local_size * 4096) > device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET])
        {
          // otherwise out-of-bound reads

          fixed_local_size = device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET] / 4096;
        }

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u -D DYNAMIC_LOCAL", fixed_local_size);
      }
      else
      {
        if ((fixed_local_size * 4096) > (device_param->device_local_mem_size - overhead))
        {
          // otherwise out-of-bound reads

          fixed_local_size = (device_param->device_local_mem_size - overhead) / 4096;
        }

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u", fixed_local_size);
      }
    }
    else
    {
      if (use_dynamic == true)
      {
        const u32 fixed_local_size = device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET] / 4096;

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u -D DYNAMIC_LOCAL", fixed_local_size);
      }
      else
      {
        const u32 fixed_local_size = (device_param->device_local_mem_size - overhead) / 4096;

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u", fixed_local_size);
      }
    }
  }

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (kwallet_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (kwallet_legacy_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  kwallet_t *kwallet = (kwallet_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KWALLET;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 2;
  token.len_max[1] = 8;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // last token, so it runs to the end of the line. the hex check is what keeps a
  // modern $kwallet$...$1$...$ hash out of this module.

  token.len_min[2] = KWALLET_CT_KEEP_HEX;
  token.len_max[2] = 0x1000000;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u32 ct_len = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (ct_len < 64) return (PARSER_CT_LENGTH);
  if (ct_len > 0x1000000) return (PARSER_CT_LENGTH);
  if (ct_len & 7) return (PARSER_CT_LENGTH);

  const u8 *ct_pos = token.buf[2];
  const int ct_hex_len = token.len[2];

  if (ct_hex_len & 1) return (PARSER_CT_LENGTH);

  if ((ct_hex_len != (int) (ct_len * 2)) && (ct_hex_len != KWALLET_CT_KEEP_HEX) && (ct_hex_len != 130)) return (PARSER_CT_LENGTH);

  /**
   * store
   */

  hex_decode (ct_pos, KWALLET_CT_KEEP_HEX, (u8 *) kwallet->ct);

  for (int i = 0; i < 16; i++) kwallet->ct[i] = byte_swap_32 (kwallet->ct[i]);

  kwallet->ct_len = ct_len;

  // an old wallet has no salt at all. the header doubles as one so that hashcat keeps
  // one salt per wallet, which is what the comp kernel needs to report through mark_hash().

  salt->salt_buf[0] = kwallet->ct[0];
  salt->salt_buf[1] = kwallet->ct[1];
  salt->salt_buf[2] = kwallet->ct[2];
  salt->salt_buf[3] = kwallet->ct[3];

  salt->salt_len  = 16;
  salt->salt_iter = ROUNDS_KWALLET_LEGACY - 1;

  digest[0] = kwallet->ct[0];
  digest[1] = kwallet->ct[1];
  digest[2] = kwallet->ct[2];
  digest[3] = kwallet->ct[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const kwallet_t *kwallet = (const kwallet_t *) esalt_buf;

  u32 ct_tmp[16];

  for (int i = 0; i < 16; i++) ct_tmp[i] = byte_swap_32 (kwallet->ct[i]);

  u8 ct_hex[KWALLET_CT_KEEP_HEX + 1];

  hex_encode ((const u8 *) ct_tmp, KWALLET_CT_KEEP, ct_hex);

  ct_hex[KWALLET_CT_KEEP_HEX] = 0;

  const int out_len = snprintf (line_buf, line_size, "%s%u$%s",
    SIGNATURE_KWALLET,
    kwallet->ct_len,
    (char *) ct_hex);

  return out_len;
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
