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
static const char *HASH_NAME      = "KDE KWallet 4.13+ (PBKDF2-HMAC-SHA512, Blowfish)";
static const u64   KERN_TYPE      = 36400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DYNAMIC_SHARED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$kwallet$88$45975b748f882d01a9584f6bd2a564b3a0a3ceb0d9a192c7a1a335282a1b276c57d7a529016dd943bfa1cfffdd1387f029c9aaab41ba3ff4f07c07f71f222301$1$56$8f90f3b63faf4049373703f896d3511136696af6ce60b92010daa397c6eb8ea4c867288e61694002d3c152ef4d8e3119bf39cbcd6b65edb8$50000";

#include "hooks_common.c"

typedef struct kwallet_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[8];
  u64 out[8];

} kwallet_tmp_t;

typedef struct kwallet
{
  u32 ct[16];
  u32 ct_len;

} kwallet_t;

static const char *SIGNATURE_KWALLET = "$kwallet$";

// only the first 64 byte of the wallet are needed to tell a key apart, and a wallet file
// can be megabytes, so the rest of the ciphertext is dropped on parse. JtR does the same
// in its split(), which is why its own hashes come in both forms.

#define KWALLET_CT_KEEP     64
#define KWALLET_CT_KEEP_HEX (KWALLET_CT_KEEP * 2)

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/openwall/john/blob/bleeding-jumbo/run/kwallet2john.py to extract the hash. Only the first 64 byte of the ciphertext field are used, so a hash line from a large wallet can be cut down to that: keep the '$kwallet$<length>$' prefix as it is and shorten the hex that follows to 128 characters.";
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
  const u64 tmp_size = (const u64) sizeof (kwallet_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  kwallet_t *kwallet = (kwallet_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 7;

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

  token.sep[2]     = '$';
  token.len_min[2] = KWALLET_CT_KEEP_HEX;
  token.len_max[2] = 0x1000000;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 1;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 3;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 2;
  token.len_max[5] = 512;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len_min[6] = 1;
  token.len_max[6] = 8;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // ciphertext length as recorded in the wallet header

  const u32 ct_len = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (ct_len < 64) return (PARSER_CT_LENGTH);
  if (ct_len > 0x1000000) return (PARSER_CT_LENGTH);
  if (ct_len & 7) return (PARSER_CT_LENGTH);

  // ciphertext, either complete or already cut down by us or by JtR

  const u8 *ct_pos = token.buf[2];
  const int ct_hex_len = token.len[2];

  if (ct_hex_len & 1) return (PARSER_CT_LENGTH);

  if ((ct_hex_len != (int) (ct_len * 2)) && (ct_hex_len != KWALLET_CT_KEEP_HEX) && (ct_hex_len != 130)) return (PARSER_CT_LENGTH);

  // minor version, this module is the PBKDF2 one

  if (token.buf[3][0] != '1') return (PARSER_SALT_VALUE);

  // salt

  const u32 salt_len = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  if (salt_len < 1) return (PARSER_SALT_LENGTH);
  if (salt_len > 256) return (PARSER_SALT_LENGTH);

  if (token.len[5] != (int) (salt_len * 2)) return (PARSER_SALT_LENGTH);

  // iterations

  const u32 iter = hc_strtoul ((const char *) token.buf[6], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  /**
   * store
   */

  hex_decode (ct_pos, KWALLET_CT_KEEP_HEX, (u8 *) kwallet->ct);

  for (int i = 0; i < 16; i++) kwallet->ct[i] = byte_swap_32 (kwallet->ct[i]);

  kwallet->ct_len = ct_len;

  hex_decode (token.buf[5], token.len[5], (u8 *) salt->salt_buf);

  for (int i = 0; i < 64; i++) salt->salt_buf[i] = byte_swap_32 (salt->salt_buf[i]);

  salt->salt_len  = salt_len;
  salt->salt_iter = iter - 1;

  // a wallet carries no verifier, the kernel decides on the decrypted header alone and
  // reports through mark_hash(). the digest only has to keep hashes apart on the host.

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

  u32 salt_tmp[64];

  for (int i = 0; i < 64; i++) salt_tmp[i] = byte_swap_32 (salt->salt_buf[i]);

  u8 salt_hex[(256 * 2) + 1];

  hex_encode ((const u8 *) salt_tmp, salt->salt_len, salt_hex);

  salt_hex[salt->salt_len * 2] = 0;

  const int out_len = snprintf (line_buf, line_size, "%s%u$%s$1$%u$%s$%u",
    SIGNATURE_KWALLET,
    kwallet->ct_len,
    (char *) ct_hex,
    salt->salt_len,
    (char *) salt_hex,
    salt->salt_iter + 1);

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
