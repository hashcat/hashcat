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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 3;
static const u32   DGST_POS1      = 7;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 6;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Windows Phone 8+ PIN/password";
static const char *HASH_RECIPE    = "sha256(utf16le(pass) . salt)";
static const u64   KERN_TYPE      = 13800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_UTF16LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "060a4a94cb2263bcefe74705bd0efe7643d09c2bc25fc69f6a32c1b8d5a5d0d9:4647316184156410832507278642444030512402463246148636510356103432440257733102761444262383653100802140838605535187005586063548643765207865344068042278454875021452355870320020868064506248840047414683714173748364871633802572014845467035357710118327480707136422";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

typedef struct win8phone
{
  u32 salt_buf[32];

} win8phone_t;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm13800_s04' pipeline, timeout reached
        return true;
      }
    }
  }

  return false;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // AMD-GPU-PRO
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == false))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // Only the first word changes in the loop of the optimized mask kernel. With plain rotates, the
  // compiler computes the message schedule terms that do not depend on it once, before the loop.
  // The other kernels gain nothing from plain rotates or run slower with them. The option reaches
  // NVIDIA builds alone, and the AMD branch above holds the string, so the vendor is asked here.

  if (device_param->opencl_device_vendor_id != VENDOR_ID_NV) return jit_build_options;

  if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) return jit_build_options;

  if (user_options_extra->attack_kern != ATTACK_KERN_BF) return jit_build_options;

  hc_asprintf (&jit_build_options, "-D NO_FUNNELSHIFT");

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (win8phone_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  win8phone_t *esalt = (win8phone_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 64;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[1]     = hashconfig->separator;
  token.len[1]     = 256;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // hash

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  // salt

  const u8 *salt_pos = token.buf[1];

  u32 *salt_buf = esalt->salt_buf;

  for (int i = 0, j = 0; i < 32; i += 1, j += 8)
  {
    salt_buf[i] = hex_to_u32 (salt_pos + j);

    salt_buf[i] = byte_swap_32 (salt_buf[i]);
  }

  // the recipe kernels read the whole salt from salt_buf in its original byte order

  for (int i = 0; i < 32; i++) salt->salt_buf[i] = byte_swap_32 (salt_buf[i]);

  salt->salt_len = 128;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const win8phone_t *esalt = (const win8phone_t *) esalt_buf;

  char buf[256 + 1] = { 0 };

  for (int i = 0, j = 0; i < 32; i += 1, j += 8)
  {
    snprintf (buf + j, 9, "%08x", esalt->salt_buf[i]);
  }

  const int line_len = snprintf (line_buf, line_size, "%08x%08x%08x%08x%08x%08x%08x%08x%c%s",
    digest[0],
    digest[1],
    digest[2],
    digest[3],
    digest[4],
    digest[5],
    digest[6],
    digest[7],
    hashconfig->separator,
    buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
