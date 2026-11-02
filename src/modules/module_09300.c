/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Cisco-IOS $9$ (scrypt)";
static const u64   KERN_TYPE      = 8900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$9$87023684531115$phio0TBQwaO7KZ8toQFyGFyDvyOzidaypRWN0uKX0hU";

#include "hooks_common.c"

u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *SIGNATURE_CISCO9 = "$9$";

static const u32 SCRYPT_THREADS = 32;

#include "scrypt_common.c"

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CISCO9;

  token.len[0]     = 3;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 14;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  token.len[2]     = 43;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt is not encoded

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len  = salt_len;

  // fixed scrypt configuration in this mode

  salt->scrypt_N  = 16384;
  salt->scrypt_r  = 1;
  salt->scrypt_p  = 1;

  salt->salt_iter    = salt->scrypt_N;
  if (salt->scrypt_p < 1) return (PARSER_SALT_VALUE);

  salt->salt_repeats = salt->scrypt_p - 1;

  // base64 decode hash

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  u8 tmp_buf[100] = { 0 };

  const int tmp_len = base64_decode (itoa64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  char tmp_buf[64];

  base64_encode (int_to_itoa64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

  tmp_buf[43] = 0; // cut it here

  const int line_len = snprintf (line_buf, line_size, "%s%s$%s", SIGNATURE_CISCO9, (const unsigned char *) salt->salt_buf, tmp_buf);

  return line_len;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = scrypt_module_jit_build_options (hashconfig, user_options, user_options_extra, hashes, device_param);

  // With plain rotates, the compiler keeps the Salsa20/8 double rounds of the loop kernel as a
  // loop instead of unrolling them, and at the N, r and p that every 9300 hash uses, that runs
  // faster. 8900 builds the same kernel and runs slower with plain rotates at its own settings, so
  // the option stays with this module.

  if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
  {
    char *nv_build_options = NULL;

    hc_asprintf (&nv_build_options, "%s -D NO_FUNNELSHIFT", jit_build_options);

    hcfree (jit_build_options);

    return nv_build_options;
  }

  if (device_param->is_metal == false) return jit_build_options;

  // On Metal this kernel runs faster when the backend builds it at the size optimization level,
  // where the other scrypt modes gain from the default level.

  char *metal_build_options = NULL;

  hc_asprintf (&metal_build_options, "%s -D METAL_OPT_SIZE", jit_build_options);

  hcfree (jit_build_options);

  return metal_build_options;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = scrypt_module_benchmark_cost;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = scrypt_module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
}
