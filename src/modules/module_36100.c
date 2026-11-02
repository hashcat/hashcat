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
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_GENERIC_KDF;
static const char *HASH_NAME      = "yescrypt";
static const u64   KERN_TYPE      = 36100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MULTIHASH_DESPITE_ESALT;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$y$j9T$oJqQoBLMgF5$77xERSZazujSxPgj6nYmzH5r0O2HelZJUyfW.ta7vxD";

#include "hooks_common.c"

static const char *SIGNATURE_YESCRYPT = "$y$";

static const int SIGNATURE_YESCRYPT_LEN = 3;

static const u32 YESCRYPT_THREADS = 32;

#include "yescrypt_common.c"

// The kernel reads the first two members of the esalt as the yescrypt parameters, so anything a mode
// adds of its own goes behind them. See gost_yescrypt_t in module_36200.c for the other layout.

typedef struct yescrypt
{
  u32 flags;
  u32 t;

} yescrypt_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (yescrypt_t);

  return esalt_size;
}

u64 module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u64 tmp_size = yescrypt_module_extra_tmp_size (hashconfig, user_options, user_options_extra, hashes, sizeof (yescrypt_t));

  return tmp_size;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = yescrypt_module_jit_build_options (hashconfig, user_options, user_options_extra, hashes, device_param, sizeof (yescrypt_t));

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  yescrypt_t *yescrypt = (yescrypt_t *) esalt_buf;

  u32 flags;
  u32 t;

  const int rc = yescrypt_hash_decode (digest, salt, &flags, &t, SIGNATURE_YESCRYPT, SIGNATURE_YESCRYPT_LEN, line_buf, line_len);

  if (rc != PARSER_OK) return (rc);

  yescrypt->flags = flags;
  yescrypt->t     = t;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const yescrypt_t *yescrypt = (const yescrypt_t *) esalt_buf;

  if (line_size <= SIGNATURE_YESCRYPT_LEN) return 0;

  memcpy (line_buf, SIGNATURE_YESCRYPT, SIGNATURE_YESCRYPT_LEN);

  const int line_len = yescrypt_hash_encode (digest, salt, yescrypt->flags, yescrypt->t, line_buf, line_size, SIGNATURE_YESCRYPT_LEN);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = yescrypt_module_benchmark_cost;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = yescrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = yescrypt_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_kernel_loops_max         = yescrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = yescrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = yescrypt_module_kernel_threads_max;
  module_ctx->module_kernel_threads_min       = yescrypt_module_kernel_threads_min;
  module_ctx->module_tmp_size                 = yescrypt_module_tmp_size;
}
