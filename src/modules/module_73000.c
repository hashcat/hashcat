
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
#include "memory.h"
#include "emu_inc_hash_md4.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_USER_DEFINED;
static const char *HASH_NAME      = "Generic Hash [Bridged: Python]";
static const u64   KERN_TYPE      = 73000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_AUTODETECT_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_MULTIHASH_DESPITE_ESALT
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const u64   BRIDGE_TYPE    = BRIDGE_TYPE_LAUNCH_LOOP
                                  | BRIDGE_TYPE_UPDATE_SELFTEST;
static const char *BRIDGE_NAME    = "python_generic_hash";
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "33522b0fd9812aa68586f66dba7c17a8ce64344137f9c7d8b11f32a6921c22de*9348746780603343";

#include "hooks_common.c"

const char *module_bridge_name    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BRIDGE_NAME;     }
u64         module_bridge_type    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BRIDGE_TYPE;     }

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 out_buf[32][64];
  u32 out_len[32];
  u32 out_cnt;

} generic_io_tmp_t;

typedef struct
{
  u32 hash_buf[256];
  u32 hash_len;

  u32 salt_buf[256];
  u32 salt_len;

} generic_io_t;

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (generic_io_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (generic_io_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  generic_io_t *generic_io = (generic_io_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.len_min[0] = 0;
  token.len_max[0] = 1024;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[1] = 0;
  token.len_max[1] = 1024;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // To keep this as generic as possible,
  // we make a hash of the input data so it fits into digest[]
  // and the same for the salt

  const u8 *salt_buf = token.buf[1];
  const int salt_len = token.len[1];

  memcpy (generic_io->salt_buf, salt_buf, salt_len);

  generic_io->salt_len = salt_len;

  md4_ctx_t ctx1;

  md4_init (&ctx1);
  md4_update (&ctx1, (const u32 *) generic_io->salt_buf, generic_io->salt_len);
  md4_final (&ctx1);

  salt->salt_buf[0] = ctx1.h[0];
  salt->salt_buf[1] = ctx1.h[1];
  salt->salt_buf[2] = ctx1.h[2];
  salt->salt_buf[3] = ctx1.h[3];

  salt->salt_len  = 16;
  salt->salt_iter = 1;

  // digest

  const u8 *hash_buf = token.buf[0];
  const int hash_len = token.len[0];

  memcpy (generic_io->hash_buf, hash_buf, hash_len);

  generic_io->hash_len = hash_len;

  md4_ctx_t ctx2;

  md4_init (&ctx2);
  md4_update (&ctx2, (const u32 *) generic_io->hash_buf, generic_io->hash_len);
  md4_final (&ctx2);

  digest[0] = ctx2.h[0];
  digest[1] = ctx2.h[1];
  digest[2] = ctx2.h[2];
  digest[3] = ctx2.h[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const generic_io_t *generic_io = (const generic_io_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s*%s", (char *) generic_io->hash_buf, (char *) generic_io->salt_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_bridge_name              = module_bridge_name;
  module_ctx->module_bridge_type              = module_bridge_type;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
