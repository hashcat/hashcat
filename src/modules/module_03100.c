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
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DATABASE_SERVER;
static const char *HASH_NAME      = "Oracle H: Type (Oracle 7+)";
static const u64   KERN_TYPE      = 3100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_UPPER
                                  | OPTS_TYPE_ST_UPPER;
static const u32   SALT_TYPE      = SALT_TYPE_GENERIC;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "792FCB0AE31D8489:7284616727";

#include "hooks_common.c"

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

  return jit_build_options;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 30; // http://www.red-database-security.de/whitepaper/oracle_passwords.html

  return pw_max;
}

u32 module_combined_len_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // the optimized kernel keeps user name and password in one buffer

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  const u32 combined_len_max = (optimized_kernel == true) ? 64 : 0;

  return combined_len_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 16;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[1] = 1;
  token.len_max[1] = 30;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos + 0);
  digest[1] = hex_to_u32 (hash_pos + 8);
  digest[2] = 0;
  digest[3] = 0;

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  int line_len = snprintf (line_buf, line_size, "%08X%08X", byte_swap_32 (digest[0]), byte_swap_32 (digest[1]));

  line_buf[line_len] = hashconfig->separator;

  line_len += 1;

  line_len += generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, (u8 *) line_buf + line_len);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_combined_len_max         = module_combined_len_max;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_pw_max                   = module_pw_max;
}
