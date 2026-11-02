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
static const u32   DGST_POS1      = 4;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "FortiGate (FortiOS)";
static const char *HASH_RECIPE    = "sha1(salt . pass . \"\\xa3\\x88\\xba\\x2e\\x42\\x4c\\xb0\\x4a\\x53\\x79\\x30\\xc1\\x31\\x07\\xcc\\x3f\" . \"\\xa1\\x32\\x90\\x29\\xa9\\x81\\x5b\\x70\")";
static const u64   KERN_TYPE      = 7000;
static const u32   OPTI_TYPE      = OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "AK1FCIhM0IUIQVFJgcDFwLCMi7GppdwtRzMyDpFOFxdpH8=";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

static const char *SIGNATURE_FORTIGATE = "AK1";

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  u32 pw_max = PW_MAX;

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  if (optimized_kernel == true)
  {
    pw_max = 19;
  }

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_FORTIGATE;

  token.len[0]  = 3;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 44;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * verify data
   */

  const u8 *hash_pos = token.buf[1];
  const int hash_len = token.len[1];

  // decode salt + SHA1 hash (12 + 20 = 32)

  u8 tmp_buf[100] = { 0 };

  const int decoded_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (decoded_len != 32) return (PARSER_HASH_LENGTH);

  /**
   * store data
   */

  // salt

  u32 salt_len = 12;

  memcpy (salt->salt_buf, tmp_buf, salt_len);

  salt->salt_len = salt_len;

  // digest

  memcpy (digest, tmp_buf + salt_len, 20);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= SHA1M_A;
    digest[1] -= SHA1M_B;
    digest[2] -= SHA1M_C;
    digest[3] -= SHA1M_D;
    digest[4] -= SHA1M_E;
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  char tmp_buf[64];

  // salt

  memcpy (tmp_buf, salt->salt_buf, 12);

  // digest

  u32 tmp[5];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];
  tmp[4] = digest[4];

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    tmp[0] += SHA1M_A;
    tmp[1] += SHA1M_B;
    tmp[2] += SHA1M_C;
    tmp[3] += SHA1M_D;
    tmp[4] += SHA1M_E;
  }

  tmp[0] = byte_swap_32 (tmp[0]);
  tmp[1] = byte_swap_32 (tmp[1]);
  tmp[2] = byte_swap_32 (tmp[2]);
  tmp[3] = byte_swap_32 (tmp[3]);
  tmp[4] = byte_swap_32 (tmp[4]);

  memcpy (tmp_buf + 12, tmp, 20);

  // base64 encode (salt + SHA1)

  char ptr_plain[48];

  base64_encode (int_to_base64, (const u8 *) tmp_buf, 12 + 20, (u8 *) ptr_plain);

  ptr_plain[44] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s%s", SIGNATURE_FORTIGATE, ptr_plain);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_pw_max                   = module_pw_max;
}
