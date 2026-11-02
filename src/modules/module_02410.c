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
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Cisco-ASA MD5";
static const u64   KERN_TYPE      = 2410;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_GENERIC;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "YjDBNr.A0AN7DA8s:4684";

#include "hooks_common.c"

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = PW_MAX;

  if (optimized_kernel == true)
  {
    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      pw_max = 47; // with salt_len 1, but 44 if salt_len is 4
    }
    else
    {
      pw_max = 31;
    }
  }

  return pw_max;
}

u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_min = 1;

  return salt_min;
}

u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_max = 4;

  return salt_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 16;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  token.len_min[1] = 1;
  token.len_max[1] = 4;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = itoa64_to_int (hash_pos[ 0]) <<  0
            | itoa64_to_int (hash_pos[ 1]) <<  6
            | itoa64_to_int (hash_pos[ 2]) << 12
            | itoa64_to_int (hash_pos[ 3]) << 18;
  digest[1] = itoa64_to_int (hash_pos[ 4]) <<  0
            | itoa64_to_int (hash_pos[ 5]) <<  6
            | itoa64_to_int (hash_pos[ 6]) << 12
            | itoa64_to_int (hash_pos[ 7]) << 18;
  digest[2] = itoa64_to_int (hash_pos[ 8]) <<  0
            | itoa64_to_int (hash_pos[ 9]) <<  6
            | itoa64_to_int (hash_pos[10]) << 12
            | itoa64_to_int (hash_pos[11]) << 18;
  digest[3] = itoa64_to_int (hash_pos[12]) <<  0
            | itoa64_to_int (hash_pos[13]) <<  6
            | itoa64_to_int (hash_pos[14]) << 12
            | itoa64_to_int (hash_pos[15]) << 18;

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  digest[4] = digest[0]; // store for encoder
  digest[5] = digest[1];
  digest[6] = digest[2];
  digest[7] = digest[3];

  digest[0] &= 0x00ffffff;
  digest[1] &= 0x00ffffff;
  digest[2] &= 0x00ffffff;
  digest[3] &= 0x00ffffff;

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 tmp[4];

  tmp[0] = digest[4];
  tmp[1] = digest[5];
  tmp[2] = digest[6];
  tmp[3] = digest[7];

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    tmp[0] += MD5M_A;
    tmp[1] += MD5M_B;
    tmp[2] += MD5M_C;
    tmp[3] += MD5M_D;
  }

  u8 *out_buf = (u8 *) line_buf;

  out_buf[ 0] = int_to_itoa64 ((tmp[0] >>  0) & 0x3f);
  out_buf[ 1] = int_to_itoa64 ((tmp[0] >>  6) & 0x3f);
  out_buf[ 2] = int_to_itoa64 ((tmp[0] >> 12) & 0x3f);
  out_buf[ 3] = int_to_itoa64 ((tmp[0] >> 18) & 0x3f);
  out_buf[ 4] = int_to_itoa64 ((tmp[1] >>  0) & 0x3f);
  out_buf[ 5] = int_to_itoa64 ((tmp[1] >>  6) & 0x3f);
  out_buf[ 6] = int_to_itoa64 ((tmp[1] >> 12) & 0x3f);
  out_buf[ 7] = int_to_itoa64 ((tmp[1] >> 18) & 0x3f);
  out_buf[ 8] = int_to_itoa64 ((tmp[2] >>  0) & 0x3f);
  out_buf[ 9] = int_to_itoa64 ((tmp[2] >>  6) & 0x3f);
  out_buf[10] = int_to_itoa64 ((tmp[2] >> 12) & 0x3f);
  out_buf[11] = int_to_itoa64 ((tmp[2] >> 18) & 0x3f);
  out_buf[12] = int_to_itoa64 ((tmp[3] >>  0) & 0x3f);
  out_buf[13] = int_to_itoa64 ((tmp[3] >>  6) & 0x3f);
  out_buf[14] = int_to_itoa64 ((tmp[3] >> 12) & 0x3f);
  out_buf[15] = int_to_itoa64 ((tmp[3] >> 18) & 0x3f);

  int out_len = 16;

  out_buf[out_len] = hashconfig->separator;

  out_len += 1;

  out_len += generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
}
