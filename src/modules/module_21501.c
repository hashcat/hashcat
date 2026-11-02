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
static const u32   DGST_POS0      = 14;
static const u32   DGST_POS1      = 15;
static const u32   DGST_POS2      = 6;
static const u32   DGST_POS3      = 7;
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_EAS;
static const char *HASH_NAME      = "SolarWinds Orion v2";
static const u64   KERN_TYPE      = 21500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$solarwinds$1$3pHkk55NTYpAeV3EJjcAww==$N4Ii2PxXX/bTZZwslQLIKrp0wvfZ5aN9hpyiR896ozJMJTPO1Q7BK1Eht8Vhl4kXq/42Vn2zp3qYeAkRuqsuEw==";

#include "hooks_common.c"

typedef struct solarwinds_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[260];
  u32  out[260];

} solarwinds_tmp_t;

typedef struct solarwinds
{
  u32 salt_buf[64 + 1];

} solarwinds_t;

static const u32 ROUNDS_SOLARWINDS_ORION = 1000;

static const char *SIGNATURE_SOLARWINDS_ORION_V2 = "$solarwinds$1$";

u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_min = 16;

  return salt_min;
}

u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_max = 16;

  return salt_max;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (solarwinds_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (solarwinds_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  solarwinds_t *solarwinds = (solarwinds_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SOLARWINDS_ORION_V2;

  token.len[0]     = 14;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 24;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[2]     = '$';
  token.len[2]     = 88;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  salt->salt_iter = ROUNDS_SOLARWINDS_ORION - 1;

  // save original salt for encode function
  // this is the only reason why we have an esalt in this hash-mode

  const char *salt_pos = (const char *) token.buf[1];
  const int   salt_len = token.len[1];

  memcpy (solarwinds->salt_buf, salt_pos, salt_len);

  // for pbkdf2 salt we need to do hash-mode specific modifications

  // salt

  u8 tmp_buf[256];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  int tmp_len = base64_decode (base64_to_int, (const u8 *)salt_pos, salt_len, tmp_buf);

  if (tmp_len != 16) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  // hash

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  // the token is a fixed 88 base64 characters, and 88 of them without padding decode to 66 bytes,
  // which is 2 more than the digest holds. A valid hash ends in == and decodes to exactly 64.

  if (tmp_len != 64) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, tmp_len);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  const solarwinds_t *solarwinds = (const solarwinds_t *) esalt_buf;

  // hash

  u64 tmp[9];

  tmp[0] = byte_swap_64 (digest[0]);
  tmp[1] = byte_swap_64 (digest[1]);
  tmp[2] = byte_swap_64 (digest[2]);
  tmp[3] = byte_swap_64 (digest[3]);
  tmp[4] = byte_swap_64 (digest[4]);
  tmp[5] = byte_swap_64 (digest[5]);
  tmp[6] = byte_swap_64 (digest[6]);
  tmp[7] = byte_swap_64 (digest[7]);
  tmp[8] = 0;

  char hash_enc[256] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp, 64, (u8 *) hash_enc);

  // output
  const int line_len = snprintf (line_buf, line_size, "%s%s$%s", SIGNATURE_SOLARWINDS_ORION_V2, (const char *) solarwinds->salt_buf, hash_enc);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
