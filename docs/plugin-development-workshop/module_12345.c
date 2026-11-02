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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH;
static const char *HASH_NAME      = "Workshop Example";
static const u64   KERN_TYPE      = 12345;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "dc1153d3069912c5ce8c4fc75797c5b4:10000:49493e63559ba3669b1b14ad958aaed1086433a1bcd2d1ac9df28ced1d14f810";

#include "hooks_common.c"

// Place any extra needed methods here

typedef struct workshop
{
  u32 encrypted_data[8];

} workshop_t;

typedef struct workshop_temp
{
  u32 digest_buf[4];

} workshop_temp_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (workshop_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (workshop_temp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  workshop_t *workshop = (workshop_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt = 3;

  // Salt
  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.sep[0]     = ':';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // Rounds
  token.len_min[1] = 5;
  token.len_max[1] = 5;
  token.sep[1]     = ':';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // Encrypted data
  token.len_min[2] = 64;
  token.len_max[2] = 64;
  token.sep[2]     = ':';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // Salt information
  const u8 *salt_pos = token.buf[0];
  salt->salt_buf[0] = hex_to_u32(salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32(salt_pos + 8);
  salt->salt_buf[2] = hex_to_u32(salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32(salt_pos + 24);
  salt->salt_len = 16;

  // Number of rounds - salt-iter determines the number of times the loop() is called
  const u8 *rounds_pos = token.buf[1];
  salt->salt_iter = hc_strtoul ((const char *) rounds_pos, NULL, 10);

  // Encrypted data
  const u8 *encrypted_data_pos = token.buf[2];
  for(int index = 0; index < 8; index++)
  {
    workshop->encrypted_data[index] = hex_to_u32(encrypted_data_pos + (index * 8));
  }

  // We are using this to compare with the COMPARE_M method
  digest[0] = workshop->encrypted_data[0];
  digest[1] = workshop->encrypted_data[1];
  digest[2] = workshop->encrypted_data[2];
  digest[3] = workshop->encrypted_data[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const workshop_t *workshop = (const workshop_t *) esalt_buf;

  /* 64 hex characters - 32 bytes - encdata */
  u8 encrypted_data[32];
  memcpy (encrypted_data, workshop->encrypted_data, sizeof (workshop->encrypted_data));
  u8 hex_encrypted_data[64 + 1] = { 0 };
  for (u32 i = 0, j = 0; i < 32; i++, j += 2)
  {
    u8_to_hex (encrypted_data[i], hex_encrypted_data + j);
  }

  const int line_len = snprintf (line_buf, line_size, "%08x%08x%08x%08x:%u:%s",
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]),
    salt->salt_iter,
    hex_encrypted_data);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
