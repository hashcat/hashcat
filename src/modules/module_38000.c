/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Mikrotik RouterOS EC-SRP5 password hash (Curve25519)
 * Hash format: $mikrotik$username$hex_salt_16B$hex_verifier_28B
 *
 * Approach: username stored in salt_buf_pc, username_len in salt_len_pc.
 * salt_buf[0..3] = 16-byte salt. This avoids esalt entirely.
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
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Mikrotik RouterOS EC-SRP5 (Curve25519)";
static const u64   KERN_TYPE      = 38000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$mikrotik$hashcat$3069ece5c30baced372fb3d64647d42f$25772ddb1fa2e0f13511d7d7dc8c611b6529dd915d10482243dfca38";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use tools/routeros2hashcat.py to extract hashes from RouterOS .backup files, unpacked config directories, or NAND flash config stores";
}

typedef struct mikrotik_ecsrp5_tmp
{
  u32 out[8];

} mikrotik_ecsrp5_tmp_t;

static const char *SIGNATURE_MIKROTIK = "$mikrotik$";

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (mikrotik_ecsrp5_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MIKROTIK;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 255;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 56;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // Salt (16 bytes) → salt_buf[0..3]
  const u8 *salt_pos = token.buf[2];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  // Username → salt_buf_pc as raw bytes (salt_buf_pc is u32[64] = 256 bytes)
  const u8 *username_pos = token.buf[1];
  const u32 username_len = token.len[1];

  memset (salt->salt_buf_pc, 0, sizeof (salt->salt_buf_pc));
  memcpy (salt->salt_buf_pc, username_pos, MIN (username_len, 255));
  salt->salt_len_pc = username_len;

  salt->salt_len  = 16;
  salt->salt_iter = 1;

  // Verifier (28 bytes = 7 u32) → digest
  // byte_swap_32 after hex_to_u32 to store as BE numeric values (like module_01400)
  const u8 *verifier_pos = token.buf[3];

  for (u32 i = 0; i < 7; i++)
  {
    digest[i] = byte_swap_32 (hex_to_u32 (verifier_pos + (i * 8)));
  }

  digest[7] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // Username from salt_buf_pc
  char username[256] = { 0 };
  const u32 username_len = salt->salt_len_pc;
  memcpy (username, salt->salt_buf_pc, MIN (username_len, 255));

  // Salt — reverse hex_to_u32 byte swap
  char salt_hex[33] = { 0 };
  for (u32 i = 0; i < 4; i++)
  {
    snprintf (salt_hex + (i * 8), 9, "%08x", byte_swap_32 (salt->salt_buf[i]));
  }

  // Verifier — digest stores BE u32 values, print directly
  char verifier_hex[57] = { 0 };
  for (u32 i = 0; i < 7; i++)
  {
    snprintf (verifier_hex + (i * 8), 9, "%08x", digest[i]);
  }

  int bytes_written = snprintf (line_buf, line_size, "%s%s$%s$%s",
    SIGNATURE_MIKROTIK,
    username,
    salt_hex,
    verifier_hex);

  return bytes_written;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
