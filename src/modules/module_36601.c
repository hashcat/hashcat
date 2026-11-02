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
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DATABASE_SERVER;
static const char *HASH_NAME      = "MSSQL (2025)";
static const u64   KERN_TYPE      = 36600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "0x03004DB403DDD3A508F81058E6AD92A6A20E5C72A06AD0B00C0A733EAD6582BE2443AFA70C9516C2DFDC60EA927B40BD732D7763477484FC014435AAC4D57EA88237B39806C1";

#include "hooks_common.c"

typedef struct pbkdf2_sha512
{
  u32 salt_buf[64];

} pbkdf2_sha512_t;

typedef struct pbkdf2_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} pbkdf2_sha512_tmp_t;

static const char *SIGNATURE_MSSQL2025 = "0x0300";

/*
 * PBKDF2-HMAC-SHA512 iteration count used by SQL Server 2025.
 * This value is fixed and not stored in the hash itself.
 */
static const u32 MSSQL2025_ITER = 100000;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pbkdf2_sha512_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  /*
   * Hash format: 0x0300 <4-byte hex salt> <64-byte hex derived key>
   *   token[0] = "0x0300" (6 chars, version signature)
   *   token[1] = salt     (8 hex chars = 4 bytes)
   *   token[2] = hash     (128 hex chars = 64 bytes)
   */

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MSSQL2025;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 8;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = 128;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /*
   * Iteration count is fixed at 100,000 for SQL Server 2025.
   * salt_iter is stored as (iterations - 1) per hashcat convention.
   */

  salt->salt_iter = MSSQL2025_ITER - 1;

  /*
   * Decode the 4-byte hex salt
   */

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  memcpy (pbkdf2_sha512->salt_buf, salt->salt_buf, salt->salt_len);

  /*
   * Include the iteration count in the salt uniqueness key so that
   * two hashes differing only in iter are treated as distinct salts.
   */

  salt->salt_buf[4] = salt->salt_iter;

  /*
   * Decode the 64-byte (128 hex char) derived key.
   * hex_to_u64 stores bytes in little-endian order (first hex pair is the LSB),
   * so byte_swap_64 is required to convert each word to the big-endian
   * representation that the PBKDF2 kernel comparison expects.
   */

  const u8 *hash_pos = token.buf[2];

  digest[0] = hex_to_u64 (hash_pos +   0);
  digest[1] = hex_to_u64 (hash_pos +  16);
  digest[2] = hex_to_u64 (hash_pos +  32);
  digest[3] = hex_to_u64 (hash_pos +  48);
  digest[4] = hex_to_u64 (hash_pos +  64);
  digest[5] = hex_to_u64 (hash_pos +  80);
  digest[6] = hex_to_u64 (hash_pos +  96);
  digest[7] = hex_to_u64 (hash_pos + 112);

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
  /*
   * OPTS_TYPE_HASH_COPY preserves the original hash string verbatim,
   * so we can simply return it here without re-encoding.
   */

  return snprintf (line_buf, line_size, "%s", hash_info->orighash);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
