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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "MS Office 2010";
static const u64   KERN_TYPE      = 9500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$office$*2010*100000*128*16*34170046140146368675746031258762*de5bc114991bb3a5679a6e24320bdb09*1b72a4ddffba3dcd5395f6a5ff75b126cb832b733c298e86162028ca47a235a9";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return USAGE_NOTICE_OFFICE;
}

typedef struct office2010
{
  u32 encryptedVerifier[4];
  u32 encryptedVerifierHash[8];

} office2010_t;

typedef struct office2010_tmp
{
  u32 out[5];

} office2010_tmp_t;

static const char *SIGNATURE_OFFICE2010 = "$office$";

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (office2010_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (office2010_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  office2010_t *office2010 = (office2010_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OFFICE2010;

  token.sep[0]     = '*';
  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 4;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 6;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len[3]     = 3;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len[4]     = 2;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';
  token.len[5]     = 32;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '*';
  token.len[6]     = 32;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '*';
  token.len[7]     = 64;
  token.attr[7]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos               = token.buf[1];
  const u8 *spinCount_pos             = token.buf[2];
  const u8 *keySize_pos               = token.buf[3];
  const u8 *saltSize_pos              = token.buf[4];
  const u8 *osalt_pos                 = token.buf[5];
  const u8 *encryptedVerifier_pos     = token.buf[6];
  const u8 *encryptedVerifierHash_pos = token.buf[7];

  const u32 version   = hc_strtoul ((const char *) version_pos, NULL, 10);
  const u32 spinCount = hc_strtoul ((const char *) spinCount_pos, NULL, 10);
  const u32 keySize   = hc_strtoul ((const char *) keySize_pos, NULL, 10);
  const u32 saltSize  = hc_strtoul ((const char *) saltSize_pos, NULL, 10);

  if (version   != 2010)    return (PARSER_SALT_VALUE);
  if (spinCount != 100000)  return (PARSER_SALT_VALUE);
  if (keySize   != 128)     return (PARSER_SALT_VALUE);
  if (saltSize  != 16)      return (PARSER_SALT_VALUE);

  /**
   * salt
   */

  salt->salt_len  = 16;
  salt->salt_iter = spinCount;

  salt->salt_buf[0] = hex_to_u32 (osalt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (osalt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (osalt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (osalt_pos + 24);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  /**
   * esalt
   */

  office2010->encryptedVerifier[0] = hex_to_u32 (encryptedVerifier_pos +  0);
  office2010->encryptedVerifier[1] = hex_to_u32 (encryptedVerifier_pos +  8);
  office2010->encryptedVerifier[2] = hex_to_u32 (encryptedVerifier_pos + 16);
  office2010->encryptedVerifier[3] = hex_to_u32 (encryptedVerifier_pos + 24);

  office2010->encryptedVerifier[0] = byte_swap_32 (office2010->encryptedVerifier[0]);
  office2010->encryptedVerifier[1] = byte_swap_32 (office2010->encryptedVerifier[1]);
  office2010->encryptedVerifier[2] = byte_swap_32 (office2010->encryptedVerifier[2]);
  office2010->encryptedVerifier[3] = byte_swap_32 (office2010->encryptedVerifier[3]);

  office2010->encryptedVerifierHash[0] = hex_to_u32 (encryptedVerifierHash_pos +  0);
  office2010->encryptedVerifierHash[1] = hex_to_u32 (encryptedVerifierHash_pos +  8);
  office2010->encryptedVerifierHash[2] = hex_to_u32 (encryptedVerifierHash_pos + 16);
  office2010->encryptedVerifierHash[3] = hex_to_u32 (encryptedVerifierHash_pos + 24);
  office2010->encryptedVerifierHash[4] = hex_to_u32 (encryptedVerifierHash_pos + 32);
  office2010->encryptedVerifierHash[5] = hex_to_u32 (encryptedVerifierHash_pos + 40);
  office2010->encryptedVerifierHash[6] = hex_to_u32 (encryptedVerifierHash_pos + 48);
  office2010->encryptedVerifierHash[7] = hex_to_u32 (encryptedVerifierHash_pos + 56);

  office2010->encryptedVerifierHash[0] = byte_swap_32 (office2010->encryptedVerifierHash[0]);
  office2010->encryptedVerifierHash[1] = byte_swap_32 (office2010->encryptedVerifierHash[1]);
  office2010->encryptedVerifierHash[2] = byte_swap_32 (office2010->encryptedVerifierHash[2]);
  office2010->encryptedVerifierHash[3] = byte_swap_32 (office2010->encryptedVerifierHash[3]);
  office2010->encryptedVerifierHash[4] = byte_swap_32 (office2010->encryptedVerifierHash[4]);
  office2010->encryptedVerifierHash[5] = byte_swap_32 (office2010->encryptedVerifierHash[5]);
  office2010->encryptedVerifierHash[6] = byte_swap_32 (office2010->encryptedVerifierHash[6]);
  office2010->encryptedVerifierHash[7] = byte_swap_32 (office2010->encryptedVerifierHash[7]);

  /**
   * digest
   */

  digest[0] = office2010->encryptedVerifierHash[0];
  digest[1] = office2010->encryptedVerifierHash[1];
  digest[2] = office2010->encryptedVerifierHash[2];
  digest[3] = office2010->encryptedVerifierHash[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const office2010_t *office2010 = (const office2010_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s*%d*%d*%d*%d*%08x%08x%08x%08x*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x%08x%08x",
    SIGNATURE_OFFICE2010,
    2010,
    100000,
    128,
    16,
    salt->salt_buf[0],
    salt->salt_buf[1],
    salt->salt_buf[2],
    salt->salt_buf[3],
    office2010->encryptedVerifier[0],
    office2010->encryptedVerifier[1],
    office2010->encryptedVerifier[2],
    office2010->encryptedVerifier[3],
    office2010->encryptedVerifierHash[0],
    office2010->encryptedVerifierHash[1],
    office2010->encryptedVerifierHash[2],
    office2010->encryptedVerifierHash[3],
    office2010->encryptedVerifierHash[4],
    office2010->encryptedVerifierHash[5],
    office2010->encryptedVerifierHash[6],
    office2010->encryptedVerifierHash[7]);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
