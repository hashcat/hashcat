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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Sollet Wallet (PBKDF2-SHA256, XSalsa20)";
static const u64   KERN_TYPE      = 44200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sollet$100000*1bdaf6076a6cff7638bafcf50de39df3*d6ea195008ba3f4b5b11643351a30fc68d291e9df1bbdb62*e7987ba8546dd7e41b5b62f95429d33b";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode cracks the password of a sollet.io wallet, the \"locked\" entry it keeps in the browser's localStorage, which is JSON of the form {\"encrypted\":...,\"nonce\":...,\"kdf\":\"pbkdf2\",\"salt\":...,\"iterations\":...,\"digest\":\"sha256\"}. tools/sollet2hashcat.py writes the line. It carries the iteration count, the salt, the nonce and only the first 16 bytes of the ciphertext, so it holds nothing of the mnemonic. The password is verified against the {\"mnemonic\":\" the encrypted JSON opens with, not against the Poly1305 tag";
}

typedef struct pbkdf2_sha256_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[32];
  u32 out[32];

} pbkdf2_sha256_tmp_t;

typedef struct sollet
{
  u32 nonce[6];
  u32 ct[4];

} sollet_t;

static const char *SIGNATURE_SOLLET = "$sollet$";

static u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (sollet_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha256_tmp_t);

  return tmp_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  sollet_t *sollet = (sollet_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SOLLET;

  token.len[0]     = 8;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 7;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len[3]     = 48;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len[4]     = 32;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u32 iter = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt

  salt->salt_len = hex_decode (token.buf[2], token.len[2], (u8 *) salt->salt_buf);

  // XSalsa20 reads the nonce and the ciphertext in little endian words, which is their byte order

  hex_decode (token.buf[3], token.len[3], (u8 *) sollet->nonce);

  hex_decode (token.buf[4], token.len[4], (u8 *) sollet->ct);

  // the verifier is a known plaintext rather than a stored digest, so the ciphertext block stands
  // in for one, as hash-modes 26610 and 37230 do

  digest[0] = sollet->ct[0];
  digest[1] = sollet->ct[1];
  digest[2] = sollet->ct[2];
  digest[3] = sollet->ct[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const sollet_t *sollet = (const sollet_t *) esalt_buf;

  char salt_hex[(16 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_hex);

  char nonce_hex[(24 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) sollet->nonce, 24, (u8 *) nonce_hex);

  char ct_hex[(16 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) sollet->ct, 16, (u8 *) ct_hex);

  const int line_len = snprintf (line_buf, line_size, "%s%u*%s*%s*%s",
    SIGNATURE_SOLLET,
    salt->salt_iter + 1,
    salt_hex,
    nonce_hex,
    ct_hex);

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
