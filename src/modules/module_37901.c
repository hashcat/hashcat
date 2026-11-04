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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "BestCrypt Container (.jbc), SHA-256 + AES-XTS";
static const u64   KERN_TYPE      = 37900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "openwall";
static const char *ST_HASH        = "$BestCrypt$1$5$3$16384$240$3154116612$128$32$51f7450dccbb1c947dd46138bf0d80d588b6938b02505642dde9e1ea61481485$1$a186f281fbbc68f3b27c7b4cc16b7916a2e19c2695b34ee4133a6ac6373db67b88fb54e3def1c0d288d3170dcb5860c2f190ab199fde7f1072a2a109441e608ae46890c5f18ab80803012a43d9cc595a45c5b9ed8b3ed3330cab1a29e5a96512e2f2e0e5927d6836c3a67c1cd13a61a8201a0a99be84c3e19e6d8a12330ae72c22179d37bb7d55034bb96b5cf9f73c11fa82be31d06bfe33305b616cc72079777a5f1f4a720b56470a83da08c17cbc86e34961c4f0bdb8556e2afa0b2b890780e03304725ce7cf8c592f037beb04b393f4f02e3bc9f6582082a39d31f2e643c5f7811f30eeee2ccc6c11496b7d70dc0d300e145408d28448ff5d929c42007dbe";

#include "hooks_common.c"

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode cracks the password of a Jetico BestCrypt container (.jbc) written by key generator 5, which is what BestCrypt 8 and 9 use. Use https://github.com/hashcat/hashcat/blob/master/tools/bestcrypt2hashcat.py to write the line. The hash id and the cipher mode together pick the mode: 128 for SHA-256 is hash-mode 37900 in CBC and 37901 in XTS, 10 for SHA-512 is 37902 and 129 for Whirlpool-512 is 37903. SHA-256 has one mode per cipher because its XTS key takes a second pass of the key derivation and its CBC key does not. AES is the only cipher the container format exposes in clear, in CBC or in XTS, and the line carries one key slot, so a container with several passwords gives one line per slot. The password enters the key generator one byte per character, so one outside ASCII is not reached";
}

#define BESTCRYPT_ALG_AES     240
#define BESTCRYPT_MODE_CBC    0xBC000002
#define BESTCRYPT_MODE_XTS    0xBC000004
#define BESTCRYPT_HASH_SHA256 128

#define BESTCRYPT_SALT_LEN 64
#define BESTCRYPT_SLOT_LEN 256

typedef struct bestcrypt_sha256_tmp
{
  u32 dgst[8];
  u32 out[8];

} bestcrypt_sha256_tmp_t;

typedef struct bestcrypt
{
  u32 slot_buf[BESTCRYPT_SLOT_LEN / 4];

} bestcrypt_t;

static const char *SIGNATURE_BESTCRYPT = "$BestCrypt$";

static u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

static u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // the key generator widens the password and appends a terminator, then fills as many 64 byte
  // blocks as that needs, so no part of the password is left out here. The limit is the buffer the
  // kernel widens into, and 63 characters is the 128 bytes of two blocks.

  const u32 pw_max = 63;

  return pw_max;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (bestcrypt_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bestcrypt_sha256_tmp_t);

  return tmp_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  bestcrypt_t *bestcrypt = (bestcrypt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 12;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BESTCRYPT;

  token.len[0]     = 11;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // the format version, the key generator id and the key generator version

  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 1;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len[3]     = 1;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // the iteration count

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 7;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // the cipher and its mode

  token.sep[5]     = '$';
  token.len_min[5] = 1;
  token.len_max[5] = 5;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '$';
  token.len_min[6] = 1;
  token.len_max[6] = 10;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // the hash the key generator runs

  token.sep[7]     = '$';
  token.len_min[7] = 1;
  token.len_max[7] = 3;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // the salt and its size in bytes

  token.sep[8]     = '$';
  token.len_min[8] = 1;
  token.len_max[8] = 2;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[9]     = '$';
  token.len_min[9] = 2;
  token.len_max[9] = BESTCRYPT_SALT_LEN * 2;
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // the count of active key slots and the slot itself

  token.sep[10]    = '$';
  token.len[10]    = 1;
  token.attr[10]   = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[11]    = '$';
  token.len[11]    = BESTCRYPT_SLOT_LEN * 2;
  token.attr[11]   = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // the derivation below is the one key generator 5 version 3 writes, so the three leading fields
  // are fixed rather than read

  if (token.buf[1][0] != '1') return (PARSER_SALT_VALUE);
  if (token.buf[2][0] != '5') return (PARSER_SALT_VALUE);
  if (token.buf[3][0] != '3') return (PARSER_SALT_VALUE);

  // iterations

  const u32 iter = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // the cipher

  const u32 alg_id = hc_strtoul ((const char *) token.buf[5], NULL, 10);

  if (alg_id != BESTCRYPT_ALG_AES) return (PARSER_CIPHER);

  // the cipher mode belongs to the salt rather than to the slot. It decides how much key material
  // the derivation produces, so two slots that share a salt have to share it too.

  const u32 mode_id = hc_strtoul ((const char *) token.buf[6], NULL, 10);

  if (mode_id != BESTCRYPT_MODE_XTS) return (PARSER_CIPHER);

  salt->salt_buf_pc[0] = mode_id;
  salt->salt_len_pc    = 4;

  // SHA-256 reaches 32 bytes of key material in one pass of the derivation, and XTS takes a 64 byte
  // key, so the whole iteration count runs a second time over a salt and password block the first
  // pass stepped on. The count is the same for every salt of this mode, which the association
  // attack needs: it runs the salt loop once with salt_pos 0 and reads the per item salt in the
  // kernel, so a repeat count that varied between salts would be taken from one of them for all.

  salt->salt_repeats = 1;

  // the hash, which is what separates this mode from its two siblings

  const u32 hash_id = hc_strtoul ((const char *) token.buf[7], NULL, 10);

  if (hash_id != BESTCRYPT_HASH_SHA256) return (PARSER_SALT_VALUE);

  // the salt

  const u32 salt_size = hc_strtoul ((const char *) token.buf[8], NULL, 10);

  if (salt_size < 1)                  return (PARSER_SALT_LENGTH);
  if (salt_size > BESTCRYPT_SALT_LEN) return (PARSER_SALT_LENGTH);

  if (token.len[9] != (int) (salt_size * 2)) return (PARSER_SALT_LENGTH);

  salt->salt_len = hex_decode (token.buf[9], token.len[9], (u8 *) salt->salt_buf);

  // one active key slot per line

  if (token.buf[10][0] != '1') return (PARSER_SALT_VALUE);

  // the key slot. Only its first 128 bytes and the IV behind them take part in the check, and the
  // rest is kept so that --show prints back the line that was read.

  hex_decode (token.buf[11], token.len[11], (u8 *) bestcrypt->slot_buf);

  // the password is verified against a digest the slot carries encrypted, which is not known until
  // the slot has been decrypted, so the first block of the slot stands in for a digest the way
  // hash-modes 26610 and 37240 do

  digest[0] = bestcrypt->slot_buf[0];
  digest[1] = bestcrypt->slot_buf[1];
  digest[2] = bestcrypt->slot_buf[2];
  digest[3] = bestcrypt->slot_buf[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const bestcrypt_t *bestcrypt = (const bestcrypt_t *) esalt_buf;

  char salt_hex[(BESTCRYPT_SALT_LEN * 2) + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_hex);

  char slot_hex[(BESTCRYPT_SLOT_LEN * 2) + 1] = { 0 };

  hex_encode ((const u8 *) bestcrypt->slot_buf, BESTCRYPT_SLOT_LEN, (u8 *) slot_hex);

  const int line_len = snprintf (line_buf, line_size, "%s1$5$3$%u$%u$%u$%u$%u$%s$1$%s",
    SIGNATURE_BESTCRYPT,
    salt->salt_iter + 1,
    BESTCRYPT_ALG_AES,
    salt->salt_buf_pc[0],
    BESTCRYPT_HASH_SHA256,
    salt->salt_len,
    salt_hex,
    slot_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
