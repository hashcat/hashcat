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
static const char *HASH_NAME      = "BestCrypt Container (.jbc), Whirlpool-512";
static const u64   KERN_TYPE      = 37903;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "openwall";
static const char *ST_HASH        = "$BestCrypt$1$5$3$16384$240$3154116612$129$64$06b513b2ac314636f616747c4171700133c00d335ee6a6c3a8db60bf672531624f099fa90b8047a5aceb2492c5858cab529cf9ba5d7e8c715e33517b64ef4251$1$5fc5bf3251a22f40cd23bf7a2bed453915f9037d80630d50c4c1d9d5ed3380fbf495e3013a2f1ada864afb2d4cdcc8dcaa8f86be5898bad53244d4382a42ba857420cff29b85c644c43305e9d0daf70a8db9dcaa0acc2d6b7c7e16374c30936a7d457a155ad5f6427c2818b85065eb6ab3751f91d8321ccdbfd13df038a26a01dbee887db43564588a7387e001ec5d23b22cb003a814ebb7cb4cec9b4cfd93e15bdedff0dd6dbbfff6e7fb3abf5f29ce891e3e432795600ea447c95a0900bd48d5ecc18fd6191b34dffe411412e8e8a8a8840d95cf77a51fb58248fbf940429a977f6f392cf6d1fe7b1ead0ee7ccc5264725c476b3f1fe087ffb8d811b6b2a8b";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode cracks the password of a Jetico BestCrypt container (.jbc) written by key generator 5, which is what BestCrypt 8 and 9 use. Use https://github.com/hashcat/hashcat/blob/master/tools/bestcrypt2hashcat.py to write the line. The hash id and the cipher mode together pick the mode: 128 for SHA-256 is hash-mode 37900 in CBC and 37901 in XTS, 10 for SHA-512 is 37902 and 129 for Whirlpool-512 is 37903. SHA-256 has one mode per cipher because its XTS key takes a second pass of the key derivation and its CBC key does not. AES is the only cipher the container format exposes in clear, in CBC or in XTS, and the line carries one key slot, so a container with several passwords gives one line per slot. The password enters the key generator one byte per character, so one outside ASCII is not reached";
}

#define BESTCRYPT_ALG_AES        240
#define BESTCRYPT_MODE_CBC       0xBC000002
#define BESTCRYPT_MODE_XTS       0xBC000004
#define BESTCRYPT_HASH_WHIRLPOOL 129

#define BESTCRYPT_SALT_LEN 64
#define BESTCRYPT_SLOT_LEN 256

typedef struct bestcrypt_whirlpool_tmp
{
  u32 dgst[16];

} bestcrypt_whirlpool_tmp_t;

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
  // the key generator widens the password and appends a terminator, then fills one 64 byte block
  // with it, so the block holds 32 characters and two passwords of 32 or more that begin with the
  // same 32 derive the same key. The limit below is the buffer the kernel widens into rather than
  // that, so a longer candidate is still tried and still reported as the password it is.

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
  const u64 tmp_size = (const u64) sizeof (bestcrypt_whirlpool_tmp_t);

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

  if ((mode_id != BESTCRYPT_MODE_CBC) && (mode_id != BESTCRYPT_MODE_XTS)) return (PARSER_CIPHER);

  salt->salt_buf_pc[0] = mode_id;
  salt->salt_len_pc    = 4;

  // the hash, which is what separates this mode from its two siblings

  const u32 hash_id = hc_strtoul ((const char *) token.buf[7], NULL, 10);

  if (hash_id != BESTCRYPT_HASH_WHIRLPOOL) return (PARSER_SALT_VALUE);

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
    BESTCRYPT_HASH_WHIRLPOOL,
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
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
