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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "GPG (AES-256 (SHA-1($pass)), Symmetric, MDC)";
static const u64   KERN_TYPE      = 17060;
static const bool  LENGTH_SORT    = true;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE
                                  | KERN_BIT_AUX1;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "password";
static const char *ST_HASH        = "$gpg$*0*63*1c890c019b24ce46afd906500094ad1afde4d56b9666dee9568cf2d47315b36e501b340813a62b8b82b72492b00a4595941ebd96de8eab636a00210bc57a13*3*18*2*9*65536*20538c8d69964d96";

#include "hooks_common.c"

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }
static bool        module_length_sort    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return LENGTH_SORT;     }

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/gpg-sym2hashcat.py to extract the hashes";
}

// The whole message has to be carried in the esalt, because the SHA-1 that decides a candidate
// covers the entire decrypted plaintext and sits at the end of it. There is no prefix of the
// ciphertext that answers the question, so the cap on the message is the cap on the mode.

#define GPG_DATA_MAX 1536

// RFC 4880 5.13: 16 random bytes, 2 that repeat the last two of those, the payload, and the
// 2 byte MDC packet header followed by its 20 byte SHA-1. An empty payload is 40 bytes.

#define GPG_DATA_MIN 40

#define GPG_SALT_LEN 8

// the fields a symmetrically encrypted message fixes, which the parser pins and the encoder
// writes back unchanged

#define GPG_PK_ALGO_NONE  0
#define GPG_S2K_ITERATED  3
#define GPG_TAG_SEIPD     18
#define GPG_HASH_SHA1     2
#define GPG_CIPHER_AES256 9

#define GPG_ITER_MIN 8
#define GPG_ITER_MAX 65011712

typedef struct gpg
{
  u32 cipher_algo;
  u32 iv[4];
  u32 modulus_size;
  u32 encrypted_data[GPG_DATA_MAX / 4];
  u32 encrypted_data_size;

} gpg_t;

typedef struct gpg_tmp
{
  u32 salted_pw_block[80];

  u32 salted_pw_block_len;

  u32 h[10];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 len;

} gpg_tmp_t;

static const char *SIGNATURE_GPG = "$gpg$";

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (gpg_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (gpg_tmp_t);

  return tmp_size;
}

static bool module_hlfmt_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool hlfmt_disable = true;

  return hlfmt_disable;
}

static u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 1024;

  return kernel_loops_min;
}

static u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 65536;

  return kernel_loops_max;
}

// One cipher, so the kernel never varies. The mode still goes through the deep comp kernel,
// because that is what walks the digests of one salt. gpg draws a fresh salt for every message
// it writes, so its own output lands one digest per salt, but src/hashes.c refuses a file that
// does hold several messages on one S2K salt and count unless the mode asks for this.

static u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_AUX1;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  gpg_t *gpg = (gpg_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 10;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_GPG;

  token.sep[0]     = '*';
  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 2;
  token.len_max[2] = 4;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = GPG_DATA_MIN * 2;
  token.len_max[3] = GPG_DATA_MAX * 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len[4]     = 1;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';
  token.len[5]     = 2;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '*';
  token.len[6]     = 1;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[7]     = '*';
  token.len[7]     = 1;
  token.attr[7]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]     = '*';
  token.len_min[8] = 1;
  token.len_max[8] = 8;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len[9]     = GPG_SALT_LEN * 2;
  token.attr[9]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  if (hc_strtoul ((const char *) token.buf[1], NULL, 10) != GPG_PK_ALGO_NONE) return (PARSER_HASH_VALUE);

  // checked before hex_decode () writes, so a hash naming more than the mode can hold is
  // refused as a ciphertext length rather than as a token length

  const int enc_data_size = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (enc_data_size < GPG_DATA_MIN) return (PARSER_CT_LENGTH);
  if (enc_data_size > GPG_DATA_MAX) return (PARSER_CT_LENGTH);

  const int encrypted_data_size = hex_decode (token.buf[3], token.len[3], (u8 *) gpg->encrypted_data);

  if (encrypted_data_size != enc_data_size) return (PARSER_CT_LENGTH);

  gpg->encrypted_data_size = encrypted_data_size;

  if (hc_strtoul ((const char *) token.buf[4], NULL, 10) != GPG_S2K_ITERATED) return (PARSER_HASH_VALUE);

  if (hc_strtoul ((const char *) token.buf[5], NULL, 10) != GPG_TAG_SEIPD) return (PARSER_HASH_VALUE);

  if (hc_strtoul ((const char *) token.buf[6], NULL, 10) != GPG_HASH_SHA1) return (PARSER_HASH_VALUE);

  const u32 cipher_algo = hc_strtoul ((const char *) token.buf[7], NULL, 10);

  if (cipher_algo != GPG_CIPHER_AES256) return (PARSER_CIPHER);

  gpg->cipher_algo = cipher_algo;

  // a symmetrically encrypted message carries no IV and no modulus. CFB starts on a zero IV,
  // the random prefix of the plaintext is what the IV would otherwise be.

  gpg->iv[0] = 0;
  gpg->iv[1] = 0;
  gpg->iv[2] = 0;
  gpg->iv[3] = 0;

  gpg->modulus_size = 0;

  const u32 salt_iter = hc_strtoul ((const char *) token.buf[8], NULL, 10);

  if (salt_iter < GPG_ITER_MIN) return (PARSER_SALT_ITERATION);
  if (salt_iter > GPG_ITER_MAX) return (PARSER_SALT_ITERATION);

  salt->salt_iter = salt_iter;

  // SHA-1 gives 20 of the 32 key bytes, so the S2K runs a second time over one 0x00 prefix

  salt->salt_repeats = 1;

  salt->salt_len = hex_decode (token.buf[9], token.len[9], (u8 *) salt->salt_buf);

  if (salt->salt_len != GPG_SALT_LEN) return (PARSER_SALT_LENGTH);

  // hash fake. The siblings use the IV, which this format does not have, so the head of the
  // ciphertext stands in as the per-hash discriminator.

  digest[0] = gpg->encrypted_data[0];
  digest[1] = gpg->encrypted_data[1];
  digest[2] = gpg->encrypted_data[2];
  digest[3] = gpg->encrypted_data[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const gpg_t *gpg = (const gpg_t *) esalt_buf;

  u8 encrypted_data[(GPG_DATA_MAX * 2) + 1];

  memset (encrypted_data, 0, sizeof (encrypted_data));

  hex_encode ((const u8 *) gpg->encrypted_data, gpg->encrypted_data_size, encrypted_data);

  const int line_len = snprintf (line_buf, line_size, "%s*%d*%d*%s*%d*%d*%d*%d*%d*%08x%08x",
    SIGNATURE_GPG,
    GPG_PK_ALGO_NONE,
    gpg->encrypted_data_size,
    encrypted_data,
    GPG_S2K_ITERATED,
    GPG_TAG_SEIPD,
    GPG_HASH_SHA1,
    gpg->cipher_algo,
    salt->salt_iter,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]));

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hlfmt_disable            = module_hlfmt_disable;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_length_sort              = module_length_sort;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
