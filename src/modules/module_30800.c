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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "TronLink Wallet (PBKDF2-HMAC-SHA512, AES-256-CTR)";
static const u64   KERN_TYPE      = 30800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$tronlink$37623463666432613965366231386433*b60fdbf851a8d4d8822dbc5e3959464202a5b3d51a2da85b0832bbd4c8ff1e3072ce7e403cc3ed58713b70c9b4130aba5d763dd07d127a22d1eec3ef6190ea85";

#include "hooks_common.c"

// The wallet stores the private key as a 64 character hex string, so the ciphertext is always
// 64 bytes. The salt is a string the keystore carries verbatim and its length is not fixed by
// the format, because the extension only ever reads a keystore and never writes one.

#define TRONLINK_CT_LEN 64

static const char *SIGNATURE_TRONLINK = "$tronlink$";

typedef struct tronlink
{
  u32 ciphertext[TRONLINK_CT_LEN / 4];

} tronlink_t;

typedef struct tronlink_tmp
{
  u64 out[4];

} tronlink_tmp_t;

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use tools/tronlink2hashcat.py to extract the hash from a TronLink keystore file";
}

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (tronlink_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (tronlink_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  tronlink_t *tronlink = (tronlink_t *) esalt_buf;

  memset (tronlink, 0, sizeof (tronlink_t));

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_TRONLINK;

  // signature
  token.len[0]  = 10;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  // salt, hex encoded because the keystore carries it as free text
  token.sep[1]     = '*';
  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;
  }

  // ciphertext
  token.sep[2]  = '*';
  token.len[2]  = TRONLINK_CT_LEN * 2;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  salt->salt_iter = 1;

  // the kernel hands these to AES256_encrypt, which takes big endian words

  const u8 *ciphertext_pos = token.buf[2];

  for (int i = 0; i < (TRONLINK_CT_LEN / 4); i++)
  {
    tronlink->ciphertext[i] = byte_swap_32 (hex_to_u32 (ciphertext_pos + (i * 8)));
  }

  // there is no stored digest to match, so the kernel reports the first block of the ciphertext
  // back once the decrypted private key reads as hex

  digest[0] = tronlink->ciphertext[0];
  digest[1] = tronlink->ciphertext[1];
  digest[2] = tronlink->ciphertext[2];
  digest[3] = tronlink->ciphertext[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const tronlink_t *tronlink = (const tronlink_t *) esalt_buf;

  char tmp_salt[(SALT_MAX * 2) + 1];

  const int salt_len = generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, (u8 *) tmp_salt);

  tmp_salt[salt_len] = 0;

  char ciphertext_hex[(TRONLINK_CT_LEN * 2) + 1];

  for (int i = 0; i < (TRONLINK_CT_LEN / 4); i++)
  {
    snprintf (ciphertext_hex + (i * 8), 9, "%08x", tronlink->ciphertext[i]);
  }

  const int out_len = snprintf (line_buf, line_size, "%s%s*%s", SIGNATURE_TRONLINK, tmp_salt, ciphertext_hex);

  return out_len;
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
