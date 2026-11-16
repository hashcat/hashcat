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

#include "emu_inc_hash_base58.h"
#include "emu_inc_hash_md5.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Tezos Presale Wallet (PBKDF2-SHA512, ed25519)";
static const u64   KERN_TYPE      = 44500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_MULTIHASH_DESPITE_ESALT;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat-1625!";
static const char *ST_HASH        = "$tezos$1*2048*legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank*hashcat.research@example.com*tz1fSt5Pn9KpiBk9KBagBhHETDXNgtU5Y2wT*a19fd946bf736f513f29013aa183775634dcf3002285";

#include "hooks_common.c"

static const u32 ITER_TEZOS = 2048;

static const char *SIGNATURE_TEZOS = "$tezos$1";

typedef struct pbkdf2_sha512_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[8];
  u64 out[8];

} pbkdf2_sha512_tmp_t;

typedef struct tezos
{
  u32 mnemonic_len;
  u32 email_len;

  char mnemonic[132];
  char email[256];
  char address[37];

} tezos_t;

// Hashes that share a mnemonic and an email share a salt, and the address is deliberately left
// out of the salt so one run covers several addresses of the same wallet. The salt is an MD5 over
// the two fields and their lengths, as module_36000.c does: the fields no longer fit salt_buf at
// fixed offsets once the email reaches 255 bytes, and two lines now agree on a salt only when
// their kernel input is identical. Those fields are the esalt values the kernels read, which is
// what makes OPTS_TYPE_MULTIHASH_DESPITE_ESALT safe here. The per-address target lives in the
// digest.

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (tezos_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);

  return tmp_size;
}

static void tezos_set_salt_key (const tezos_t *tezos, salt_t *salt)
{
  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);
  md5_update (&md5_ctx, &tezos->mnemonic_len, sizeof (tezos->mnemonic_len));
  md5_update (&md5_ctx, (const u32 *) tezos->mnemonic, tezos->mnemonic_len);
  md5_update (&md5_ctx, &tezos->email_len, sizeof (tezos->email_len));
  md5_update (&md5_ctx, (const u32 *) tezos->email, tezos->email_len);
  md5_final (&md5_ctx);

  salt->salt_buf[0] = md5_ctx.h[0];
  salt->salt_buf[1] = md5_ctx.h[1];
  salt->salt_buf[2] = md5_ctx.h[2];
  salt->salt_buf[3] = md5_ctx.h[3];
  salt->salt_len = 16;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u8 *digest = (u8 *) digest_buf;

  tezos_t *tezos = (tezos_t *) esalt_buf;

  memset (tezos, 0, sizeof (tezos_t));

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_TEZOS;

  // signature
  token.sep[0]  = '*';
  token.len[0]  = 8;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  // iterations
  token.sep[1]  = '*';
  token.len[1]  = 4;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH;

  // mnemonic
  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 128;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // email
  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 255;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // tz1 address
  token.sep[4]  = '*';
  token.len[4]  = 36;
  token.attr[4] = TOKEN_ATTR_FIXED_LENGTH;

  // public key hash (hex, with a19f prefix)
  token.len[5]  = 44;
  token.attr[5] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iterations

  const u8 *iter_pos = token.buf[1];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter != ITER_TEZOS) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // mnemonic (HMAC key)

  const u8 *mnemonic_pos = token.buf[2];
  const int mnemonic_len = token.len[2];

  memcpy (tezos->mnemonic, mnemonic_pos, mnemonic_len);

  tezos->mnemonic_len = mnemonic_len;

  // email

  const u8 *email_pos = token.buf[3];
  const int email_len = token.len[3];

  memcpy (tezos->email, email_pos, email_len);

  tezos->email_len = email_len;

  tezos_set_salt_key (tezos, salt);

  // tz1 address

  const u8 *address_pos = token.buf[4];
  const int address_len = token.len[4];

  if (address_pos[0] != 't') return (PARSER_HASH_VALUE);
  if (address_pos[1] != 'z') return (PARSER_HASH_VALUE);
  if (address_pos[2] != '1') return (PARSER_HASH_VALUE);

  memcpy (tezos->address, address_pos, address_len);

  u8 address_bin[32];

  u32 address_bin_len = sizeof (address_bin);

  if (b58dec (address_bin, &address_bin_len, address_pos, address_len) == false) return (PARSER_HASH_ENCODING);

  if (address_bin_len != 27) return (PARSER_HASH_LENGTH);

  // b58dec right-aligns the result inside the buffer

  const u8 *address_dec = address_bin + (sizeof (address_bin) - address_bin_len);

  if (address_dec[0] != 0x06) return (PARSER_HASH_VALUE);
  if (address_dec[1] != 0xa1) return (PARSER_HASH_VALUE);
  if (address_dec[2] != 0x9f) return (PARSER_HASH_VALUE);

  if (b58check (address_dec, address_bin_len) == false) return (PARSER_HASH_ENCODING);

  // public key hash

  const u8 *pkh_pos = token.buf[5];

  if (pkh_pos[0] != 'a') return (PARSER_HASH_VALUE);
  if (pkh_pos[1] != '1') return (PARSER_HASH_VALUE);
  if (pkh_pos[2] != '9') return (PARSER_HASH_VALUE);
  if (pkh_pos[3] != 'f') return (PARSER_HASH_VALUE);

  hex_decode (pkh_pos + 4, 40, digest);

  // the tz1 address and the hex public key hash have to agree

  if (memcmp (address_dec + 3, digest, 20) != 0) return (PARSER_HASH_VALUE);

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u8 *digest = (const u8 *) digest_buf;

  const tezos_t *tezos = (const tezos_t *) esalt_buf;

  char pkh_hex[41] = { 0 };

  hex_encode (digest, 20, (u8 *) pkh_hex);

  const int out_len = snprintf (line_buf, line_size, "$tezos$1*%u*%s*%s*%s*a19f%s",
    ITER_TEZOS,
    tezos->mnemonic,
    tezos->email,
    tezos->address,
    pkh_hex);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
