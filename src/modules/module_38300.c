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
#include "emu_inc_hash_md5.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "Apple DMG (encrcdsa v2, PBKDF2-HMAC-SHA1 + AES-192 key)";
static const u64   KERN_TYPE      = 38300;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "po99oo";
static const char *ST_HASH        = "$dmg$3*20*20a528dfdc3dc653d5da26923cd7b07d03eda76e*192*64*17b5d1683f6cd8b076943f1397d96f2d7a966596bd4c816334f444b26c33b6dd1a2f309a375ed9c3a612b5877c75ea6c2f3053fdb4c2b9a477d6291573fcb7cd*384615";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Extract $dmg$3 hashes with dmg2john from John the Ripper PR #6029 (https://github.com/openwall/john/pull/6029) until it is merged into bleeding-jumbo";
}

typedef struct dmg_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} dmg_tmp_t;

typedef struct dmg
{
  u32 data_buf[16]; // 64-byte AES-192 wrapped key blob
  int data_len;

} dmg_t;

static const char *SIGNATURE_DMG = "$dmg$3";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (dmg_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (dmg_tmp_t);

  return tmp_size;
}

u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 20; }
u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 20; }

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  dmg_t *dmg = (dmg_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DMG;

  token.sep[0]     = '*';   // separator after the "$dmg$3" signature
  token.len[0]     = 6; // "$dmg$3"
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';   // salt len (bytes)
  token.len_min[1] = 1;
  token.len_max[1] = 2;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';   // salt hex (20 bytes)
  token.len_min[2] = 40;
  token.len_max[2] = 40;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';   // key bits (192)
  token.len_min[3] = 3;
  token.len_max[3] = 3;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';   // keyblob len (64)
  token.len_min[4] = 2;
  token.len_max[4] = 3;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';   // keyblob hex (64 bytes)
  token.len_min[5] = 128;
  token.len_max[5] = 128;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[6] = 1;     // iterations (last token, no separator)
  token.len_max[6] = 8;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // validate declared fields against the actual tokens

  const u32 declared_salt_len = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  const u32 key_bits          = hc_strtoul ((const char *) token.buf[3], NULL, 10);
  const u32 declared_blob_len = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  if (key_bits != 192) return (PARSER_CIPHER);                       // only AES-192 blobs
  if ((u32) token.len[2] / 2 != declared_salt_len) return (PARSER_SALT_LENGTH);
  if (declared_blob_len != 64) return (PARSER_HASH_LENGTH);
  if ((u32) token.len[5] / 2 != declared_blob_len) return (PARSER_HASH_LENGTH);

  // salt
  salt->salt_len = hex_decode (token.buf[2], token.len[2], (u8 *) salt->salt_buf);

  // iterations
  const u32 iter = hc_strtoul ((const char *) token.buf[6], NULL, 10);
  if (iter < 1) return (PARSER_SALT_ITERATION);
  salt->salt_iter = iter - 1;

  // keyblob -> esalt (AES-192)
  dmg->data_len = hex_decode (token.buf[5], token.len[5], (u8 *) dmg->data_buf);
  if (dmg->data_len != 64) return (PARSER_HASH_LENGTH);

  // identity digest = MD5 of the whole key blob, so distinct blobs that share a salt and a
  // leading block still get distinct identities for dedup/potfile. The kernel reports the same
  // MD5 on a match; the real password check is the CKIE test in the kernel.
  md5_ctx_t md5_ctx;

  md5_init   (&md5_ctx);
  md5_update (&md5_ctx, dmg->data_buf, 64);
  md5_final  (&md5_ctx);

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const dmg_t *dmg = (const dmg_t *) esalt_buf;

  char salt_buf[65] = { 0 };
  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_buf);

  char data_buf[129] = { 0 };
  hex_encode ((const u8 *) dmg->data_buf, dmg->data_len, (u8 *) data_buf);

  const int out_len = snprintf (line_buf, line_size, "%s*%d*%s*192*%d*%s*%u",
    SIGNATURE_DMG,
    salt->salt_len,
    salt_buf,
    dmg->data_len,
    data_buf,
    salt->salt_iter + 1);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
