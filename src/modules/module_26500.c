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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "iPhone passcode (UID key + System Keybag)";
static const u64   KERN_TYPE      = 26500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$uido$77889b1bca161ce876d976a102c7bf82$3090545724551425617156367874312887832777$50000$2d4c86b71c0c04129a47c6468e2437d1fecd88e232a7b15112d5364682dc391dbbbb921cf6e02664";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/keybag2hashcat.py to extract the hashes";
}

typedef struct iphone_passcode_tmp
{
  u32 key0[4];          // original key from pbkdf2
  u32 key1[4];          // original key from pbkdf2

  u32 iterated_key0[4]; // updated key from pbkdf2 with iterations
  u32 iterated_key1[4]; // updated key from pbkdf2 with iterations

  u32 iv[4];            // current iv

} iphone_passcode_tmp_t;

typedef struct iphone_passcode
{
  u32 uidkey[4];
  u32 classkey1[10];

} iphone_passcode_t;

static const char *SIGNATURE_IPHONE_PASSCODE = "$uido$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (iphone_passcode_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (iphone_passcode_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  iphone_passcode_t *iphone_passcode = (iphone_passcode_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_IPHONE_PASSCODE;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 32;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len[2]     = 40;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 7;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '$';
  token.len[4]     = 80;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // uidkey

  const u8 *uidkey_pos = token.buf[1];

  iphone_passcode->uidkey[0] = hex_to_u32 (uidkey_pos +  0);
  iphone_passcode->uidkey[1] = hex_to_u32 (uidkey_pos +  8);
  iphone_passcode->uidkey[2] = hex_to_u32 (uidkey_pos + 16);
  iphone_passcode->uidkey[3] = hex_to_u32 (uidkey_pos + 24);

  iphone_passcode->uidkey[0] = byte_swap_32 (iphone_passcode->uidkey[0]);
  iphone_passcode->uidkey[1] = byte_swap_32 (iphone_passcode->uidkey[1]);
  iphone_passcode->uidkey[2] = byte_swap_32 (iphone_passcode->uidkey[2]);
  iphone_passcode->uidkey[3] = byte_swap_32 (iphone_passcode->uidkey[3]);

  // salt

  const u8 *salt_pos = token.buf[2];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);
  salt->salt_buf[4] = hex_to_u32 (salt_pos + 32);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);
  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);

  salt->salt_len = 20;

  // iter

  const u8 *iter_pos = token.buf[3];

  int iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  salt->salt_iter = iter;

  // classkey1

  const u8 *classkey1_pos = token.buf[4];

  iphone_passcode->classkey1[0] = hex_to_u32 (classkey1_pos +  0);
  iphone_passcode->classkey1[1] = hex_to_u32 (classkey1_pos +  8);
  iphone_passcode->classkey1[2] = hex_to_u32 (classkey1_pos + 16);
  iphone_passcode->classkey1[3] = hex_to_u32 (classkey1_pos + 24);
  iphone_passcode->classkey1[4] = hex_to_u32 (classkey1_pos + 32);
  iphone_passcode->classkey1[5] = hex_to_u32 (classkey1_pos + 40);
  iphone_passcode->classkey1[6] = hex_to_u32 (classkey1_pos + 48);
  iphone_passcode->classkey1[7] = hex_to_u32 (classkey1_pos + 56);
  iphone_passcode->classkey1[8] = hex_to_u32 (classkey1_pos + 64);
  iphone_passcode->classkey1[9] = hex_to_u32 (classkey1_pos + 72);

  iphone_passcode->classkey1[0] = byte_swap_32 (iphone_passcode->classkey1[0]);
  iphone_passcode->classkey1[1] = byte_swap_32 (iphone_passcode->classkey1[1]);
  iphone_passcode->classkey1[2] = byte_swap_32 (iphone_passcode->classkey1[2]);
  iphone_passcode->classkey1[3] = byte_swap_32 (iphone_passcode->classkey1[3]);
  iphone_passcode->classkey1[4] = byte_swap_32 (iphone_passcode->classkey1[4]);
  iphone_passcode->classkey1[5] = byte_swap_32 (iphone_passcode->classkey1[5]);
  iphone_passcode->classkey1[6] = byte_swap_32 (iphone_passcode->classkey1[6]);
  iphone_passcode->classkey1[7] = byte_swap_32 (iphone_passcode->classkey1[7]);
  iphone_passcode->classkey1[8] = byte_swap_32 (iphone_passcode->classkey1[8]);
  iphone_passcode->classkey1[9] = byte_swap_32 (iphone_passcode->classkey1[9]);

  // hash

  digest[0] = iphone_passcode->classkey1[0];
  digest[1] = iphone_passcode->classkey1[1];
  digest[2] = iphone_passcode->classkey1[2];
  digest[3] = iphone_passcode->classkey1[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const iphone_passcode_t *iphone_passcode = (const iphone_passcode_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  const int out_len = snprintf ((char *) out_buf, line_size, "%s%08x%08x%08x%08x$%08x%08x%08x%08x%08x$%d$%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
    SIGNATURE_IPHONE_PASSCODE,
    iphone_passcode->uidkey[0],
    iphone_passcode->uidkey[1],
    iphone_passcode->uidkey[2],
    iphone_passcode->uidkey[3],
    salt->salt_buf[0],
    salt->salt_buf[1],
    salt->salt_buf[2],
    salt->salt_buf[3],
    salt->salt_buf[4],
    salt->salt_iter,
    iphone_passcode->classkey1[0],
    iphone_passcode->classkey1[1],
    iphone_passcode->classkey1[2],
    iphone_passcode->classkey1[3],
    iphone_passcode->classkey1[4],
    iphone_passcode->classkey1[5],
    iphone_passcode->classkey1[6],
    iphone_passcode->classkey1[7],
    iphone_passcode->classkey1[8],
    iphone_passcode->classkey1[9]);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
