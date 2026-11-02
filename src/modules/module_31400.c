/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Note that this module is intended to crack only the master passphrase of a SecureCRT config stored in the 2: format (versions < 9.3)
 * See https://github.com/HyperSine/how-does-SecureCRT-encrypt-password for decrypting passwords after you've cracked the master passphrase (or if there is no master passphrase)
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "SecureCRT MasterPassphrase v2";
static const u64   KERN_TYPE      = 31400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE; // OPTS_TYPE_PT_ADD80 and OPTS_TYPE_PT_ADDBITS15 added within kernel
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "S:\"Config Passphrase\"=02:ded7137400e0a1004a12f1708453968ccc270908ba02ab0345c83690d1de3d9937587be66ad2a7fe8cc6cb16ecff02e61ac05e09d4f49f284efd24f6b16d6ae3";

#include "hooks_common.c"

typedef struct scrtv2
{
  u32 ct_buf[64];
  int ct_len;

} scrtv2_t;

static const char *CONFIGPASSPHRASEV2_SIGNATURE = "S:\"Config Passphrase\"=02:"; //The whole line is part of the format to prevent confusion with other similar tokens also prefixed with 02: in the config files

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (scrtv2_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  scrtv2_t *scrtv2 = (scrtv2_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = CONFIGPASSPHRASEV2_SIGNATURE;

  token.len[0]     = 25;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 96;
  token.len_max[1] = 224;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // some fake salt so we can have an esalt

  salt->salt_buf[0] = 0;

  salt->salt_len = 4;

  const int ct_len = token.len[1];
  const u8 *ct_pos = token.buf[1];

  scrtv2->ct_len = hex_decode (ct_pos, ct_len, (u8 *) scrtv2->ct_buf);

  // hash

  digest[0] = hex_to_u32 (ct_pos +  0);
  digest[1] = hex_to_u32 (ct_pos +  8);
  digest[2] = hex_to_u32 (ct_pos + 16);
  digest[3] = hex_to_u32 (ct_pos + 24);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const scrtv2_t *scrtv2 = (const scrtv2_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf (line_buf, line_size, "%s", CONFIGPASSPHRASEV2_SIGNATURE);

  out_len += hex_encode ((const u8 *) scrtv2->ct_buf, scrtv2->ct_len, out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
}
