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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "SecureZIP AES-192";
static const u64   KERN_TYPE      = 23002;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS15;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$zip3$*0*1*192*0*53ff2de8c280778e1e0ab997*603eb37dbab9ea109e2c405e37d8cae1ec89e1e0d0b9ce5bf55d1b571c343b6a3df35fe381c30249cb0738a9b956ba8e52dfc5552894296300446a771032776c811ff8a71d9bb3c4d6c37016c027e41fea2d157d5b0ce17804b1d7c1606b7c1121d37851bd705e001f2cd755bbf305966d129a17c1d48ff8e87cfa41f479090cd456527db7d1d43f9020ad8e73f851a5*0*0*0*file.txt";

#include "hooks_common.c"

typedef struct securezip
{
  u32 data[36];
  u32 file[16];
  u32 iv[4];
  u32 iv_len;

} securezip_t;

static const char *SIGNATURE_SECUREZIP = "$zip3$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (securezip_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  securezip_t *securezip = (securezip_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt   = 11;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SECUREZIP;

  token.sep[0]      = '*';
  token.len[0]      = 6;
  token.attr[0]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]      = '*';
  token.len[1]      = 1;
  token.attr[1]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]      = '*';
  token.len[2]      = 1;
  token.attr[2]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]      = '*';
  token.len[3]      = 3;
  token.attr[3]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]      = '*';
  token.len[4]      = 1;
  token.attr[4]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]      = '*';
  token.len_min[5]  = 0;
  token.len_max[5]  = 32;
  token.attr[5]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]      = '*';
  token.len[6]      = 288;
  token.attr[6]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]      = '*';
  token.len[7]      = 1;
  token.attr[7]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]      = '*';
  token.len[8]      = 1;
  token.attr[8]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[9]      = '*';
  token.len[9]      = 1;
  token.attr[9]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[10]     = '*';
  token.len_min[10] = 0;
  token.len_max[10] = 64;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *version_pos = token.buf[ 1];
  const u8 *type_pos    = token.buf[ 2];
  const u8 *bit_len_pos = token.buf[ 3];
  const u8 *unused1_pos = token.buf[ 4];
  const u8 *iv_pos      = token.buf[ 5];
  const u8 *data_pos    = token.buf[ 6];
  const u8 *unused2_pos = token.buf[ 7];
  const u8 *unused3_pos = token.buf[ 8];
  const u8 *unused4_pos = token.buf[ 9];
  const u8 *file_pos    = token.buf[10];

  if (version_pos[0] != '0') return (PARSER_HASH_ENCODING); // version 0
  if (type_pos[0]    != '1') return (PARSER_HASH_ENCODING); // AES

  const u32 bit_len = hc_strtoul ((const char *) bit_len_pos, NULL, 10);

  if (bit_len != 192) return (PARSER_HASH_ENCODING);

  if (unused1_pos[0] != '0') return (PARSER_HASH_ENCODING);
  if (unused2_pos[0] != '0') return (PARSER_HASH_ENCODING);
  if (unused3_pos[0] != '0') return (PARSER_HASH_ENCODING);
  if (unused4_pos[0] != '0') return (PARSER_HASH_ENCODING);

  // IV:

  u8 *iv = (u8 *) securezip->iv;

  securezip->iv_len = hex_decode (iv_pos, token.len[5], iv);

  // data:

  u32 *data = securezip->data;

  hex_decode (data_pos, token.len[6], (u8 *) data);

  // file:

  u8 *file = (u8 *) securezip->file;

  memcpy (file, file_pos, token.len[10]);

  file[63] = 0;

  // fake salt:

  // make salt sorter happy: the kernel checks the ct of the first hash of a salt only, so two
  // entries that share an IV must not share a salt. The ct goes into the salt after the IV.

  salt->salt_buf[0] = iv[0];
  salt->salt_buf[1] = iv[1];
  salt->salt_buf[2] = iv[2];
  salt->salt_buf[3] = iv[3];
  salt->salt_buf[4] = data[0];
  salt->salt_buf[5] = data[1];
  salt->salt_buf[6] = data[2];
  salt->salt_buf[7] = data[3];

  salt->salt_len  = 32;

  // fake digest:

  digest[0] = data[0];
  digest[1] = data[1];
  digest[2] = data[2];
  digest[3] = data[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const securezip_t *securezip = (const securezip_t *) esalt_buf;

  // IV:

  u8 iv[33] = { 0 };

  hex_encode ((const u8 *) securezip->iv, securezip->iv_len, iv);

  // data:

  u8 data[289] = { 0 };

  hex_encode ((const u8 *) securezip->data, 144, data);

  // file:

  const u8 *file_ptr = (const u8 *) securezip->file;

  u8 file[65] = { 0 };

  memcpy (file, file_ptr, 64);

  int out_len = snprintf (line_buf, line_size, "%s*0*1*192*0*%s*%s*0*0*0*%s",
    SIGNATURE_SECUREZIP,
    iv,
    data,
    file
  );

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
}
