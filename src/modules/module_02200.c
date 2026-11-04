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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FBE;
static const char *HASH_NAME      = "EncFS (AES)";
static const u64   KERN_TYPE      = 2200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$encfs$192*10000*0*20*59e4e3c5a420133eff84e7fca2ba8fa35a932506*44*561fe2ac319eba49867cbe3a48eaf0fa776bd7c1e6ccdcbc1928e57af6f8219aeca08cad2b724cef32ad4c67";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use tools/encfs2hashcat.py on the encrypted directory or its .encfs6.xml to extract the hash. Only AES volumes are supported";
}

typedef struct encfs_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[15];
  u32  out[15];

} encfs_tmp_t;

typedef struct encfs
{
  u32 key_size;
  u32 data_len;
  u32 checksum;
  u32 data[12];

} encfs_t;

static const char *SIGNATURE_ENCFS = "$encfs$";

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (encfs_tmp_t);

  return tmp_size;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (encfs_t);

  return esalt_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  encfs_t *encfs = (encfs_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ENCFS;

  // signature
  token.len[0]     = 7;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // key size in bits
  token.sep[1]     = '*';
  token.len[1]     = 3;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // iterations
  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 10;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // cipher, 0 is AES
  token.sep[3]     = '*';
  token.len[3]     = 1;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt length
  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 2;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt
  token.sep[5]     = '*';
  token.len_min[5] = 2;
  token.len_max[5] = 80;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // data length
  token.sep[6]     = '*';
  token.len[6]     = 2;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // data, the checksum followed by the encoded volume key and IV
  token.sep[7]     = '*';
  token.len_min[7] = 72;
  token.len_max[7] = 104;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u32 key_bits = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if ((key_bits != 128) && (key_bits != 192) && (key_bits != 256)) return (PARSER_KEY_SIZE);

  const u32 iter = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  const u32 cipher = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if (cipher != 0) return (PARSER_CIPHER);

  const u32 salt_len = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  if (salt_len > 40) return (PARSER_SALT_LENGTH);

  if ((salt_len * 2) != (u32) token.len[5]) return (PARSER_SALT_LENGTH);

  const u32 key_size = key_bits / 8;

  // a blob always holds the key and a 16 byte IV, behind a 4 byte checksum

  const u32 data_len = hc_strtoul ((const char *) token.buf[6], NULL, 10);

  if (data_len != (4 + key_size + 16)) return (PARSER_CT_LENGTH);

  if ((data_len * 2) != (u32) token.len[7]) return (PARSER_CT_LENGTH);

  const u8 *data_pos = token.buf[7];

  encfs->key_size = key_size;
  encfs->data_len = data_len - 4;
  encfs->checksum = byte_swap_32 (hex_to_u32 (data_pos));

  for (u32 i = 0, j = 8; j < (data_len * 2); i += 1, j += 8)
  {
    encfs->data[i] = byte_swap_32 (hex_to_u32 (data_pos + j));
  }

  salt->salt_len  = hex_decode (token.buf[5], token.len[5], (u8 *) salt->salt_buf);
  salt->salt_iter = iter - 1;

  digest[0] = encfs->checksum;
  digest[1] = encfs->data[0];
  digest[2] = encfs->data[1];
  digest[3] = encfs->data[2];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const encfs_t *encfs = (const encfs_t *) esalt_buf;

  int line_len = 0;

  line_len += snprintf (line_buf + line_len, line_size - line_len, "%s%u*%u*0*%u*",
    SIGNATURE_ENCFS,
    encfs->key_size * 8,
    salt->salt_iter + 1,
    salt->salt_len);

  line_len += hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) line_buf + line_len);

  line_len += snprintf (line_buf + line_len, line_size - line_len, "*%u*", encfs->data_len + 4);

  u32_to_hex (byte_swap_32 (encfs->checksum), (u8 *) line_buf + line_len);

  line_len += 8;

  for (u32 i = 0; i < (encfs->data_len / 4); i++)
  {
    u32_to_hex (byte_swap_32 (encfs->data[i]), (u8 *) line_buf + line_len);

    line_len += 8;
  }

  line_buf[line_len] = 0;

  return line_len;
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
