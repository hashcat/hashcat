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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_MESSAGING;
static const char *HASH_NAME      = "Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)";
static const u64   KERN_TYPE      = 22600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$telegram$1*4000*913a7e42143b4eed0fb532dacfa04e3a0eae036ae66dd02de76323046c575531*cde5f7a3bda3812b4a3cd4df1269c6be18ca7536981522c251cab531c274776804634cdca5313dc8beb9895f903a40d874cd50dbb82e5e4d8f264820f3f2e2111a5831e1a2f16b1a75b2264c4b4485dfe0f789071130160af205f9f96aef378ee05602de2562f8c3b136a75ea01f54f4598af93f9e7f98eb66a5fd3dabaa864708fe0e84b59b77686974060f1533e3acc5367bc493915b5614603cf5601cfa0a6b8eae4c4bd24948176dd7ff470bc0863f35fdfce31a667c70e37743f662bc9c5ec86baff3ebb6bf7de96bcdfaca18baf9617a979424f792ef6e65e346ea2cbc1d53377f47c3fc681d7eda8169e6e20cd6a22dd94bf24933b8ffc4878216fa9edc7c72a073446a14b63e12b223f840217a7eac51b6afcc15bfa12afd3e85d3bd";

#include "hooks_common.c"

typedef struct telegram_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[35];
  u32 out [35];

} telegram_tmp_t;

typedef struct telegram
{
  u32 data[72];

} telegram_t;

#define DATA_LEN_TELEGRAM 288
#define SALT_LEN_TELEGRAM 32

static const char *SIGNATURE_TELEGRAM = "$telegram$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (telegram_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (telegram_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  telegram_t *telegram = (telegram_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_TELEGRAM;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 5;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 64;
  token.len_max[3] = 64;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = DATA_LEN_TELEGRAM * 2;
  token.len_max[4] = DATA_LEN_TELEGRAM * 2;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8 version = token.buf[1][0];

  if (version != '1') return (PARSER_SALT_VALUE);

  // iter

  const u8 *iter_pos = token.buf[2];

  salt->salt_iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (salt->salt_iter < 2) return (PARSER_SALT_ITERATION);

  salt->salt_iter--;

  // salt

  const u8 *salt_pos = token.buf[3];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);
  salt->salt_buf[4] = hex_to_u32 (salt_pos + 32);
  salt->salt_buf[5] = hex_to_u32 (salt_pos + 40);
  salt->salt_buf[6] = hex_to_u32 (salt_pos + 48);
  salt->salt_buf[7] = hex_to_u32 (salt_pos + 56);

  salt->salt_len = SALT_LEN_TELEGRAM;

  // digest

  const u8 *message_pos = token.buf[4];

  digest[0] = hex_to_u32 (message_pos +  0);
  digest[1] = hex_to_u32 (message_pos +  8);
  digest[2] = hex_to_u32 (message_pos + 16);
  digest[3] = hex_to_u32 (message_pos + 24);

  // data

  for (int i = 0, j = 0; i < DATA_LEN_TELEGRAM / 4; i += 1, j += 8)
  {
    telegram->data[i] = hex_to_u32 (message_pos + j);

    telegram->data[i] = byte_swap_32 (telegram->data[i]);
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const telegram_t *telegram = (const telegram_t *) esalt_buf;

  // salt

  #define SALT_BUF_LEN (SALT_LEN_TELEGRAM * 2 + 1)

  char salt_buf[SALT_BUF_LEN];

  memset (salt_buf, 0, SALT_BUF_LEN);

  for (int i = 0, j = 0; i < SALT_LEN_TELEGRAM / 4; i += 1, j += 8)
  {
    snprintf (salt_buf + j, SALT_BUF_LEN - j, "%08x", byte_swap_32 (salt->salt_buf[i]));
  }

  // message

  #define DATA_BUF_LEN (DATA_LEN_TELEGRAM * 2 + 1)

  char message[DATA_BUF_LEN];

  memset (message, 0, DATA_BUF_LEN);

  for (int i = 0, j = 0; i < DATA_LEN_TELEGRAM / 4; i += 1, j += 8)
  {
    snprintf (message + j, DATA_BUF_LEN - j, "%08x", telegram->data[i]);
  }

  // output

  const int line_len = snprintf (line_buf, line_size, "%s%i*%i*%s*%s",
    SIGNATURE_TELEGRAM,
    1,
    salt->salt_iter + 1,
    salt_buf,
    message);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
