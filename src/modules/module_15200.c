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
static const u32   DGST_SIZE      = DGST_SIZE_4_5; // because kernel uses _SHA1;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Blockchain, My Wallet, V2";
static const u64   KERN_TYPE      = 12700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$blockchain$v2$5000$288$324724252428471806184866704068819419467b2b32fd9593fd1a274e0b68bf2c72e5a1f5e748fd319056d1e47ca7b40767136a2d97d7133d14faaeca50986f66cdbc0faec0a3fabbd0ba5d08d5322b6b53da021aacfc439c45bec0e9fe02ad81db82f94e9bd36a7d4d76b505c2339fcd46565d3abab958fbeb1de8bfc53beb96cde8fe44128965477c9ef0762c62bbb1d66532b4888e174ea949db54374a2ed9686a63eb0b5b17ae293f7410bb4ae5106f108314a259c5fd097d558515d79350713412159103a8a174cd384a14f3da45efe18044e1146036000231f6042577d0add98fc959d265368e398dc1550b0bc693e9023cd9d51b40e701bd786e19c3a281a90465aa6ea3f9e756d430164ab2eb43be5b6796d7ac15b2fe99217410f2";

#include "hooks_common.c"

typedef struct mywallet_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

} mywallet_tmp_t;

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (mywallet_tmp_t);

  return tmp_size;
}

static const char *SIGNATURE_MYWALLETV2 = "$blockchain$v2$";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MYWALLETV2;

  token.len[0]     = 15;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 144;
  token.len_max[3] = 999999;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *data_pos = token.buf[3];

  // first 16 byte are IV

  for (int i = 0, j = 0; i < 16; i += 1, j += 8)
  {
    salt->salt_buf[i] = hex_to_u32 (data_pos + j);

    salt->salt_buf[i] = byte_swap_32 (salt->salt_buf[i]);
  }

  salt->salt_len = 64;

  // hash

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  return snprintf (line_buf, line_size, "%s", hash_info->orighash);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
