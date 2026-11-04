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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "Dashlane (legacy, local master password)";
static const u64   KERN_TYPE      = 34900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "Openwall123";
static const char *ST_HASH        = "$dashlane$1*523f57cffb40609f4a3b00288a1223cf8ec4b8c1610fe4afdea345a21563eae9*220*5e906e7dce3d12999bf7d627756e2267f3f5061e457a47736d1174959ed4f9e316a30fdee0a60493de83dd6f8b669ed420172ad9e2f1c1269aa9716d664cf2a005b44834f696c0473a8858647adc07d9b02ec3ece33eae250289bb1d2efbe9c4c181ae326dccabb552939f5fca72dc4b83c846e95a67eb3fbd04ca5fc216f4de16893bb434ba878e34e1870fb1814355e192488bb6bdab8e18f3c983e599800c458711a27ebeb595f6757a1393035b92bbc46bc9ccea75b77ea47b413e08b3aa9818ebf3369eb954d1fa44a202c2cd9e28d48b3dd5a185caa4674caf";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode reads the $dashlane$ line of john's dashlane2john.py unchanged, for the local files of Dashlane 4, the .aes databases and a .dash archive. Dashlane 6 and the web extension use Argon2d in a KWC3 blob and are not covered. Only the first 128 bytes of the data field are read";
}

typedef struct dashlane
{
  u32 type;
  u32 data_buf[32];

} dashlane_t;

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

static const char *SIGNATURE_DASHLANE = "$dashlane$";

// Dashlane 4 fixes the iteration count, and john has it as 10204. hashcat's loop kernel runs the
// iterations after the first, which init does.

static const u32 DASHLANE_ITER = 10204;

// only the first 128 bytes of the data are decrypted, which is what the verifier reads

#define DASHLANE_DATA_LEN 128

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (dashlane_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha1_tmp_t);

  return tmp_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  dashlane_t *dashlane = (dashlane_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DASHLANE;

  token.len[0]     = 10;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 64;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 4;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // a .aes file is not a whole number of AES blocks long, and the macOS sharedData.aes of john's
  // own vectors is shorter than the 128 bytes that are read, so only one block is asked for here

  token.sep[4]     = '*';
  token.len_min[4] = 32;
  token.len_max[4] = 1024;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type. Type 1 inflates the decrypted data, type 0 reads it directly, and john has never seen a
  // type 0 file.

  const u8 *type_pos = token.buf[1];

  if ((type_pos[0] != '0') && (type_pos[0] != '1')) return (PARSER_SALT_VALUE);

  dashlane->type = type_pos[0] - '0';

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  salt->salt_iter = DASHLANE_ITER - 1;

  // the stated length of the data, which has to agree with what the field holds

  const u32 data_len = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if (token.len[4] & 1) return (PARSER_SALT_LENGTH);

  if (data_len != (u32) (token.len[4] / 2)) return (PARSER_SALT_VALUE);

  // data. Only the first 128 bytes are decrypted, and the AES helpers read big endian words. A
  // field shorter than that leaves the rest of the buffer zero, which is what john decrypts too.

  const u8 *data_pos = token.buf[4];

  int data_hex_len = token.len[4];

  if (data_hex_len > DASHLANE_DATA_LEN * 2) data_hex_len = DASHLANE_DATA_LEN * 2;

  memset (dashlane->data_buf, 0, sizeof (dashlane->data_buf));

  hex_decode (data_pos, data_hex_len, (u8 *) dashlane->data_buf);

  for (int i = 0; i < 32; i++) dashlane->data_buf[i] = byte_swap_32 (dashlane->data_buf[i]);

  // the verifier is the inflated plaintext rather than a stored digest, so the first words of the
  // data stand in for one, as hash-mode 26610 does

  digest[0] = dashlane->data_buf[0];
  digest[1] = dashlane->data_buf[1];
  digest[2] = dashlane->data_buf[2];
  digest[3] = dashlane->data_buf[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  return snprintf (line_buf, line_size, "%s", hash_info->orighash);
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
