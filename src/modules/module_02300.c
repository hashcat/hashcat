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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "OpenSSL enc (AES-CBC, EVP_BytesToKey)";
static const u64   KERN_TYPE      = 2300;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$openssl$0$2$8$104b209a894f6f85$b0fd3c6fa26babf573a66d28d887c3763d8486dc95789d108e681e8c1943d5ef$0$64$b02c988ebdb3ab5fd68a946d97e5e13bc451abfcc9af6a383398c499ca894175b0fd3c6fa26babf573a66d28d887c3763d8486dc95789d108e681e8c1943d5ef$1$hashcat";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use tools/openssl2hashcat.py to extract the hash. A line that checks only the padding is refused, because the padding alone lets one wrong password in 255 through: pass -p with at least 5 bytes of text the file is known to contain, or -a with a minimum share of printable ASCII. The share a line needs falls as it carries more data, from 85 percent at 48 bytes to 55 percent at 256, and a line carrying less than 48 bytes cannot use -a at all. Files written with -pbkdf2 or -iter are not supported";
}

#define OPENSSL_ENC_CIPHER_AES256 0
#define OPENSSL_ENC_CIPHER_AES128 1

#define OPENSSL_ENC_MD_MD5    0
#define OPENSSL_ENC_MD_SHA1   1
#define OPENSSL_ENC_MD_SHA256 2

#define OPENSSL_ENC_KPA_NONE  0
#define OPENSSL_ENC_KPA_TEXT  1
#define OPENSSL_ENC_KPA_ASCII 2

#define OPENSSL_ENC_DATA_MAX 256

// A wrong password only reaches the checks below if the last block decrypted to valid PKCS#7
// padding, which one candidate in 255 manages, so the padding cannot tell a right password from
// a wrong one on its own. These are the limits that keep what is left under one false positive
// in 2^32: 5 bytes of known plaintext, or an ascii share over a window of at least 18 bytes.

#define OPENSSL_ENC_KPT_MIN          5
#define OPENSSL_ENC_ASCII_WINDOW_MIN 18

// The minimum number of ASCII bytes that keeps the check under one false positive in 2^32,
// indexed by the window the parser can count on. A 0 means no percentage is enough for that
// window. Regenerate with gen-ascii-min-table.py rather than editing by hand.

static const u8 OPENSSL_ENC_ASCII_MIN[241] =
{
    0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
    0,   0,  18,  19,  20,  20,  21,  22,  23,  23,  24,  24,  25,  26,  26,  27,
   28,  28,  29,  30,  30,  31,  31,  32,  33,  33,  34,  34,  35,  35,  36,  37,
   37,  38,  38,  39,  39,  40,  41,  41,  42,  42,  43,  43,  44,  45,  45,  46,
   46,  47,  47,  48,  48,  49,  49,  50,  50,  51,  52,  52,  53,  53,  54,  54,
   55,  55,  56,  56,  57,  57,  58,  58,  59,  59,  60,  60,  61,  61,  62,  63,
   63,  64,  64,  65,  65,  66,  66,  67,  67,  68,  68,  69,  69,  70,  70,  71,
   71,  72,  72,  73,  73,  74,  74,  75,  75,  76,  76,  77,  77,  78,  78,  79,
   79,  80,  80,  81,  81,  82,  82,  83,  83,  84,  84,  85,  85,  86,  86,  87,
   87,  87,  88,  88,  89,  89,  90,  90,  91,  91,  92,  92,  93,  93,  94,  94,
   95,  95,  96,  96,  97,  97,  98,  98,  99,  99, 100, 100, 101, 101, 101, 102,
  102, 103, 103, 104, 104, 105, 105, 106, 106, 107, 107, 108, 108, 109, 109, 110,
  110, 110, 111, 111, 112, 112, 113, 113, 114, 114, 115, 115, 116, 116, 117, 117,
  118, 118, 118, 119, 119, 120, 120, 121, 121, 122, 122, 123, 123, 124, 124, 125,
  125, 125, 126, 126, 127, 127, 128, 128, 129, 129, 130, 130, 131, 131, 132, 132,
  132,
};

typedef struct openssl_enc
{
  u32 cipher;
  u32 md;
  u32 salt[2];

  u32 inlined;
  u32 last[8];

  u32 data_len;
  u32 data[OPENSSL_ENC_DATA_MAX / 4];

  u32 kpa;
  u32 kpt_len;
  u32 kpt[64];
  u32 ascii_pct;

} openssl_enc_t;

static const char *SIGNATURE_OPENSSL_ENC = "$openssl$";

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (openssl_enc_t);

  return esalt_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  openssl_enc_t *openssl_enc = (openssl_enc_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OPENSSL_ENC;

  // signature
  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // cipher
  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // md
  token.sep[2]     = '$';
  token.len[2]     = 1;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt length
  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt
  token.sep[4]     = '$';
  token.len[4]     = 16;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // the last block, behind the one before it unless the file is a single block
  token.sep[5]     = '$';
  token.len_min[5] = 32;
  token.len_max[5] = 64;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // inlined
  token.sep[6]     = '$';
  token.len[6]     = 1;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // the rest: [datalen$data$]kpa[$kpt]
  token.len_min[7] = 1;
  token.len_max[7] = 1024;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u32 cipher = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (cipher > OPENSSL_ENC_CIPHER_AES128) return (PARSER_CIPHER);

  const u32 md = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (md > OPENSSL_ENC_MD_SHA256) return (PARSER_HASH_VALUE);

  // EVP_BytesToKey always reads 8 salt bytes

  const u32 salt_len = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if (salt_len != 8) return (PARSER_SALT_LENGTH);

  const u32 inlined = hc_strtoul ((const char *) token.buf[6], NULL, 10);

  if (inlined > 1) return (PARSER_HASH_VALUE);

  const u32 last_len = (inlined == 1) ? 16 : 32;

  if (token.len[5] != (int) (last_len * 2)) return (PARSER_CT_LENGTH);

  const u8 *tail_pos = token.buf[7];
  int       tail_len = token.len[7];

  u32 data_len = 0;

  const u8 *data_pos = NULL;

  if (inlined == 0)
  {
    hc_token_t token2;

    memset (&token2, 0, sizeof (hc_token_t));

    token2.token_cnt  = 3;

    // data length
    token2.sep[0]     = '$';
    token2.len_min[0] = 2;
    token2.len_max[0] = 3;
    token2.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                      | TOKEN_ATTR_VERIFY_DIGIT;

    // data
    token2.sep[1]     = '$';
    token2.len_min[1] = 32;
    token2.len_max[1] = OPENSSL_ENC_DATA_MAX * 2;
    token2.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                      | TOKEN_ATTR_VERIFY_HEX;

    // kpa[$kpt]
    token2.len_min[2] = 1;
    token2.len_max[2] = 1024;
    token2.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    const int rc_tokenizer2 = input_tokenizer (tail_pos, tail_len, &token2);

    if (rc_tokenizer2 != PARSER_OK) return (rc_tokenizer2);

    data_len = hc_strtoul ((const char *) token2.buf[0], NULL, 10);

    if ((data_len * 2) != (u32) token2.len[1]) return (PARSER_CT_LENGTH);

    if ((data_len % 16) != 0) return (PARSER_CT_LENGTH);

    data_pos = token2.buf[1];

    tail_pos = token2.buf[2];
    tail_len = token2.len[2];
  }

  // kpa 0 checks the padding only, 1 searches the decrypted data for kpt and 2 takes kpt as the
  // share of printable ASCII the data must reach, in percent

  const u32 kpa = tail_pos[0] - '0';

  if (kpa > OPENSSL_ENC_KPA_ASCII) return (PARSER_HASH_VALUE);

  u32 kpt_len = 0;

  const u8 *kpt_pos = NULL;

  if (tail_len > 1)
  {
    if (tail_pos[1] != '$') return (PARSER_SEPARATOR_UNMATCHED);

    kpt_pos = tail_pos + 2;
    kpt_len = tail_len - 2;

    if (kpt_len == 0) return (PARSER_PT_LENGTH);
    if (kpt_len > 255) return (PARSER_PT_LENGTH);
  }

  if ((kpa != OPENSSL_ENC_KPA_NONE) && (kpt_len == 0)) return (PARSER_PT_LENGTH);

  u32 ascii_pct = 0;

  if (kpa == OPENSSL_ENC_KPA_ASCII)
  {
    ascii_pct = hc_strtoul ((const char *) kpt_pos, NULL, 10);

    if (ascii_pct == 0) ascii_pct = 90;

    if (ascii_pct > 100) return (PARSER_HASH_VALUE);
  }

  // Refuse a hash whose checks leave a false positive rate worse than one in 2^32. The padding is
  // 1 in 255 by itself, so a line that checks nothing else can never qualify.

  if (kpa == OPENSSL_ENC_KPA_NONE) return (PARSER_HASH_VALUE);

  if (kpa == OPENSSL_ENC_KPA_TEXT)
  {
    if (kpt_len < OPENSSL_ENC_KPT_MIN) return (PARSER_PT_LENGTH);
  }
  else
  {
    // The kernel counts the plaintext that is left once the padding is stripped, and how much that
    // is depends on the password. The parser therefore takes the smallest it can be, 16 bytes short
    // of what the line carries, which is the weakest case and so the safe one to judge. An inlined
    // line carries no data field and leaves at most a single block, never enough.

    const u32 window = (inlined == 1) ? 0 : ((data_len > 16) ? data_len - 16 : 0);

    if (window < OPENSSL_ENC_ASCII_WINDOW_MIN) return (PARSER_HASH_VALUE);

    const u32 need = ((ascii_pct * window) + 99) / 100;

    if (need < OPENSSL_ENC_ASCII_MIN[window]) return (PARSER_HASH_VALUE);
  }

  memset (openssl_enc, 0, sizeof (openssl_enc_t));

  openssl_enc->cipher = cipher;
  openssl_enc->md     = md;

  hex_decode (token.buf[4], 16, (u8 *) openssl_enc->salt);

  openssl_enc->inlined = inlined;

  for (u32 i = 0; i < (last_len / 4); i++)
  {
    openssl_enc->last[i] = byte_swap_32 (hex_to_u32 (token.buf[5] + (i * 8)));
  }

  openssl_enc->data_len = data_len;

  for (u32 i = 0; i < (data_len / 4); i++)
  {
    openssl_enc->data[i] = byte_swap_32 (hex_to_u32 (data_pos + (i * 8)));
  }

  openssl_enc->kpa       = kpa;
  openssl_enc->kpt_len   = kpt_len;
  openssl_enc->ascii_pct = ascii_pct;

  if (kpt_len > 0) memcpy (openssl_enc->kpt, kpt_pos, kpt_len);

  // the salt and the last block tell two files apart, and the check type keeps a padding-only line
  // from standing in for a stronger one of the same file

  u8 *salt_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_ptr + 0, openssl_enc->salt, 8);
  memcpy (salt_ptr + 8, openssl_enc->last, last_len);

  salt_ptr[8 + last_len] = (u8) kpa;

  salt->salt_len = 8 + last_len + 1;

  const u32 last_pos = (last_len / 4) - 4;

  digest[0] = openssl_enc->last[last_pos + 0];
  digest[1] = openssl_enc->last[last_pos + 1];
  digest[2] = openssl_enc->last[last_pos + 2];
  digest[3] = openssl_enc->last[last_pos + 3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const openssl_enc_t *openssl_enc = (const openssl_enc_t *) esalt_buf;

  int line_len = 0;

  line_len += snprintf (line_buf + line_len, line_size - line_len, "%s%u$%u$8$", SIGNATURE_OPENSSL_ENC, openssl_enc->cipher, openssl_enc->md);

  line_len += hex_encode ((const u8 *) openssl_enc->salt, 8, (u8 *) line_buf + line_len);

  line_buf[line_len++] = '$';

  const u32 last_words = (openssl_enc->inlined == 1) ? 4 : 8;

  for (u32 i = 0; i < last_words; i++)
  {
    u32_to_hex (byte_swap_32 (openssl_enc->last[i]), (u8 *) line_buf + line_len);

    line_len += 8;
  }

  line_len += snprintf (line_buf + line_len, line_size - line_len, "$%u$", openssl_enc->inlined);

  if (openssl_enc->inlined == 0)
  {
    line_len += snprintf (line_buf + line_len, line_size - line_len, "%u$", openssl_enc->data_len);

    for (u32 i = 0; i < (openssl_enc->data_len / 4); i++)
    {
      u32_to_hex (byte_swap_32 (openssl_enc->data[i]), (u8 *) line_buf + line_len);

      line_len += 8;
    }

    line_buf[line_len++] = '$';
  }

  line_buf[line_len++] = '0' + openssl_enc->kpa;

  if (openssl_enc->kpt_len > 0)
  {
    line_buf[line_len++] = '$';

    memcpy (line_buf + line_len, openssl_enc->kpt, openssl_enc->kpt_len);

    line_len += openssl_enc->kpt_len;
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
  module_ctx->module_usage_notice             = module_usage_notice;
}
