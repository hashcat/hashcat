/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_CIPHER_KPA;
static const char *HASH_NAME      = "Hashids (salt search)";
static const u64   KERN_TYPE      = 35900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$hashids$0**1,2,3*ROiyIx";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode searches for the salt of a Hashids encoder, the password being the salt. The line is $hashids$<min_length>*<alphabet as hex, empty for the default alphabet>*<the encoded numbers, separated by commas>*<the hashid>, so the numbers behind one hashid have to be known, for example a record id seen beside its hashid. The salt and the alphabet are taken as bytes, which is what the Hashids libraries do for ASCII. An alphabet with multibyte characters does not work, since the libraries count each of those as one symbol. Hashids reads only the start of the salt, one character fewer than the alphabet holds, so any salt with the same start cracks the line";
}

#define HASHIDS_ALPHA_MAX  128
#define HASHIDS_SEPS_MAX   64
#define HASHIDS_VALUES_MAX 8
#define HASHIDS_OUT_MAX    128

typedef struct hashids
{
  u64 values[HASHIDS_VALUES_MAX];
  u32 values_cnt;
  u32 values_hash;

  u32 alpha[HASHIDS_ALPHA_MAX / 4];
  u32 alpha_len;

  u32 seps[HASHIDS_SEPS_MAX / 4];
  u32 seps_len;

  u32 extra[HASHIDS_SEPS_MAX / 4];
  u32 extra_len;

  u32 guards_cnt;
  u32 min_length;

  u32 target[HASHIDS_OUT_MAX / 4];
  u32 target_len;

  // the alphabet as the line gives it, for writing the line back, and whether it gave one

  u32 alpha_in[HASHIDS_ALPHA_MAX / 4];
  u32 alpha_in_len;
  u32 alpha_given;

} hashids_t;

typedef struct hashids_tmp
{
  u32 unused;

} hashids_tmp_t;

static const char *SIGNATURE_HASHIDS = "$hashids$";

static const char *HASHIDS_DEFAULT_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

static const char *HASHIDS_SEPARATORS = "cfhistuCFHISTU";

static u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (hashids_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (hashids_tmp_t);

  return tmp_size;
}

static bool hashids_has (const u8 *buf, const u32 len, const u8 c)
{
  for (u32 i = 0; i < len; i++)
  {
    if (buf[i] == c) return true;
  }

  return false;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hashids_t *hashids = (hashids_t *) esalt_buf;

  memset (hashids, 0, sizeof (hashids_t));

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_HASHIDS;

  token.len[0]     = 9;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 3;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 0;
  token.len_max[2] = HASHIDS_ALPHA_MAX * 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = HASHIDS_VALUES_MAX * 21;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = HASHIDS_OUT_MAX;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // min_length

  const u32 min_length = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (min_length > HASHIDS_OUT_MAX) return (PARSER_SALT_VALUE);

  hashids->min_length = min_length;

  // the alphabet, or the default one

  u8 *alpha_in = (u8 *) hashids->alpha_in;

  if (token.len[2] > 0)
  {
    if ((token.len[2] % 2) != 0) return (PARSER_SALT_LENGTH);

    hashids->alpha_in_len = hex_decode (token.buf[2], token.len[2], alpha_in);
    hashids->alpha_given  = 1;
  }
  else
  {
    const u32 len = (u32) strlen (HASHIDS_DEFAULT_ALPHABET);

    memcpy (alpha_in, HASHIDS_DEFAULT_ALPHABET, len);

    hashids->alpha_in_len = len;
    hashids->alpha_given  = 0;
  }

  // The parts of the setup that do not depend on the salt. The separators are the characters of
  // cfhistuCFHISTU the alphabet holds, in that order. The rest of the alphabet keeps its first
  // occurrence of each character.

  const u32 alpha_in_len = hashids->alpha_in_len;

  const u32 seps_all_len = (u32) strlen (HASHIDS_SEPARATORS);

  u8 *seps  = (u8 *) hashids->seps;
  u8 *alpha = (u8 *) hashids->alpha;
  u8 *extra = (u8 *) hashids->extra;

  u32 seps_len = 0;

  for (u32 i = 0; i < seps_all_len; i++)
  {
    const u8 c = (u8) HASHIDS_SEPARATORS[i];

    if (hashids_has (alpha_in, alpha_in_len, c) == true)
    {
      seps[seps_len] = c;

      seps_len++;
    }
  }

  u8 alpha_all[HASHIDS_ALPHA_MAX];

  u32 alpha_all_len = 0;

  for (u32 i = 0; i < alpha_in_len; i++)
  {
    const u8 c = alpha_in[i];

    if (hashids_has (alpha_all, alpha_all_len, c) == true) continue;

    if (hashids_has (seps, seps_len, c) == true) continue;

    alpha_all[alpha_all_len] = c;

    alpha_all_len++;
  }

  if ((alpha_all_len + seps_len) < 16) return (PARSER_SALT_VALUE);

  // ceil (len / 3.5) separators at least, taken from the front of the unshuffled alphabet

  const u32 seps_min = ((alpha_all_len * 2) + 6) / 7;

  const u32 missing = (seps_min > seps_len) ? seps_min - seps_len : 0;

  for (u32 i = 0; i < missing; i++) extra[i] = alpha_all[i];

  for (u32 i = missing; i < alpha_all_len; i++) alpha[i - missing] = alpha_all[i];

  hashids->seps_len  = seps_len;
  hashids->extra_len = missing;
  hashids->alpha_len = alpha_all_len - missing;

  if ((hashids->seps_len + hashids->extra_len) > HASHIDS_SEPS_MAX) return (PARSER_SALT_VALUE);

  // ceil (len / 12) guards

  hashids->guards_cnt = (hashids->alpha_len + 11) / 12;

  // the numbers

  const u8 *values_pos = token.buf[3];
  const u32 values_len = token.len[3];

  u32 values_cnt = 0;

  u32 i = 0;

  while (i < values_len)
  {
    if (values_cnt == HASHIDS_VALUES_MAX) return (PARSER_SALT_VALUE);

    u32 digits = 0;

    u64 value = 0;

    while ((i < values_len) && (values_pos[i] != ','))
    {
      const u8 c = values_pos[i];

      if ((c < '0') || (c > '9')) return (PARSER_SALT_VALUE);

      const u64 d = c - '0';

      if (value > ((0xffffffffffffffffULL - d) / 10)) return (PARSER_SALT_VALUE);

      value = (value * 10) + d;

      digits++;

      i++;
    }

    if (digits == 0) return (PARSER_SALT_VALUE);

    hashids->values[values_cnt] = value;

    values_cnt++;

    if (i < values_len) i++;

    if ((i == values_len) && (values_pos[values_len - 1] == ',')) return (PARSER_SALT_VALUE);
  }

  hashids->values_cnt = values_cnt;

  u32 values_hash = 0;

  for (u32 v = 0; v < values_cnt; v++)
  {
    values_hash += (u32) (hashids->values[v] % (v + 100));
  }

  hashids->values_hash = values_hash;

  // the hashid

  if ((u32) token.len[4] < min_length) return (PARSER_HASH_LENGTH);

  memcpy (hashids->target, token.buf[4], token.len[4]);

  hashids->target_len = token.len[4];

  // The hashid stands in for a digest, as the ciphertext block does in hash-modes 26610 and 37230.
  // The salt holds what tells two lines apart, so that lines with the same hashid but other numbers
  // or another alphabet are not taken for duplicates. Only the kernel's esalt is read on the device.

  digest[0] = hashids->target[0];
  digest[1] = hashids->target[1];
  digest[2] = hashids->target[2];
  digest[3] = hashids->target[3];

  u32 *salt_buf = salt->salt_buf;

  for (u32 n = 0; n < (HASHIDS_OUT_MAX / 4); n++) salt_buf[n] = hashids->target[n];

  u64 *salt_values = (u64 *) (salt_buf + (HASHIDS_OUT_MAX / 4));

  for (u32 v = 0; v < HASHIDS_VALUES_MAX; v++) salt_values[v] = hashids->values[v];

  u64 fnv = 0xcbf29ce484222325;

  for (u32 n = 0; n < alpha_in_len; n++)
  {
    fnv ^= alpha_in[n];
    fnv *= 0x100000001b3;
  }

  salt_buf[48] = values_cnt;
  salt_buf[49] = min_length;
  salt_buf[50] = hashids->target_len;
  salt_buf[51] = alpha_in_len;
  salt_buf[52] = (u32) (fnv >>  0);
  salt_buf[53] = (u32) (fnv >> 32);

  salt->salt_len = 54 * 4;

  salt->salt_iter = 1;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const hashids_t *hashids = (const hashids_t *) esalt_buf;

  char alpha_hex[(HASHIDS_ALPHA_MAX * 2) + 1] = { 0 };

  if (hashids->alpha_given == 1)
  {
    hex_encode ((const u8 *) hashids->alpha_in, hashids->alpha_in_len, (u8 *) alpha_hex);
  }

  char values[(HASHIDS_VALUES_MAX * 21) + 1] = { 0 };

  int values_len = 0;

  for (u32 v = 0; v < hashids->values_cnt; v++)
  {
    values_len += snprintf (values + values_len, sizeof (values) - values_len, (v == 0) ? "%" PRIu64 : ",%" PRIu64, hashids->values[v]);
  }

  char target[HASHIDS_OUT_MAX + 1] = { 0 };

  memcpy (target, hashids->target, hashids->target_len);

  const int line_len = snprintf (line_buf, line_size, "%s%u*%s*%s*%s",
    SIGNATURE_HASHIDS,
    hashids->min_length,
    alpha_hex,
    values,
    target);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
