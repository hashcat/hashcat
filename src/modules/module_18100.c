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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OTP;
static const char *HASH_NAME      = "TOTP (HMAC-SHA1)";
static const u64   KERN_TYPE      = 18100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS15
                                  | OPTS_TYPE_SUGGEST_KG
                                  | OPTS_TYPE_COMBI_PURE_SWAP;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "597056:3600:613004:1234567890:322664:9876543210";

#include "hooks_common.c"

typedef struct totp
{
  u64 step;

} totp_t;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (totp_t);

  return esalt_size;
}

static int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const void *tmps, const u32 *src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 *dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  return base32_encode (int_to_base32, (const u8 *) src_buf, src_len, (u8 *) dst_buf);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  totp_t *totp = (totp_t *) esalt_buf;

  hc_token_t token;

  // 1 to 4 TOTP codes, with an optional time step in seconds as the last token
  // 597056:3600
  // 597056:3600:30
  // 597056:3600:613004:1234567890
  // 597056:3600:613004:1234567890:60
  // 597056:3600:613004:1234567890:322664:9876543210
  // 597056:3600:613004:1234567890:322664:9876543210:90
  // 597056:3600:613004:1234567890:322664:9876543210:068798:111222333
  // 597056:3600:613004:1234567890:322664:9876543210:068798:111222333:120
  int count;
  for (count = 9; count > 1; count -= 1)
  {
    memset (&token, 0, sizeof (hc_token_t));

    token.token_cnt = count;

    const int pair_cnt = count / 2;

    for (int i = 0; i < 2 * pair_cnt; i += 2)
    {
      token.sep[i + 0]     = ':';
      token.len[i + 0]     = 6;
      token.attr[i + 0]    = TOKEN_ATTR_FIXED_LENGTH
                           | TOKEN_ATTR_VERIFY_DIGIT;

      // 0 to 18446744073709551616
      token.sep[i + 1]     = ':';
      token.len_min[i + 1] = 1;
      token.len_max[i + 1] = 20;
      token.attr[i + 1]    = TOKEN_ATTR_VERIFY_LENGTH
                           | TOKEN_ATTR_VERIFY_DIGIT;

      if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
      {
        token.len_min[i + 1] *= 2;
        token.len_max[i + 1] *= 2;
        token.attr[i + 1]     = TOKEN_ATTR_VERIFY_LENGTH
                              | TOKEN_ATTR_VERIFY_BASE16;
      }
    }

    if (count % 2 == 1)
    {
      token.sep[count - 1]     = ':';
      token.len_min[count - 1] = 1;
      token.len_max[count - 1] = 10;
      token.attr[count - 1]    = TOKEN_ATTR_VERIFY_LENGTH
                               | TOKEN_ATTR_VERIFY_DIGIT;
    }

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer == PARSER_OK) break;

    // failed all tokenizers
    if (count == 2) return (rc_tokenizer);
  }

  // the RFC 6238 default time step is 30 seconds
  u64 step = 30;

  if (count % 2 == 1)
  {
    step = hc_strtoull ((const char *) token.buf[count - 1], NULL, 10);

    if (step == 0) return (PARSER_SALT_VALUE);
  }

  totp->step = step;

  count /= 2;

  for (int i = 0; i < count; i += 1)
  {
    // now we need to reduce our hash into a token
    int otp_code = hc_strtoul ((const char *) token.buf[2 * i + 0], NULL, 10);

    digest[i] = otp_code;

    const u8 *salt_pos = token.buf[2 * i + 1];

    // convert ascii timestamp to ulong timestamp
    u64 timestamp = hc_strtoull ((const char *) salt_pos, NULL, 10);

    // store the original salt value. Step division will destroy granularity for output
    salt->salt_buf[4 * i + 3] = ((u32) (timestamp >>  0));
    salt->salt_buf[4 * i + 2] = ((u32) (timestamp >> 32));

    // divide our timestamp by our step
    timestamp /= step;

    // convert counter to 8-byte salt
    salt->salt_buf[4 * i + 1] = byte_swap_32 ((u32) (timestamp >>  0));
    salt->salt_buf[4 * i + 0] = byte_swap_32 ((u32) (timestamp >> 32));
  }

  // verify unique salts
  for (int i = 0; i < count; i += 1)
  {
    u32 s0 = salt->salt_buf[4 * i + 0];
    u32 s1 = salt->salt_buf[4 * i + 1];

    for (int j = i + 1; j < count; j += 1)
    {
      if (salt->salt_buf[4 * j + 0] == s0 &&
          salt->salt_buf[4 * j + 1] == s1)
      {
        return (PARSER_SALT_VALUE);
      }
    }
  }

  // our salt will always be 8 bytes, but we are going to cheat and store it twice, so...
  salt->salt_len = 16 * count;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const totp_t *totp = (const totp_t *) esalt_buf;

  // salt_buf[4 * i + 2] and salt_buf[4 * i + 3] hold the original 64 bit timestamp

  int count = salt->salt_len / 16;

  // all but the last TOTP code
  int i = 0, line_len = 0;
  for (; i < count - 1; i += 1)
  {
    const u64 tmp_salt_buf = (((u64) (salt->salt_buf[4 * i + 2])) << 32) | ((u64) (salt->salt_buf[4 * i + 3]));
    const int ret = snprintf (line_buf + line_len, line_size - line_len, "%06d%c%" PRIu64 "%c", digest[i], ':', tmp_salt_buf, ':');
    line_len += ret;

    // error
    if (ret < 0)
    {
      return ret;
    }
  }

  // the last TOTP code, with the time step if it is not the RFC 6238 default of 30
  const u64 tmp_salt_buf = (((u64) (salt->salt_buf[4 * i + 2])) << 32) | ((u64) (salt->salt_buf[4 * i + 3]));

  int ret;

  if (totp->step == 30)
  {
    ret = snprintf (line_buf + line_len, line_size - line_len, "%06d%c%" PRIu64, digest[i], ':', tmp_salt_buf);
  }
  else
  {
    ret = snprintf (line_buf + line_len, line_size - line_len, "%06d%c%" PRIu64 "%c%" PRIu64, digest[i], ':', tmp_salt_buf, ':', totp->step);
  }

  line_len += ret;

  // error
  if (ret < 0)
  {
    return ret;
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_build_plain_postprocess  = module_build_plain_postprocess;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
}
