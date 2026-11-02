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
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "CRAM-MD5";
static const char *HASH_RECIPE    = "hmac_md5(pass, salt)";
static const u64   KERN_TYPE      = 50;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_BASE64
                                  | OPTS_TYPE_ST_ADD80
                                  | OPTS_TYPE_ST_ADDBITS14;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$cram_md5$MTI=$dXNlciBiOGYwNjk5MTE0YjA1Nzg4OTIyM2RmMDg0ZjgyMjQ2Zg==";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

typedef struct cram_md5
{
  u32 user[16];

} cram_md5_t;

static const char *SIGNATURE_CRAM_MD5 = "$cram_md5$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (cram_md5_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  cram_md5_t *cram_md5 = (cram_md5_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CRAM_MD5;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = ((SALT_MIN * 8) / 6) + 0;
  token.len_max[1] = ((SALT_MAX * 8) / 6) + 3;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[2]     = '$';
  token.len_min[2] = 44;
  token.len_max[2] = 132;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // hash

  const u8 *hash_pos = token.buf[2];
  const int hash_len = token.len[2];

  u8 tmp_buf[256] = { 0 };

  const int tmp_len = base64_decode (base64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len < 32 + 1) return (PARSER_HASH_LENGTH);

  u32 user_len = tmp_len - 32;

  const u8 *tmp_hash = tmp_buf + user_len;

  user_len--; // skip the trailing space

  if (is_valid_hex_string (tmp_hash, 32) == false) return (PARSER_HASH_ENCODING);

  digest[0] = hex_to_u32 (tmp_hash +  0);
  digest[1] = hex_to_u32 (tmp_hash +  8);
  digest[2] = hex_to_u32 (tmp_hash + 16);
  digest[3] = hex_to_u32 (tmp_hash + 24);

  // store username for host only (output hash if cracked)

  // module_hash_encode reads user back with %s, so it needs room for a terminator as well as for
  // the name itself. base64 without padding decodes longer than base64 with it, which is how a
  // name longer than the member gets here.

  if (user_len >= sizeof (cram_md5->user)) return (PARSER_SALT_LENGTH);

  memset (cram_md5->user, 0, sizeof (cram_md5->user));
  memcpy (cram_md5->user, tmp_buf, user_len);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const cram_md5_t *cram_md5 = (const cram_md5_t *) esalt_buf;

  // challenge

  char chal_buf[SALT_MAX * 2];

  const int chal_len = base64_encode (int_to_base64, (const u8 *) salt->salt_buf, salt->salt_len, (u8 *) chal_buf);

  chal_buf[chal_len] = 0;

  // response

  char tmp_buf[SALT_MAX * 2];

  const int tmp_len = snprintf (tmp_buf, sizeof (tmp_buf), "%s %08x%08x%08x%08x",
    (const char *) cram_md5->user,
    byte_swap_32 (digest[0]),
    byte_swap_32 (digest[1]),
    byte_swap_32 (digest[2]),
    byte_swap_32 (digest[3]));

  tmp_buf[tmp_len] = 0;

  char resp_buf[SALT_MAX * 2] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp_buf, tmp_len, (u8 *) resp_buf);

  const int line_len = snprintf (line_buf, line_size, "%s%s$%s", SIGNATURE_CRAM_MD5, chal_buf, resp_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
