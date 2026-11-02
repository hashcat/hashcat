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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "OSPFv2/RIPv2 MD5 authentication";
static const char *HASH_RECIPE    = "md5(salt . pad(pass, 16))";
static const u64   KERN_TYPE      = 40001;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$netmd5$0201002c0a0a0afe0000000000000002000001106225f41bffffff00000a1201000000280a0a0afe00000000$46ab0f2c7f0a65102bcc25b1c4ea445b";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

// RFC 2328 D.4.3 and RFC 2082: the digest is MD5 of the packet followed by the key, null padded
// or cut to 16 bytes. A line is the packet in hex with the digest, either as digest:packet or in
// the $netmd5$packet$digest form of Ettercap and John the Ripper. The packet is the salt, decoded
// here, so it can take the whole salt buffer.

static const char *SIGNATURE_NETMD5 = "$netmd5$";

static const u32 NETMD5_KEY_LEN = 16;

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // a longer key cannot be configured, and the recipe would hash only its first 16 bytes

  const u32 pw_max = NETMD5_KEY_LEN;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  const int sig_len = (int) strlen (SIGNATURE_NETMD5);

  const bool is_netmd5 = (line_len >= sig_len) && (memcmp (line_buf, SIGNATURE_NETMD5, sig_len) == 0);

  // $netmd5$packet$digest or digest:packet, the packet is token 1 in both

  const u32 hash_idx = (is_netmd5 == true) ? 2 : 0;
  const u32 salt_idx = 1;

  if (is_netmd5 == true)
  {
    token.token_cnt  = 3;

    token.signatures_cnt    = 1;
    token.signatures_buf[0] = SIGNATURE_NETMD5;

    token.len[0]     = sig_len;
    token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_SIGNATURE;

    token.sep[1]     = '$';
    token.len_min[1] = 2;
    token.len_max[1] = SALT_MAX * 2;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[2]     = '$';
    token.len[2]     = 32;
    token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }
  else
  {
    token.token_cnt  = 2;

    token.sep[0]     = hashconfig->separator;
    token.len[0]     = 32;
    token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[1]     = hashconfig->separator;
    token.len_min[1] = 2;
    token.len_max[1] = SALT_MAX * 2;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // packet

  const u8 *salt_pos = token.buf[salt_idx];
  const int salt_len = token.len[salt_idx];

  if ((salt_len % 2) != 0) return (PARSER_SALT_LENGTH);

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  // digest

  const u8 *hash_pos = token.buf[hash_idx];

  digest[0] = hex_to_u32 (&hash_pos[ 0]);
  digest[1] = hex_to_u32 (&hash_pos[ 8]);
  digest[2] = hex_to_u32 (&hash_pos[16]);
  digest[3] = hex_to_u32 (&hash_pos[24]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const int line_len = snprintf (line_buf, line_size, "%s", hash_info->orighash);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_pw_max                   = module_pw_max;
}
