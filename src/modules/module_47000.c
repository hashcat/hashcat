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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RFID;
static const char *HASH_NAME      = "OSDP Secure Channel (SCBK)";
static const u64   KERN_TYPE      = 47000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat1hashcat2";
static const char *ST_HASH        = "$osdp$a1b2c3d4e5f60718*2938475665748392*aaded62fb4904de06dbed43707000006";

#include "hooks_common.c"

// The OSDP Secure Channel handshake. The CP sends RND.A in osdp_CHLNG, the PD answers with RND.B
// and the client cryptogram in osdp_CCRYPT. The PD derives S-ENC by encrypting 0x01 0x82 and the
// first 6 bytes of RND.A under the SCBK, and the client cryptogram is RND.A . RND.B encrypted under
// S-ENC. The SCBK is an AES-128 key, so a candidate is exactly 16 bytes.

static const char *SIGNATURE_OSDP = "$osdp$";

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use tools/osdp2hashcat.py to extract the hash from an OSDPCAP capture";
}

static u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 16;

  return pw_min;
}

static u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 16;

  return pw_max;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OSDP;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 16;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len[2]     = 16;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt is RND.A . RND.B

  const u8 *rnd_a_pos = token.buf[1];
  const u8 *rnd_b_pos = token.buf[2];

  salt->salt_buf[0] = hex_to_u32 (&rnd_a_pos[0]);
  salt->salt_buf[1] = hex_to_u32 (&rnd_a_pos[8]);
  salt->salt_buf[2] = hex_to_u32 (&rnd_b_pos[0]);
  salt->salt_buf[3] = hex_to_u32 (&rnd_b_pos[8]);

  salt->salt_len = 16;

  // hash is the client cryptogram

  const u8 *hash_pos = token.buf[3];

  digest[0] = hex_to_u32 (&hash_pos[ 0]);
  digest[1] = hex_to_u32 (&hash_pos[ 8]);
  digest[2] = hex_to_u32 (&hash_pos[16]);
  digest[3] = hex_to_u32 (&hash_pos[24]);

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u8 *out_buf = (u8 *) line_buf;

  u32 out_len = strlen (SIGNATURE_OSDP);

  memcpy (out_buf, SIGNATURE_OSDP, out_len);

  u32_to_hex (salt->salt_buf[0], &out_buf[out_len]); out_len += 8;
  u32_to_hex (salt->salt_buf[1], &out_buf[out_len]); out_len += 8;

  out_buf[out_len] = '*';

  out_len++;

  u32_to_hex (salt->salt_buf[2], &out_buf[out_len]); out_len += 8;
  u32_to_hex (salt->salt_buf[3], &out_buf[out_len]); out_len += 8;

  out_buf[out_len] = '*';

  out_len++;

  u32_to_hex (digest[0], &out_buf[out_len]); out_len += 8;
  u32_to_hex (digest[1], &out_buf[out_len]); out_len += 8;
  u32_to_hex (digest[2], &out_buf[out_len]); out_len += 8;
  u32_to_hex (digest[3], &out_buf[out_len]); out_len += 8;

  const int line_len = (int) out_len;

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_usage_notice             = module_usage_notice;
}
