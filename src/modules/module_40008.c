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
static const char *HASH_NAME      = "Oracle o5logon (AUTH_SESSKEY padding check)";
static const char *HASH_RECIPE    = "pt = aes_cbc_decrypt_bin(pad(sha1_bin(pass . cut(fromhex(salt), 48, 10)), 24), cut(fromhex(salt), 16, 16), cut(fromhex(salt), 32, 16)); cut(pt, 8, 8) == fromhex('0808080808080808')";
static const u64   KERN_TYPE      = 40008;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "123456";
static const char *ST_HASH        = "$o5logon$22E8FA41826608560F0B2A713724689F3D28640577B511B9C36178418C138210D820F7800C14C579D5094F4BBB0E0EBD*A0F9FC5E0D992692AA35";

#include "hooks_common.c"

static const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

// The Oracle o5logon exchange, as oracle2john extracts it from a capture. A client derives an
// AES-192 key from sha1 (password . AUTH_VFR_DATA) zero extended to 24 bytes and decrypts the
// server's 48 byte AUTH_SESSKEY. Only its last block is needed: under CBC that block's plaintext
// depends on the last 2 ciphertext blocks alone, so the recipe decrypts bytes 32 to 47 with bytes
// 16 to 31 as the IV, and the right password leaves 8 bytes of 0x08 padding in the second half.
//
// The padding is there on a narrow range of unpatched 11g servers. Later ones, including the Oracle
// 12 capture in issue 371, fill those bytes at random, and this mode cannot crack them: given the
// right password it reports no crack rather than a wrong one. The full check also decrypts the
// client's AUTH_SESSKEY and AUTH_PASSWORD and combines them through MD5, which a recipe cannot
// express today.
//
// oracle2john writes 2 further fields for a full capture, AUTH_PASSWORD and the client's
// AUTH_SESSKEY. A line carrying them is refused rather than checked this weakly, so that it stays
// available to a mode that implements the full check.

static const char *SIGNATURE_O5LOGON = "$o5logon$";

#define O5LOGON_SESSKEY_HEX 96
#define O5LOGON_VFR_HEX     20

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_O5LOGON;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = O5LOGON_SESSKEY_HEX;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = O5LOGON_VFR_HEX;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // The recipe reads both fields out of the salt with fromhex (), so the salt is their hex text in
  // the order the line carries it, AUTH_SESSKEY then AUTH_VFR_DATA.

  u8 *salt_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_ptr, token.buf[1], O5LOGON_SESSKEY_HEX);

  memcpy (salt_ptr + O5LOGON_SESSKEY_HEX, token.buf[2], O5LOGON_VFR_HEX);

  salt->salt_len = O5LOGON_SESSKEY_HEX + O5LOGON_VFR_HEX;

  // The recipe ends in a comparison, so every hash of this mode carries the same digest: the bytes
  // the recipe compares, zero padded to 16. Keep it in step with the constant in HASH_RECIPE.

  digest[0] = 0x08080808;
  digest[1] = 0x08080808;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
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
}
