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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH_SALTED;
static const char *HASH_NAME      = "UUID v5 (RFC 4122 name-based, SHA-1)";
static const char *HASH_RECIPE    = "hex(and(sha1_bin(salt . pass), fromhex('ffffffffffff0fff3fffffffffffffff')))";
static const u64   KERN_TYPE      = 40005;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "1cc9c588-793e-5098-a328-1dcf2519d238:6ba7b810-9dad-11d1-80b4-00c04fd430c8";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

// The version a name-based UUID of this mode carries in the high nibble of byte 6. The variant in
// the top 2 bits of byte 8 is the RFC 4122 one, binary 10.

static const u8 UUID_VERSION = 5;

// A UUID in its canonical text form: 32 hex digits in groups of 8, 4, 4, 4 and 12, joined by
// dashes. These are the positions of its 16 bytes.

static const u32 UUID_OFFS[16] = { 0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34 };

static bool uuid_decode (const u8 *buf, u8 *out)
{
  if (buf[ 8] != '-') return false;
  if (buf[13] != '-') return false;
  if (buf[18] != '-') return false;
  if (buf[23] != '-') return false;

  for (u32 i = 0; i < 16; i++)
  {
    const u32 pos = UUID_OFFS[i];

    if (is_valid_hex_char (buf[pos + 0]) == false) return false;
    if (is_valid_hex_char (buf[pos + 1]) == false) return false;

    out[i] = hex_to_u8 (&buf[pos]);
  }

  return true;
}

static void uuid_encode (const u8 *in, u8 *buf)
{
  for (u32 i = 0; i < 16; i++) u8_to_hex (in[i], &buf[UUID_OFFS[i]]);

  buf[ 8] = '-';
  buf[13] = '-';
  buf[18] = '-';
  buf[23] = '-';
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  // <uuid>:<namespace uuid>

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 36;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH;

  token.len[1]     = 36;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8 uuid[16];

  if (uuid_decode (token.buf[0], uuid) == false) return (PARSER_HASH_ENCODING);

  if ((uuid[6] >> 4) != UUID_VERSION) return (PARSER_HASH_VALUE);

  if ((uuid[8] & 0xc0) != 0x80) return (PARSER_HASH_VALUE);

  // the version and the variant are set over the digest, so they are cleared on both sides

  uuid[6] &= 0x0f;
  uuid[8] &= 0x3f;

  // the and () result is compared in memory order

  memcpy (digest, uuid, 16);

  u8 ns[16];

  if (uuid_decode (token.buf[1], ns) == false) return (PARSER_SALT_ENCODING);

  memcpy (salt->salt_buf, ns, 16);

  salt->salt_len = 16;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  u8 uuid[16];

  memcpy (uuid, digest_buf, 16);

  uuid[6] |= UUID_VERSION << 4;
  uuid[8] |= 0x80;

  u8 *out_buf = (u8 *) line_buf;

  uuid_encode (uuid, out_buf);

  out_buf[36] = hashconfig->separator;

  uuid_encode ((const u8 *) salt->salt_buf, &out_buf[37]);

  const int out_len = 36 + 1 + 36;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
}
