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
static const u32   DGST_POS0      = 3;
static const u32   DGST_POS1      = 4;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "IPMI2 RAKP HMAC-SHA1";
static const char *HASH_RECIPE    = "hmac_sha1(pass, salt)";
static const u64   KERN_TYPE      = 7300;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_ST_ADD80
                                  | OPTS_TYPE_ST_ADDBITS15;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "3437343735333336383831353232323433383333303236303337333338363232303135383237333638363532373231343030313131333838323734373138363632343133333335353030353633373533333133313530363533303738343334313330303630343633333237373037383537333630303233303830303437323838333237313438363238343434383831363634323431333430383735323038:f4b376e25868751fc0264f573ff1fe50b65ce5a2";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

typedef struct rakp
{
  u32 salt_buf[128];
  u32 salt_len;

} rakp_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (rakp_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  rakp_t *rakp = (rakp_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 64;
  token.len_max[0] = 512;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]     = 40;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *salt_pos = token.buf[0];
  const int salt_len = token.len[0];

  u8 *rakp_ptr = (u8 *) rakp->salt_buf;

  int i;
  int j;

  if (salt_len & 1) return (PARSER_TOKEN_LENGTH);

  // i + 1, not i: hex_to_u8 () reads two characters, so an odd salt_len read one past the token

  for (i = 0, j = 0; (i + 1) < salt_len; i += 2, j += 1)
  {
    rakp_ptr[j] = hex_to_u8 (salt_pos + i);
  }

  rakp_ptr[j] = 0x80;

  rakp->salt_len = j;

  // the recipe kernels read the salt from salt_buf in its original byte order

  memcpy (salt->salt_buf, rakp->salt_buf, j);

  salt->salt_len = j;

  for (i = 0; i < 64; i++)
  {
    rakp->salt_buf[i] = byte_swap_32 (rakp->salt_buf[i]);
  }

  const u8 *hash_pos = token.buf[1];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const rakp_t *rakp = (const rakp_t *) esalt_buf;

  const u8 *ptr = (const u8 *) rakp->salt_buf;

  int line_len = 0;

  for (u32 i = 0; i < rakp->salt_len; i++)
  {
    line_len += snprintf (line_buf + line_len, line_size - line_len, "%02x", ptr[i ^ 3]); // the ^ 3 index converts LE -> BE
  }

  line_len += snprintf (line_buf + line_len, line_size - line_len, "%c%08x%08x%08x%08x%08x",
    hashconfig->separator,
    digest[0],
    digest[1],
    digest[2],
    digest[3],
    digest[4]);

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
