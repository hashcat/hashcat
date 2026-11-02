
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
#include "emu_inc_hash_md4.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = 80 * sizeof (u32); // 320 bytes: md4 digest at 0, plaintext stored at +64 for up to 256 chars
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PLAIN;
static const char *HASH_NAME      = "Plaintext";
static const char *HASH_RECIPE    = "md4(pass)";
static const u64   KERN_TYPE      = 900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_MEET_IN_MIDDLE
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS14
                                  | OPTS_TYPE_AUTODETECT_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_NONE;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "hashcat";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

bool module_potfile_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool potfile_disable = true;

  return potfile_disable;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 1;

  token.len_min[0] = 1;
  token.len_max[0] = 256 * 2 + 6; /* 256 without $HEX[...] */
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *unhex_buf = token.buf[0];
  int unhex_len       = token.len[0];

  if (is_hexify (unhex_buf, unhex_len))
  {
    unhex_len = exec_unhexify (unhex_buf, unhex_len, (u8 *) unhex_buf, unhex_len);
  }

  if ((u32) unhex_len > hashconfig->pw_max)
  {
    return (PARSER_HASH_LENGTH);
  }

  memset (digest, 0, hashconfig->dgst_size);

  const u8 *pw_buf = unhex_buf;
  const int pw_len = unhex_len;

  memcpy ((char *) digest + 64, pw_buf, pw_len);

  //strncpy ((char *) digest + 64, (char *) input_buf, 64);

  u32 w[64] = { 0 };

  //strncpy ((char *) w, (char *) input_buf, 64);

  memcpy (w, pw_buf, pw_len);

  md4_ctx_t ctx;

  md4_init (&ctx);
  md4_update (&ctx, w, pw_len);
  md4_final (&ctx);

  digest[0] = ctx.h[0];
  digest[1] = ctx.h[1];
  digest[2] = ctx.h[2];
  digest[3] = ctx.h[3];

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= MD4M_A;
    digest[1] -= MD4M_B;
    digest[2] -= MD4M_C;
    digest[3] -= MD4M_D;
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const char *ptr = (const char *) digest_buf;

  const char *line_ptr = ptr + 64;
  size_t line_len      = strnlen (line_ptr, 256);

  if (need_hexify ((const u8 *) line_ptr, line_len, ':', 0))
  {
    char tmp_buf[256 * 2 + 6 + 1] = { 0 };

    int tmp_len = 0;

    tmp_buf[tmp_len++] = '$';
    tmp_buf[tmp_len++] = 'H';
    tmp_buf[tmp_len++] = 'E';
    tmp_buf[tmp_len++] = 'X';
    tmp_buf[tmp_len++] = '[';

    const size_t hex_len = exec_hexify ((const u8 *) line_ptr, line_len, (u8 *) tmp_buf + tmp_len);

    tmp_len += (int) hex_len;

    tmp_buf[tmp_len++] = ']';

    tmp_buf[tmp_len++] = 0;

    return snprintf (line_buf, tmp_len, "%s", tmp_buf);
  }

  return snprintf (line_buf, line_size, "%.*s", (int) line_len, line_ptr);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_potfile_disable          = module_potfile_disable;
}
