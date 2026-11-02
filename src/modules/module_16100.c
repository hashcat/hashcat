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
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // originally DGST_SIZE_4_;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "TACACS+";
static const u64   KERN_TYPE      = 16100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$tacacs-plus$0$5fde8e68$4e13e8fb33df$c006";

#include "hooks_common.c"

typedef struct tacacs_plus
{
  u32 session_buf[16];

  u32 ct_data_buf[64];
  u32 ct_data_len;

  u32 sequence_buf[16];

} tacacs_plus_t;

static const char *SIGNATURE_TACACS_PLUS = "$tacacs-plus$0$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (tacacs_plus_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  tacacs_plus_t *tacacs_plus = (tacacs_plus_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_TACACS_PLUS;

  token.len[0]     = 15;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 8;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len_min[2] = 12;
  token.len_max[2] = 256;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 4;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // session

  const u8 *session_pos = token.buf[1];

  u8 *session_ptr = (u8 *) tacacs_plus->session_buf;

  session_ptr[0] = hex_to_u8 (session_pos + 0);
  session_ptr[1] = hex_to_u8 (session_pos + 2);
  session_ptr[2] = hex_to_u8 (session_pos + 4);
  session_ptr[3] = hex_to_u8 (session_pos + 6);

  // ct_buf

  const u8 *ct_buf_pos = token.buf[2];
  const int ct_buf_len = token.len[2];

  u8 *ct_data_ptr = (u8 *) tacacs_plus->ct_data_buf;

  for (int i = 0, j = 0; j < ct_buf_len; i += 1, j += 2)
  {
    ct_data_ptr[i] = hex_to_u8 (&ct_buf_pos[j]);

    tacacs_plus->ct_data_len++;
  }

  // sequence

  const u8 *sequence_pos = token.buf[3];

  u8 *sequence_ptr = (u8 *) tacacs_plus->sequence_buf;

  sequence_ptr[0] = hex_to_u8 (sequence_pos + 0);
  sequence_ptr[1] = hex_to_u8 (sequence_pos + 2);

  // fake salt

  salt->salt_buf[0] = tacacs_plus->session_buf[0];
  salt->salt_buf[1] = tacacs_plus->sequence_buf[0];
  salt->salt_buf[2] = tacacs_plus->ct_data_buf[0];
  salt->salt_buf[3] = tacacs_plus->ct_data_buf[1];

  salt->salt_len = 16;

  // fake hash

  digest[0] = tacacs_plus->ct_data_buf[2];
  digest[1] = tacacs_plus->ct_data_buf[3];
  digest[2] = tacacs_plus->ct_data_buf[4];
  digest[3] = tacacs_plus->ct_data_buf[5];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const tacacs_plus_t *tacacs_plus = (const tacacs_plus_t *) esalt_buf;

  char ct_data[256 + 1] = { 0 };

  const u8 *ct_data_ptr = (const u8 *) tacacs_plus->ct_data_buf;

  for (u32 i = 0, j = 0; i < tacacs_plus->ct_data_len; i += 1, j += 2)
  {
    snprintf (ct_data + j, 3, "%02x", ct_data_ptr[i]);
  }

  const u8 *session_ptr  = (const u8 *) tacacs_plus->session_buf;
  const u8 *sequence_ptr = (const u8 *) tacacs_plus->sequence_buf;

  const int line_len = snprintf (line_buf, line_size, "%s%02x%02x%02x%02x$%s$%02x%02x",
    SIGNATURE_TACACS_PLUS,
    session_ptr[0],
    session_ptr[1],
    session_ptr[2],
    session_ptr[3],
    ct_data,
    sequence_ptr[0],
    sequence_ptr[1]);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
}
