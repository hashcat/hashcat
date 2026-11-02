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
#include "emu_inc_hash_sha1.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 3;
static const u32   DGST_POS1      = 7;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 6;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Amazon AWS Signature Version 4";
static const u64   KERN_TYPE      = 28700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_ST_ADD80;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$AWS-Sig-v4$0$20220221T000000Z$us-east-1$s3$421ab6e4af9f49fa30fa9c253fcfeb2ce91668e139e6b23303c5f75b04f8a3c4$3755ed2bc1b2346e003ccaa7d02ae8b73c72bcbe9f452ccf066c78504d786bbb";

#include "hooks_common.c"

static const char *SIGNATURE_AWS_SIG_V4 = "$AWS-Sig-v4$0$";

typedef struct aws4_sig_v4
{
  u32 date[3];
  u32 date_len;

  u32 longdate[4];
  u32 longdate_len;

  u32 region[4];
  u32 region_len;

  u32 service[4];
  u32 service_len;

  u32 canonical[8];
  u32 canonical_len;

  u32 stringtosign[64];
  u32 stringtosign_len;

} aws4_sig_v4_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (aws4_sig_v4_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // reduce pw_max by 4

  u32 pw_max = PW_MAX - 4;

  if (user_options->optimized_kernel == true && hashconfig->has_optimized_kernel == true)
  {
    pw_max = PW_MAX_OLD - 4;
  }

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  aws4_sig_v4_t *esalt = (aws4_sig_v4_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 6;
  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_AWS_SIG_V4;

  token.len[0]     = 14;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // longdate
  token.sep[1]     = '$';
  token.len[1]     = 16;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  // region
  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 16;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // service
  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 16;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // canonical
  token.sep[4]     = '$';
  token.len[4]     = 32 * 2;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // digest
  token.sep[5]     = '$';
  token.len[5]     = 32 * 2;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  memset (esalt, 0, sizeof (aws4_sig_v4_t));

  bool parse_rc = false;

  // longdate

  const u8 *longdate_pos = token.buf[1];
  const int longdate_len = token.len[1];

  parse_rc = generic_salt_decode (hashconfig, longdate_pos, longdate_len, (u8 *) esalt->longdate, (int *) &esalt->longdate_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // date

  parse_rc = generic_salt_decode (hashconfig, longdate_pos, 8, (u8 *) esalt->date, (int *) &esalt->date_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // region

  const u8 *region_pos = token.buf[2];
  const int region_len = token.len[2];

  parse_rc = generic_salt_decode (hashconfig, region_pos, region_len, (u8 *) esalt->region, (int *) &esalt->region_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // service

  const u8 *service_pos = token.buf[3];
  const int service_len = token.len[3];

  parse_rc = generic_salt_decode (hashconfig, service_pos, service_len, (u8 *) esalt->service, (int *) &esalt->service_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // canonical

  const u8 *canonical_pos = token.buf[4];
  const int canonical_len = token.len[4];

  esalt->canonical_len = hex_decode (canonical_pos, canonical_len, (u8 *) esalt->canonical);

  // handle unique salts detection

  sha1_ctx_t sha1_ctx;

  sha1_init   (&sha1_ctx);
  sha1_update (&sha1_ctx, esalt->canonical, esalt->canonical_len);
  sha1_final  (&sha1_ctx);

  // store sha1(esalt->canonical) in salt_buf

  salt->salt_iter = 1;

  salt->salt_len = 20;

  memcpy (salt->salt_buf, sha1_ctx.h, salt->salt_len);

  // stringtosign

  char *stringtosign_ptr = (char *) esalt->stringtosign;

  size_t off = 0;

  memcpy (stringtosign_ptr + off, (char *) "AWS4-HMAC-SHA256", 16);
  off += 16;

  stringtosign_ptr[off] = 0x0a;
  off += 1;

  memcpy (stringtosign_ptr + off, (char *) esalt->longdate, esalt->longdate_len);
  off += esalt->longdate_len;

  stringtosign_ptr[off] = 0x0a;
  off += 1;

  memcpy (stringtosign_ptr + off, (char *) esalt->date, esalt->date_len);
  off += esalt->date_len;

  stringtosign_ptr[off] = 0x2f;
  off += 1;

  memcpy (stringtosign_ptr + off, (char *) esalt->region, esalt->region_len);
  off += esalt->region_len;

  stringtosign_ptr[off] = 0x2f;
  off += 1;

  memcpy (stringtosign_ptr + off, (char *) esalt->service, esalt->service_len);
  off += esalt->service_len;

  stringtosign_ptr[off] = 0x2f;
  off += 1;

  memcpy (stringtosign_ptr + off, (char *) "aws4_request", 12);
  off += 12;

  stringtosign_ptr[off] = 0x0a;
  off += 1;

  memcpy (stringtosign_ptr + off, (const char *) canonical_pos, canonical_len);
  off += canonical_len;

  esalt->stringtosign_len = off;

  // digest

  const u8 *hash_pos = token.buf[5];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const aws4_sig_v4_t *esalt = (const aws4_sig_v4_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  // signature

  int out_len = snprintf (line_buf, line_size, "%s", SIGNATURE_AWS_SIG_V4);

  // longdate

  out_len += generic_salt_encode (hashconfig, (const u8 *) esalt->longdate, (const int) esalt->longdate_len, out_buf + out_len);

  out_buf[out_len] = '$';

  out_len++;

  // region

  out_len += generic_salt_encode (hashconfig, (const u8 *) esalt->region, (const int) esalt->region_len, out_buf + out_len);

  out_buf[out_len] = '$';

  out_len++;

  // service

  out_len += generic_salt_encode (hashconfig, (const u8 *) esalt->service, (const int) esalt->service_len, out_buf + out_len);

  out_buf[out_len] = '$';

  out_len++;

  // canonical

  out_len += hex_encode ((const u8 *) esalt->canonical, esalt->canonical_len, out_buf + out_len);

  out_buf[out_len] = '$';

  out_len++;

  // digest

  u32 tmp[8];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];
  tmp[4] = digest[4];
  tmp[5] = digest[5];
  tmp[6] = digest[6];
  tmp[7] = digest[7];

  tmp[0] = byte_swap_32 (tmp[0]);
  tmp[1] = byte_swap_32 (tmp[1]);
  tmp[2] = byte_swap_32 (tmp[2]);
  tmp[3] = byte_swap_32 (tmp[3]);
  tmp[4] = byte_swap_32 (tmp[4]);
  tmp[5] = byte_swap_32 (tmp[5]);
  tmp[6] = byte_swap_32 (tmp[6]);
  tmp[7] = byte_swap_32 (tmp[7]);

  u32_to_hex (tmp[0], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[1], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[2], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[3], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[4], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[5], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[6], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[7], out_buf + out_len); out_len += 8;

  out_buf[out_len] = 0;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
}
