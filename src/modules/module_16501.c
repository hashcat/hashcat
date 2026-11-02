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
#include "emu_inc_hash_md5.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_16;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FRAMEWORK;
static const char *HASH_NAME      = "Perl Mojolicious session cookie (HMAC-SHA256, >= v9.19)";
// Padded cookie with HMAC-SHA256 signature was introduced in version v9.19 of Mojolicious framework
// It's very like JWT HS256 tokens without a header, so it reuses the kernel.
// For versions pre v9.19, that uses non-padded HMAC-SHA1 signed cookies, use module 150.
static const u64   KERN_TYPE      = 16511;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_SELF_TEST_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "mojolicious=eyJiYXIiOiJhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmNhYmMiLCJleHBpcmVzIjoxNzU1MDIxNjM4LCJmb29vIjoxfVpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo---078935cd386250a467f9d7bfe379d6f0175679545460660c3ca090eb4c69ddbf";

#include "hooks_common.c"

typedef struct mojolicious
{
  u32 salt_buf[1024];
  u32 salt_len;

  u32 signature_len;

} mojolicious_t;

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_iter = 1;
  salt->salt_len  = 16;

  return salt;
}

void *module_benchmark_esalt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  mojolicious_t *mojolicious = (mojolicious_t *) hcmalloc (sizeof (mojolicious_t));

  mojolicious->signature_len = 43;
  mojolicious->salt_len      = 32;

  return mojolicious;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (mojolicious_t);

  return esalt_size;
}

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info)
{
  return 16511;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  mojolicious_t *mojolicious = (mojolicious_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  // total = max 4096 characters
  // name=value = max 4030 characters

  // cookie name
  token.sep[0]     = '=';
  token.len_min[0] = 1;
  token.len_max[0] = 128;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  // cookie value: uses a fixed length as the value is padded to 1025
  // bytes with 'Z' characters before being base64 encoded. Note that
  // '=' is replaced with '-' in the base64 output.
  token.len[1]  = 1368;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH;

  // '--' as separator
  token.sep[2]     = '-';
  token.len_min[2] = 0;
  token.len_max[2] = 0;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // '--' as separator
  token.sep[3]     = '-';
  token.len_min[3] = 0;
  token.len_max[3] = 0;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // signature: hmac_sha256 hex encoded
  token.len_min[4] = 64;
  token.len_max[4] = 64;
  token.attr[4] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const int name_len = token.len[0];
  const int payload_len = token.len[1];
  mojolicious->signature_len = token.len[4];

  // esalt

  const int esalt_len = name_len + 1 + payload_len;

  if (esalt_len > 4096) return (PARSER_SALT_LENGTH);

  memcpy (mojolicious->salt_buf, line_buf, esalt_len);

  mojolicious->salt_len = esalt_len;

  // salt

  // Create a hash of the esalt because esalt buffer can change somewhere behind salt->salt_buf size
  // Not a regular MD5 but good enough

  u32 hash[4];

  hash[0] = 0;
  hash[1] = 1;
  hash[2] = 2;
  hash[3] = 3;

  u32 block[16];

  memset (block, 0, sizeof (block));

  for (int i = 0; i < 1024; i += 16)
  {
    for (int j = 0; j < 16; j++)
    {
      block[j] = mojolicious->salt_buf[i + j];

      md5_transform (block + 0, block + 4, block + 8, block + 12, hash);
    }
  }

  salt->salt_buf[0] = hash[0];
  salt->salt_buf[1] = hash[1];
  salt->salt_buf[2] = hash[2];
  salt->salt_buf[3] = hash[3];

  salt->salt_len = 16;

  const u8 *hash_pos = token.buf[4];
  u32 *digest = (u32 *) digest_buf;

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
  const mojolicious_t *mojolicious = (const mojolicious_t *) esalt_buf;

  const u32 *digest32 = (const u32 *) digest_buf;

  char ptr_plain[128];

  u32 tmp[8];

  tmp[0] = byte_swap_32 (digest32[0]);
  tmp[1] = byte_swap_32 (digest32[1]);
  tmp[2] = byte_swap_32 (digest32[2]);
  tmp[3] = byte_swap_32 (digest32[3]);
  tmp[4] = byte_swap_32 (digest32[4]);
  tmp[5] = byte_swap_32 (digest32[5]);
  tmp[6] = byte_swap_32 (digest32[6]);
  tmp[7] = byte_swap_32 (digest32[7]);

  u8 *out_buf = (u8 *) ptr_plain;

  int out_len = 0;

  u32_to_hex (tmp[0], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[1], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[2], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[3], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[4], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[5], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[6], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[7], out_buf + out_len); out_len += 8;

  out_buf[64]=0;

  const int line_len = snprintf (line_buf, line_size, "%s--%s", (char *) mojolicious->salt_buf, (char *) ptr_plain);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_esalt          = module_benchmark_esalt;
  module_ctx->module_benchmark_salt           = module_benchmark_salt;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kern_type_dynamic        = module_kern_type_dynamic;
}
