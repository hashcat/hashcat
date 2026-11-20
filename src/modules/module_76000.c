/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_GENERIC_KDF;
static const char *HASH_NAME      = "Argon2id [Bridged: Remote]";
static const u64   KERN_TYPE      = 76000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_SELF_TEST_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const u64   BRIDGE_TYPE    = BRIDGE_TYPE_REPLACE_LOOP;
static const char *BRIDGE_NAME    = "remote_gpu_argon";
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$argon2id$v=19$m=65536,t=3,p=1$FBMjI4RJBhIykCgol1KEJA$2ky5GAdhT1kH4kIgPN/oERE3Taiy43vNN70a3HpiKQU";

#include "hooks_common.c"

const char *module_bridge_name    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BRIDGE_NAME;     }
u64         module_bridge_type    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BRIDGE_TYPE;     }

typedef struct argon2id
{
  u32 iterations;
  u32 parallelism;
  u32 memory_usage_in_kib;

  u32 digest_len;

} argon2id_t;

typedef struct argon2id_tmp
{
  u32 first_block[16][256];
  u32 second_block[16][256];

  u32 final_block[256];

} argon2id_tmp_t;

static const char *SIGNATURE_ARGON2ID = "$argon2id$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (argon2id_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (argon2id_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  argon2id_t *argon2id = (argon2id_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ARGON2ID;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 4;
  token.sep[1]     = '$';
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  // memoryUsageInKib
  token.len_min[2] = 3;
  token.len_max[2] = 12;
  token.sep[2]     = ',';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // iteration
  token.len_min[3] = 3;
  token.len_max[3] = 5;
  token.sep[3]     = ',';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // parallelism
  token.len_min[4] = 3;
  token.len_max[4] = 5;
  token.sep[4]     = '$';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  // salt
  token.len_min[5] = ((SALT_MIN * 8) / 6) + 0;
  token.len_max[5] = ((SALT_MAX * 8) / 6) + 3;
  token.sep[5]     = '$';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // target hash
  token.len_min[6] = ((  1 * 8) / 6) + 0;
  token.len_max[6] = ((128 * 8) / 6) + 3;
  token.sep[6]     = '$';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const int version_len = token.len[1];
  const u8 *version_pos = token.buf[1];

  if (version_len != 4) return (PARSER_HASH_VALUE);

  if (memcmp (version_pos, "v=19", 4)) return (PARSER_HASH_VALUE);

  // argon2id config

  const u8 *mem_pos = token.buf[2];
  const u8 *it_pos = token.buf[3];
  const u8 *par_pos = token.buf[4];

  argon2id->memory_usage_in_kib = hc_strtoul ((const char *) mem_pos + 2, NULL, 10);
  argon2id->iterations = hc_strtoul ((const char *) it_pos + 2, NULL, 10);
  argon2id->parallelism = hc_strtoul ((const char *) par_pos + 2, NULL, 10);

  if (argon2id->memory_usage_in_kib < 1) return (PARSER_HASH_VALUE);
  if (argon2id->iterations < 1) return (PARSER_HASH_VALUE);
  if (argon2id->parallelism < 1) return (PARSER_HASH_VALUE);

  if (argon2id->parallelism > 16 ) return (PARSER_HASH_VALUE);

  // salt
  const int salt_len = token.len[5];
  const u8 *salt_pos = token.buf[5];

  // single (dummy) loop for this implementation!
  salt->salt_iter = 1;

  // Hashes are grouped by salt, and sort_by_salt () compares only the salt string, salt_iter and
  // salt_buf_pc. the memory cost, the iterations and the parallelism go into salt_buf_pc,
  // which the kernel does not read, so 2 hashes that share a salt string but differ in m, t or p stay
  // separate salts.

  salt->salt_buf_pc[0] = argon2id->memory_usage_in_kib;
  salt->salt_buf_pc[1] = argon2id->iterations;
  salt->salt_buf_pc[2] = argon2id->parallelism;

  u8 tmp_buf[512] = { 0 };

  int tmp_len = base64_decode (base64_to_int, (const u8 *) salt_pos, salt_len, tmp_buf);

  if (tmp_len > (int) sizeof (salt->salt_buf)) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  // digest/ target hash
  const int digest_len = token.len[6];
  const u8 *digest_pos = token.buf[6];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, (const u8 *) digest_pos, digest_len, tmp_buf);

  if (tmp_len != (int) DGST_SIZE) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, tmp_len);

  argon2id->digest_len = tmp_len;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  u32 *digest = (u32 *) digest_buf;

  argon2id_t *argon2id = (argon2id_t *) esalt_buf;

  // salt
  char base64_salt[512] = { 0 };
  int len1 = base64_encode (int_to_base64, (const u8 *) salt->salt_buf, salt->salt_len, (u8 *) base64_salt);

  for (int i = len1 - 1; i >=0; i--) if (base64_salt[i] == '=') base64_salt[i] = 0;

  // digest
  char base64_digest[512] = { 0 };
  int len2 = base64_encode (int_to_base64, (const u8 *) digest, argon2id->digest_len, (u8 *) base64_digest);

  for (int i = len2 - 1; i >=0; i--) if (base64_digest[i] == '=') base64_digest[i] = 0;

  const int out_len = snprintf (line_buf, line_size, "%sv=19$m=%d,t=%d,p=%d$%s$%s",
    SIGNATURE_ARGON2ID,
    argon2id->memory_usage_in_kib,
    argon2id->iterations,
    argon2id->parallelism,
    base64_salt,
    base64_digest);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_bridge_name              = module_bridge_name;
  module_ctx->module_bridge_type              = module_bridge_type;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
