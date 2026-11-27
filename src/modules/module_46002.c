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
#include "memory.h"

#include "argon2_common.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Lace Wallet (SBV1, Argon2id + ChaCha20-Poly1305)";
static const u64   KERN_TYPE      = 46002;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "LaceTest2026!";
static const char *ST_HASH        = "$sbv1$534256310011223344556677889900aabbccddee1100223344556677889900aabbccddeecafebabedeadbeef01020304f9c0e959b951b852bd88cba6e0f947a788fe1382e5847680c22d30f29c1dcbe25188f05fecb37077f06e2eab0c546440";

// SBV1 cost parameters are fixed by the format (lace secret-box kdf.ts)

#define SBV1_ARGON_MEM 19456  // KiB
#define SBV1_ARGON_TIME 2
#define SBV1_ARGON_PAR  1

#define SBV1_HEADER_LEN 48    // magic(4) + salt(32) + nonce(12)
#define SBV1_CT_MIN     17    // 1 byte ct + 16 byte tag
#define SBV1_CT_MAX     2048

// this must exist so that argon2_common.c can work with correct sizes

typedef struct sbv1
{
  u32 nonce[3];            // 12 bytes
  u32 ct[SBV1_CT_MAX / 4]; // ct without the tag (tag rides in the digest)
  u32 ct_len;

} sbv1_t;

typedef struct merged_options
{
  argon2_options_t argon2_options;
  sbv1_t s;

} merged_options_t;

static const char *SIGNATURE_SBV1 = "$sbv1$";

#include "hooks_common.c"
#include "argon2_common.c"

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (merged_options_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) 4;

  return tmp_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  merged_options_t *merged_options = (merged_options_t *) esalt_buf;

  argon2_options_t *argon2_options = &merged_options->argon2_options;
  sbv1_t *s                        = &merged_options->s;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SBV1;

  token.len[0]     = 6;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = (SBV1_HEADER_LEN + SBV1_CT_MIN) * 2;
  token.len_max[1] = (SBV1_HEADER_LEN + 16 + SBV1_CT_MAX) * 2; // + the 16-byte tag
  token.sep[1]     = 0;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8 tmp[(SBV1_HEADER_LEN + SBV1_CT_MAX) + 16];

  const int env_len = hex_decode (token.buf[1], token.len[1], tmp);

  if (env_len < SBV1_HEADER_LEN + SBV1_CT_MIN) return (PARSER_HASH_LENGTH);

  // magic gate: "SBV1"

  if (tmp[0] != 'S' || tmp[1] != 'B' || tmp[2] != 'V' || tmp[3] != '1') return (PARSER_SIGNATURE_UNMATCHED);

  // Argon2id parameters are FIXED by the SBV1 format (not carried in the line)

  argon2_options->type    = 2;  // Argon2id
  argon2_options->version = 19; // 0x13
  argon2_options->memory_usage_in_kib = SBV1_ARGON_MEM;
  argon2_options->iterations          = SBV1_ARGON_TIME;
  argon2_options->parallelism         = SBV1_ARGON_PAR;

  argon2_options->segment_length     = MAX (2, (argon2_options->memory_usage_in_kib / (ARGON2_SYNC_POINTS * argon2_options->parallelism)));
  argon2_options->lane_length        = argon2_options->segment_length * ARGON2_SYNC_POINTS;
  argon2_options->memory_block_count = argon2_options->lane_length * argon2_options->parallelism;
  argon2_options->digest_len         = 32;

  // salt (32 bytes at offset 4)

  salt->salt_len = 32;

  memcpy (salt->salt_buf, tmp + 4, 32);

  salt->salt_iter = argon2_options->iterations * ARGON2_SYNC_POINTS;
  salt->salt_dimy = argon2_options->parallelism;

  // sort_by_salt () never reads the esalt, so m and p go into salt_buf_pc, same as the other Argon2
  // modes

  salt->salt_buf_pc[0] = argon2_options->memory_usage_in_kib;
  salt->salt_buf_pc[1] = argon2_options->parallelism;

  // nonce (12 bytes at offset 36), LE-packed

  memcpy ((u8 *) s->nonce, tmp + 36, 12);

  // ct + tag from offset 48; tag = last 16 bytes, LE-packed into the digest

  const int box_len = env_len - SBV1_HEADER_LEN;
  const int ct_len  = box_len - 16;

  if (ct_len < 1 || ct_len > SBV1_CT_MAX) return (PARSER_CT_LENGTH);

  memcpy ((u8 *) s->ct, tmp + SBV1_HEADER_LEN, ct_len);

  s->ct_len = ct_len;

  const u8 *tag = tmp + SBV1_HEADER_LEN + ct_len;

  digest[0] = (u32) tag[0]  | ((u32) tag[1]  << 8) | ((u32) tag[2]  << 16) | ((u32) tag[3]  << 24);
  digest[1] = (u32) tag[4]  | ((u32) tag[5]  << 8) | ((u32) tag[6]  << 16) | ((u32) tag[7]  << 24);
  digest[2] = (u32) tag[8]  | ((u32) tag[9]  << 8) | ((u32) tag[10] << 16) | ((u32) tag[11] << 24);
  digest[3] = (u32) tag[12] | ((u32) tag[13] << 8) | ((u32) tag[14] << 16) | ((u32) tag[15] << 24);

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const merged_options_t *merged_options = (const merged_options_t *) esalt_buf;
  const sbv1_t *s                        = &merged_options->s;

  const u32 *digest = (const u32 *) digest_buf;

  u8 env[SBV1_HEADER_LEN + SBV1_CT_MAX];

  env[0] = 'S';
  env[1] = 'B';
  env[2] = 'V';
  env[3] = '1';

  for (int i = 0; i < 32; i++) env[4 + i] = (salt->salt_buf[i / 4] >> ((i % 4) * 8)) & 0xff;

  memcpy (env + 36, (const u8 *) s->nonce, 12);

  memcpy (env + SBV1_HEADER_LEN, (const u8 *) s->ct, s->ct_len);

  u8 tag_raw[16];

  memcpy (tag_raw, digest, 16); // LE-packed words -> raw tag bytes on LE hosts

  memcpy (env + SBV1_HEADER_LEN + s->ct_len, tag_raw, 16);

  const int env_len = SBV1_HEADER_LEN + s->ct_len + 16;

  // hex_encode does not terminate the string; the zeroed buffer ends it

  u8 hex[SBV1_HEADER_LEN * 2 + SBV1_CT_MAX * 2 + 16 * 2 + 1] = { 0 };

  hex_encode (env, env_len, hex);

  return snprintf (line_buf, line_size, "%s%s", SIGNATURE_SBV1, hex);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_attack_exec            = module_attack_exec;
  module_ctx->module_benchmark_cost         = argon2_module_benchmark_cost;
  module_ctx->module_dgst_pos0              = module_dgst_pos0;
  module_ctx->module_dgst_pos1              = module_dgst_pos1;
  module_ctx->module_dgst_pos2              = module_dgst_pos2;
  module_ctx->module_dgst_pos3              = module_dgst_pos3;
  module_ctx->module_dgst_size              = module_dgst_size;
  module_ctx->module_esalt_size             = module_esalt_size;
  module_ctx->module_extra_buffer_size      = argon2_module_extra_buffer_size;
  module_ctx->module_extra_tuningdb_block   = argon2_module_extra_tuningdb_block;
  module_ctx->module_hash_category          = module_hash_category;
  module_ctx->module_hash_decode            = module_hash_decode;
  module_ctx->module_hash_encode            = module_hash_encode;
  module_ctx->module_hash_name              = module_hash_name;
  module_ctx->module_jit_build_options      = argon2_module_jit_build_options;
  module_ctx->module_kern_type              = module_kern_type;
  module_ctx->module_opti_type              = module_opti_type;
  module_ctx->module_opts_type              = module_opts_type;
  module_ctx->module_salt_type              = module_salt_type;
  module_ctx->module_st_hash                = module_st_hash;
  module_ctx->module_st_pass                = module_st_pass;
  module_ctx->module_tmp_size               = module_tmp_size;
}
