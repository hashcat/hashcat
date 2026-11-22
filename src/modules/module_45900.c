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
static const char *HASH_NAME      = "Sparrow Wallet (SPRW1, Argon2id 256MiB + XTS-AES-128)";
static const u64   KERN_TYPE      = 45900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_DIMY_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_ITERATION_OVERRIDE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "KatSparrow777!";
static const char *ST_HASH        = "$sparrow$1$000102030405060708090a0b0c0d0e0f$6dd10019cd94e71b$6927a10c68444e53ea27012e81376ad9980139af764f9e6156273ed98b153346ecef740804dd6acdbb4367549f615ac276057863204043484521a8901dba2b09";

// drongo Argon2KeyDeriver.SPRW1_PARAMETERS (fixed by the SPRW1 format)

#define SPARROW_ARGON_TIME 10
#define SPARROW_ARGON_MEM  262144 // 256 MiB in KiB
#define SPARROW_ARGON_PAR  4

#include "hooks_common.c"

typedef struct wallet_sparrow
{
  u32 h2salt[2];  // 8-byte H2 FileEncrypt salt (PBKDF2 stage)
  u32 ct[16];     // first 64 bytes of XTS unit 0 (store-header block)

} wallet_sparrow_t;

// this must exist so that argon2_common.c can work with correct sizes

typedef struct merged_options
{
  argon2_options_t argon2_options;
  wallet_sparrow_t w;

} merged_options_t;

#include "argon2_common.c"

static const char *SIGNATURE_SPARROW = "$sparrow$";

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

static void pack_le (u32 *dst, const u8 *src, const int nbytes, const int max_words)
{
  for (int i = 0; i < max_words; i++) dst[i] = 0;
  for (int i = 0; i < nbytes; i++) dst[i / 4] |= ((u32) src[i]) << ((i % 4) * 8);
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  merged_options_t *merged_options = (merged_options_t *) esalt_buf;

  argon2_options_t *argon2_options = &merged_options->argon2_options;
  wallet_sparrow_t *w              = &merged_options->w;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SPARROW;

  token.len[0]     = 9;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;   token.len_max[1] = 1;   token.sep[1] = '$'; token.attr[1] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;
  token.len_min[2] = 32;  token.len_max[2] = 32;  token.sep[2] = '$'; token.attr[2] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.len_min[3] = 16;  token.len_max[3] = 16;  token.sep[3] = '$'; token.attr[3] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  token.len_min[4] = 128; token.len_max[4] = 128; token.sep[4] = '$'; token.attr[4] = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // SPRW1 version gate: only "1" exists

  const u32 version = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (version != 1) return (PARSER_HASH_VALUE);

  // Argon2id parameters are FIXED by the SPRW1 format (not carried in the line)

  argon2_options->type    = 2;  // Argon2id
  argon2_options->version = 19; // 0x13
  argon2_options->memory_usage_in_kib = SPARROW_ARGON_MEM;
  argon2_options->iterations          = SPARROW_ARGON_TIME;
  argon2_options->parallelism         = SPARROW_ARGON_PAR;

  const char *test_limit = NULL;

  test_limit = getenv ("HASHCAT_ITER_OVERRIDE");

  if (test_limit != NULL)
  {
    u64 limit = 0;

    if (test_limit[0] == 0) return (PARSER_SALT_ITERATION);

    for (u32 i = 0; test_limit[i] != 0; i++)
    {
      if ((test_limit[i] < '0') || (test_limit[i] > '9')) return (PARSER_SALT_ITERATION);

      limit = limit * 10 + (test_limit[i] - '0');

      if (limit > 0xffffffffULL) return (PARSER_SALT_ITERATION);
    }

    if (limit != 0)
    {
      // Argon2 loops advance in four slices per pass.
      if ((limit < ARGON2_SYNC_POINTS) || ((limit % ARGON2_SYNC_POINTS) != 0)) return (PARSER_SALT_ITERATION);

      argon2_options->iterations = MIN (argon2_options->iterations, (u32) (limit / ARGON2_SYNC_POINTS));
      argon2_options->memory_usage_in_kib = MIN (argon2_options->memory_usage_in_kib, 4096);
    }
  }

  argon2_options->segment_length     = MAX (2, (argon2_options->memory_usage_in_kib / (ARGON2_SYNC_POINTS * argon2_options->parallelism)));
  argon2_options->lane_length        = argon2_options->segment_length * ARGON2_SYNC_POINTS;
  argon2_options->memory_block_count = argon2_options->lane_length * argon2_options->parallelism;
  argon2_options->digest_len         = 32;

  u8 tmp[128];

  // Argon2id salt (16 bytes, hex)

  const int salt_len = hex_decode (token.buf[2], token.len[2], tmp);

  if (salt_len != 16) return (PARSER_SALT_LENGTH);

  salt->salt_len  = salt_len;

  memcpy (salt->salt_buf, tmp, salt_len);

  salt->salt_iter = argon2_options->iterations * ARGON2_SYNC_POINTS;
  salt->salt_dimy = argon2_options->parallelism;

  // sort_by_salt () compares only the salt string, salt_iter and salt_buf_pc, so m and p go into
  // salt_buf_pc, same as the other Argon2 modes. The SPRW1 parameters are fixed, but this keeps the
  // salt layout uniform and feeds module_benchmark_cost ().

  salt->salt_buf_pc[0] = argon2_options->memory_usage_in_kib;
  salt->salt_buf_pc[1] = argon2_options->parallelism;

  // H2 FileEncrypt salt (8 bytes, hex)

  const int h2salt_len = hex_decode (token.buf[3], token.len[3], tmp);

  if (h2salt_len != 8) return (PARSER_SALT_LENGTH);

  pack_le (w->h2salt, tmp, 8, 2);

  // XTS unit 0 prefix (64 bytes, hex)

  const int ct_len = hex_decode (token.buf[4], token.len[4], tmp);

  if (ct_len != 64) return (PARSER_SALT_LENGTH);

  pack_le (w->ct, tmp, 64, 16);

  // Boolean oracle (structural gate in-kernel): fixed all-zero digest,
  // comp emits r=0 only when the decrypted header shape matches.

  digest[0] = 0;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const merged_options_t *merged_options = (const merged_options_t *) esalt_buf;
  const wallet_sparrow_t *w              = &merged_options->w;

  u8 raw[64];

  char h_salt[33]   = { 0 };
  char h_h2salt[17] = { 0 };
  char h_ct[129]    = { 0 };

  for (int i = 0; i < 16; i++) raw[i] = (salt->salt_buf[i / 4] >> ((i % 4) * 8)) & 0xff;

  hex_encode (raw, 16, (u8 *) h_salt);

  for (int i = 0; i < 8; i++) raw[i] = (w->h2salt[i / 4] >> ((i % 4) * 8)) & 0xff;

  hex_encode (raw, 8, (u8 *) h_h2salt);

  for (int i = 0; i < 64; i++) raw[i] = (w->ct[i / 4] >> ((i % 4) * 8)) & 0xff;

  hex_encode (raw, 64, (u8 *) h_ct);

  return snprintf (line_buf, line_size, "%s1$%s$%s$%s",
    SIGNATURE_SPARROW,
    h_salt,
    h_h2salt,
    h_ct);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost       = argon2_module_benchmark_cost;
  module_ctx->module_esalt_size           = module_esalt_size;
  module_ctx->module_extra_buffer_size    = argon2_module_extra_buffer_size;
  module_ctx->module_extra_tuningdb_block = argon2_module_extra_tuningdb_block;
  module_ctx->module_hash_decode          = module_hash_decode;
  module_ctx->module_hash_encode          = module_hash_encode;
  module_ctx->module_jit_build_options    = argon2_module_jit_build_options;
  module_ctx->module_tmp_size             = module_tmp_size;
}
