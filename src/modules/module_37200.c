/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "gocryptfs";
static const u64   KERN_TYPE      = 37200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "4321";
static const char *ST_HASH        = "$gocryptfs$2*1*65536*8*1*c97f0d91b8b00afbfa3deab56ac15c028fce0d2ca6c117708c070526620bb58a*80e27fe62a19b29fbd369220e839d8311d7765ab1e06c697723814463be668f9d595cde59a98db0aa5cf61d9639bd4e65d3618a340c5edbad7095fb5a5c7df97";

#include "hooks_common.c"

u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/gocryptfs2hashcat.py to extract the hash from a gocryptfs.conf";
}

typedef struct gocryptfs
{
  u32 iv[4];
  u32 data[8];
  u32 tag[4];

  u32 hkdf;

} gocryptfs_t;

static const char *SIGNATURE_GOCRYPTFS = "$gocryptfs$";

static const u32 SCRYPT_THREADS = 32;

#include "scrypt_common.c"

// The master key of a gocryptfs volume is wrapped with AES-256-GCM under a key that scrypt derives
// from the password. With the HKDF feature flag, which every volume since gocryptfs 1.3 sets, that
// scrypt output goes through HKDF-SHA256 first and the nonce is 16 bytes. Without it the scrypt
// output is the GCM key and the nonce is 12 bytes. The wrapped key is always 32 bytes and the tag
// is 16, so the EncryptedKey of the config file is 64 or 60 bytes.

#define GOCRYPTFS_BLOB_LEN_HKDF   64
#define GOCRYPTFS_BLOB_LEN_LEGACY 60

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (gocryptfs_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  gocryptfs_t *gocryptfs = (gocryptfs_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_GOCRYPTFS;

  token.len[0]     = 11;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 1;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 7;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 3;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';
  token.len_min[5] = 1;
  token.len_max[5] = 3;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '*';
  token.len[6]     = 64;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '*';
  token.len_min[7] = GOCRYPTFS_BLOB_LEN_LEGACY * 2;
  token.len_max[7] = GOCRYPTFS_BLOB_LEN_HKDF   * 2;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // the config file version. Only 2 is known, and the fields below are read from it

  const u8 *version_pos = token.buf[1];

  if (version_pos[0] != '2') return (PARSER_SALT_VALUE);

  // the HKDF feature flag, which also fixes the nonce length

  const u8 *hkdf_pos = token.buf[2];

  if ((hkdf_pos[0] != '0') && (hkdf_pos[0] != '1')) return (PARSER_SALT_VALUE);

  gocryptfs->hkdf = hkdf_pos[0] - '0';

  const int iv_len = (gocryptfs->hkdf == 1) ? 16 : 12;

  // scrypt settings

  const u8 *N_pos = token.buf[3];
  const u8 *r_pos = token.buf[4];
  const u8 *p_pos = token.buf[5];

  salt->scrypt_N = hc_strtoul ((const char *) N_pos, NULL, 10);
  salt->scrypt_r = hc_strtoul ((const char *) r_pos, NULL, 10);
  salt->scrypt_p = hc_strtoul ((const char *) p_pos, NULL, 10);

  if (salt->scrypt_N < 1) return (PARSER_SALT_VALUE);
  if (salt->scrypt_r < 1) return (PARSER_SALT_VALUE);
  if (salt->scrypt_p < 1) return (PARSER_SALT_VALUE);

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  // salt

  const u8 *salt_pos = token.buf[6];
  const int salt_len = token.len[6];

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  // the EncryptedKey: the nonce, the wrapped master key and the GCM tag, one after the other

  const u8 *blob_pos = token.buf[7];
  const int blob_len = token.len[7];

  if (blob_len != ((iv_len + 32 + 16) * 2)) return (PARSER_HASH_LENGTH);

  u8 blob_buf[GOCRYPTFS_BLOB_LEN_HKDF] = { 0 };

  hex_decode (blob_pos, blob_len, blob_buf);

  memcpy (gocryptfs->iv,   blob_buf,              iv_len);
  memcpy (gocryptfs->data, blob_buf + iv_len,      32);
  memcpy (gocryptfs->tag,  blob_buf + iv_len + 32, 16);

  for (int i = 0; i < 4; i++) gocryptfs->iv[i]   = byte_swap_32 (gocryptfs->iv[i]);
  for (int i = 0; i < 8; i++) gocryptfs->data[i] = byte_swap_32 (gocryptfs->data[i]);
  for (int i = 0; i < 4; i++) gocryptfs->tag[i]  = byte_swap_32 (gocryptfs->tag[i]);

  // digest

  digest[0] = gocryptfs->tag[0];
  digest[1] = gocryptfs->tag[1];
  digest[2] = gocryptfs->tag[2];
  digest[3] = gocryptfs->tag[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const gocryptfs_t *gocryptfs = (const gocryptfs_t *) esalt_buf;

  const int iv_len = (gocryptfs->hkdf == 1) ? 16 : 12;

  // the salt

  char salt_hex[(32 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_hex);

  // the EncryptedKey, rebuilt from its three parts

  u8 blob_buf[GOCRYPTFS_BLOB_LEN_HKDF] = { 0 };

  u32 tmp_iv[4];
  u32 tmp_data[8];
  u32 tmp_tag[4];

  for (int i = 0; i < 4; i++) tmp_iv[i]   = byte_swap_32 (gocryptfs->iv[i]);
  for (int i = 0; i < 8; i++) tmp_data[i] = byte_swap_32 (gocryptfs->data[i]);
  for (int i = 0; i < 4; i++) tmp_tag[i]  = byte_swap_32 (gocryptfs->tag[i]);

  memcpy (blob_buf,              tmp_iv,   iv_len);
  memcpy (blob_buf + iv_len,     tmp_data, 32);
  memcpy (blob_buf + iv_len + 32, tmp_tag, 16);

  char blob_hex[(GOCRYPTFS_BLOB_LEN_HKDF * 2) + 1] = { 0 };

  hex_encode (blob_buf, iv_len + 32 + 16, (u8 *) blob_hex);

  const int line_len = snprintf (line_buf, line_size, "%s2*%u*%u*%u*%u*%s*%s",
    SIGNATURE_GOCRYPTFS,
    gocryptfs->hkdf,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    salt_hex,
    blob_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = scrypt_module_benchmark_cost;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = scrypt_module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = scrypt_module_jit_build_options;
  module_ctx->module_kernel_accel_max         = scrypt_module_kernel_accel_max;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
  module_ctx->module_tune_variants            = scrypt_module_tune_variants;
  module_ctx->module_usage_notice             = module_usage_notice;
}
