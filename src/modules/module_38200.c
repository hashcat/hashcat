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
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Cisco-IOS $14$ (MD5 (Type 5) + scrypt, Convoluted)";
static const u64   KERN_TYPE      = 38200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_INIT2
                                  | KERN_BIT_LOOP2_PREPARE
                                  | KERN_BIT_LOOP2;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$14$ZeF0$Yh3cTZvrtSWBcT$6ImC5D6iNVvt4fwM14oDbj.Vd5KWkpl8WjUffnRdH5E";

#include "hooks_common.c"

u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *SIGNATURE_CISCO14 = "$14$";

static const u32 SCRYPT_THREADS = 32;

#include "scrypt_common.c"

u64 module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u64 scrypt_tmp_size = scrypt_module_extra_tmp_size (hashconfig, user_options, user_options_extra, hashes);

  // bits 62/63 are error sentinels (mixed configuration / self-test mismatch); propagate as-is

  if (scrypt_tmp_size & (3ULL << 62)) return scrypt_tmp_size;

  // + md5crypt digest_buf[4] (16 bytes) + assembled "$1$<salt>$<hash>" buffer (32 bytes, 30 used)

  return scrypt_tmp_size + 16 + 32;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_CISCO14;

  token.len[0]     = 4;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;

  // bounded by m38200-pure.cl's pw_buf[8] (32 bytes): assembled "$1$<salt>$<hash>" is 3 + salt_len + 1 + 22 bytes

  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = '$';
  token.len[2]     = 14;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[3]     = '$';
  token.len[3]     = 43;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type5 salt (the original Type 5 / $1$ salt), not encoded

  const u8 *salt_pc_pos = token.buf[1];
  const int salt_pc_len = token.len[1];

  u8 *salt_buf_pc_ptr = (u8 *) salt->salt_buf_pc;

  memcpy (salt_buf_pc_ptr, salt_pc_pos, salt_pc_len);

  salt->salt_len_pc = salt_pc_len;

  // type9 (scrypt) salt, not encoded

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr, salt_pos, salt_len);

  salt->salt_len = salt_len;

  // fixed scrypt configuration, same as mode 9300

  salt->scrypt_N  = 16384;
  salt->scrypt_r  = 1;
  salt->scrypt_p  = 1;

  salt->salt_iter    = 1000; // MD5-crypt (Type 5), fixed round count, matches mode 500
  salt->salt_iter2   = salt->scrypt_N; // scrypt ROMix
  salt->salt_repeats = salt->scrypt_p - 1;

  // base64 decode hash

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  u8 tmp_buf[100] = { 0 };

  const int tmp_len = base64_decode (itoa64_to_int, hash_pos, hash_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_HASH_LENGTH);

  memcpy (digest, tmp_buf, 32);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  char tmp_buf[64];

  base64_encode (int_to_itoa64, (const u8 *) digest_buf, 32, (u8 *) tmp_buf);

  tmp_buf[43] = 0; // cut it here

  const int line_len = snprintf (line_buf, line_size, "%s%s$%s$%s", SIGNATURE_CISCO14, (const unsigned char *) salt->salt_buf_pc, (const unsigned char *) salt->salt_buf, tmp_buf);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = scrypt_module_jit_build_options;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
}
