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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Juniper/NetBSD sha1crypt";
static const char *HASH_RECIPE    = "h = hmac_sha1_bin(pass, salt); for i = 1 to iter { h = hmac_sha1_bin(pass, h) }; hex(h)";
static const u64   KERN_TYPE      = 40038;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sha1$20000$75552156$HhYMDdaEHiK3eMIzTldOFPnw.s2Q";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha1_tmp_t);

  return tmp_size;
}

static const char *SIGNATURE_NETBSD_SHA1CRYPT = "$sha1$";

static void netbsd_sha1crypt_decode (u8 digest[20], const u8 buf[28], u8 *additional_byte)
{
  int l;

  l  = itoa64_to_int (buf[ 0]) <<  0;
  l |= itoa64_to_int (buf[ 1]) <<  6;
  l |= itoa64_to_int (buf[ 2]) << 12;
  l |= itoa64_to_int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 4]) <<  0;
  l |= itoa64_to_int (buf[ 5]) <<  6;
  l |= itoa64_to_int (buf[ 6]) << 12;
  l |= itoa64_to_int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[ 8]) <<  0;
  l |= itoa64_to_int (buf[ 9]) <<  6;
  l |= itoa64_to_int (buf[10]) << 12;
  l |= itoa64_to_int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[12]) <<  0;
  l |= itoa64_to_int (buf[13]) <<  6;
  l |= itoa64_to_int (buf[14]) << 12;
  l |= itoa64_to_int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[16]) <<  0;
  l |= itoa64_to_int (buf[17]) <<  6;
  l |= itoa64_to_int (buf[18]) << 12;
  l |= itoa64_to_int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[20]) <<  0;
  l |= itoa64_to_int (buf[21]) <<  6;
  l |= itoa64_to_int (buf[22]) << 12;
  l |= itoa64_to_int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = itoa64_to_int (buf[24]) <<  0;
  l |= itoa64_to_int (buf[25]) <<  6;
  l |= itoa64_to_int (buf[26]) << 12;
  l |= itoa64_to_int (buf[27]) << 18;

  additional_byte[0] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

static void netbsd_sha1crypt_encode (const u8 digest[20], u8 additional_byte, u8 buf[30])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 1] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 2] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 3] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 5] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 6] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 7] = int_to_itoa64 (l & 0x3f);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[ 9] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[10] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[11] = int_to_itoa64 (l & 0x3f);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[13] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[14] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[15] = int_to_itoa64 (l & 0x3f);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[17] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[18] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[19] = int_to_itoa64 (l & 0x3f);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[21] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[22] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[23] = int_to_itoa64 (l & 0x3f);

  l = (additional_byte << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[25] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[26] = int_to_itoa64 (l & 0x3f); l >>= 6;
  buf[27] = int_to_itoa64 (l & 0x3f);
  buf[28] = 0;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_NETBSD_SHA1CRYPT;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 8;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

  token.sep[3]     = '$';
  token.len[3]     = 28;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter

  const u8 *iter_pos = token.buf[1];

  u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 99) return (PARSER_SALT_ITERATION); // (actually: CRYPT_SHA1_ITERATIONS should be 24680 or more)

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  memcpy ((u8 *) salt->salt_buf_pc, salt_pos, salt_len);

  salt->salt_len_pc = salt_len;

  // hash

  const u8 *hash_pos = token.buf[3];

  netbsd_sha1crypt_decode ((u8 *) digest, hash_pos, (u8 *) salt->salt_sign);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);

  // the first HMAC takes the salt, "$sha1$" and the iteration count as its message

  char *ptr = (char *) salt->salt_buf;

  const int salt_len_msg = snprintf (ptr, 64, "%s$sha1$%u", (char *) salt->salt_buf_pc, iter);

  salt->salt_len = salt_len_msg;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // encode the digest:

  u32 tmp[5] = { 0 }; // this (useless?) initialization makes scan-build happy

  tmp[0] = byte_swap_32 (digest[0]);
  tmp[1] = byte_swap_32 (digest[1]);
  tmp[2] = byte_swap_32 (digest[2]);
  tmp[3] = byte_swap_32 (digest[3]);
  tmp[4] = byte_swap_32 (digest[4]);

  char ptr_plain[32] = { 0 };

  netbsd_sha1crypt_encode ((unsigned char *) tmp, salt->salt_sign[0], (unsigned char *) ptr_plain);

  // salt

  char tmp_salt[(SALT_MAX * 2) + 1];

  memcpy (tmp_salt, salt->salt_buf_pc, salt->salt_len_pc);

  tmp_salt[salt->salt_len_pc] = 0;

  // output:

  const int line_len = snprintf (line_buf, line_size, "$sha1$%u$%s$%s",
    salt->salt_iter + 1,
    tmp_salt,
    ptr_plain);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
