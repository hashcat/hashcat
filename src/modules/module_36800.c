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
#include "blowfish_common.c"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PRIVATE_KEY;
static const char *HASH_NAME      = "OpenSSH Private Keys (bcrypt-pbkdf)";
static const u64   KERN_TYPE      = 36800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DYNAMIC_SHARED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sshng$6$16$89b7dac5965613fa4f2faf9284983843$274$6f70656e7373682d6b65792d7631000000000a6165733235362d63747200000006626372797074000000180000001089b7dac5965613fa4f2faf92849838430000001000000001000000330000000b7373682d6564323535313900000020979ccdbbb3f2c8b04842e77fdd5475b21963e7ddad9a4d029d712322f5c930ee000000909e38aa2f92ae189f7e4f04ef62fcd869ceb572e5c047ea0e9dfbb4657c38a13506d580ff8709a8787810a53688e3b0c7b7af155422aed8089da87a63da0147d8c8e04a6d236e70f0c6be5fbeb0b620d7abe928b10169fd3e48c1b526d3ead3a28fa4385969aebea6621baada8821a20035be97e2fa42575f5e4246e174ac3c96b19e89623ff267a2629090da6f79f7e4$16$130";

#include "hooks_common.c"

// must stay identical to the copy in OpenCL/m36800-pure.cl
typedef struct sshng_bcrypt
{
  u32 cipher;
  u32 ct_offset;
  u32 rounds;
  u32 salt_buf[4];
  u32 ct_buf[4];
  u32 data_buf[8192];
  int data_len;

} sshng_bcrypt_t;

// must stay identical to the copy in OpenCL/m36800-pure.cl
typedef struct sshng_bcrypt_tmp
{
  u32 pass_hash[16];
  u32 sha2salt[2][16];
  u32 out[2][8];

} sshng_bcrypt_tmp_t;

static const char *SIGNATURE_SSHNG = "$sshng$";

// cipher ids as emitted by ssh2john
#define SSHNG_CIPHER_AES256_CBC 2
#define SSHNG_CIPHER_AES256_CTR 6

// fixed at 16 bytes in sshkey.c
#define SSHNG_SALT_LEN 16


// sizeof (sshng_bcrypt_t.data_buf), against around 3 KB for an RSA-4096 blob
#define SSHNG_DATA_MAX 32768

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (sshng_bcrypt_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (sshng_bcrypt_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  sshng_bcrypt_t *sshng = (sshng_bcrypt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  // $sshng$<cipher>$<saltlen>$<salt>$<datalen>$<data>$<rounds>$<ctoffset>

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SSHNG;

  token.len[0]     = 7;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = 2;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len[3]     = SSHNG_SALT_LEN * 2;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 8;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 64;
  token.len_max[5] = 65536;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len_min[6] = 1;
  token.len_max[6] = 8;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // last token runs to end of line: no trailing separator to match
  token.len_min[7] = 1;
  token.len_max[7] = 8;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // cipher

  const int cipher = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if ((cipher != SSHNG_CIPHER_AES256_CBC) && (cipher != SSHNG_CIPHER_AES256_CTR)) return (PARSER_CIPHER);

  sshng->cipher = cipher;

  // salt length

  const int salt_len_verify = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (salt_len_verify != SSHNG_SALT_LEN) return (PARSER_SALT_LENGTH);

  // salt, swapped because sha512_update() reads big-endian packed

  const u8 *salt_pos = token.buf[3];

  for (int i = 0, j = 0; i < SSHNG_SALT_LEN / 4; i += 1, j += 8)
  {
    sshng->salt_buf[i] = byte_swap_32 (hex_to_u32 (&salt_pos[j]));
  }

  // rounds -> salt_iter, so they spread over _loop invocations

  const u32 rounds = hc_strtoul ((const char *) token.buf[6], NULL, 10);

  if (rounds == 0) return (PARSER_SALT_ITERATION);

  salt->salt_iter = rounds;

  sshng->rounds = rounds;

  // salt_buf/salt_len for hashcat's own bookkeeping

  memcpy (salt->salt_buf, sshng->salt_buf, SSHNG_SALT_LEN);

  salt->salt_len = SSHNG_SALT_LEN;

  // ciphertext offset within the blob

  // The last token runs to the end of the line, and hc_strtoul () reads digits until it meets one
  // that is not, so on this token it reads to whatever follows the line rather than stopping at a
  // separator the way it does on every other numeric field. Convert a copy that ends where the
  // token does.

  char ct_offset_str[16];

  const int ct_offset_len = MIN (token.len[7], (int) sizeof (ct_offset_str) - 1);

  memcpy (ct_offset_str, token.buf[7], ct_offset_len);

  ct_offset_str[ct_offset_len] = 0;

  const u32 ct_offset = hc_strtoul (ct_offset_str, NULL, 10);

  // the blob, kept whole for the encoder

  if (token.len[5] > (SSHNG_DATA_MAX * 2)) return (PARSER_HASH_LENGTH);

  sshng->data_len = hex_decode (token.buf[5], token.len[5], (u8 *) sshng->data_buf);

  const int data_len = sshng->data_len;

  // declared length against the blob supplied

  const int data_len_verify = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  if (data_len_verify != data_len) return (PARSER_HASH_LENGTH);

  // the encrypted section has to leave one AES block to verify against

  // ct_offset comes off the line as a decimal and is added to before it is compared, so a value
  // near UINT32_MAX wrapped and passed a check it could not pass, and the read below then started
  // that far into the blob. Subtract from data_len instead, which cannot wrap.

  if (data_len < 16) return (PARSER_SALT_VALUE);

  if (ct_offset > (u32) (data_len - 16)) return (PARSER_SALT_VALUE);

  sshng->ct_offset = ct_offset;

  // the first block holds the two check integers, big-endian packed to match
  // the AES keystream it meets in _comp

  const u8 *data_pos = &token.buf[5][ct_offset * 2];

  for (int i = 0, j = 0; i < 4; i += 1, j += 8)
  {
    sshng->ct_buf[i] = byte_swap_32 (hex_to_u32 (&data_pos[j]));
  }

  // fake digest: the encrypted check integers, distinct per key

  digest[0] = sshng->ct_buf[0];
  digest[1] = sshng->ct_buf[1];
  digest[2] = sshng->ct_buf[2];
  digest[3] = sshng->ct_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const sshng_bcrypt_t *sshng = (const sshng_bcrypt_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  u8 salt_hex[(SSHNG_SALT_LEN * 2) + 1] = { 0 };

  // swapped back for u32_to_hex

  u32_to_hex (byte_swap_32 (sshng->salt_buf[0]), salt_hex +  0);
  u32_to_hex (byte_swap_32 (sshng->salt_buf[1]), salt_hex +  8);
  u32_to_hex (byte_swap_32 (sshng->salt_buf[2]), salt_hex + 16);
  u32_to_hex (byte_swap_32 (sshng->salt_buf[3]), salt_hex + 24);

  int out_len = snprintf ((char *) out_buf, line_size, "%s%u$%d$%s$%d$",
    SIGNATURE_SSHNG,
    sshng->cipher,
    SSHNG_SALT_LEN,
    salt_hex,
    sshng->data_len);

  out_len += hex_encode ((const u8 *) sshng->data_buf, sshng->data_len, out_buf + out_len);

  out_len += snprintf ((char *) out_buf + out_len, line_size - out_len, "$%u$%u",
    sshng->rounds,
    sshng->ct_offset);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = blowfish_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = blowfish_module_jit_cache_disable;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
