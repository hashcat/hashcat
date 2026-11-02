/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Further credits:
 * The password-storage algorithm used by Radmin 3 was analyzed and made public
 * by synacktiv:
 * https://www.synacktiv.com/publications/cracking-radmin-server-3-passwords.html
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "emu_inc_bignum_2048.h"
#include "emu_inc_radmin3_constants.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_SERVER;
static const char *HASH_NAME      = "Radmin3";
static const u64   KERN_TYPE      = 29200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS15
                                  | OPTS_TYPE_PT_UTF16LE
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$radmin3$75007300650072006e0061006d006500*c63bf695069d564844c4849e7df6d41f1fbc5f3a7d8fe27c5f20545a238398fa*0062fb848c21d606baa0a91d7177daceb69ad2f6d090c2f1b3a654cfb417be66f739ae952f5c7c5170743459daf854a22684787b24f8725337b3c3bd1e0f2a6285768ceccca77f26c579d42a66372df7782b2eefccb028a0efb51a4257dd0804d05e0a83f611f2a0f10ffe920568cc7af1ec426f450ec99ade1f2a4905fd319f8c190c2db0b0e24627d635bc2b4a2c4c9ae956b1e02784c9ce958eb9883c60ba8ea2731dd0e515f492c44f39324e4027587c1330f14216e17f212eaec949273797ae74497782ee8b6f640dd2d124c59db8c37724c8a5a63bad005f8e491b459ff1b92f861ab6d99a2548cb8902b0840c7f20a108ede6bf9a60093053781216fe";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/radmin3_to_hashcat.pl to extract the hashes";
}

static const char *SIGNATURE_RADMIN3 = "$radmin3$";

typedef struct radmin3
{
  u32 user[64];
  u32 user_len;

  u32 pre[PRECOMP_DATALEN]; // 1047552 * 4 bytes for PRECOMP_BITS = 10

} radmin3_t;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm29200_sxx' pipeline, timeout reached
        return true;
      }
    }
  }

  return false;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (radmin3_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  radmin3_t *esalt = (radmin3_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;
  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_RADMIN3;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // user name
  token.sep[1]     = '*';
  token.len_min[1] = (SALT_MIN * 2);
  token.len_max[1] = (SALT_MAX * 2) - 1; // we store the colon (:) in esalt->user[]
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  // SHA1 salt
  token.sep[2]     = '*';
  token.len[2]     = 64;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // verifier
  token.len[3]     = 512;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // user name:

  if ((token.len[1] % 2) != 0) return (PARSER_SALT_LENGTH);

  u8 *u = (u8 *) esalt->user;

  hex_decode (token.buf[1], token.len[1], u);

  esalt->user_len = token.len[1] / 2;

  u[esalt->user_len] = ':';

  esalt->user_len++;

  // call byte_swap () to avoid it in the kernel:

  for (u32 i = 0; i < 64; i++)
  {
    esalt->user[i] = byte_swap_32 (esalt->user[i]);
  }

  // salt (for salted SHA1):

  if ((token.len[2] % 2) != 0) return (PARSER_SALT_LENGTH);

  u8 *s = (u8 *) salt->salt_buf;

  hex_decode (token.buf[2], token.len[2], s);

  salt->salt_len = token.len[2] / 2;

  // call byte_swap () to avoid it in the kernel:

  for (u32 i = 0; i < 64; i++)
  {
    salt->salt_buf[i] = byte_swap_32 (salt->salt_buf[i]);
  }

  // verifier:

  if ((token.len[3] % 2) != 0) return (PARSER_SALT_LENGTH);

  u8 *v = (u8 *) salt->salt_buf_pc;

  hex_decode (token.buf[3], token.len[3], v);

  // the verifier is a big-endian number, the bignum code works on limbs

  bn2048_from_be (salt->salt_buf_pc, salt->salt_buf_pc);

  // digest

  // convert our verifier to Montgomery form (s.t. we avoid converting it back on GPU):

  u32 dgst[64] = { 0 };

  bn2048_to_mont (dgst, salt->salt_buf_pc, RADMIN3_M, RADMIN3_N0, RADMIN3_R);

  digest[0] = dgst[0];
  digest[1] = dgst[1];
  digest[2] = dgst[2];
  digest[3] = dgst[3];

  /*
   * pre-computed values for BigNum exponentiation:
   */

  memcpy (esalt->pre, RADMIN3_PRE, sizeof (RADMIN3_PRE));

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const radmin3_t *esalt = (const radmin3_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  // signature

  int out_len = snprintf (line_buf, line_size, "%s", SIGNATURE_RADMIN3);

  // user

  u32 u[64];

  for (u32 i = 0; i < 64; i++)
  {
    u[i] = byte_swap_32 (esalt->user[i]);
  }

  out_len += generic_salt_encode (hashconfig, (const u8 *) u, (const int) esalt->user_len - 1, out_buf + out_len); // -1 because of the ':' optimization

  out_buf[out_len] = '*';

  out_len++;

  // salt

  u32 s[64];

  for (u32 i = 0; i < 64; i++)
  {
    s[i] = byte_swap_32 (salt->salt_buf[i]);
  }

  out_len += generic_salt_encode (hashconfig, (const u8 *) s, (const int) salt->salt_len, out_buf + out_len);

  out_buf[out_len] = '*';

  out_len++;

  // verifier

  u32 verifier[64];

  bn2048_to_be (verifier, salt->salt_buf_pc);

  out_len += generic_salt_encode (hashconfig, (const u8 *) verifier, 256, out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = module_usage_notice;
}
