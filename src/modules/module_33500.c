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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // originally DGST_SIZE_4_2
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_CIPHER_KPA;
static const char *HASH_NAME      = "RC4 40-bit DropN";
static const u64   KERN_TYPE      = 33500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_SUGGEST_KG // collisions by using pt_len != pass_len
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashc";
static const char *ST_HASH        = "$rc4$40$0$e9a41693b759cf88929ca31203694f$0$48656c6c6f";

#include "hooks_common.c"

typedef struct rc4
{
  u32 dropN;
  u32 ct_len;
  u32 pt_len;
  u32 pt_off;

  u32 pt[2];
  u32 ct[16];

} rc4_t;

static const char *SIGNATURE_RC4 = "$rc4$";
#define RC4_KEY_BITS 40
#define PW_LEN (RC4_KEY_BITS / 8) // 5

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303, compiler timeout but only with -a0
        return true;
      }
    }
  }

  return false;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // We must override whatever tuningdb entry or -T value was set by the user with this
  // That's because of RC code in inc_cipher_rc4.cl has this for GPU (different on CPU):
  // #define KEY32(t,k) (((k) * 32) + ((t) & 31) + (((t) / 32) * 2048))
  // #define KEY8(t,k) (((k) & 3) + (((k) / 4) * 128) + (((t) & 31) * 4) + (((t) / 32) * 8192))

  u32 native_threads = (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU) ? 1 : 32;

  hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", native_threads);

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (rc4_t);

  return esalt_size;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = PW_LEN;

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = PW_LEN;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  rc4_t *rc4 = (rc4_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_RC4;

  token.len[0]     = strlen (SIGNATURE_RC4);
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;
  // key bit

  token.sep[1]     = '$';
  token.len_min[1] = 2;
  token.len_max[1] = 3;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // dropN

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 3;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // ciphertext

  token.sep[3]     = '$';
  token.len_min[3] = 1 * 2;
  token.len_max[3] = 64 * 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // plaintext offset

  token.sep[4]     = '$';
  token.len[4]     = 1;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // plaintext

  token.sep[5]     = '$';
  token.len_min[5] = 1 * 2;
  token.len_max[5] = 8 * 2; // sizeof (rc4->pt)
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // key bit

  const u8 *key_bit_pos = token.buf[1];

  u32 key_bit = hc_strtoul ((const char *) key_bit_pos, NULL, 10);

  if (key_bit != RC4_KEY_BITS) return (PARSER_KEY_SIZE);

  // dropN

  const u8 *dropN_pos = token.buf[2];

  rc4->dropN = hc_strtoul ((const char *) dropN_pos, NULL, 10);

  // ciphertext

  u32 salt_len = 0;
  u32 salt_buf[16];

  memset (salt_buf, 0, sizeof (salt_buf));

  u8 *salt_buf_ptr = (u8 *) salt_buf;

  const u8 *ciphertext_pos = token.buf[3];
  const u32 ciphertext_len = token.len[3];

  rc4->ct_len = ciphertext_len / 2;

  u8 *ct = (u8 *) rc4->ct;

  for (u32 i = 0, j = 0; i < rc4->ct_len; i += 1, j += 2)
  {
    ct[i] = hex_to_u8 (ciphertext_pos + j);

    salt_buf_ptr[i] = ct[i];
    salt_len++;
  }

  // fake salt (part 1)

  md5_ctx_t md5_ctx;

  md5_init   (&md5_ctx);
  md5_update (&md5_ctx, salt_buf, salt_len);

  // plaintext offset

  const u8 *pt_offset_pos = token.buf[4];

  rc4->pt_off = hc_strtoul ((const char *) pt_offset_pos, NULL, 10);

  if (rc4->pt_off > rc4->ct_len) return PARSER_PT_OFFSET;

  // plaintext

  const u8 *plaintext_pos = token.buf[5];
  const u32 plaintext_len = token.len[5];

  rc4->pt_len = plaintext_len / 2;

  if (rc4->pt_len > rc4->ct_len) return PARSER_PT_LENGTH;

  if ((rc4->pt_off + rc4->pt_len) > rc4->ct_len) return PARSER_PT_OFFSET;

  u8 *pt = (u8 *) rc4->pt;
  u8 *dgst = (u8 *) digest;

  salt_len = 0;
  memset (salt_buf, 0, sizeof (salt_buf));

  for (u32 i = 0, j = 0; i < rc4->pt_len; i += 1, j += 2)
  {
    pt[i] = hex_to_u8 (plaintext_pos + j);

    dgst[i] = pt[i];

    salt_buf_ptr[i] = pt[i];
    salt_len++;
  }

  // fake salt (part 2)

  md5_update (&md5_ctx, salt_buf, salt_len);
  md5_final  (&md5_ctx);

  salt->salt_buf[0] = md5_ctx.h[0];
  salt->salt_buf[1] = md5_ctx.h[1];
  salt->salt_buf[2] = md5_ctx.h[2];
  salt->salt_buf[3] = md5_ctx.h[3];

  salt->salt_len = 16;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const rc4_t *rc4 = (const rc4_t *) esalt_buf;

  snprintf (line_buf, line_size, "%s%u$%u$", SIGNATURE_RC4, RC4_KEY_BITS, rc4->dropN);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = strlen (line_buf);

  u8 *ct = (u8 *) rc4->ct;

  for (u32 i = 0; i < rc4->ct_len; i++)
  {
    u8_to_hex (ct[i], out_buf + out_len); out_len += 2;
  }

  out_buf[out_len++] = '$';

  char tmp_buf[10] = { 0 };

  snprintf ((char *) tmp_buf, sizeof (tmp_buf), "%u", rc4->pt_off);

  snprintf ((char *) out_buf + out_len, sizeof (tmp_buf), "%u", rc4->pt_off);

  out_len += strlen (tmp_buf);

  out_buf[out_len++] = '$';

  u8 *dgst = (u8 *) digest;

  for (u32 i = 0; i < rc4->pt_len; i++)
  {
    u8_to_hex (dgst[i], out_buf + out_len); out_len += 2;
  }

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
