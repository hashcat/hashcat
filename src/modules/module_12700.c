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
static const u32   DGST_SIZE      = DGST_SIZE_4_5; // because kernel uses _SHA1;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Blockchain, My Wallet";
static const u64   KERN_TYPE      = 12700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$blockchain$288$713253722114000682636604801283547365b7a53a802a7388d08eb7e6c32c1efb4a157fe19bca940a753d7f16e8bdaf491aa9cf6cda4035ac48d56bb025aced81455424272f3e0459ec7674df3e82abd7323bc09af4fd0869fd790b3f17f8fe424b8ec81a013e1476a5c5a6a53c4b85a055eecfbc13eccf855f905d3ddc3f0c54015b8cb177401d5942af833f655947bfc12fc00656302f31339187de2a69ab06bc61073933b3a48c9f144177ae4b330968eb919f8a22cec312f734475b28cdfe5c25b43c035bf132887f3241d86b71eb7e1cf517f99305b19c47997a1a1f89df6248749ac7f38ca7c88719cf16d6af2394307dce55600b8858f4789cf1ae8fd362ef565cd9332f32068b3c04c9282553e658b759c2e76ed092d67bd55961ae";

#include "hooks_common.c"

typedef struct mywallet_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[10];
  u32 out[10];

  u32 out1[10];

} mywallet_tmp_t;

static const char *SIGNATURE_MYWALLET = "$blockchain$";
static const int   ROUNDS_MYWALLET    = 10;

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = ROUNDS_MYWALLET - 1;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = ROUNDS_MYWALLET - 1;

  return kernel_loops_max;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (mywallet_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MYWALLET;

  token.len[0]     = 12;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 144;
  token.len_max[2] = 65536;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * salt
   */

  const u8 *salt_pos = token.buf[2];

  // first 16 byte are IV

  for (int i = 0, j = 0; i < 16; i += 1, j += 8)
  {
    salt->salt_buf[i] = hex_to_u32 (salt_pos + j);

    salt->salt_buf[i] = byte_swap_32 (salt->salt_buf[i]);
  }

  salt->salt_len = 64;

  salt->salt_iter = ROUNDS_MYWALLET - 1;

  /**
   * digest buf
   */

  digest[0] = salt->salt_buf[4];
  digest[1] = salt->salt_buf[5];
  digest[2] = salt->salt_buf[6];
  digest[3] = salt->salt_buf[7];
  digest[4] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  return snprintf (line_buf, line_size, "%s", hash_info->orighash);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_min;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_max;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
