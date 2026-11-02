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

static const u32   ATTACK_EXEC       = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0         = 0;
static const u32   DGST_POS1         = 1;
static const u32   DGST_POS2         = 2;
static const u32   DGST_POS3         = 3;
static const u32   DGST_SIZE         = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY     = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME         = "Bitcoin raw private key (P2WPKH, Bech32), compressed";
static const u64   KERN_TYPE         = 30901;
static const u32   OPTI_TYPE         = OPTI_TYPE_NOT_SALTED;
static const u64   OPTS_TYPE         = OPTS_TYPE_STOCK_MODULE
                                     | OPTS_TYPE_PT_BASE58
                                     | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE         = SALT_TYPE_NONE;
static const char *ST_PASS           = "4d1987d7a341d51557af59996845740135ab2506515426ada57cc8ec05adf794";
static const char *ST_HASH           = "bc1q926ca6n7wz7gm2gfd8xc5p0vu687ngvnknpx74";
static const char *BENCHMARK_MASK    = "?h?h?h?h?h?h?h7a341d51557af59996845740135ab2506515426ada57cc8ec05adf794";
static const u32   RAW_LEN           = 64;

#include "hooks_common.c"

const char *module_benchmark_mask    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BENCHMARK_MASK;  }

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: self-test failed
        return true;
      }
    }
  }

  return false;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 16;

  return kernel_loops_max;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return RAW_LEN;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return RAW_LEN;
}

static u32 polymod_checksum (const u8 *data, const u32 data_len)
{
  const u32 CONSTS[5] = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

  u32 c = 1;

  for (u32 i = 0; i < data_len; i++) // data_len is always 44 for us
  {
    const u32 b = c >> 25;

    c = ((c & 0x01ffffff) << 5) ^ data[i];

    for (u32 j = 0; j < 5; j++)
    {
      const u32 bit_set = (b >> j) & 1;

      if (bit_set == 0) continue;

      c ^= CONSTS[j];
    }
  }

  return c;
}

static const char *SIGNATURE_BITCOIN_BECH32 = "bc1"; // human readable part (HRP) + "1"
static const char *BECH32_BASE32_ALPHABET   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BITCOIN_BECH32;

  token.len[0]  =  3;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]  = 39; // 42 - 3 (SIGNATURE_BITCOIN_BECH32)
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_BECH32;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // Bech32 decode:

  u8 t[64] = { 0 }; // only 42 - 3 = 39 needed

  for (u32 i = 3; i < 42; i++) // skip first 3 bytes ("bc1")
  {
    // this is actually a search that we could do also with strstr ():
    // note: we always have a hit, because we verified this with TOKEN_ATTR_VERIFY_BECH32

    for (u32 j = 0; j < 32; j++)
    {
      if (BECH32_BASE32_ALPHABET[j] == line_buf[i])
      {
        t[i - 3] = j;

        break;
      }
    }
  }

  if (t[0] != 0) // check if "version"/type is BECH32, we do NOT accept BECH32M
  {
    return (PARSER_HASH_ENCODING);
  }

  /*
   * Check the checksum of the address:
   */

  u32 checksum = t[33] << 25
               | t[34] << 20
               | t[35] << 15
               | t[36] << 10
               | t[37] <<  5
               | t[38] <<  0;

  u8 data[64] = { 0 }; // only 44 bytes actually needed

  data[0] = 3; // HRP = Human Readable Part, 3 base32 chars => 5 bytes prefix
  data[1] = 3; // these 5 bytes come from: hrp_expand ("bc"), human readable part
  data[2] = 0;
  data[3] = 2;
  data[4] = 3;

  for (u32 i = 0; i < 42 - 3 - 6; i++) // skip "bc1" (start) and checksum (end)
  {
    data[i + 5] = t[i];
  }

  data[38] = 0; // "clear" the 6 checksum bytes (for correct "polymod" checksum below)
  data[39] = 0;
  data[40] = 0;
  data[41] = 0;
  data[42] = 0;
  data[43] = 0;

  u32 polymod = polymod_checksum (data, 44) ^ 1; // BECH32M would xor with 0x2bc830a3

  if (polymod != checksum) // or (polymod_checksum (data, 44) ^ checksum) != 1
  {
    return (PARSER_HASH_ENCODING);
  }

  /*
   * transform/convert back to the ripemd hash (reverse translate_8to5 (), i.e. translate_5to8).
   * We extend the 8 bit blocks here to 32 bit blocks (4 * 8 = 32 bits), therefore we convert
   * 5 bit "blocks" to 32 bit blocks (from the base32 range: 0..31 to u32: 0..0xffffffff):
   */

   // note: t[0] needs to be skipped (version info)

  digest[0] = ((u32) t[ 1] << 27) | ((u32) t[ 2] << 22) | ((u32) t[ 3] << 17) | ((u32) t[ 4] << 12)
            | ((u32) t[ 5] <<  7) | ((u32) t[ 6] <<  2) | (t[ 7] >>  3);

  digest[1] = ((u32) t[ 7] << 29) | ((u32) t[ 8] << 24) | ((u32) t[ 9] << 19) | ((u32) t[10] << 14)
            | ((u32) t[11] <<  9) | ((u32) t[12] <<  4) | (t[13] >>  1);

  digest[2] = ((u32) t[13] << 31) | ((u32) t[14] << 26) | ((u32) t[15] << 21) | ((u32) t[16] << 16)
            | ((u32) t[17] << 11) | ((u32) t[18] <<  6) | ((u32) t[19] <<  1) | (t[20] >>  4);

  digest[3] = ((u32) t[20] << 28) | ((u32) t[21] << 23) | ((u32) t[22] << 18) | ((u32) t[23] << 13)
            | ((u32) t[24] <<  8) | ((u32) t[25] <<  3) | (t[26] >>  2);

  digest[4] = ((u32) t[26] << 30) | ((u32) t[27] << 25) | ((u32) t[28] << 20) | ((u32) t[29] << 15)
            | ((u32) t[30] << 10) | ((u32) t[31] <<  5) | ((u32) t[32] <<  0);

  // a final byte swap is needed for the kernel code:

  for (u32 i = 0; i < 5; i++)
  {
    digest[i] = byte_swap_32 (digest[i]);
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  // note: here we work mostly with char/u8 type because it's easier to base32 encode
  // (at least conceptually), but this could be easily extended to u32 variable types:

  const u8 *digest = (const u8 *) digest_buf;

  u8 b[20] = { 0 };

  for (u32 i = 0; i < 20; i++) // i < length (digest)
  {
    b[i] = digest[i];
  }

  /*
   * convert 8 bit "blocks" to 5 bit blocks, translate_8to5 () (for base32, 0..31):
   */

  u8 t[64] = { 0 }; // only 39 bytes actually needed

  t[ 0] = 0; // set "version"/type to BECH32, we do NOT support BECH32M

  t[ 1] = (               (b[ 0] >> 3)) & 31;
  t[ 2] = ((b[ 0] << 2) | (b[ 1] >> 6)) & 31;
  t[ 3] = (               (b[ 1] >> 1)) & 31;
  t[ 4] = ((b[ 1] << 4) | (b[ 2] >> 4)) & 31;
  t[ 5] = ((b[ 2] << 1) | (b[ 3] >> 7)) & 31;
  t[ 6] = (               (b[ 3] >> 2)) & 31;
  t[ 7] = ((b[ 3] << 3) | (b[ 4] >> 5)) & 31;
  t[ 8] = (               (b[ 4] >> 0)) & 31;

  t[ 9] = (               (b[ 5] >> 3)) & 31;
  t[10] = ((b[ 5] << 2) | (b[ 6] >> 6)) & 31;
  t[11] = (               (b[ 6] >> 1)) & 31;
  t[12] = ((b[ 6] << 4) | (b[ 7] >> 4)) & 31;
  t[13] = ((b[ 7] << 1) | (b[ 8] >> 7)) & 31;
  t[14] = (               (b[ 8] >> 2)) & 31;
  t[15] = ((b[ 8] << 3) | (b[ 9] >> 5)) & 31;
  t[16] = (               (b[ 9] >> 0)) & 31;

  t[17] = (               (b[10] >> 3)) & 31;
  t[18] = ((b[10] << 2) | (b[11] >> 6)) & 31;
  t[19] = (               (b[11] >> 1)) & 31;
  t[20] = ((b[11] << 4) | (b[12] >> 4)) & 31;
  t[21] = ((b[12] << 1) | (b[13] >> 7)) & 31;
  t[22] = (               (b[13] >> 2)) & 31;
  t[23] = ((b[13] << 3) | (b[14] >> 5)) & 31;
  t[24] = (               (b[14] >> 0)) & 31;

  t[25] = (               (b[15] >> 3)) & 31;
  t[26] = ((b[15] << 2) | (b[16] >> 6)) & 31;
  t[27] = (               (b[16] >> 1)) & 31;
  t[28] = ((b[16] << 4) | (b[17] >> 4)) & 31;
  t[29] = ((b[17] << 1) | (b[18] >> 7)) & 31;
  t[30] = (               (b[18] >> 2)) & 31;
  t[31] = ((b[18] << 3) | (b[19] >> 5)) & 31;
  t[32] = (               (b[19] >> 0)) & 31;

  // note: some further t[] array items will be set after we know the checksum of this part

  /*
   * Checksum:
   */

  u8 data[64] = { 0 }; // only 44 bytes actually needed

  data[0] = 3; // hrp_expand ("bc"), human readable part
  data[1] = 3;
  data[2] = 0;
  data[3] = 2;
  data[4] = 3;

  for (u32 i = 0; i < 33; i++)
  {
   data[i + 5] = t[i];
  }

  // data[38] = data[39] = data[40] = data[41] = data[42] = data[43] = 0;

  u32 polymod = polymod_checksum (data, 44) ^ 1; // BECH32M would xor with 0x2bc830a3

  t[33] = (polymod >> 25) & 31;
  t[34] = (polymod >> 20) & 31;
  t[35] = (polymod >> 15) & 31;
  t[36] = (polymod >> 10) & 31;
  t[37] = (polymod >>  5) & 31;
  t[38] = (polymod >>  0) & 31;

  /*
   * BASE32 encode:
   */

  u8 bech32_address[64] = { 0 }; // only 39 bytes needed: 1 + 32 + 6

  for (u32 i = 0; i < 39; i++)
  {
    const u32 idx = t[i];

    bech32_address[i] = BECH32_BASE32_ALPHABET[idx];
  }

  bech32_address[39] = 0; // be extra safe, terminate the "C" string with NUL byte

  return snprintf (line_buf, line_size, "%s%s", SIGNATURE_BITCOIN_BECH32, bech32_address);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
