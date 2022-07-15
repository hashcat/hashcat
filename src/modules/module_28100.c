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
#include "emu_inc_hash_sha1.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_8_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Windows Hello PIN/Password";
static const u64   KERN_TYPE      = 28100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$WINHELLO$*SHA512*10000*00761655*3b3d3197efb2839a6072e922cc03be910be55d1e60389689c05b520d2d57c06258dc5a48798ba65424004cbe2e003d0509036f3394bcae108eb6b77c7eb306d7*c0772a3aca949db60f274f315b3a5f63fea552fc0d1f2032db5293ca9690735217d918d4cf697aa45b2fe598168804040e18fe00758be94aac971985ea7a5521*bff47e398df761733b5aeda7035cdf289547db3afb94b70cbad2aaea21a5cd58*8a4d5b88832e10bad57303324e6c9021733733df4acbf91366f51cebdc755e00fe1d01b3202469ee6ad5e667975b4f50e3110b00ef60414cd2cf96cc47df532e36b997727ffec2924d979d3fb6e677cb5827f4313131a46be8712926c42158339b55183e2fd7f2f0761980b1413897825c3759c566ff8a438189a6c8fb2d630dc33c6330de45c784d11957c686b40b6fe31fd8f2b1b664f542392326af5d334fdf92155343335e1b964955ac0b0e6f7254a599f0f0dc99becc2216515ba9e9472a54e60a14507fc353ebc47b9f0a8249a2a1bfa5d2cf526bd15ee68bd52e944ece9de6bbda913bc5083e26229673340fcc5285df0d38cbc7bb14584ced2fe9e9b3c283fa3c5ad4dd2034b7a67c8e7a1632fae8979a0abdd19be91c6bc371966121e04d433923e44df0b60c156bd90bc61c9fed01a7a76353f79dd4da3e07e12810ec3765128ec44b44b0789d6aa9e9702211a22ab8055ea32e9513fb1bd9d24ca04b33282632f63ab1b213e9644f97bc31dc4d2e7050c1fa23c0000facbf7c76fd7be4b112586f73f0c27abcf7cbe8c9d9fb83af70f60c490936fef84ed5301f73917b4e4170674a5d5e4bfbebdfeda9584221a0f190545efea7245dd2517ade393bedc255c4e016d9919e6e3f3711bca677fc099bf4e1730a752ea2a90a20ff3d09c909771849d3b009ba8d95d2b84fff889e38b079f1325aa42daa067a52abb5c064de3a5040e4a64e76b397b5c9ee6d045f3b5150cf428a92c141735908bb278077d52beefdc87efa156b8ebda071cb425fad0372a8a7cb6eb29926e8f6411ff1b818750c5b6888302fee9b1591b1c23db131538db2aa3de61dcd76fb7067be7ab71ee372bac18be0f446c974e92e79e27e7e3b2aa5ffc3f5f923f2df8ac2edcbb9392d1ac35e4cd52037d9dceedec6391e713e78770307bfde6a31b4e115904d285ac35db055ae8253b9968b7ed7b948da5f*785435725a573571565662727670754100";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

typedef struct winhello
{
  // we need a lot of padding here because sha512_update expects them to be multiple of 128

  u32 mk_buf[16];
  u32 mk_buf_pc[8];
  u32 hmac_buf[32];
  u32 blob_buf[256];
  u32 magicv_buf[32];

  int mk_len;
  int hmac_len;
  int blob_len;
  int magicv_len;

} winhello_t;

typedef struct winhello_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} winhello_tmp_t;

static const char *SIGNATURE_WINHELLO = "$WINHELLO$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (winhello_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (winhello_tmp_t);

  return tmp_size;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 4; // https://docs.microsoft.com/en-us/windows/security/information-protection/tpm/tpm-fundamentals#anti-hammering

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 127; // https://docs.microsoft.com/en-us/windows/security/information-protection/tpm/tpm-fundamentals#anti-hammering

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  winhello_t *winhello = (winhello_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 9;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_WINHELLO;

  token.len_min[0] = 10;
  token.len_max[0] = 10;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 6; // fixed SHA512
  token.len_max[1] = 6;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  // pbkdf2 iter
  token.len_min[2] = 5; // fixed 10000
  token.len_max[2] = 5;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // pbdfk2 salt
  token.len_min[3] = 8;
  token.len_max[3] = 8;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // sign (hash)
  token.len_min[4] = 128;
  token.len_max[4] = 128;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // mk
  token.len_min[5] = 128;
  token.len_max[5] = 128;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // hmac
  token.len_min[6] = 64;
  token.len_max[6] = 64;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // verify blob
  token.len_min[7] = 1384;
  token.len_max[7] = 1384;
  token.sep[7]     = '*';
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // magicv
  token.len_min[8] = 34; // fixed 785435725a573571565662727670754100
  token.len_max[8] = 34;
  token.sep[8]     = '*';
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *sha512_pos = token.buf[1];
  const u8 *iter_pos   = token.buf[2];
  const u8 *salt_pos   = token.buf[3];
  const u8 *sign_pos   = token.buf[4];
  const u8 *mk_pos     = token.buf[5];
  const u8 *hmac_pos   = token.buf[6];
  const u8 *blob_pos   = token.buf[7];
  const u8 *magicv_pos = token.buf[8];

  const int salt_len   = token.len[3];
  const int mk_len     = token.len[5];
  const int hmac_len   = token.len[6];
  const int blob_len   = token.len[7];
  const int magicv_len = token.len[8];

  // verify

  if (memcmp (sha512_pos, "SHA512", 6) != 0) return (PARSER_SALT_VALUE);

  // pbkdf2 iter

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  salt->salt_iter = iter - 1;

  // pbkdf2 salt

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  for (u32 i = 0, j = 0; i < salt->salt_len; i += 4, j += 1)
  {
    salt->salt_buf[j] = byte_swap_32 (salt->salt_buf[j]);
  }

  // mk

  winhello->mk_len = hex_decode (mk_pos, mk_len, (u8 *) winhello->mk_buf);

  for (int i = 0, j = 0; i < winhello->mk_len; i += 4, j += 1)
  {
    winhello->mk_buf[j] = byte_swap_32 (winhello->mk_buf[j]);
  }

  // hmac

  winhello->hmac_len = hex_decode (hmac_pos, hmac_len, (u8 *) winhello->hmac_buf);

  for (int i = 0, j = 0; i < winhello->hmac_len; i += 4, j += 1)
  {
    winhello->hmac_buf[j] = byte_swap_32 (winhello->hmac_buf[j]);
  }

  // blob

  winhello->blob_len = hex_decode (blob_pos, blob_len, (u8 *) winhello->blob_buf);

  for (int i = 0, j = 0; i < winhello->blob_len; i += 4, j += 1)
  {
    winhello->blob_buf[j] = byte_swap_32 (winhello->blob_buf[j]);
  }

  // magicv

  winhello->magicv_len = hex_decode (magicv_pos, magicv_len, (u8 *) winhello->magicv_buf);

  for (int i = 0, j = 0; i < winhello->magicv_len; i += 4, j += 1)
  {
    winhello->magicv_buf[j] = byte_swap_32 (winhello->magicv_buf[j]);
  }

  // sign (hash)

  digest[0] = hex_to_u64 (sign_pos +   0);
  digest[1] = hex_to_u64 (sign_pos +  16);
  digest[2] = hex_to_u64 (sign_pos +  32);
  digest[3] = hex_to_u64 (sign_pos +  48);
  digest[4] = hex_to_u64 (sign_pos +  64);
  digest[5] = hex_to_u64 (sign_pos +  80);
  digest[6] = hex_to_u64 (sign_pos +  96);
  digest[7] = hex_to_u64 (sign_pos + 112);

  digest[0] = byte_swap_64 (digest[0]);
  digest[1] = byte_swap_64 (digest[1]);
  digest[2] = byte_swap_64 (digest[2]);
  digest[3] = byte_swap_64 (digest[3]);
  digest[4] = byte_swap_64 (digest[4]);
  digest[5] = byte_swap_64 (digest[5]);
  digest[6] = byte_swap_64 (digest[6]);
  digest[7] = byte_swap_64 (digest[7]);

  // precompute mk

  sha1_ctx_t sha1_ctx;

  sha1_init   (&sha1_ctx);
  sha1_update (&sha1_ctx, winhello->mk_buf, winhello->mk_len);
  sha1_final  (&sha1_ctx);

  winhello->mk_buf_pc[0] = sha1_ctx.h[0];
  winhello->mk_buf_pc[1] = sha1_ctx.h[1];
  winhello->mk_buf_pc[2] = sha1_ctx.h[2];
  winhello->mk_buf_pc[3] = sha1_ctx.h[3];
  winhello->mk_buf_pc[4] = sha1_ctx.h[4];
  winhello->mk_buf_pc[5] = 0;
  winhello->mk_buf_pc[6] = 0;
  winhello->mk_buf_pc[7] = 0;

  // yes we can precompute the first block of both sha512 here, because length is 128 + hmac lenght + magic length, but
  // speed improvement is negligible, but readability would drop a lot

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u64 *digest = (const u64 *) digest_buf;

  const winhello_t *winhello = (const winhello_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf (line_buf, line_size, "%s*SHA512*%u*", SIGNATURE_WINHELLO, salt->salt_iter + 1);

  u32 tmp32[256];

  for (u32 i = 0, j = 0; i < salt->salt_len; i += 4, j += 1)
  {
    tmp32[j] = byte_swap_32 (salt->salt_buf[j]);
  }

  out_len += hex_encode ((u8 *) tmp32, salt->salt_len, out_buf + out_len);

  out_buf[out_len] = '*';

  out_len++;

  u64 tmp[8];

  tmp[0] = byte_swap_64 (digest[0]);
  tmp[1] = byte_swap_64 (digest[1]);
  tmp[2] = byte_swap_64 (digest[2]);
  tmp[3] = byte_swap_64 (digest[3]);
  tmp[4] = byte_swap_64 (digest[4]);
  tmp[5] = byte_swap_64 (digest[5]);
  tmp[6] = byte_swap_64 (digest[6]);
  tmp[7] = byte_swap_64 (digest[7]);

  u64_to_hex (tmp[0], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[1], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[2], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[3], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[4], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[5], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[6], out_buf + out_len); out_len += 16;
  u64_to_hex (tmp[7], out_buf + out_len); out_len += 16;

  out_buf[out_len] = '*';

  out_len++;

  for (int i = 0, j = 0; i < winhello->mk_len; i += 4, j += 1)
  {
    tmp32[j] = byte_swap_32 (winhello->mk_buf[j]);
  }

  out_len += hex_encode ((u8 *) tmp32, winhello->mk_len, out_buf + out_len);

  out_buf[out_len] = '*';

  out_len++;

  for (int i = 0, j = 0; i < winhello->hmac_len; i += 4, j += 1)
  {
    tmp32[j] = byte_swap_32 (winhello->hmac_buf[j]);
  }

  out_len += hex_encode ((u8 *) tmp32, winhello->hmac_len, out_buf + out_len);

  out_buf[out_len] = '*';

  out_len++;

  for (int i = 0, j = 0; i < winhello->blob_len; i += 4, j += 1)
  {
    tmp32[j] = byte_swap_32 (winhello->blob_buf[j]);
  }

  out_len += hex_encode ((u8 *) tmp32, winhello->blob_len, out_buf + out_len);

  out_buf[out_len] = '*';

  out_len++;

  for (int i = 0, j = 0; i < winhello->magicv_len; i += 4, j += 1)
  {
    tmp32[j] = byte_swap_32 (winhello->magicv_buf[j]);
  }

  out_len += hex_encode ((u8 *) tmp32, winhello->magicv_len, out_buf + out_len);

  out_buf[out_len] = 0;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
