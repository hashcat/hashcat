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
#include "memory.h"
#include "emu_inc_hash_sha512.h"
#include "emu_inc_hash_sha256.h"
#include "emu_inc_cipher_aes.h"
#include "ext_secp256k1.h"
#include "zlib.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "Electrum Wallet (Salt-Type 5)";
static const u64   KERN_TYPE      = 21800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HOOK23;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$electrum$5*02170fee7c35f1ef3b229edc90fbd0793b688a0d6f41137a97aab2343d315cce16*94cf72d8f5d774932b414a3344984859e43721268d2eb35fa531de5a2fc7024b463c730a54f4f46229dd9fede5034b19ac415c2916e9c16b02094f845795df0c397ff76d597886b1f9e014ad1a8f64a3f617d9900aa645b3ba86f16ce542251fc22c41d93fa6bc118be96d9582917e19d2a299743331804cfc7ce2c035367b4cbcfb70adfb1e10a0f2795769f2165d8fd13daa8b45eeac495b5b63e91a87f63b42e483f84a881e49adecacf6519cb564694b42dd9fe80fcbc6cdb63cf5ae33f35255266f5c2524dd93d3cc15eba0f2ccdc3c109cc2d7e8f711b8b440f168caf8b005e8bcdfe694148e94a04d2a738f09349a96600bd8e8edae793b26ebae231022f24e96cb158db141ac40400a9e9ef099e673cfe017281537c57f82fb45c62bdb64462235a6eefb594961d5eb2c46537958e4d04250804c6e9f343ab7a0db07af6b8a9d1a6c5cfcd311b8fb8383ac9ed9d98d427d526c2f517fc97473bd87cb59899bd0e8fb8c57fa0f7e0d53daa57c972cf92764af4b1725a5fb8f504b663ec519731929b3caaa793d8ee74293eee27d0e208a60e26290bc546e6fa9ed865076e13febfea249729218c1b5752e912055fbf993fbac5df2cca2b37c5e0f9c30789858ceeb3c482a8db123966775aeed2eee2fc34efb160d164929f51589bff748ca773f38978bff3508d5a7591fb2d2795df983504a788071f469d78c88fd7899cabbc5804f458653d0206b82771a59522e1fa794d7de1536c51a437f5d6df5efd6654678e5794ca429b5752e1103340ed80786f1e9da7f5b39af628b2212e4d88cd36b8a7136d50a6b6e275ab406ba7c57cc70d77d01c4c16e9363901164fa92dc9e9b99219d5376f24862e775968605001e71b000e2c7123b4b43f3ca40db17efd729388782e46e64d43ccb947db4eb1473ff1a3836b74fe312cd1a33b73b8b8d80c087088932277773c329f2f66a01d6b3fc1e651c56959ebbed7b14a21b977f3acdedf1a0d98d519a74b50c39b3052d840106da4145345d86ec0461cddafacc2a4f0dd646457ad05bf04dcbcc80516a5c5ed14d2d639a70e77b686f19cbfb63f546d81ae19cc8ba35cce3f3b5b9602df25b678e14411fecec87b8347f5047513df415c6b1a3d39871a6bcb0f67d9cf8311596deae45fd1d84a04fd58f1fd55c5156b7309af09094c99a53674809cb87a45f95a2d69f9997a38085519cb4e056f9efd56672a2c1fe927d5ea8eec25b8aff6e56f9a2310f1a481daf407b8adf16201da267c59973920fd21bb087b88123ef98709839d6a3ee34efb8ccd5c15ed0e46cff3172682769531164b66c8689c35a26299dd26d09233d1f64f9667474141cf9c6a6de7f2bc52c3bb44cfe679ff4b912c06df406283836b3581773cb76d375304f46239da5996594a8d03b14c02f1b35a432dc44a96331242ae31174*33a7ee59d6d17ed1ee99dc0a71771227e6f3734b17ba36eb589bdced56244135";

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

typedef struct electrum_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} electrum_tmp_t;

typedef struct
{
  u32 ukey[8];

  u32 hook_success;

} electrum_hook_t;

typedef struct electrum_hook_salt
{
  u32 data_buf[256];

  u8 ephemeral_pubkey_raw[33];

  secp256k1_pubkey ephemeral_pubkey_struct;

} electrum_hook_salt_t;

static const char *SIGNATURE_ELECTRUM = "$electrum$5*";

void module_hook23 (hc_device_param_t *device_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  electrum_hook_t *hook_items = (electrum_hook_t *) device_param->hooks_buf;

  electrum_hook_salt_t *electrums = (electrum_hook_salt_t *) hook_salts_buf;
  electrum_hook_salt_t *electrum  = &electrums[salt_pos];

  u32 *data_buf = electrum->data_buf;

  // we need to copy it because the secp256k1_ec_pubkey_tweak_mul () function has side effects

  secp256k1_pubkey ephemeral_pubkey = electrum->ephemeral_pubkey_struct; // shallow copy is safe !

  // this hook data needs to be updated (the "hook_success" variable):

  electrum_hook_t *hook_item = &hook_items[pw_pos];

  hook_item->hook_success = 0;

  u32 ukey[9]; // (32 + 1) + 3 = 9 * 4 = 36 bytes (+1 for holding the "sign" of the curve point)

  ukey[0] = hook_item->ukey[0];
  ukey[1] = hook_item->ukey[1];
  ukey[2] = hook_item->ukey[2];
  ukey[3] = hook_item->ukey[3];
  ukey[4] = hook_item->ukey[4];
  ukey[5] = hook_item->ukey[5];
  ukey[6] = hook_item->ukey[6];
  ukey[7] = hook_item->ukey[7];
  ukey[8] = 0;

  /*
   * Start with Elliptic Curve Cryptography (ECC)
   */

  u8 *tmp_buf = (u8 *) ukey;

  const size_t length = 33; // NOT a bug (32 + 1 for the sign)

  bool multiply_success = hc_secp256k1_pubkey_tweak_mul (&ephemeral_pubkey, tmp_buf, length);

  if (multiply_success == false) return;

  u32 input[64] = { 0 };

  memcpy (input, tmp_buf, length);

  sha512_ctx_t sha512_ctx;

  sha512_init        (&sha512_ctx);
  sha512_update_swap (&sha512_ctx, input, length);
  sha512_final       (&sha512_ctx);

  // ... now we have the result in sha512_ctx.h[0]...sha512_ctx.h[7]

  u32 iv[4];

  iv[0] = v32b_from_v64 (sha512_ctx.h[0]);
  iv[1] = v32a_from_v64 (sha512_ctx.h[0]);
  iv[2] = v32b_from_v64 (sha512_ctx.h[1]);
  iv[3] = v32a_from_v64 (sha512_ctx.h[1]);

  iv[0] = byte_swap_32 (iv[0]);
  iv[1] = byte_swap_32 (iv[1]);
  iv[2] = byte_swap_32 (iv[2]);
  iv[3] = byte_swap_32 (iv[3]);

  u32 key[4];

  key[0] = v32b_from_v64 (sha512_ctx.h[2]);
  key[1] = v32a_from_v64 (sha512_ctx.h[2]);
  key[2] = v32b_from_v64 (sha512_ctx.h[3]);
  key[3] = v32a_from_v64 (sha512_ctx.h[3]);

  key[0] = byte_swap_32 (key[0]);
  key[1] = byte_swap_32 (key[1]);
  key[2] = byte_swap_32 (key[2]);
  key[3] = byte_swap_32 (key[3]);

  // init AES

  AES_KEY aes_key;

  memset (&aes_key, 0, sizeof (aes_key));

  aes128_set_decrypt_key (aes_key.rdk, key, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);

  int aes_len = 1024; // in my tests (very few) it also worked with only 128 input bytes !
  // int aes_len = 128;

  u32 data[4];
  u32 out[4];

  u32 out_full[256]; // 1024 / 4

  // we need to run it at least once:

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  aes128_decrypt (aes_key.rdk, data, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

  out[0] ^= iv[0];

  // early reject

  if ((out[0] & 0x0007ffff) != 0x00059c78) return;

  out[1] ^= iv[1];
  out[2] ^= iv[2];
  out[3] ^= iv[3];

  out_full[0] = out[0];
  out_full[1] = out[1];
  out_full[2] = out[2];
  out_full[3] = out[3];

  iv[0] = data[0];
  iv[1] = data[1];
  iv[2] = data[2];
  iv[3] = data[3];

  // for aes_len > 16 we need to loop

  for (int i = 16, j = 4; i < aes_len; i += 16, j += 4)
  {
    data[0] = data_buf[j + 0];
    data[1] = data_buf[j + 1];
    data[2] = data_buf[j + 2];
    data[3] = data_buf[j + 3];

    aes128_decrypt (aes_key.rdk, data, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];

    out_full[j + 0] = out[0];
    out_full[j + 1] = out[1];
    out_full[j + 2] = out[2];
    out_full[j + 3] = out[3];
  }

  // decompress with zlib:

  size_t  compressed_data_len   = aes_len;
  u8     *compressed_data       = (u8 *) out_full;

  size_t  decompressed_data_len = 16; // we do NOT need more than the first bytes for validation
  u8     *decompressed_data     = (unsigned char *) hcmalloc (decompressed_data_len);

  z_stream inf;

  inf.zalloc = Z_NULL;
  inf.zfree  = Z_NULL;
  inf.opaque = Z_NULL;

  inf.next_in   = compressed_data;
  inf.avail_in  = compressed_data_len;

  inf.next_out  = decompressed_data;
  inf.avail_out = decompressed_data_len;

  // inflate:

  inflateInit2 (&inf, MAX_WBITS);

  int zlib_ret = inflate (&inf, Z_NO_FLUSH);

  inflateEnd (&inf);

  if ((zlib_ret != Z_OK) && (zlib_ret != Z_STREAM_END))
  {
    hcfree (decompressed_data);

    return;
  }

  if ((memcmp (decompressed_data, "{\n    \"",   7) == 0) ||
      (memcmp (decompressed_data, "{\r\n    \"", 8) == 0))
  {
    hook_item->hook_success = 1;
  }

  hcfree (decompressed_data);
}

u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_size = (const u64) sizeof (electrum_hook_t);

  return hook_size;
}

u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_salt_size = (const u64) sizeof (electrum_hook_salt_t);

  return hook_salt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (electrum_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = PW_MAX;

  return pw_max;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D NO_UNROLL");

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  electrum_hook_salt_t *electrum = (electrum_hook_salt_t *) hook_salt_buf;

  token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ELECTRUM;

  token.len[0]     = 12;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 66;
  token.len_max[1] = 66;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len_min[2] = 2048;
  token.len_max[2] = 2048;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 64;
  token.len_max[3] = 64;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *ephemeral_pos = token.buf[1];
  const u8 *data_buf_pos  = token.buf[2];
  const u8 *mac_pos       = token.buf[3];

  /**
   * store data
   */

  // ephemeral pubkey:

  for (u32 i = 0, j = 0; j < 66; i += 1, j += 2)
  {
    electrum->ephemeral_pubkey_raw[i] = hex_to_u8 (ephemeral_pos + j);
  }

  size_t length = 33;

  bool parse_success = hc_secp256k1_pubkey_parse (&electrum->ephemeral_pubkey_struct, electrum->ephemeral_pubkey_raw, length);

  if (parse_success == false) return (PARSER_SALT_VALUE);

  // data buf:

  u8* data_buf_ptr = (u8 *) electrum->data_buf;

  for (u32 i = 0, j = 0; j < 2048; i += 1, j += 2)
  {
    data_buf_ptr[i] = hex_to_u8 (data_buf_pos + j);
  }

  // digest / mac:

  for (u32 i = 0, j = 0; j < 64; i += 1, j += 8)
  {
    digest[i] = hex_to_u32 (mac_pos + j);

    digest[i] = byte_swap_32 (digest[i]);
  }

  // fake salt

  salt->salt_buf[0] = electrum->data_buf[0];
  salt->salt_buf[1] = electrum->data_buf[1];
  salt->salt_buf[2] = electrum->data_buf[2];
  salt->salt_buf[3] = electrum->data_buf[3];

  salt->salt_len = 16;

  salt->salt_iter = 1024 - 1;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  u32 *digest = (u32 *) digest_buf;

  electrum_hook_salt_t *electrum = (electrum_hook_salt_t *) hook_salt_buf;

  // ephemeral pubkey:

  char ephemeral[66 + 1];

  memset (ephemeral, 0, sizeof (ephemeral));

  for (u32 i = 0, j = 0; i < 33; i += 1, j += 2)
  {
    const u8 *ptr = (const u8 *) electrum->ephemeral_pubkey_raw;

    snprintf (ephemeral + j, 66 + 1 - j, "%02x", ptr[i]);
  }

  // data buf:

  char data_buf[2048 + 1];

  memset (data_buf, 0, sizeof (data_buf));

  for (u32 i = 0, j = 0; i < 1024; i += 1, j += 2)
  {
    const u8 *ptr = (const u8 *) electrum->data_buf;

    snprintf (data_buf + j, 2048 + 1 - j, "%02x", ptr[i]);
  }

  // mac:

  char mac[64 + 1];

  memset (mac, 0, sizeof (mac));

  for (u32 i = 0, j = 0; i < 8; i += 1, j += 8)
  {
    snprintf (mac + j, 64 + 1 - j, "%08x", digest[i]);
  }

  int bytes_written = snprintf (line_buf, line_size, "%s%s*%s*%s",
    SIGNATURE_ELECTRUM,
    ephemeral,
    data_buf,
    mac);

  return bytes_written;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = MODULE_DEFAULT;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
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
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = module_hook23;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_hook_size                = module_hook_size;
  module_ctx->module_jit_build_options        = module_jit_build_options;
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
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
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
