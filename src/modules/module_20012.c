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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "DiskCryptor SHA512 + XTS 1024 bit";
static const u64   KERN_TYPE      = 20012;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_UTF16LE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$diskcryptor$0*37f6252cf81f8049f68deb41de5becfb46851909e5d4f41f8f5da4c4dc830992c5e29905fa6e0cb755e42c6cfc0509a751a2a4f01fb884968c9fd18bc9007c1ee7e67d1b7cf0e23ba82235517b93db8ebcc96943eb90d782a210e38205af60388475386996c82a1d1dc6a9581057c264577b78f261870ec9cfb3c10a989c2cc8abb97ea18dc09b54d1723ebf74a0c6f9d1b1d6a633559d885d633243eb2108fa51b13aded97671c2281126ff74aae7f6ab9efa3f8a04cef5bcf6fad9d2f1d52275bdb5c12e402baad1f42390af081bea192d2f392bccd57eedfc6fb82b66839d02f6468eb32834980580121466873d8694195628ab46195a6eb06c8d06f9ec9d6093d91d440ae35d890a6f4d92d2cda4254dace1be9bdbaf979c011b28425cfb26803b66a85ee46f5b8bfe72ba16052775bbe28e22306d708143da0c1b5f20887967d1f26bd85112213d303035e0187cd2386db8d02dd2d30171c5276b69529d0de9851812a6ab726b27eb2a539a578fd53a98b64e65be8c0b98db42e266d755f9247706aa503d70d6e9ed3d2b0c81a653ca87dda4c94687e177380738ffe50fe43a08132aa8a898b482df6dd59cd3c3738c36f4d316d648667ae65841eeda636ce16e74668b635d261912d58d96e34843a61004a1b5b8ca4c3221ff8bdde75af488d32089b62dbb5b23aec9d8b6366746b8ed71868e691faf05fd288751f79875a474bf2c2f27d543b2f411aad3432776a1201c4e0e026f081d04b907e231cf59280689708357ab9a96734e104a59f6a9b9853f2702229408f7e1de9fa09e682b3f10ca1398bdadbc4586a0ca6cd75c51bd3793039bc1017ac14722f0007032b78d931e06a80c298b90f820c14f8fe597caf3212bac02da64b5a7517a5a33d32fb4debb9f4f7880d749ede9e60bbe9bb60c5ca344aa08ec60d5b1356ee78d7935efdf72da581dff8fb88f166b75d732a60ea3d4a5899d053bc93ca2d61e6c874ea5845de27f0fc1f93689de6233157912ca1174fc4652c70a49aa0fd47a76eca905619706c0d5b8a5331dbb01b18ca782b06c07656856049ebc3df24975a18ccf666583d8534cc4da34336d5bacb878674c19772b97d95c6bbf5b2f4e23f5b3f223990cd5ad6e639cf790253c524a518cd38036856b00c76a195983783c21f30f92acbd822a20f8201216273a03436eb73b7aeda816ef7c7b767f1449700e88979ad690b52e95f9e00cb5b8dac58503cb2be74f9f1c7a0f469095275c08c4cd11e38d249b083ffb46fee84a4e3caceec00ac54bcc62bf504674a39e01b5f081e513d6c54f305c4f76ed9d8be9dd3f6c143ab81f55c7928f3fea3ea1fb0852b3cc2180d0809b1b38e403acf4d03a507b3f940260af48e1e40cb77c54f386e72d56b2637464a1c49f30460dab6109f1c0d9a50dd64eaeb0a43974095e972149c1b06be3b3420cb445d68280678c4fd42616933828d1f69e3dd5ad231b0f9424a0d4a03b2b078468d8a3e8d72cff262d55d1cbf12925e6b510dfe0afdee35bfd6563b9d72a7c6e0106921dc7913d2573439c9d3999aff7bf0fb4cb8c4269c97315ab0eff22077b5e3107c6779136a4ebc5be5d0ba3dafa2d91423ecc78541088b27cfe0782262aba458acc6a4bb73831591d663ab9081a9bda29036127cc29c29f47edb32c813ba126b85fe5458a215deb017221bd5888db5b3bf7e2096692579d38f9d615b5b0b1415deac13937d5359de70b28ed3817669a955c0852a2bf1dc602c6d37a29d576dc5d748e678d35812d8cef3faba407de7e294034d7a34bd9dc3cf4df3b32fad4b9c0ebd253673df0f1e53c17a2e6159f73bd24e3ab0acbb89e12832816e1fc87103e7bcb1bbab395810066c3bc79a5f580d9645c20977e76f01b9f2f1fcbfecdd19e21030cf91dd460ecd19befdcbee3c6ea8a55a92b5cd2f51efb650d3d585a8da91d50cb27877d7317b1a28f93d30597b5b98acbdf71d544771b5fed1bf3a2e0271c950baad47112038662107873f4b8d422cf07a14686925eff4d37c37debbc5d625e2be713095b30dbc62ab572f2c072551871ccc4175a84657dbe12c7d08077a1169fd1ef258de6bf32ea872c7d6d2401ab6fd1d8fe0fa426c84700d231bee87124a5cbd91fab435de01e7025792c2e5e78342b3d04dc9798bb00fe8e66cb3861762b1c3de99c3c7bd1f4275e13b0d37d5ace24624e0c5ae7c3151835eec2f9864cabbba2d801981587c164e63d61844452dbaaeefa7332241d1d55a25722b475bcfe0b6fd31cb505d042708cd1e11f15bb1c8f5b9b3216ebbfb65a6a80c8a5d0ea85e08e9cc858efa532740501fa075c4dfe5823fc0e478f24d2acba43a86bf832f0cf88d762eb0174bcb6c9bbdcc8168cd4a68948e4c7a4320aa12fbd8e76e228d03cd07d7e625838689d9ecbb4c049dbaafc95999979035b93799fd75cd2c1669d05500fad4f5c2c8a328ac8473aba545f469f2f1b03fe2667c1aabc26f1930cf913deb1c7154473178a6ebada4bccfc70d0ad7aa38cc112146ae7921efdda088d5cb897e084886845a4fa0871b1d6fad873a6263431f0569b133f25c30ccd85921abb1cccf364072af20eb6e08f4521e4a2c83f2707250d1b81c7397b37182bcc6cd0e918a474855c21806638ebd1af67445dc073938a9d35fd58076eff2919cd36b5c6fc0e3ae4ce60720fcbacf8093109d9241d646f87e157a31b7738970279b58488b1e4cd07792ebc8e87ba6b43870fab867cfbc55ddc1e6c4ab1a7c3a1cfc1d9a4d09f1fea3633d5f3462b8d78716111ed7aa7b505ee96fff24b4bd3918e952a7d13021325ba543ff0cdb90cb74621ec74fd9a6e6add2b1ea21115c39f083c3534cb3e946db992128984fddd4d85e8cf6c39";

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

typedef struct diskcryptor_esalt
{
  u32 salt_buf[512];

} diskcryptor_esalt_t;

typedef struct pbkdf2_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

} pbkdf2_sha512_tmp_t;

static const int   DISKCRYPTOR_VERSION   =    0;
static const int   ROUNDS_DISKCRYPTOR    = 1000;
static const char *SIGNATURE_DISKCRYPTOR = "$diskcryptor$";

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (diskcryptor_esalt_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = PW_MAX;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  diskcryptor_esalt_t *diskcryptor_esalt = (diskcryptor_esalt_t *) esalt_buf;

  token_t token;

  token.token_cnt = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DISKCRYPTOR;

  token.len[0]     = 13;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[2]     = 4096;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u8 *version = token.buf[1];

  if (version[0] != '0' + DISKCRYPTOR_VERSION) return (PARSER_SALT_VALUE);

  // esalt

  const u8 *data_buf = token.buf[2];

  for (u32 i = 0; i < 512; i++)
  {
    diskcryptor_esalt->salt_buf[i] = hex_to_u32 (&data_buf[i * 8]);
  }

  // salt param

  salt->salt_len  = 64;
  salt->salt_iter = ROUNDS_DISKCRYPTOR - 1;

  // salt

  salt->salt_buf[ 0] = diskcryptor_esalt->salt_buf[ 0];
  salt->salt_buf[ 1] = diskcryptor_esalt->salt_buf[ 1];
  salt->salt_buf[ 2] = diskcryptor_esalt->salt_buf[ 2];
  salt->salt_buf[ 3] = diskcryptor_esalt->salt_buf[ 3];
  salt->salt_buf[ 4] = diskcryptor_esalt->salt_buf[ 4];
  salt->salt_buf[ 5] = diskcryptor_esalt->salt_buf[ 5];
  salt->salt_buf[ 6] = diskcryptor_esalt->salt_buf[ 6];
  salt->salt_buf[ 7] = diskcryptor_esalt->salt_buf[ 7];
  salt->salt_buf[ 8] = diskcryptor_esalt->salt_buf[ 8];
  salt->salt_buf[ 9] = diskcryptor_esalt->salt_buf[ 9];
  salt->salt_buf[10] = diskcryptor_esalt->salt_buf[10];
  salt->salt_buf[11] = diskcryptor_esalt->salt_buf[11];
  salt->salt_buf[12] = diskcryptor_esalt->salt_buf[12];
  salt->salt_buf[13] = diskcryptor_esalt->salt_buf[13];
  salt->salt_buf[14] = diskcryptor_esalt->salt_buf[14];
  salt->salt_buf[15] = diskcryptor_esalt->salt_buf[15];

  // digest

  digest[0] = diskcryptor_esalt->salt_buf[16];
  digest[1] = diskcryptor_esalt->salt_buf[17];
  digest[2] = diskcryptor_esalt->salt_buf[18];
  digest[3] = diskcryptor_esalt->salt_buf[19];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const diskcryptor_esalt_t *diskcryptor_esalt = (const diskcryptor_esalt_t *) esalt_buf;

  // first only add the signature and version number:

  int line_len = snprintf (line_buf, line_size, "%s%i*", SIGNATURE_DISKCRYPTOR, DISKCRYPTOR_VERSION);

  // ... then add the full header (in hexadecimal):

  for (u32 i = 0; i < 512; i++)
  {
    line_len += snprintf (line_buf + line_len, line_size - line_len, "%08x", byte_swap_32 (diskcryptor_esalt->salt_buf[i]));
  }

  return line_len;
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
  module_ctx->module_esalt_size               = module_esalt_size;
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
