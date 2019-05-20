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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 3;
static const u32   DGST_POS1      = 4;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "JKS Java Key Store Private Keys (SHA1)";
static const u64   KERN_TYPE      = 15500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_APPENDED_SALT;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_UTF16BE
                                  | OPTS_TYPE_ST_ADD80
                                  | OPTS_TYPE_ST_ADDBITS15;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$jksprivk$*338BD2FBEBA7B3EF198A4CBFC6E18AFF1E229367*5225850113575146134463704406336350011656*D5253EB151EB92DC73E542D8C0A4D7A848A5B0C0E370E625E6547D4E6F23416FC85A27BC295731B8021CDFBD003551C66C434FFBC87DACAD1FDF39022320034A2F86E779F2B1B3325428A666518FA89507AD63E15FD9C57B9E36EF5B642A2F448A9A3F09B79AD93D65F46B8692CD07539FD140146F8F219DC262971AF019E18EDC16C3C240569E1673F4D98BC818CCF28298D5A7BFF038A663DD10FE5E48643C3217C237D342164E2D41EF15075431FBD5B34800E5AE7EB80FAA5AE9982A55F35379AA7B31217E7F1C5F1964A15024A305AE4B3981FE1C80C163BC38ECA5581F11867E5C34C5D124D0367B3737E5E5BB14D2CAB26A698C8DAAB755C82BA6B823BCAECDD4A89C831651ACE5A6029FD0D3515C5D1D53AD8B9062CE8C445373862035CBBF60D490CA2E4975EE6E0358EC32E871FAB15347E3032E21F30F543BAAB01D779BA833CA0B8C7591B42C7C59A8FDD46D7DECEC0E91ADBF331177605E7830ABED62FAD7D5D806D8EFD01C38765940B7F97168FC72C39BF4C98F944FFC310CA8F4EB1D0F960F352CC5E2BB23A1EB221072A5471EDA2CE81C04595B8D37088CFB5C14F6A4A881AD12125DEFBB8154EB4C130AB7FD9933FD36DF1A6A26B51AB169866788678FCED988C8E017CA84354F487A5508210181AFB8B3AD0753E3E28BE674DFBD4E4FBDFD1E30D592F4EA3A77A2F0F5CF9A175DBC590EF5D42971A39918F12B92DCD8BFD56BE9A3459856B5587603C7B53062663A4C8894BBC9894FB1663BF30F32D907664328138B7A50EAC7F8E3183D74562A5C90FE1889AC4C5FE43EBEB8974563B6682F92591ECA4FA0DA72236C3851DA102DB6BA0CC07BFD32F7E962AB0EDCF4A8DEA6525174F5BB5C021E2A9A3F7F761E9CA90B6E27FB7E55CD91DA184FAC5E534E8AD25314C56CE5796506A0CA70881782F9C5147D87705065D68BD67D2B0344205BA6445D562273690004CA5A303274FB283A75F49BA968D7947943AA98F2AF9CB8253B425B86225E7395A331AC4CB1B1700C64D4F458D5D642C54148AE6DA41D9E26657D331B157D76042C2CF3057B83997C23D8BF68FB3C7337CAFB8B324AD0DF7A80B554B4D7F9AD6ED527E7932F1741A573C152A41610F6517E3F4A3BC6B66685871A7CE3795C559BD47CDB8E34CB2C1DFE980518D79E2078C258C54F312EB38609F640E7DC013E0F2A16A25BB5971882B4308D27930CA99FEC231AE927B62215A1B56098C362B7F20593953B29428681875070E84BF5B60BEA3948127151634123DA77C814AAD54CE10905763C8C19BC191C0C40458C809402E1957C4C05C4EAE27576B2D30593F7FDCC9A248DB5DB23CF2FA22A92C016090F611690BF0AB5B8B2866ED25F345EFE85DF3311C9E91C37CEE709CF16E7CB09D01BECD2961D094C02D42EC85BF47FAB1B67A13B9A1741C15F7156D57A71BFFABB03B71E69707913A5C136B3D69CE3F71ABFE376F0A21D723FFA2E60AC180689D3E8AF4348C9F555CD897387327FC8BA2B9C51A7298547E556A11A60441EF5331A1BFB847A3D23DD9F7C50E636A2C6309BC82E1A8852F5A8569B6D93*14*78D6A2424484CF5149932B7EA8BF*test";

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

typedef struct jks_sha1
{
  u32 checksum[5];
  u32 iv[5];
  u32 enc_key_buf[4096];
  u32 enc_key_len;
  u32 der[5];
  u32 alias[16];

} jks_sha1_t;

static const char *SIGNATURE_JKS_SHA1 = "$jksprivk$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (jks_sha1_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = PW_MAX;

  if (optimized_kernel == true)
  {
    pw_max = 16;
  }

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  jks_sha1_t *jks_sha1 = (jks_sha1_t *) esalt_buf;

  token_t token;

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_JKS_SHA1;

  token.sep[0]     = '*';
  token.len_min[0] = 10;
  token.len_max[0] = 10;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 40;
  token.len_max[1] = 40;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len_min[2] = 40;
  token.len_max[2] = 40;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = 2;
  token.len_max[3] = 16384;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 2;
  token.len_max[4] = 2;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';
  token.len_min[5] = 28;
  token.len_max[5] = 28;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '*';
  token.len_min[6] = 0;
  token.len_max[6] = 64;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // checksum

  const u8 *checksum_pos = token.buf[1];

  jks_sha1->checksum[0] = hex_to_u32 ((const u8 *) &checksum_pos[ 0]);
  jks_sha1->checksum[1] = hex_to_u32 ((const u8 *) &checksum_pos[ 8]);
  jks_sha1->checksum[2] = hex_to_u32 ((const u8 *) &checksum_pos[16]);
  jks_sha1->checksum[3] = hex_to_u32 ((const u8 *) &checksum_pos[24]);
  jks_sha1->checksum[4] = hex_to_u32 ((const u8 *) &checksum_pos[32]);

  // iv

  const u8 *iv_pos = token.buf[2];

  jks_sha1->iv[0] = hex_to_u32 ((const u8 *) &iv_pos[ 0]);
  jks_sha1->iv[1] = hex_to_u32 ((const u8 *) &iv_pos[ 8]);
  jks_sha1->iv[2] = hex_to_u32 ((const u8 *) &iv_pos[16]);
  jks_sha1->iv[3] = hex_to_u32 ((const u8 *) &iv_pos[24]);
  jks_sha1->iv[4] = hex_to_u32 ((const u8 *) &iv_pos[32]);

  // enc_key

  const u8 *enc_key_pos = token.buf[3];
  const int enc_key_len = token.len[3];

  u8 *enc_key_buf = (u8 *) jks_sha1->enc_key_buf;

  for (int i = 0, j = 0; j < enc_key_len; i += 1, j += 2)
  {
    enc_key_buf[i] = hex_to_u8 ((const u8 *) &enc_key_pos[j]);

    jks_sha1->enc_key_len++;
  }

  // der1

  const u8 *der1_pos = token.buf[4];

  u8 *der = (u8 *) jks_sha1->der;

  der[0] = hex_to_u8 ((const u8 *) &der1_pos[0]);

  // der2

  const u8 *der2_pos = token.buf[5];

  for (int i = 6, j = 0; j < 28; i += 1, j += 2)
  {
    der[i] = hex_to_u8 ((const u8 *) &der2_pos[j]);
  }

  der[1] = 0;
  der[2] = 0;
  der[3] = 0;
  der[4] = 0;
  der[5] = 0;

  // alias

  const u8 *alias_pos = token.buf[6];

  strncpy ((char *) jks_sha1->alias, (const char *) alias_pos, 64);

  // fake salt

  salt->salt_buf[0] = jks_sha1->iv[0];
  salt->salt_buf[1] = jks_sha1->iv[1];
  salt->salt_buf[2] = jks_sha1->iv[2];
  salt->salt_buf[3] = jks_sha1->iv[3];
  salt->salt_buf[4] = jks_sha1->iv[4];

  salt->salt_len = 20;

  // fake digest

  digest[0] = byte_swap_32 (jks_sha1->der[0]);
  digest[1] = byte_swap_32 (jks_sha1->der[1]);
  digest[2] = byte_swap_32 (jks_sha1->der[2]);
  digest[3] = byte_swap_32 (jks_sha1->der[3]);
  digest[4] = byte_swap_32 (jks_sha1->der[4]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const jks_sha1_t *jks_sha1 = (const jks_sha1_t *) esalt_buf;

  char enc_key[16384 + 1] = { 0 };

  u8 *ptr = (u8 *) jks_sha1->enc_key_buf;

  for (u32 i = 0, j = 0; i < jks_sha1->enc_key_len; i += 1, j += 2)
  {
    sprintf (enc_key + j, "%02X", ptr[i]);
  }

  u8 *der = (u8 *) jks_sha1->der;

  const int line_len = snprintf (line_buf, line_size, "%s*%08X%08X%08X%08X%08X*%08X%08X%08X%08X%08X*%s*%02X*%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X*%s",
    SIGNATURE_JKS_SHA1,
    byte_swap_32 (jks_sha1->checksum[0]),
    byte_swap_32 (jks_sha1->checksum[1]),
    byte_swap_32 (jks_sha1->checksum[2]),
    byte_swap_32 (jks_sha1->checksum[3]),
    byte_swap_32 (jks_sha1->checksum[4]),
    byte_swap_32 (jks_sha1->iv[0]),
    byte_swap_32 (jks_sha1->iv[1]),
    byte_swap_32 (jks_sha1->iv[2]),
    byte_swap_32 (jks_sha1->iv[3]),
    byte_swap_32 (jks_sha1->iv[4]),
    enc_key,
    der[ 0],
    der[ 6],
    der[ 7],
    der[ 8],
    der[ 9],
    der[10],
    der[11],
    der[12],
    der[13],
    der[14],
    der[15],
    der[16],
    der[17],
    der[18],
    der[19],
    (char *) jks_sha1->alias
  );

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
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
