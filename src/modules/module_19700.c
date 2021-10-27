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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Kerberos 5, etype 18, TGS-REP";
static const u64   KERN_TYPE      = 19700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5tgs$18$srv_http$synacktiv.local$16ce51f6eba20c8ee534ff8a$57d07b23643a516834795f0c010da8f549b7e65063e5a367ca9240f9b800adad1734df7e7d5dd8307e785de4f40aacf901df41aa6ce695f8619ec579c1fa57ee93661cf402aeef4e3a42e7e3477645d52c09dc72feade03512dffe0df517344f673c63532b790c242cc1d50f4b4b34976cb6e08ab325b3aefb2684262a5ee9faacb14d059754f50553be5bfa5c4c51e833ff2b6ac02c6e5d4c4eb193e27d7dde301bd1ddf480e5e282b8c27ef37b136c8f140b56de105b73adeb1de16232fa1ab5c9f6";
//static const char *ST_HASH        = "$krb5tgs$18$CLIENT1$$VALJEAN.LOCAL$*valjean.local/CLIENT1$*$89dcdcdf385512b99b21dfd7$1f3d349af8775987651876b9714f3a1ff4f7a18f4af2f544689201ea39ac3f905b886e14a73dfa5d1d903310abb633cbb13782cd3cf9761310af993ef86b0d88e32fdf0917e73503b3ab3d9c762a2e9d3f7607434f965e2750e5157e38333056b17d854460edb351e5b0f50c0becc3ceede14448b2af649175e0f53748349793540cfa97b3f184d69f36e61c334d2e8270c86a4f0daf532290826963075e859cdf535747aabdd2cf2f340575ebc3bdc8781d80c0d7178d99273562526fbaeec4866a6a61d1a5f9b3e480ba3c2d64af9839b7a5f611c3e80bc5cbde455df4ec667869e9bf3d3443737921b56a159d70e0a17c5ab8b8f70ef8920d31bd0f56bb9948eb40a1f08d6dfcb617ba5b539ce14ef3c4b37fdcbed6d5b079999dc9b51c7ae037f4116f96feb080b15a9e713402a0dfc46d151b478111940a595b685524f461fde02482d777dae07ae7417505f1d0aa4c1a1ccda3dd083b3c959105c23b061d2995b8c5e675d261cd11b5754264d283ab2d85c5cf5e4bdfaac39c46946a42830548f7815680e7f98f6596ebc0b0539dffe5d59a63590c1b3aeebf858e2b84e9eb4027e55da2726c2b3e94916e74b58bc269fed4b3e5da5476010f92970b93424290c5311303a6d9ea8fafea02331ab195df8c6c2a8221d2a893fa3573321700b130a3a300ebfa22b5e7996bd7ec7cdcae0a47165a43bc99087bed1a1e10477259206e7c7a4a13c8625cabe2baab7f2958783c1bd7f3ca516b5c67cdb62ec0f9519d4275b908bf7aeb2773d03262a4984e1a0e31756bea8b0610ec6690565d267b1a5bed3d9c51226ec2dd2ff8dd45a7c4e41637830640947b6fc23ef463c57b58e9fe30877e179742905e5a2e2daabc8a124356de818f55ef3957fe1d2f74095c2c040d145ef7d84a0df6ddc9eb6cb7e53b00ea21b84d43583bff3c9b3828e410fa8660dfc1e597e681ea94f49f9e4274d8e8661d33da26290c153ec6d5bca60d558727c96edb6ba6d4a9837f698dd748e3a1dc088f8827b3325abdbf9080c441967a6b8fd483500025119a53ed100084a8dd9816e3067b38ac9c98a2bd730048a401aaf45aeb2fe25c9e609830739a41300ed98dc28ab5249340f4e9d8c4d48f5ca0981e022705502798f39516c889ed74b8aac8d0438924b8a3b79ad6108ea551a6f9acdd56ad56383b8c0ba6ed7e3e06f3d09f8ee636cad9696d08282d64c42632f5ba6e066032b2484de8519ea5a27c5ab5eeace286cbce46b51ed68e6df845153a8be23d614a3351471c2e6e2b11f1"

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

typedef struct krb5tgs_18
{
  u32 user[128];
  u32 domain[128];
  u32 account_info[512];
  u32 account_info_len;

  u32 checksum[3];
  u32 edata2[5120];
  u32 edata2_len;

} krb5tgs_18_t;

typedef struct krb5tgs_18_tmp
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[16];
  u32 out[16];

} krb5tgs_18_tmp_t;

static const char *SIGNATURE_KRB5TGS = "$krb5tgs$18$";

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // AMD Radeon Pro W5700X Compute Engine; 1.2 (Apr 22 2021 21:54:44); 11.3.1; 20E241
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    return true;
  }

  return false;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (krb5tgs_18_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5tgs_18_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5tgs_18_t *krb5tgs = (krb5tgs_18_t *) esalt_buf;

  token_t token;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5TGS;

  token.len[0]  = 12;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  /**
   * $krb5tgs$18$*user*realm*$checksum$edata2
   * $krb5tgs$18$*user*realm*spn*$checksum$edata2
   */

  // assume no signature found
  if (line_len < 12) return (PARSER_SALT_LENGTH);

  char *spn_info_start = strchr ((const char *) line_buf + 12 + 1, '*');

  int is_spn_provided = 0;
  int is_machine_account = 0;

  const char *usr_start  = line_buf + strlen(SIGNATURE_KRB5TGS);
  char *usr_end = strchr ((const char *) usr_start, '$');

  if (usr_end == NULL)
  {
    return (PARSER_SEPARATOR_UNMATCHED);
  }

  if (*(usr_end+1) == '$'){
    is_machine_account = 1;
    usr_end++;
  }

  int usr_len = usr_end - usr_start;
  usr_len++; // we want the $ char included

  // assume $krb5tgs$17$user$realm$checksum$edata2
  if (spn_info_start == NULL)
  {
    token.token_cnt  = 5;

    token.len[1]     = usr_len;
    token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

    token.sep[2]     = '$';
    token.len_min[2] = 1;
    token.len_max[2] = 512;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[3]     = '$';
    // hmac-sha1 stripped to 12bytes
    token.len_min[3] = 24;
    token.len_max[3] = 24;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[4]     = '$';
    token.len_min[4] = 64;
    token.len_max[4] = 40960;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }
  // assume $krb5tgs$18$user$realm$*spn*$checksum$edata2
  else
  {
    char *spn_info_stop = strchr ((const char *) spn_info_start + 1, '*');

    if (spn_info_stop == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    spn_info_stop++; // we want the * $char included
    spn_info_stop++; // we want the $ char included

    const int spn_info_len = spn_info_stop - spn_info_start;

    token.token_cnt  = 6;

    token.len[1]     = usr_len;
    token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

    token.sep[2]     = '$';
    token.len_min[2] = 1;
    token.len_max[2] = 512;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.len[3]     = spn_info_len;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH;

    token.sep[4]     = '$';
    token.len_min[4] = 24;
    token.len_max[4] = 24;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[5]     = '$';
    token.len_min[5] = 64;
    token.len_max[5] = 40960;
    token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    is_spn_provided = 1;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos;
  const u8 *domain_pos;
  const u8 *checksum_pos;
  const u8 *data_pos;

  int user_len;
  int domain_len;
  int data_len;
  int account_info_len;

  token.len[1]--; //Removing trailing '$' due to TOKEN_ATTR_FIXED_LENGTH
  user_pos = token.buf[1];
  user_len = token.len[1];

  memcpy (krb5tgs->user, user_pos, user_len);

  domain_pos = token.buf[2];
  domain_len = token.len[2];

  memcpy (krb5tgs->domain, domain_pos, domain_len);

  checksum_pos = token.buf[3 + is_spn_provided];

  data_pos = token.buf[4 + is_spn_provided];
  data_len = token.len[4 + is_spn_provided];


  // domain must be uppercase

  u8 domain[128];

  memcpy (domain, domain_pos, domain_len);
  uppercase (domain, domain_len);

  if (is_machine_account){
    //Format = uppercase(domain) + "host" + lowercase(fqdn)(without $)
    account_info_len = snprintf ((char *)krb5tgs->account_info, 512, "%shost%.*s.%s",
    domain,
    user_len - 1, //remove $
    (char*)krb5tgs->user,
    domain);

    lowercase( (u8 *)(krb5tgs->account_info) + domain_len + 4, // domain_len + "host"
    account_info_len - domain_len + 4);
  } else {
    //Format = uppercase(domain) + lowercase(username)
    account_info_len = snprintf ((char *)krb5tgs->account_info, 512, "%s%s",
    domain,
    (char*)krb5tgs->user);
  }

  krb5tgs->account_info_len = account_info_len;

  // hmac-sha1 is reduced to 12 bytes
  krb5tgs->checksum[0] = byte_swap_32 (hex_to_u32 (checksum_pos +  0));
  krb5tgs->checksum[1] = byte_swap_32 (hex_to_u32 (checksum_pos +  8));
  krb5tgs->checksum[2] = byte_swap_32 (hex_to_u32 (checksum_pos + 16));

  u8 *edata_ptr = (u8 *) krb5tgs->edata2;

  for (int i = 0; i < data_len; i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *edata_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  krb5tgs->edata2_len = data_len / 2;

  salt->salt_buf[0] = krb5tgs->checksum[0];
  salt->salt_buf[1] = krb5tgs->checksum[1];
  salt->salt_buf[2] = krb5tgs->checksum[2];

  salt->salt_len = 12;

  salt->salt_iter = 4096 - 1;

  digest[0] = krb5tgs->checksum[0];
  digest[1] = krb5tgs->checksum[1];
  digest[2] = krb5tgs->checksum[2];
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5tgs_18_t *krb5tgs = (const krb5tgs_18_t *) esalt_buf;

  char data[5120 * 4 * 2] = { 0 };

  for (u32 i = 0, j = 0; i < krb5tgs->edata2_len; i += 1, j += 2)
  {
    u8 *ptr_edata2 = (u8 *) krb5tgs->edata2;

    sprintf (data + j, "%02x", ptr_edata2[i]);
  }

  const int line_len = snprintf (line_buf, line_size, "%s%s$%s$%08x%08x%08x$%s",
    SIGNATURE_KRB5TGS,
    (char *) krb5tgs->user,
    (char *) krb5tgs->domain,
    krb5tgs->checksum[0],
    krb5tgs->checksum[1],
    krb5tgs->checksum[2],
    data);

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
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
