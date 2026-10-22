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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "Kerberos 5, etype 3, AS-REP";
static const u64   KERN_TYPE      = 38600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$krb5asrep$3$user$realm$a2afda2f7f57adde2d3359f7427b0f7d$73fa8102fd97b2d911b0217306de09f2c3291373695cedb678c14d0d7a0e085754520ae4326daad0e40c26851d711e64a3cd4c83239e8b62aa99c718db38de8d01ccd3069efb1fc1c3cdfa75911a01944d920bd1cdf191469dc47b59140cb727e8732563eb9edaa1d33af55bf2586920050a69f092157a1c6f7cdc4a7e0860255073dc5afe1793c44fccc0377d4b0c701ff2cee8e8868f96ad1f730d51a0cc76aad0834e0a1d15e1e233b79222ca4a9f56041c53f6ba0ad679175119041b30a10762d11f7d1ceea17195dee83bdafe9024e288a2abb94b254a204cb9e2a53e647bb32d8bc89f5e340bb4f6ece082abc1";

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

static const char *SIGNATURE_KRB5ASREP = "$krb5asrep$3$";

// the kernel assembles the password and the salt in a 256 byte buffer, so the two limits have to
// stay within it together

#define MAX_SALT_LEN 128

#define MAX_PW_LEN    64

#define MAX_EDATA2_LEN 20480

// the principal and the realm are kept as the line carries them, to print it back, and salt_buf is
// what the key is derived from: the realm in upper case followed by the principal, as it is for the
// other Kerberos modes

typedef struct krb5asrep_3
{
  u32 user[MAX_SALT_LEN / 4];
  u32 realm[MAX_SALT_LEN / 4];
  u32 joined;

  u32 salt_buf[MAX_SALT_LEN / 4];
  u32 salt_len;

  u32 checksum[4];
  u32 edata2[MAX_EDATA2_LEN / 4];
  u32 edata2_len;

} krb5asrep_3_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (krb5asrep_3_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = MAX_PW_LEN;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  krb5asrep_3_t *krb5asrep = (krb5asrep_3_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  memset (krb5asrep, 0, sizeof (krb5asrep_3_t));

  /**
   * format 1: $krb5asrep$3$user@realm:checksum$edata2
   * format 2: $krb5asrep$3$user$realm$checksum$edata2
   *
   * The first is what GetNPUsers.py writes for every encryption type it has no branch of its own
   * for, the principal and the realm joined the way the reply carries them. The second is the one
   * 32100 and 32200 take, with the two apart.
   */

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_KRB5ASREP;

  const int sig_len = (int) strlen (SIGNATURE_KRB5ASREP);

  token.len[0]  = sig_len;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  if (line_len < (sig_len + 1)) return (PARSER_SALT_LENGTH);

  // hc_strchr_next, not strchr: the field ends where the line ends, not at a NUL the caller is not
  // required to put there

  const u8 *after_sig = (const u8 *) line_buf + sig_len;

  const int after_sig_len = line_len - sig_len;

  const u8 *colon  = hc_strchr_next (after_sig, after_sig_len, ':');
  const u8 *dollar = hc_strchr_next (after_sig, after_sig_len, '$');

  bool joined = false;

  if (colon != NULL)
  {
    if (dollar == NULL) joined = true;
    else if (colon < dollar) joined = true;
  }

  // the two shapes put the checksum and the data at different tokens

  u32 checksum_token = 0;
  u32 data_token     = 0;

  if (joined == true)
  {
    token.token_cnt  = 4;

    checksum_token   = 2;
    data_token       = 3;

    token.sep[1]     = ':';
    token.len_min[1] = 3;
    token.len_max[1] = MAX_SALT_LEN;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[2]     = '$';
    token.len[2]     = 32;
    token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[3]     = '$';
    token.len_min[3] = 64;
    token.len_max[3] = MAX_EDATA2_LEN * 2;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }
  else
  {
    token.token_cnt  = 5;

    checksum_token   = 3;
    data_token       = 4;

    token.sep[1]     = '$';
    token.len_min[1] = 1;
    token.len_max[1] = MAX_SALT_LEN - 1;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[2]     = '$';
    token.len_min[2] = 1;
    token.len_max[2] = MAX_SALT_LEN - 1;
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.sep[3]     = '$';
    token.len[3]     = 32;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[4]     = '$';
    token.len_min[4] = 64;
    token.len_max[4] = MAX_EDATA2_LEN * 2;
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos  = NULL;
  const u8 *realm_pos = NULL;

  int user_len  = 0;
  int realm_len = 0;

  if (joined == true)
  {
    // the realm is what follows the last '@', so a principal that carries one of its own keeps it

    const u8 *at = hc_strchr_last (token.buf[1], token.len[1], '@');

    if (at == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    user_pos  = token.buf[1];
    user_len  = (int) (at - token.buf[1]);

    realm_pos = at + 1;
    realm_len = token.len[1] - (user_len + 1);
  }
  else
  {
    user_pos  = token.buf[1];
    realm_pos = token.buf[2];

    user_len  = token.len[1];
    realm_len = token.len[2];
  }

  if ((user_len < 1) || (realm_len < 1)) return (PARSER_SALT_LENGTH);

  if ((user_len + realm_len) > MAX_SALT_LEN) return (PARSER_SALT_LENGTH);

  memcpy (krb5asrep->user,  user_pos,  user_len);
  memcpy (krb5asrep->realm, realm_pos, realm_len);

  // the Kerberos salt is the realm in upper case followed by the principal, with no separator

  u8 *salt_ptr = (u8 *) krb5asrep->salt_buf;

  memcpy (salt_ptr, realm_pos, realm_len);

  uppercase (salt_ptr, realm_len);

  memcpy (salt_ptr + realm_len, user_pos, user_len);

  krb5asrep->salt_len = realm_len + user_len;

  // the esalt was zeroed above, so only the joined shape has to say so

  if (joined == true) krb5asrep->joined = 1;

  // the line keeps the first two blocks of the ciphertext apart from the rest, the way the etype 23
  // and etype 3 TGS-REP formats do, although nothing here is a checksum of its own: the checksum of
  // a DES encryption type sits inside the plaintext

  const u8 *checksum_pos = token.buf[checksum_token];

  krb5asrep->checksum[0] = hex_to_u32 (checksum_pos +  0);
  krb5asrep->checksum[1] = hex_to_u32 (checksum_pos +  8);
  krb5asrep->checksum[2] = hex_to_u32 (checksum_pos + 16);
  krb5asrep->checksum[3] = hex_to_u32 (checksum_pos + 24);

  const u8 *data_pos = token.buf[data_token];

  const int data_len = token.len[data_token];

  // DES has an eight byte block and the plaintext is not padded any further, so the ciphertext the
  // two fields make up together is a whole number of blocks

  if ((data_len % 16) != 0) return (PARSER_TOKEN_LENGTH);

  u8 *edata_ptr = (u8 *) krb5asrep->edata2;

  for (int i = 0; i < data_len; i += 2)
  {
    const u8 p0 = data_pos[i + 0];
    const u8 p1 = data_pos[i + 1];

    *edata_ptr++ = hex_convert (p1) << 0
                 | hex_convert (p0) << 4;
  }

  krb5asrep->edata2_len = data_len / 2;

  salt->salt_buf[0] = krb5asrep->checksum[0];
  salt->salt_buf[1] = krb5asrep->checksum[1];
  salt->salt_buf[2] = krb5asrep->checksum[2];
  salt->salt_buf[3] = krb5asrep->checksum[3];

  salt->salt_len = 16;

  digest[0] = krb5asrep->checksum[0];
  digest[1] = krb5asrep->checksum[1];
  digest[2] = krb5asrep->checksum[2];
  digest[3] = krb5asrep->checksum[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const krb5asrep_3_t *krb5asrep = (const krb5asrep_3_t *) esalt_buf;

  char *data = (char *) hcmalloc ((MAX_EDATA2_LEN * 2) + 1);

  const u8 *ptr_edata2 = (const u8 *) krb5asrep->edata2;

  for (u32 i = 0, j = 0; i < krb5asrep->edata2_len; i += 1, j += 2)
  {
    snprintf (data + j, 3, "%02x", ptr_edata2[i]);
  }

  // the line goes back out in the shape it came in as

  int line_len;

  if (krb5asrep->joined == 1)
  {
    line_len = snprintf (line_buf, line_size, "%s%s@%s:%08x%08x%08x%08x$%s",
      SIGNATURE_KRB5ASREP,
      (const char *) krb5asrep->user,
      (const char *) krb5asrep->realm,
      byte_swap_32 (krb5asrep->checksum[0]),
      byte_swap_32 (krb5asrep->checksum[1]),
      byte_swap_32 (krb5asrep->checksum[2]),
      byte_swap_32 (krb5asrep->checksum[3]),
      data);
  }
  else
  {
    line_len = snprintf (line_buf, line_size, "%s%s$%s$%08x%08x%08x%08x$%s",
      SIGNATURE_KRB5ASREP,
      (const char *) krb5asrep->user,
      (const char *) krb5asrep->realm,
      byte_swap_32 (krb5asrep->checksum[0]),
      byte_swap_32 (krb5asrep->checksum[1]),
      byte_swap_32 (krb5asrep->checksum[2]),
      byte_swap_32 (krb5asrep->checksum[3]),
      data);
  }

  hcfree (data);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_benchmark_cost           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
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
  module_ctx->module_hash_hints               = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hash_recipe              = MODULE_DEFAULT;
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
  module_ctx->module_kern_bits                = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_length_sort              = MODULE_DEFAULT;
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
  module_ctx->module_register_options         = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
