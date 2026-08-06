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
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PRIVATE_KEY;
static const char *HASH_NAME      = "OpenSSH Private Keys (bcrypt/AES-256-CTR, OpenSSH-Key-V1)";
static const u64   KERN_TYPE      = 22961;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sshng$6$16$c212cbfe1cfe1befb3f18370ecede7f0$274$6f70656e7373682d6b65792d7631000000000a6165733235362d637472000000066263727970740000001800000010c212cbfe1cfe1befb3f18370ecede7f00000001000000001000000330000000b7373682d6564323535313900000020039bf13c89595b3e7f2608b71344e16f7f8222024692530c9061393e259282ce0000009004f1ae87b3ab0e20c665d5617030dea1fb282115e655ea64e758a7ab85ab0043534bd45a890eed06d0e1903dd91308bac8f042f56cf05fe0359cbf3676baefc8a0c7ec93f34351e21b125a1c8e50176deba09b2007906ac14bf3948cfcb03b4a2de1d66d48a95035f20959ef72cd261dcb763bf4234eefcb9ee80e9ea36b903b9701a961e9a31d08f0927fee95fdf342$16$130";

typedef struct sshng_openssh
{
  u32 data_buf[16384];
  int data_len;

  u32 salt_buf[4];
  u32 ct_buf[4];

  u32 rounds;
  u32 cipher_offset;

  int cipher;

} sshng_openssh_t;

static const char *SIGNATURE_SSHNG = "$sshng$";

u32 module_kernel_threads_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 1;
}

u32 module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 1;
}

static u32 read_u32_be (const u8 *buf)
{
  return ((u32) buf[0] << 24)
       | ((u32) buf[1] << 16)
       | ((u32) buf[2] <<  8)
       | ((u32) buf[3] <<  0);
}

static bool read_ssh_string (const u8 *buf, const int buf_len, int *offset, const u8 **ptr, int *len)
{
  if (*offset + 4 > buf_len) return false;

  const u32 str_len = read_u32_be (buf + *offset);

  *offset += 4;

  if (*offset + (int) str_len > buf_len) return false;

  *ptr = buf + *offset;
  *len = (int) str_len;

  *offset += (int) str_len;

  return true;
}

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

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (sshng_openssh_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  sshng_openssh_t *esalt = (sshng_openssh_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SSHNG;

  token.len[0]  = 7;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]  = '$';
  token.len[1]  = 1;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]  = '$';
  token.len[3]  = 32;
  token.attr[3] = TOKEN_ATTR_FIXED_LENGTH
                | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 8;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 64;
  token.len_max[5] = (int) (sizeof (esalt->data_buf) * 2);
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len_min[6] = 1;
  token.len_max[6] = 10;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[7]     = '$';
  token.len_min[7] = 1;
  token.len_max[7] = 10;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return rc_tokenizer;

  const int cipher = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (cipher != 6) return PARSER_CIPHER;

  esalt->cipher = cipher;

  const int salt_len_verify = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (salt_len_verify != 16) return PARSER_SALT_LENGTH;

  const u8 *salt_pos = token.buf[3];
  u8 salt_bytes[16];

  esalt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  esalt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  esalt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  esalt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  hex_decode (salt_pos, 32, salt_bytes);

  salt->salt_buf[0] = esalt->salt_buf[0];
  salt->salt_buf[1] = esalt->salt_buf[1];
  salt->salt_buf[2] = esalt->salt_buf[2];
  salt->salt_buf[3] = esalt->salt_buf[3];
  salt->salt_len    = 16;

  const int data_len_verify = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  esalt->data_len = hex_decode (token.buf[5], token.len[5], (u8 *) esalt->data_buf);

  if (data_len_verify != esalt->data_len) return PARSER_HASH_LENGTH;

  const u8 *data = (const u8 *) esalt->data_buf;

  static const u8 openssh_magic[] = "openssh-key-v1";

  if (esalt->data_len < 15) return PARSER_HASH_LENGTH;
  if (memcmp (data, openssh_magic, 14) != 0) return PARSER_HASH_VALUE;
  if (data[14] != 0) return PARSER_HASH_VALUE;

  int offset = 15;

  const u8 *ciphername = NULL;
  const u8 *kdfname    = NULL;
  const u8 *kdfopts    = NULL;

  int ciphername_len = 0;
  int kdfname_len    = 0;
  int kdfopts_len    = 0;

  if (read_ssh_string (data, esalt->data_len, &offset, &ciphername, &ciphername_len) == false) return PARSER_HASH_VALUE;
  if (read_ssh_string (data, esalt->data_len, &offset, &kdfname,    &kdfname_len)    == false) return PARSER_HASH_VALUE;
  if (read_ssh_string (data, esalt->data_len, &offset, &kdfopts,    &kdfopts_len)    == false) return PARSER_HASH_VALUE;

  if ((ciphername_len != 10) || (memcmp (ciphername, "aes256-ctr", 10) != 0)) return PARSER_CIPHER;
  if ((kdfname_len    !=  6) || (memcmp (kdfname,    "bcrypt",     6) != 0)) return PARSER_SALT_VALUE;

  if (kdfopts_len != 24) return PARSER_SALT_LENGTH;

  const u32 kdf_salt_len = read_u32_be (kdfopts + 0);

  if (kdf_salt_len != 16) return PARSER_SALT_LENGTH;
  if (memcmp (kdfopts + 4, salt_bytes, 16) != 0) return PARSER_SALT_VALUE;

  const u32 rounds = read_u32_be (kdfopts + 20);

  const int rounds_verify = hc_strtoul ((const char *) token.buf[6], NULL, 10);

  if (rounds == 0) return PARSER_SALT_ITERATION;
  if ((u32) rounds_verify != rounds) return PARSER_SALT_ITERATION;

  esalt->rounds = rounds;

  if (offset + 4 > esalt->data_len) return PARSER_HASH_LENGTH;

  const u32 nr_keys = read_u32_be (data + offset);

  offset += 4;

  if (nr_keys < 1) return PARSER_HASH_VALUE;

  for (u32 i = 0; i < nr_keys; i++)
  {
    const u8 *pubkey = NULL;
    int pubkey_len = 0;

    if (read_ssh_string (data, esalt->data_len, &offset, &pubkey, &pubkey_len) == false) return PARSER_HASH_VALUE;
  }

  if (offset + 4 > esalt->data_len) return PARSER_HASH_LENGTH;

  const u32 priv_len = read_u32_be (data + offset);

  offset += 4;

  if (priv_len < 16) return PARSER_HASH_LENGTH;
  if ((priv_len & 15) != 0) return PARSER_HASH_LENGTH;
  if (offset + (int) priv_len != esalt->data_len) return PARSER_HASH_LENGTH;

  const int cipher_offset_verify = hc_strtoul ((const char *) token.buf[7], NULL, 10);

  if (cipher_offset_verify != offset) return PARSER_HASH_VALUE;

  esalt->cipher_offset = (u32) offset;

  esalt->ct_buf[0] = read_u32_be (data + offset +  0);
  esalt->ct_buf[1] = read_u32_be (data + offset +  4);
  esalt->ct_buf[2] = read_u32_be (data + offset +  8);
  esalt->ct_buf[3] = read_u32_be (data + offset + 12);

  digest[0] = esalt->ct_buf[0];
  digest[1] = esalt->ct_buf[1];
  digest[2] = esalt->ct_buf[2];
  digest[3] = esalt->ct_buf[3];

  return PARSER_OK;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const sshng_openssh_t *esalt = (const sshng_openssh_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf ((char *) out_buf, line_size, "%s%d$16$%08x%08x%08x%08x$%d$",
    SIGNATURE_SSHNG,
    esalt->cipher,
    byte_swap_32 (esalt->salt_buf[0]),
    byte_swap_32 (esalt->salt_buf[1]),
    byte_swap_32 (esalt->salt_buf[2]),
    byte_swap_32 (esalt->salt_buf[3]),
    esalt->data_len);

  out_len += hex_encode ((const u8 *) esalt->data_buf, esalt->data_len, out_buf + out_len);

  out_len += snprintf ((char *) out_buf + out_len, line_size - out_len, "$%u$%u",
    esalt->rounds,
    esalt->cipher_offset);

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
  module_ctx->module_kernel_threads_max       = module_kernel_threads_max;
  module_ctx->module_kernel_threads_min       = module_kernel_threads_min;
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
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
