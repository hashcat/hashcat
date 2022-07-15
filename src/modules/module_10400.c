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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "PDF 1.1 - 1.3 (Acrobat 2 - 4)";
static const u64   KERN_TYPE      = 10400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000";

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

typedef struct pdf
{
  int  V;
  int  R;
  int  P;

  int  enc_md;

  u32  id_buf[8];
  u32  u_buf[32];
  u32  o_buf[32];

  int  id_len;
  int  o_len;
  int  u_len;

  u32  rc4key[2];
  u32  rc4data[2];

} pdf_t;

static const char *SIGNATURE_PDF = "$pdf$";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  u32 native_threads = 0;

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    native_threads = 1;
  }
  else if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
  {
    #if defined (__APPLE__)

    native_threads = 32;

    #else

    if (device_param->device_local_mem_size < 49152)
    {
      native_threads = MIN (device_param->kernel_preferred_wgs_multiple, 32); // We can't just set 32, because Intel GPU need 8
    }
    else
    {
      native_threads = device_param->kernel_preferred_wgs_multiple;
    }

    #endif
  }

  hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u -D _unroll", native_threads);

  return jit_build_options;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pdf_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 32; // https://www.pdflib.com/knowledge-base/pdf-password-security/encryption/

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  pdf_t *pdf = (pdf_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 12;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PDF;

  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[3] = 2;
  token.len_max[3] = 2;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4] = 1;
  token.len_max[4] = 6;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[5] = 1;
  token.len_max[5] = 1;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[6] = 2;
  token.len_max[6] = 2;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[7] = 32;
  token.len_max[7] = 32;
  token.sep[7]     = '*';
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[8] = 2;
  token.len_max[8] = 2;
  token.sep[8]     = '*';
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[9] = 64;
  token.len_max[9] = 64;
  token.sep[9]     = '*';
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[10] = 2;
  token.len_max[10] = 2;
  token.sep[10]     = '*';
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[11] = 64;
  token.len_max[11] = 64;
  token.sep[11]     = '*';
  token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *V_pos      = token.buf[1];
  const u8 *R_pos      = token.buf[2];
  const u8 *bits_pos   = token.buf[3];
  const u8 *P_pos      = token.buf[4];
  const u8 *enc_md_pos = token.buf[5];
  const u8 *id_len_pos = token.buf[6];
  const u8 *id_buf_pos = token.buf[7];
  const u8 *u_len_pos  = token.buf[8];
  const u8 *u_buf_pos  = token.buf[9];
  const u8 *o_len_pos  = token.buf[10];
  const u8 *o_buf_pos  = token.buf[11];

  // validate data

  const int V = strtol ((const char *) V_pos, NULL, 10);
  const int R = strtol ((const char *) R_pos, NULL, 10);
  const int P = strtol ((const char *) P_pos, NULL, 10);

  if (V != 1) return (PARSER_SALT_VALUE);
  if (R != 2) return (PARSER_SALT_VALUE);

  const int enc_md = strtol ((const char *) enc_md_pos, NULL, 10);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const int id_len = strtol ((const char *) id_len_pos, NULL, 10);
  const int u_len  = strtol ((const char *) u_len_pos,  NULL, 10);
  const int o_len  = strtol ((const char *) o_len_pos,  NULL, 10);

  if (id_len != 16) return (PARSER_SALT_VALUE);
  if (u_len  != 32) return (PARSER_SALT_VALUE);
  if (o_len  != 32) return (PARSER_SALT_VALUE);

  const int bits = strtol ((const char *) bits_pos, NULL, 10);

  if (bits != 40) return (PARSER_SALT_VALUE);

  // copy data to esalt

  pdf->V = V;
  pdf->R = R;
  pdf->P = P;

  pdf->enc_md = enc_md;

  pdf->id_buf[0] = hex_to_u32 (id_buf_pos +  0);
  pdf->id_buf[1] = hex_to_u32 (id_buf_pos +  8);
  pdf->id_buf[2] = hex_to_u32 (id_buf_pos + 16);
  pdf->id_buf[3] = hex_to_u32 (id_buf_pos + 24);
  pdf->id_len    = id_len;

  pdf->u_buf[0]  = hex_to_u32 (u_buf_pos +  0);
  pdf->u_buf[1]  = hex_to_u32 (u_buf_pos +  8);
  pdf->u_buf[2]  = hex_to_u32 (u_buf_pos + 16);
  pdf->u_buf[3]  = hex_to_u32 (u_buf_pos + 24);
  pdf->u_buf[4]  = hex_to_u32 (u_buf_pos + 32);
  pdf->u_buf[5]  = hex_to_u32 (u_buf_pos + 40);
  pdf->u_buf[6]  = hex_to_u32 (u_buf_pos + 48);
  pdf->u_buf[7]  = hex_to_u32 (u_buf_pos + 56);
  pdf->u_len     = u_len;

  pdf->o_buf[0]  = hex_to_u32 (o_buf_pos +  0);
  pdf->o_buf[1]  = hex_to_u32 (o_buf_pos +  8);
  pdf->o_buf[2]  = hex_to_u32 (o_buf_pos + 16);
  pdf->o_buf[3]  = hex_to_u32 (o_buf_pos + 24);
  pdf->o_buf[4]  = hex_to_u32 (o_buf_pos + 32);
  pdf->o_buf[5]  = hex_to_u32 (o_buf_pos + 40);
  pdf->o_buf[6]  = hex_to_u32 (o_buf_pos + 48);
  pdf->o_buf[7]  = hex_to_u32 (o_buf_pos + 56);
  pdf->o_len     = o_len;

  // we use ID for salt, maybe needs to change, we will see...

  salt->salt_buf[0] = pdf->id_buf[0];
  salt->salt_buf[1] = pdf->id_buf[1];
  salt->salt_buf[2] = pdf->id_buf[2];
  salt->salt_buf[3] = pdf->id_buf[3];
  salt->salt_len    = pdf->id_len;

  digest[0] = pdf->u_buf[0];
  digest[1] = pdf->u_buf[1];
  digest[2] = pdf->u_buf[2];
  digest[3] = pdf->u_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const pdf_t *pdf = (const pdf_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "$pdf$%d*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x%08x%08x%08x%08x",
    pdf->V,
    pdf->R,
    40,
    pdf->P,
    pdf->enc_md,
    pdf->id_len,
    byte_swap_32 (pdf->id_buf[0]),
    byte_swap_32 (pdf->id_buf[1]),
    byte_swap_32 (pdf->id_buf[2]),
    byte_swap_32 (pdf->id_buf[3]),
    pdf->u_len,
    byte_swap_32 (pdf->u_buf[0]),
    byte_swap_32 (pdf->u_buf[1]),
    byte_swap_32 (pdf->u_buf[2]),
    byte_swap_32 (pdf->u_buf[3]),
    byte_swap_32 (pdf->u_buf[4]),
    byte_swap_32 (pdf->u_buf[5]),
    byte_swap_32 (pdf->u_buf[6]),
    byte_swap_32 (pdf->u_buf[7]),
    pdf->o_len,
    byte_swap_32 (pdf->o_buf[0]),
    byte_swap_32 (pdf->o_buf[1]),
    byte_swap_32 (pdf->o_buf[2]),
    byte_swap_32 (pdf->o_buf[3]),
    byte_swap_32 (pdf->o_buf[4]),
    byte_swap_32 (pdf->o_buf[5]),
    byte_swap_32 (pdf->o_buf[6]),
    byte_swap_32 (pdf->o_buf[7])
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
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
