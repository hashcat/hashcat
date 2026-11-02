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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 3;
static const u32   DGST_POS1      = 7;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 6;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "PDF 1.7 Level 3 (Acrobat 9)";
static const char *HASH_RECIPE    = "sha256(pass . salt)";
static const u64   KERN_TYPE      = 1410;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_APPENDED_SALT
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_ST_ADD80
                                  | OPTS_TYPE_ST_ADDBITS15
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$pdf$5*5*256*-1028*1*16*28562274676426582441147358074521*127*a3aab04cff2c536118870976d768f1fdd445754d6b2dd81fba10bb6e742acd7f2856227467642658244114735807452100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return USAGE_NOTICE_PDF;
}

typedef struct pdf
{
  int V;
  int R;
  int P;

  int enc_md;

  u32 id_buf[8];
  u32 u_buf[32];
  u32 o_buf[32];

  int id_len;
  int o_len;
  int u_len;

  u32 rc4key[2];
  u32 rc4data[2];

} pdf_t;

static const char *SIGNATURE_PDF  = "$pdf$";
static const int   ROUNDS_PDF17L8 = 64;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pdf_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // https://www.pdflib.com/knowledge-base/pdf-password-security/encryption/

  const u32 pw_max = (optimized_kernel == false) ? 127 : hashconfig->pw_max;

  return pw_max;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Only the first word changes in the loop of the optimized mask kernel. With plain rotates, the
  // compiler computes the message schedule terms that do not depend on it once, before the loop.
  // The other kernels gain nothing from plain rotates or run slower with them.

  if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) return jit_build_options;

  if (user_options_extra->attack_kern != ATTACK_KERN_BF) return jit_build_options;

  hc_asprintf (&jit_build_options, "-D NO_FUNNELSHIFT");

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  pdf_t *pdf = (pdf_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 16;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PDF;

  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 1;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len[3]     = 3;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 11;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[5]     = '*';
  token.len[5]     = 1;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '*';
  token.len_min[6] = 1;
  token.len_max[6] = 4;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[7]     = '*';
  token.len_min[7] = 0;
  token.len_max[7] = 1024;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[8]     = '*';
  token.len_min[8] = 1;
  token.len_max[8] = 4;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[9]     = '*';
  token.len_min[9] = 0;
  token.len_max[9] = 1024;
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[10]     = '*';
  token.len_min[10] = 1;
  token.len_max[10] = 4;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[11]     = '*';
  token.len_min[11] = 0;
  token.len_max[11] = 1024;
  token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.sep[12]     = '*';
  token.len_min[12] = 1;
  token.len_max[12] = 4;
  token.attr[12]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[13]     = '*';
  token.len_min[13] = 0;
  token.len_max[13] = 1024;
  token.attr[13]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.sep[14]     = '*';
  token.len_min[14] = 1;
  token.len_max[14] = 4;
  token.attr[14]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[15]     = '*';
  token.len_min[15] = 0;
  token.len_max[15] = 1024;
  token.attr[15]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *V_pos      = token.buf[1];
  const u8 *R_pos      = token.buf[2];
  const u8 *bits_pos   = token.buf[3];
  const u8 *enc_md_pos = token.buf[5];
  const u8 *u_len_pos  = token.buf[8];
  const u8 *u_buf_pos  = token.buf[9];
  const int u_buf_len  = token.len[9];

  // validate data

  const int V = strtol ((const char *) V_pos, NULL, 10);
  const int R = strtol ((const char *) R_pos, NULL, 10);

  int vr_ok = 0;

  if ((V == 5) && (R == 5)) vr_ok = 1;
  if ((V == 5) && (R == 6)) vr_ok = 1;

  if (vr_ok == 0) return (PARSER_SALT_VALUE);

  const int bits = strtol ((const char *) bits_pos, NULL, 10);

  if (bits != 256) return (PARSER_SALT_VALUE);

  int enc_md = strtol ((const char *) enc_md_pos, NULL, 10);

  if ((enc_md != 0) && (enc_md != 1)) return (PARSER_SALT_VALUE);

  const u32 u_len  = hc_strtoul ((const char *) u_len_pos,  NULL, 10);

  // copy data to esalt

  if (u_len < 40) return (PARSER_SALT_VALUE);

  // 80 characters are validated here and read below, so the field has to hold 80. u_len is the
  // length the line declares for itself, which is not the length of the field the tokenizer
  // measured, and the token is allowed to be shorter than that.

  if (u_buf_len < 80) return (PARSER_SALT_LENGTH);

  if (is_valid_hex_string (u_buf_pos, 80) == false) return (PARSER_SALT_ENCODING);

  for (int i = 0, j = 0; i < 8 + 2; i += 1, j += 8)
  {
    pdf->u_buf[i] = hex_to_u32 (&u_buf_pos[j]);
  }

  salt->salt_buf[0] = pdf->u_buf[8];
  salt->salt_buf[1] = pdf->u_buf[9];

  salt->salt_len  = 8;
  salt->salt_iter = ROUNDS_PDF17L8;

  digest[0] = byte_swap_32 (pdf->u_buf[0]);
  digest[1] = byte_swap_32 (pdf->u_buf[1]);
  digest[2] = byte_swap_32 (pdf->u_buf[2]);
  digest[3] = byte_swap_32 (pdf->u_buf[3]);
  digest[4] = byte_swap_32 (pdf->u_buf[4]);
  digest[5] = byte_swap_32 (pdf->u_buf[5]);
  digest[6] = byte_swap_32 (pdf->u_buf[6]);
  digest[7] = byte_swap_32 (pdf->u_buf[7]);

  // extra

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= SHA256M_A;
    digest[1] -= SHA256M_B;
    digest[2] -= SHA256M_C;
    digest[3] -= SHA256M_D;
    digest[4] -= SHA256M_E;
    digest[5] -= SHA256M_F;
    digest[6] -= SHA256M_G;
    digest[7] -= SHA256M_H;
  }

  salt->salt_buf[2] = 0x80;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const int line_len = snprintf (line_buf, line_size, "%s", hash_info->orighash);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_usage_notice             = module_usage_notice;
}
