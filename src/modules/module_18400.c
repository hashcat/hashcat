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
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "Open Document Format (ODF) 1.2 (SHA-256, AES)";
static const u64   KERN_TYPE      = 18400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$odf$*1*1*100000*32*751854d8b90731ce0579f96bea6f0d4ac2fb2f546b31f1b6af9a5f66952a0bf4*16*2185a966155baa9e2fb597298febecbc*16*c18eaae34bcbbe9119be017fe5f8b52d*0*051e0f1ce0e866f2b771029e03a6c7119aad132af54c4e45824f16f61f357a40407ab82744fe6370c7b2346075fcd4c2e58ab244411b3ab1d532a46e2321599ef13c3d3472fc2f14d480d8c33215e473da67f90540279d3ef1f62dde314fa222796046e496c951235ddf88aa754620b7810d22ebc8835c90dce9276946f52b8ea7d95d2f86e4cc725366a8b3edacc2ce88518e535991a5f84d5ea8795dc02bfb731b5f202ecaf7d4b245d928c4248709fcdf3fba2acf1a08be0c1eee7dbeda07e8c3a6983565635e99952b8ad79d31c965f245ae90b5cc3dba6387898c66fa35cad9ac9595c41b62e68efcdd73185b38e220cf004269b77ec6974474b03b7569afc3b503a2bf8b2d035756f3f4cb880d9ba815e5c944508a0bde214076c35bf0e0814a96d21ccaa744c9056948ed935209f5c7933841d2ede3d28dd84da89d477d4a0041ce6d8ddab891d929340db6daa921d69b46fd5aee306d0bcef88c38acbb495d0466df7e2f744e3d10201081215c02db5dd479a4cda15a3338969c7baec9d3d2c378a8dd30449319b149dc3b4e7f00996a59fcb5f243d0df2cbaf749241033f7865aefa960adfeb8ebf205b270f90b1f82c34f80d5a8a0db7aec89972a32f5daa2a73c5895d1fced01b3ab8e576bd2630eff01cad97781f4966d4b528e1b15f011f28ae907a352073c96b203adc7742d2b79b2e2f440b17e7856ae119e08d15d8bdf951f6d4a3f9b516da2d9a8f9dd93488f8e0119f3da19138ab787f0d7098a652cccd914aa0ff81d375bd6a5a165acc936f591639059287975cfc3ca4342e5f9501b3249a76d14e56d6d56b319e036bc0449ac7b5afa24ffbea11babed8183edf8d4fdca1c3f0d23bfd4a02797627d556634f1a9304e03737604bd86f6b5a26aa687d6df73383e0f7dfe62a131e8dbb8c3f4f13d24857dd29d76984eac6c45df7428fc79323ffa1f4e7962d705df74320141ed1f16d1ad483b872168df60315ffadbfa1b7f4afaed8a0017421bf5e05348cb5c707a5e852d6fee6077ec1c33bc707bcd97b7701ee05a03d6fa78b0d31c8c97ea16e0edf434961bd5cc7cbb7eb2553730f0405c9bd21cee09b3f7c1bc57779fdfc15f3935985737a1b522004c4436b631a39a66e8577a03f5020e6aa41952c0662c8c57f66caa483b47af38b8cb5d457245fd3241749e17433e6f929233e8862d7c584111b1991b2d6e94278e7e6e1908cee5a83d94c78b75a84a695d25aeb9fdde72174fe6dd75e8d406671f44892a385a4a1e249f61ebc993e985607423a0a5742e668d52c1ebf5cecae7c2b7908f4627b92ec49354a9ccff8cb5763ad074a00e65a485a41bf4c25ce7e6fae49358a58547b1c0ca79713e297310c0a367c3de196f1dd685ca4be643bdf1e4f6b034211d020557e37a3b6614d061010b4a3416b6b279728c245d3322";

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

typedef struct odf12_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} odf12_tmp_t;

typedef struct odf12
{
  u32 iterations;
  u32 iv[4];
  u32 checksum[8];
  u32 encrypted_data[256];

} odf12_t;

static const char *SIGNATURE_ODF = "$odf$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (odf12_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (odf12_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is selected
  // IOW, even in optimized kernel mode it support length 256

  const u32 pw_max = PW_MAX;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  odf12_t *odf12 = (odf12_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt = 12;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ODF;

  token.len_min[0] = 5;
  token.len_max[0] = 5;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
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

  token.len_min[3] = 4;
  token.len_max[3] = 6;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4] = 2;
  token.len_max[4] = 2;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[5] = 64;
  token.len_max[5] = 64;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

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

  token.len_min[9] = 32;
  token.len_max[9] = 32;
  token.sep[9]     = '*';
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[10] = 1;
  token.len_max[10] = 1;
  token.sep[10]     = '*';
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.len[11]     = 2048;
  token.attr[11]    = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *checksum         = token.buf[5];
  const u8 *iv               = token.buf[7];
  const u8 *salt_buf         = token.buf[9];
  const u8 *encrypted_data   = token.buf[11];

  const u32 cipher_type   = strtol ((const char *) token.buf[1],  NULL, 10);
  const u32 checksum_type = strtol ((const char *) token.buf[2],  NULL, 10);
  const u32 iterations    = strtol ((const char *) token.buf[3],  NULL, 10);
  const u32 key_size      = strtol ((const char *) token.buf[4],  NULL, 10);
  const u32 iv_len        = strtol ((const char *) token.buf[6],  NULL, 10);
  const u32 salt_len      = strtol ((const char *) token.buf[8],  NULL, 10);
  const u32 unused        = strtol ((const char *) token.buf[10], NULL, 10);

  if (cipher_type   !=  1) return (PARSER_SALT_VALUE);
  if (checksum_type !=  1) return (PARSER_SALT_VALUE);
  if (key_size      != 32) return (PARSER_SALT_VALUE);
  if (iv_len        != 16) return (PARSER_SALT_VALUE);
  if (salt_len      != 16) return (PARSER_SALT_VALUE);
  if (unused        !=  0) return (PARSER_SALT_VALUE);

  // esalt

  odf12->iterations = iterations;

  odf12->checksum[0] = hex_to_u32 (&checksum[ 0]);
  odf12->checksum[1] = hex_to_u32 (&checksum[ 8]);
  odf12->checksum[2] = hex_to_u32 (&checksum[16]);
  odf12->checksum[3] = hex_to_u32 (&checksum[24]);
  odf12->checksum[4] = hex_to_u32 (&checksum[32]);
  odf12->checksum[5] = hex_to_u32 (&checksum[40]);
  odf12->checksum[6] = hex_to_u32 (&checksum[48]);
  odf12->checksum[7] = hex_to_u32 (&checksum[56]);

  odf12->iv[0] = hex_to_u32 (&iv[0]);
  odf12->iv[1] = hex_to_u32 (&iv[8]);
  odf12->iv[2] = hex_to_u32 (&iv[16]);
  odf12->iv[3] = hex_to_u32 (&iv[24]);

  for (int i = 0, j = 0; i < 256; i += 1, j += 8)
  {
    odf12->encrypted_data[i] = hex_to_u32 (&encrypted_data[j]);
  }

  // salt

  salt->salt_len = salt_len;

  salt->salt_iter = iterations - 1;

  salt->salt_buf[0] = hex_to_u32 (&salt_buf[ 0]);
  salt->salt_buf[1] = hex_to_u32 (&salt_buf[ 8]);
  salt->salt_buf[2] = hex_to_u32 (&salt_buf[16]);
  salt->salt_buf[3] = hex_to_u32 (&salt_buf[24]);

  /**
   * digest
   */

  digest[0] = odf12->checksum[0];
  digest[1] = odf12->checksum[1];
  digest[2] = odf12->checksum[2];
  digest[3] = odf12->checksum[3];
  digest[4] = odf12->checksum[4];
  digest[5] = odf12->checksum[5];
  digest[6] = odf12->checksum[6];
  digest[7] = odf12->checksum[7];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const odf12_t *odf12 = (const odf12_t *) esalt_buf;

  int out_len = snprintf (line_buf, line_size, "%s*1*1*%u*32*%08x%08x%08x%08x%08x%08x%08x%08x*16*%08x%08x%08x%08x*16*%08x%08x%08x%08x*0*",
    SIGNATURE_ODF,
    odf12->iterations,
    byte_swap_32 (odf12->checksum[0]),
    byte_swap_32 (odf12->checksum[1]),
    byte_swap_32 (odf12->checksum[2]),
    byte_swap_32 (odf12->checksum[3]),
    byte_swap_32 (odf12->checksum[4]),
    byte_swap_32 (odf12->checksum[5]),
    byte_swap_32 (odf12->checksum[6]),
    byte_swap_32 (odf12->checksum[7]),
    byte_swap_32 (odf12->iv[0]),
    byte_swap_32 (odf12->iv[1]),
    byte_swap_32 (odf12->iv[2]),
    byte_swap_32 (odf12->iv[3]),
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]));

  u8 *out_buf = (u8 *) line_buf;

  for (int i = 0; i < 256; i++)
  {
    u32_to_hex (odf12->encrypted_data[i], out_buf + out_len); out_len += 8;
  }

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
