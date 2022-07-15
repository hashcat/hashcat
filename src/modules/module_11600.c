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
#include "emu_inc_cipher_aes.h"
#include "cpu_crc32.h"
#include "ext_lzma.h"
#include "zlib.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "7-Zip";
static const u64   KERN_TYPE      = 11600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG
                                  | OPTS_TYPE_HOOK23;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$7z$0$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269";

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

typedef struct seven_zip_tmp
{
  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  int len;

} seven_zip_tmp_t;

typedef struct seven_zip_hook
{
  u32 ukey[8];

  u32 hook_success;

} seven_zip_hook_t;

typedef struct seven_zip_hook_salt
{
  u32 iv_buf[4];
  u32 iv_len;

  u32 salt_buf[4];
  u32 salt_len;

  u32 crc;
  u32 crc_len;

  u8  data_type;

  u32 data_buf[0x200000];
  u32 data_len;

  u32 unpack_size;

  char coder_attributes[5 + 1];
  u8   coder_attributes_len;

  int aes_len; // pre-computed length of the maximal (subset of) data we need for AES-CBC

} seven_zip_hook_salt_t;

typedef struct seven_zip_hook_extra
{
  void **aes;
  void **unp;

} seven_zip_hook_extra_t;

static const char *SIGNATURE_SEVEN_ZIP = "$7z$";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // HIP
  if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // ROCM
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == true))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  return jit_build_options;
}

bool module_hook_extra_param_init (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  seven_zip_hook_extra_t *seven_zip_hook_extra = (seven_zip_hook_extra_t *) hook_extra_param;

  #define AESSIZE 8 * 1024 * 1024
  #define UNPSIZE 9999999

  seven_zip_hook_extra->aes = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));

  if (seven_zip_hook_extra->aes == NULL) return false;

  seven_zip_hook_extra->unp = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));

  if (seven_zip_hook_extra->unp == NULL) return false;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    seven_zip_hook_extra->aes[backend_devices_idx] = hcmalloc (AESSIZE);

    if (seven_zip_hook_extra->aes[backend_devices_idx] == NULL) return false;

    seven_zip_hook_extra->unp[backend_devices_idx] = hcmalloc (UNPSIZE);

    if (seven_zip_hook_extra->unp[backend_devices_idx] == NULL) return false;
  }

  return true;
}

bool module_hook_extra_param_term (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  seven_zip_hook_extra_t *seven_zip_hook_extra = (seven_zip_hook_extra_t *) hook_extra_param;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    hcfree (seven_zip_hook_extra->aes[backend_devices_idx]);
    hcfree (seven_zip_hook_extra->unp[backend_devices_idx]);
  }

  hcfree (seven_zip_hook_extra->aes);
  hcfree (seven_zip_hook_extra->unp);

  return true;
}

void module_hook23 (hc_device_param_t *device_param, MAYBE_UNUSED const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  seven_zip_hook_t *hook_items = (seven_zip_hook_t *) device_param->hooks_buf;

  seven_zip_hook_salt_t *seven_zips = (seven_zip_hook_salt_t *) hook_salts_buf;
  seven_zip_hook_salt_t *seven_zip  = &seven_zips[salt_pos];

  seven_zip_hook_extra_t *seven_zip_hook_extra = (seven_zip_hook_extra_t *) hook_extra_param;

  u8   data_type   = seven_zip->data_type;
  u32 *data_buf    = seven_zip->data_buf;
  u32  unpack_size = seven_zip->unpack_size;

  // this hook data needs to be updated (the "hook_success" variable):

  seven_zip_hook_t *hook_item = &hook_items[pw_pos];

  const u32 *ukey = (const u32 *) hook_item->ukey;

  // init AES

  AES_KEY aes_key;

  memset (&aes_key, 0, sizeof (aes_key));

  aes256_set_decrypt_key (aes_key.rdk, ukey, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);

  int aes_len = seven_zip->aes_len;

  u32 data[4];
  u32 out[4];
  u32 iv[4];

  iv[0] = seven_zip->iv_buf[0];
  iv[1] = seven_zip->iv_buf[1];
  iv[2] = seven_zip->iv_buf[2];
  iv[3] = seven_zip->iv_buf[3];

  u32 *out_full = (u32 *) seven_zip_hook_extra->aes[device_param->device_id];

  // if aes_len > 16 we need to loop

  int i = 0;
  int j = 0;

  for (i = 0, j = 0; i < aes_len - 16; i += 16, j += 4)
  {
    data[0] = data_buf[j + 0];
    data[1] = data_buf[j + 1];
    data[2] = data_buf[j + 2];
    data[3] = data_buf[j + 3];

    aes256_decrypt (aes_key.rdk, data, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

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

  // we need to run it at least once:

  data[0] = data_buf[j + 0];
  data[1] = data_buf[j + 1];
  data[2] = data_buf[j + 2];
  data[3] = data_buf[j + 3];

  aes256_decrypt (aes_key.rdk, data, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

  out[0] ^= iv[0];
  out[1] ^= iv[1];
  out[2] ^= iv[2];
  out[3] ^= iv[3];

  out_full[j + 0] = out[0];
  out_full[j + 1] = out[1];
  out_full[j + 2] = out[2];
  out_full[j + 3] = out[3];

  /*
   * check the CRC32 "hash"
   */

  u32 seven_zip_crc = seven_zip->crc;

  u32 crc;

  if (data_type == 0) // uncompressed
  {
    crc = cpu_crc32_buffer ((u8 *) out_full, unpack_size);
  }
  else
  {
    u32 crc_len = seven_zip->crc_len;

    char *coder_attributes = seven_zip->coder_attributes;

    // input buffers and length

    u8 *compressed_data = (u8 *) out_full;

    SizeT compressed_data_len = aes_len;

    // output buffers and length

    unsigned char *decompressed_data = (unsigned char *) seven_zip_hook_extra->unp[device_param->device_id];

    SizeT decompressed_data_len = crc_len;

    int ret;

    if (data_type == 1) // LZMA1
    {
      ret = hc_lzma1_decompress (compressed_data, &compressed_data_len, decompressed_data, &decompressed_data_len, coder_attributes);
    }
    else if (data_type == 7) // inflate using zlib (DEFLATE compression)
    {
      ret = SZ_ERROR_DATA;

      z_stream inf;

      inf.zalloc = Z_NULL;
      inf.zfree  = Z_NULL;
      inf.opaque = Z_NULL;

      inf.avail_in  = compressed_data_len;
      inf.next_in   = compressed_data;

      inf.avail_out = decompressed_data_len;
      inf.next_out  = decompressed_data;

      // inflate:

      inflateInit2 (&inf, -MAX_WBITS);

      int zlib_ret = inflate (&inf, Z_NO_FLUSH);

      inflateEnd (&inf);

      if ((zlib_ret == Z_OK) || (zlib_ret == Z_STREAM_END))
      {
        ret = SZ_OK;
      }
    }
    else // we only support LZMA2 in addition to LZMA1
    {
      ret = hc_lzma2_decompress (compressed_data, &compressed_data_len, decompressed_data, &decompressed_data_len, coder_attributes);
    }

    if (ret != SZ_OK)
    {
      hook_item->hook_success = 0;

      return;
    }

    crc = cpu_crc32_buffer (decompressed_data, crc_len);
  }

  if (crc == seven_zip_crc)
  {
    hook_item->hook_success = 1;
  }
  else
  {
    hook_item->hook_success = 0;
  }
}

u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_size = (const u64) sizeof (seven_zip_hook_t);

  return hook_size;
}

u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_salt_size = (const u64) sizeof (seven_zip_hook_salt_t);

  return hook_salt_size;
}

u64 module_hook_extra_param_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_extra_param_size = (const u64) sizeof (seven_zip_hook_extra_t);

  return hook_extra_param_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (seven_zip_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = PW_MAX;

  if (optimized_kernel == true)
  {
    pw_max = 20;
  }

  return pw_max;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 kernel_loops_min = KERNEL_LOOPS_MIN;

  if (optimized_kernel == true)
  {
    kernel_loops_min = 4096;
  }

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 kernel_loops_max = KERNEL_LOOPS_MAX;

  if (optimized_kernel == true)
  {
    kernel_loops_max = 4096;
  }

  return kernel_loops_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  seven_zip_hook_salt_t *seven_zip = (seven_zip_hook_salt_t *) hook_salt_buf;

  hc_token_t token;

  token.token_cnt  = 11;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SEVEN_ZIP;

  token.len[0]      = 4;
  token.attr[0]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]      = '$';
  token.len_min[1]  = 1;
  token.len_max[1]  = 1;
  token.attr[1]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]      = '$';
  token.len_min[2]  = 1;
  token.len_max[2]  = 2;
  token.attr[2]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]      = '$';
  token.len_min[3]  = 1;
  token.len_max[3]  = 1;
  token.attr[3]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]      = '$';
  token.len_min[4]  = 0;
  token.len_max[4]  = 64;
  token.attr[4]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[5]      = '$';
  token.len_min[5]  = 1;
  token.len_max[5]  = 2;
  token.attr[5]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]      = '$';
  token.len_min[6]  = 32;
  token.len_max[6]  = 32;
  token.attr[6]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]      = '$';
  token.len_min[7]  = 1;
  token.len_max[7]  = 10;
  token.attr[7]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]      = '$';
  token.len_min[8]  = 1;
  token.len_max[8]  = 8;
  token.attr[8]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[9]      = '$';
  token.len_min[9]  = 1;
  token.len_max[9]  = 8;
  token.attr[9]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[10]     = '$';
  token.len_min[10] = 2;
  token.len_max[10] = 0x200000 * 4 * 2;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *data_type_pos       = token.buf[ 1];
  const u8 *NumCyclesPower_pos  = token.buf[ 2];
  const u8 *salt_len_pos        = token.buf[ 3];
  const u8 *salt_buf_pos        = token.buf[ 4];
  const u8 *iv_len_pos          = token.buf[ 5];
  const u8 *iv_buf_pos          = token.buf[ 6];
  const u8 *crc_buf_pos         = token.buf[ 7];
  const u8 *data_len_pos        = token.buf[ 8];
  const u8 *unpack_size_pos     = token.buf[ 9];
  const u8 *data_buf_pos        = token.buf[10];

  const int data_type_len       = token.len[ 1];
  const int NumCyclesPower_len  = token.len[ 2];
  const int salt_len_len        = token.len[ 3];
  const int salt_buf_len        = token.len[ 4];
  const int iv_len_len          = token.len[ 5];
  const int iv_buf_len          = token.len[ 6];
  const int crc_buf_len         = token.len[ 7];
  const int data_len_len        = token.len[ 8];
  const int unpack_size_len     = token.len[ 9];
        int data_buf_len        = token.len[10];

  // fields only used when data was compressed:

  u8 *crc_len_pos = (u8 *) strchr ((const char *) data_buf_pos, '$');

  u32 crc_len_len          = 0;
  u8 *coder_attributes_pos = 0;
  u32 coder_attributes_len = 0;

  if (crc_len_pos != NULL)
  {
    data_buf_len = crc_len_pos - data_buf_pos;

    crc_len_pos++;

    coder_attributes_pos = (u8 *) strchr ((const char *) crc_len_pos, '$');

    if (coder_attributes_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    crc_len_len = coder_attributes_pos - crc_len_pos;

    coder_attributes_pos++;
  }

  if (is_valid_hex_string (data_buf_pos, data_buf_len) == false) return (PARSER_SALT_ENCODING);

  const int iter         = hc_strtoul ((const char *) NumCyclesPower_pos, NULL, 10);
  const int crc          = hc_strtoul ((const char *) crc_buf_pos,        NULL, 10);
  const int data_type    = hc_strtoul ((const char *) data_type_pos,      NULL, 10);
  const int salt_len     = hc_strtoul ((const char *) salt_len_pos,       NULL, 10);
  const int iv_len       = hc_strtoul ((const char *) iv_len_pos,         NULL, 10);
  const int unpack_size  = hc_strtoul ((const char *) unpack_size_pos,    NULL, 10);
  const int data_len     = hc_strtoul ((const char *) data_len_pos,       NULL, 10);

  // if neither uncompressed nor truncated, then we need the length for crc and coder attributes

  int crc_len = 0;

  bool is_compressed = ((data_type != 0) && (data_type != 0x80));

  if (is_compressed == true)
  {
    if (crc_len_pos == NULL) return (PARSER_SEPARATOR_UNMATCHED);

    coder_attributes_len = line_len - 1 - 2 - 1 - data_type_len - 1 - NumCyclesPower_len - 1 - salt_len_len - 1 - salt_buf_len - 1 - iv_len_len - 1 - iv_buf_len - 1 - crc_buf_len - 1 - data_len_len - 1 - unpack_size_len - 1 - data_buf_len - 1 - crc_len_len - 1;

    crc_len = hc_strtoul ((const char *) crc_len_pos, NULL, 10);
  }

  /**
   * verify some data
   */

  // this check also returns an error with data_type == 0x80 (special case that means "truncated")

  if ((data_type != 0) && (data_type != 1) && (data_type != 2) && (data_type != 7))
  {
    return (PARSER_SALT_VALUE);
  }

  if (salt_len != 0) return (PARSER_SALT_VALUE);

  if ((data_len * 2) != data_buf_len) return (PARSER_SALT_VALUE);

  if (data_len > 0x200000 * 4) return (PARSER_SALT_VALUE);

  if (unpack_size > data_len) return (PARSER_SALT_VALUE);

  if (is_compressed == true)
  {
    if (crc_len_len > 7) return (PARSER_SALT_VALUE);

    if (coder_attributes_len > 10) return (PARSER_SALT_VALUE);

    if ((coder_attributes_len % 2) != 0) return (PARSER_SALT_VALUE);

    // we should be more strict about the needed attribute_len:

    if (data_type == 1) // LZMA1
    {
      if ((coder_attributes_len / 2) != 5) return (PARSER_SALT_VALUE);
    }
    else if (data_type == 2) // LZMA2
    {
      if ((coder_attributes_len / 2) != 1) return (PARSER_SALT_VALUE);
    }
  }

  /**
   * store data
   */

  seven_zip->data_type = data_type;

  seven_zip->iv_buf[0] = hex_to_u32 (iv_buf_pos +  0);
  seven_zip->iv_buf[1] = hex_to_u32 (iv_buf_pos +  8);
  seven_zip->iv_buf[2] = hex_to_u32 (iv_buf_pos + 16);
  seven_zip->iv_buf[3] = hex_to_u32 (iv_buf_pos + 24);

  seven_zip->iv_len = iv_len;

  memcpy (seven_zip->salt_buf, salt_buf_pos, salt_buf_len); // we just need that for later ascii_digest()

  seven_zip->salt_len = 0;

  seven_zip->crc = crc;

  for (int i = 0, j = 0; j < data_buf_len; i += 1, j += 8)
  {
    seven_zip->data_buf[i] = hex_to_u32 (data_buf_pos + j);
  }

  seven_zip->data_len = data_len;

  seven_zip->unpack_size = unpack_size;

  seven_zip->crc_len = crc_len;

  memset (seven_zip->coder_attributes, 0, sizeof (seven_zip->coder_attributes));

  seven_zip->coder_attributes_len = 0;

  if (is_compressed == 1)
  {
    if (is_valid_hex_string (coder_attributes_pos, coder_attributes_len) == false) return (PARSER_SALT_ENCODING);

    for (u32 i = 0, j = 0; j < coder_attributes_len; i += 1, j += 2)
    {
      seven_zip->coder_attributes[i] = hex_to_u8 ((const u8 *) &coder_attributes_pos[j]);

      seven_zip->coder_attributes_len++;
    }
  }

  // normally: crc_len <= unpacksize <= packsize (== data_len)

  int aes_len = data_len;

  if (crc_len != 0) // it is 0 only in case of uncompressed data or truncated data
  {
    // in theory we could just use crc_len, but sometimes (very rare) the compressed data
    // is larger than the original data! (because of some additional bytes from lzma/headers)
    // the +0.5 is used to round up (just to be sure we don't truncate)

    if (data_type == 1) // LZMA1 uses more bytes
    {
      aes_len = 32.5f + (float) crc_len * 1.05f; // +5% max (only for small random inputs)
    }
    else if (data_type == 2) // LZMA2 is more clever (e.g. uncompressed chunks)
    {
      aes_len =  4.5f + (float) crc_len * 1.01f; // +1% max (only for small random inputs)
    }

    // just make sure we never go beyond the data_len limit itself

    aes_len = MIN (aes_len, data_len);
  }

  seven_zip->aes_len = aes_len;

  // real salt

  salt->salt_buf[0] = seven_zip->data_buf[0];
  salt->salt_buf[1] = seven_zip->data_buf[1];
  salt->salt_buf[2] = seven_zip->data_buf[2];
  salt->salt_buf[3] = seven_zip->data_buf[3];

  salt->salt_len = 16;

  salt->salt_sign[0] = data_type;

  salt->salt_iter = 1u << iter;

  /**
   * digest
   */

  digest[0] = crc;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  seven_zip_hook_salt_t *seven_zip = (seven_zip_hook_salt_t *) hook_salt_buf;

  const u32 data_len = seven_zip->data_len;

  char *data_buf = (char *) hcmalloc ((data_len * 2) + 1);

  for (u32 i = 0, j = 0; i < data_len; i += 1, j += 2)
  {
    const u8 *ptr = (const u8 *) seven_zip->data_buf;

    snprintf (data_buf + j, (data_len * 2) + 1 - j, "%02x", ptr[i]);
  }

  u32 salt_iter = salt->salt_iter;

  u32 iv[4];

  iv[0] = byte_swap_32 (seven_zip->iv_buf[0]);
  iv[1] = byte_swap_32 (seven_zip->iv_buf[1]);
  iv[2] = byte_swap_32 (seven_zip->iv_buf[2]);
  iv[3] = byte_swap_32 (seven_zip->iv_buf[3]);

  u32 iv_len = seven_zip->iv_len;

  u32 cost = 0; // the log2 () of salt_iter

  while (salt_iter >>= 1)
  {
    cost++;
  }

  int bytes_written = snprintf (line_buf, line_size, "%s%u$%u$%u$%s$%u$%08x%08x%08x%08x$%u$%u$%u$%s",
    SIGNATURE_SEVEN_ZIP,
    salt->salt_sign[0],
    cost,
    seven_zip->salt_len,
    (char *) seven_zip->salt_buf,
    iv_len,
    iv[0],
    iv[1],
    iv[2],
    iv[3],
    seven_zip->crc,
    seven_zip->data_len,
    seven_zip->unpack_size,
    data_buf);

  if (seven_zip->data_type > 0)
  {
    bytes_written += snprintf (line_buf + bytes_written, line_size - bytes_written, "$%u$", seven_zip->crc_len);

    const u8 *ptr = (const u8 *) seven_zip->coder_attributes;

    for (u32 i = 0, j = 0; i < seven_zip->coder_attributes_len; i += 1, j += 2)
    {
      bytes_written += snprintf (line_buf + bytes_written, line_size - bytes_written, "%02x", ptr[i]);
    }
  }

  hcfree (data_buf);

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
  module_ctx->module_esalt_size               = MODULE_DEFAULT;
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
  module_ctx->module_hook_extra_param_size    = module_hook_extra_param_size;
  module_ctx->module_hook_extra_param_init    = module_hook_extra_param_init;
  module_ctx->module_hook_extra_param_term    = module_hook_extra_param_term;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = module_hook23;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_hook_size                = module_hook_size;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
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
