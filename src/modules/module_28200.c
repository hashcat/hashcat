/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Exodus Desktop Wallet (scrypt)";
static const u64   KERN_TYPE      = 28200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_LOOP_PREPARE
                                  | OPTS_TYPE_SELF_TEST_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "EXODUS:16384:8:1:IYkXZgFETRmFp4wQXyP8XMe3LtuOw8wMdLcBVQ+9YWE=:lq0W9ekN5sC0O7Xw:UD4a6mUUhkTbQtGWitXHZUg0pQ4RHI6W/KUyYE95m3k=:ZuNQckXOtr4r21x+DT1zpQ==";

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

typedef struct exodus
{
  u32 iv[4];
  u32 data[8];
  u32 tag[4];

} exodus_t;

static const char *SIGNATURE_EXODUS = "EXODUS";

static const u32 SCRYPT_THREADS = 32;

static const u64 SCRYPT_N = 16384;
static const u64 SCRYPT_R = 8;
static const u64 SCRYPT_P = 1;

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 1024;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 1024;

  return kernel_loops_max;
}

u32 module_kernel_threads_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_min = (user_options->kernel_threads_chgd == true) ? user_options->kernel_threads : SCRYPT_THREADS;

  return kernel_threads_min;
}

u32 module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_max = (user_options->kernel_threads_chgd == true) ? user_options->kernel_threads : SCRYPT_THREADS;

  return kernel_threads_max;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 4;

  return pw_min;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (exodus_t);

  return esalt_size;
}

u32 tmto = 0;

const char *module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel)
{
  // preprocess tmto in case user has overridden
  // it's important to set to 0 otherwise so we can postprocess tmto in that case

  tmto = (user_options->scrypt_tmto_chgd == true) ? user_options->scrypt_tmto : 0;

  // we enforce the same configuration for all hashes, so this should be fine

  const u64 scrypt_N = (hashes->salts_buf[0].scrypt_N) ? hashes->salts_buf[0].scrypt_N : SCRYPT_N;
  const u64 scrypt_r = (hashes->salts_buf[0].scrypt_r) ? hashes->salts_buf[0].scrypt_r : SCRYPT_R;

  const u64 size_per_accel = (128 * scrypt_r * scrypt_N * module_kernel_threads_max (hashconfig, user_options, user_options_extra)) >> tmto;

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  const u32 device_processors = device_param->device_processors;

  const u64 available_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4));

  u32 kernel_accel_new = device_processors;

  if (kernel_accel)
  {
    // from command line or tuning db has priority

    kernel_accel_new = user_options->kernel_accel;
  }
  else
  {
    // find a nice kernel_accel programmatically

    if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((size_per_accel * device_processors) > available_mem) // not enough memory
      {
        const float multi = (float) available_mem / size_per_accel;

        int accel_multi;

        for (accel_multi = 1; accel_multi <= 2; accel_multi++)
        {
          kernel_accel_new = multi * (1 << accel_multi);

          if (kernel_accel_new >= device_processors) break;
        }

        // we need some space for tmps[], ...

        kernel_accel_new -= (1 << accel_multi);

        // clamp if close to device processors -- 10% good?

        if ((kernel_accel_new > device_processors) && ((kernel_accel_new - device_processors) <= (device_processors / 10)))
        {
          kernel_accel_new = device_processors;
        }
      }
      else
      {
        for (int i = 1; i <= 8; i++)
        {
          if ((size_per_accel * device_processors * i) < available_mem)
          {
            kernel_accel_new = device_processors * i;
          }
        }
      }
    }
    else
    {
      for (int i = 1; i <= 8; i++)
      {
        if ((size_per_accel * device_processors * i) < available_mem)
        {
          kernel_accel_new = device_processors * i;
        }
      }
    }
  }

  // fix tmto if user allows

  if (tmto == 0)
  {
    const u32 tmto_start = 1;
    const u32 tmto_stop  = 5;

    for (u32 tmto_new = tmto_start; tmto_new <= tmto_stop; tmto_new++)
    {
      if (available_mem > (kernel_accel_new * (size_per_accel >> tmto_new)))
      {
        tmto = tmto_new;

        break;
      }
    }
  }

  char *new_device_name = hcstrdup (device_param->device_name);

  for (size_t i = 0; i < strlen (new_device_name); i++)
  {
    if (new_device_name[i] == ' ') new_device_name[i] = '_';
  }

  lines_pos += snprintf (lines_buf + lines_pos, lines_sz - lines_pos, "%s * %u 1 %u A\n", new_device_name, user_options->hash_mode, kernel_accel_new);

  hcfree (new_device_name);

  return lines_buf;
}

u64 module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // we need to set the self-test hash settings to pass the self-test
  // the decoder for the self-test is called after this function

  const u64 scrypt_N = (hashes->salts_buf[0].scrypt_N) ? hashes->salts_buf[0].scrypt_N : SCRYPT_N;
  const u64 scrypt_r = (hashes->salts_buf[0].scrypt_r) ? hashes->salts_buf[0].scrypt_r : SCRYPT_R;

  const u64 size_per_accel = 128 * scrypt_r * scrypt_N * module_kernel_threads_max (hashconfig, user_options, user_options_extra);

  u64 size_scrypt = size_per_accel * device_param->kernel_accel_max;

  return size_scrypt / (1 << tmto);
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = 0; // we'll add some later

  return tmp_size;
}

u64 module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u64 scrypt_N = (hashes->salts_buf[0].scrypt_N) ? hashes->salts_buf[0].scrypt_N : SCRYPT_N;
  const u64 scrypt_r = (hashes->salts_buf[0].scrypt_r) ? hashes->salts_buf[0].scrypt_r : SCRYPT_R;
  const u64 scrypt_p = (hashes->salts_buf[0].scrypt_p) ? hashes->salts_buf[0].scrypt_p : SCRYPT_P;

  // we need to check that all hashes have the same scrypt settings

  for (u32 i = 1; i < hashes->salts_cnt; i++)
  {
    if ((hashes->salts_buf[i].scrypt_N != scrypt_N)
     || (hashes->salts_buf[i].scrypt_r != scrypt_r)
     || (hashes->salts_buf[i].scrypt_p != scrypt_p))
    {
      return -1;
    }
  }

  const u64 tmp_size = 128ULL * scrypt_r * scrypt_p;

  return tmp_size;
}

bool module_warmup_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return true;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u64 scrypt_N = (hashes->salts_buf[0].scrypt_N) ? hashes->salts_buf[0].scrypt_N : SCRYPT_N;
  const u64 scrypt_r = (hashes->salts_buf[0].scrypt_r) ? hashes->salts_buf[0].scrypt_r : SCRYPT_R;
  const u64 scrypt_p = (hashes->salts_buf[0].scrypt_p) ? hashes->salts_buf[0].scrypt_p : SCRYPT_P;

  const u64 extra_buffer_size = device_param->extra_buffer_size;

  const u64 kernel_power_max = ((OPTS_TYPE & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors) * device_param->kernel_threads_max * device_param->kernel_accel_max;

  const u64 size_scrypt = 128ULL * scrypt_r * scrypt_N;

  const u64 scrypt_tmto_final = (kernel_power_max * size_scrypt) / extra_buffer_size;

  const u64 tmp_size = 128ULL * scrypt_r * scrypt_p;

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D SCRYPT_N=%u -D SCRYPT_R=%u -D SCRYPT_P=%u -D SCRYPT_TMTO=%" PRIu64 " -D SCRYPT_TMP_ELEM=%" PRIu64,
    hashes->salts_buf[0].scrypt_N,
    hashes->salts_buf[0].scrypt_r,
    hashes->salts_buf[0].scrypt_p,
    scrypt_tmto_final,
    tmp_size / 16);

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  exodus_t *exodus = (exodus_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_EXODUS;

  token.sep[0]     = ':';
  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = ':';
  token.len_min[1] = 1;
  token.len_max[1] = 6;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = ':';
  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = ':';
  token.len_min[3] = 1;
  token.len_max[3] = 6;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = ':';
  token.len[4]     = 44;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[5]     = ':';
  token.len[5]     = 16;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[6]     = ':';
  token.len[6]     = 44;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[7]     = ':';
  token.len[7]     = 24;
  token.attr[7]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8  tmp_buf[512];
  int tmp_len;

  // scrypt settings

  const u8 *N_pos = token.buf[1];
  const u8 *r_pos = token.buf[2];
  const u8 *p_pos = token.buf[3];

  salt->scrypt_N = hc_strtoul ((const char *) N_pos, NULL, 10);
  salt->scrypt_r = hc_strtoul ((const char *) r_pos, NULL, 10);
  salt->scrypt_p = hc_strtoul ((const char *) p_pos, NULL, 10);

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  // salt

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  for (int i = 0; i < 8; i++) salt->salt_buf[i] = byte_swap_32 (salt->salt_buf[i]);

  salt->salt_len = tmp_len;

  // iv

  const u8 *iv_pos = token.buf[5];
  const int iv_len = token.len[5];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, iv_pos, iv_len, tmp_buf);

  memcpy (exodus->iv, tmp_buf, tmp_len);

  for (int i = 0; i < 4; i++) exodus->iv[i] = byte_swap_32 (exodus->iv[i]);

  // data

  const u8 *data_pos = token.buf[6];
  const int data_len = token.len[6];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, data_pos, data_len, tmp_buf);

  memcpy (exodus->data, tmp_buf, tmp_len);

  for (int i = 0; i < 8; i++) exodus->data[i] = byte_swap_32 (exodus->data[i]);

  // tag

  const u8 *tag_pos = token.buf[7];
  const int tag_len = token.len[7];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, tag_pos, tag_len, tmp_buf);

  memcpy (exodus->tag, tmp_buf, tmp_len);

  for (int i = 0; i < 4; i++) exodus->tag[i] = byte_swap_32 (exodus->tag[i]);

  // digest

  digest[0] = exodus->tag[0];
  digest[1] = exodus->tag[1];
  digest[2] = exodus->tag[2];
  digest[3] = exodus->tag[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  //const u32 *digest = (const u32 *) digest_buf;

  const exodus_t *exodus = (const exodus_t *) esalt_buf;

  // salt

  u32 tmp_salt[8] = { 0 };

  for (int i = 0; i < 8; i++) tmp_salt[i] = byte_swap_32 (salt->salt_buf[i]);

  char base64_salt[64];

  int base64_salt_len = base64_encode (int_to_base64, (const u8 *) tmp_salt, salt->salt_len, (u8 *) base64_salt);

  base64_salt[base64_salt_len] = 0;

  // iv

  u32 tmp_iv[4] = { 0 };

  for (int i = 0; i < 4; i++) tmp_iv[i] = byte_swap_32 (exodus->iv[i]);

  char base64_iv[64];

  int base64_iv_len = base64_encode (int_to_base64, (const u8 *) tmp_iv, 12, (u8 *) base64_iv);

  base64_iv[base64_iv_len] = 0;

  // data

  u32 tmp_data[8] = { 0 };

  for (int i = 0; i < 8; i++) tmp_data[i] = byte_swap_32 (exodus->data[i]);

  char base64_data[64];

  int base64_data_len = base64_encode (int_to_base64, (const u8 *) tmp_data, 32, (u8 *) base64_data);

  base64_data[base64_data_len] = 0;

  // tag

  u32 tmp_tag[4] = { 0 };

  for (int i = 0; i < 4; i++) tmp_tag[i] = byte_swap_32 (exodus->tag[i]);

  char base64_tag[64];

  int base64_tag_len = base64_encode (int_to_base64, (const u8 *) tmp_tag, 16, (u8 *) base64_tag);

  base64_tag[base64_tag_len] = 0;

  // output

  const int line_len = snprintf (line_buf, line_size, "%s:%u:%u:%u:%s:%s:%s:%s",
    SIGNATURE_EXODUS,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    base64_salt,
    base64_iv,
    base64_data,
    base64_tag);

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
  module_ctx->module_extra_buffer_size        = module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = module_extra_tuningdb_block;
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
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
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
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = module_warmup_disable;
}
