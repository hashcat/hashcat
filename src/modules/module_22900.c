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

#define HC_PEM_SALT_LENGTH    8
#define HC_PEM_MAX_BLOCK_SIZE 16
#define HC_PEM_MAX_KEY_LENGTH 32
#define HC_PEM_MAX_DATA_LENGTH 12288

// The longest OpenSSL cipher name I can find is 24 characters, so add on seven
// more characters for luck and one for the \0 gives us 32.
#define HC_PEM_MAX_CIPHER_NAME_LENGTH 32

static const u32 ATTACK_EXEC   = ATTACK_EXEC_INSIDE_KERNEL;
static const u32 DGST_POS0     = 0;
static const u32 DGST_POS1     = 1;
static const u32 DGST_POS2     = 2;
static const u32 DGST_POS3     = 3;
static const u32 DGST_SIZE     = DGST_SIZE_4_4;
static const u32 HASH_CATEGORY = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME   = "PEM encrypted private key";
static const u64 KERN_TYPE     = 22911;  // Kernel used for the benchmark esalt; will likely be overridden in production
static const u32 OPTI_TYPE     = OPTI_TYPE_ZERO_BYTE;
static const u64 OPTS_TYPE     = OPTS_TYPE_PT_GENERATE_LE
                               | OPTS_TYPE_BINARY_HASHFILE;
static const u32 SALT_TYPE     = SALT_TYPE_EMBEDDED;
static const char *ST_PASS     = "hashcat";
static const char *ST_HASH     = NULL;  // Benchmark / self-test hash provided in module_benchmark_esalt

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

typedef enum hc_pem_cipher_type
{
  HC_PEM_CIPHER_TYPE_3DES   = 1,
  HC_PEM_CIPHER_TYPE_DES    = 2,
  HC_PEM_CIPHER_TYPE_AES128 = 3,
  HC_PEM_CIPHER_TYPE_AES192 = 4,
  HC_PEM_CIPHER_TYPE_AES256 = 5,
} hc_pem_cipher_type_t;

typedef enum hc_pem_cipher_mode
{
  HC_PEM_CIPHER_MODE_CBC = 1,
} hc_pem_cipher_mode_t;

typedef struct pem_cipher
{
  char *name;

  u32 block_size;
  u32 key_length;
  u32 cipher_type;
  u32 cipher_mode;
} hc_pem_cipher_t;

static hc_pem_cipher_t pem_ciphers[] = {
  {"des-ede3-cbc", 8, 24, HC_PEM_CIPHER_TYPE_3DES,   HC_PEM_CIPHER_MODE_CBC},
  {"des-cbc",      8,  8, HC_PEM_CIPHER_TYPE_DES,    HC_PEM_CIPHER_MODE_CBC},
  {"aes-128-cbc", 16, 16, HC_PEM_CIPHER_TYPE_AES128, HC_PEM_CIPHER_MODE_CBC},
  {"aes-192-cbc", 16, 24, HC_PEM_CIPHER_TYPE_AES192, HC_PEM_CIPHER_MODE_CBC},
  {"aes-256-cbc", 16, 32, HC_PEM_CIPHER_TYPE_AES256, HC_PEM_CIPHER_MODE_CBC},
  {NULL,           0,  0, 0,                           0}
};

typedef struct pem
{
  hc_pem_cipher_t *chosen_cipher;

  u32 salt_iv[HC_PEM_MAX_BLOCK_SIZE / 4];

  u32 data[HC_PEM_MAX_DATA_LENGTH / 4];
  size_t data_len;
} pem_t;

typedef struct pem_tmp
{
  u32 key[HC_PEM_MAX_KEY_LENGTH / 4];
} pem_tmp_t;


u32 module_pw_max (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  const u32 pw_max = 64;

  return pw_max;
}

bool module_outfile_check_disable (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  const bool outfile_check_disable = true;

  return outfile_check_disable;
}

int module_hash_binary_count (MAYBE_UNUSED const hashes_t * hashes)
{
  return 1;
}

int module_hash_binary_parse (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra, hashes_t * hashes)
{
  hash_t *hashes_buf = hashes->hashes_buf;
  hash_t *hash = &hashes_buf[0];

  memset (hash->salt, 0, sizeof (salt_t));
  memset (hash->esalt, 0, sizeof (pem_t));

  return module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hashes->hashfile, strlen (hashes->hashfile));
}

static int peminator (char *buf, char *type, char **start, size_t * len)
{
  char start_header[256], end_header[256];

  snprintf (start_header, 256, "-----BEGIN %s-----", type);
  snprintf (end_header, 256, "-----END %s-----", type);

  char *start_point = buf;

  while (start_point != NULL)
  {
    if ((start_point = strstr (start_point, start_header)) == NULL)
      return -1;

    if (start_point != buf && start_point[-1] != '\n')
      continue;

    if (start_point[strlen (start_header)] == '\n')
      break;
  }

  char *end_point = start_point;

  while (end_point != NULL)
  {
    if ((end_point = strstr (end_point, end_header)) == NULL)
      return -1;

    if (end_point[-1] == '\n' && (end_point[strlen (end_header)] == '\n' || end_point[strlen (end_header)] == '\0'))
    {
      break;
    }
    else
    {
      end_point++;
    }
  }

  *start = start_point + strlen (start_header) + 1;
  *len = end_point - *start;

  return 0;
}

static int parse_dek_info (char *line, char *cipher_name, u8 * salt)
{
  line += strlen ("DEK-Info: ");

  u8 i = 0;
  int salty = -1;

  for (; *line != '\0'; line++)
  {
    if (salty >= 0)
    {
      if (i++ % 2 == 0)
      {
        if (line[1] == '\0')
        {
          return PARSER_SALT_LENGTH;
        }

        salt[salty++] = hex_to_u8 ((u8 *) line);

        if (salty > HC_PEM_MAX_BLOCK_SIZE)
        {
          return PARSER_SALT_LENGTH;
        }
      }
      else if (line[1] == '\0')
      {
        if (salty < HC_PEM_SALT_LENGTH)
        {
          // Malformed salt, not long enough for PKCS5's liking
          return PARSER_SALT_LENGTH;
        }
        else
        {
          return 0;
        }
      }
    }
    else if (*line == ',')
    {
      cipher_name[i] = '\0';
      salty = 0;
      i = 0;
    }
    else
    {
      cipher_name[i++] = *line;
      if (i >= HC_PEM_MAX_CIPHER_NAME_LENGTH)
      {
        return PARSER_CIPHER;
      }
    }
  }

  return PARSER_SALT_VALUE;
}

static int parse_pem_key_data (char *buf, char *cipher_name, u8 * salt, u8 * data, size_t * data_len)
{
  char *pemdata;
  size_t pemdata_len;

  if (peminator (buf, "RSA PRIVATE KEY", &pemdata, &pemdata_len) < 0)
  {
    if (peminator (buf, "DSA PRIVATE KEY", &pemdata, &pemdata_len) < 0)
    {
      if (peminator (buf, "EC PRIVATE KEY", &pemdata, &pemdata_len) < 0)
      {
        if (peminator (buf, "PRIVATE KEY", &pemdata, &pemdata_len) < 0)
        {
          return PARSER_HASH_FILE;
        }
      }
    }
  }

  u8 in_header = 1, *b64data;
  char line[256];
  size_t pd_idx = 0, l_idx = 0, b64_idx = 0;

  b64data = hcmalloc (pemdata_len);

  for (pd_idx = 0; pd_idx < pemdata_len; pd_idx++)
  {
    if (in_header)
    {
      if (pemdata[pd_idx] == '\n')
      {
        if (l_idx == 0)
        {
          // Empty line!
          in_header = 0;
          continue;
        }

        line[l_idx] = '\0';

        if (strstr (line, "DEK-Info: ") == line)
        {
          int err;

          if ((err = parse_dek_info (line, cipher_name, salt)) < 0)
          {
            return err;
          }
        }

        l_idx = 0;
      }
      else
      {
        line[l_idx++] = pemdata[pd_idx];
      }
    }
    else
    {
      if (pemdata[pd_idx] != '\n')
        b64data[b64_idx++] = pemdata[pd_idx];
    }
  }

  if (b64_idx * 6 / 8 > HC_PEM_MAX_DATA_LENGTH)
  {
    return PARSER_TOKEN_LENGTH;
  }

  *data_len = base64_decode (base64_to_int, b64data, b64_idx, data);

  return 0;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED void *digest_buf, salt_t * salt, void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t * hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  pem_t *pem = (pem_t *) esalt_buf;

  HCFILE fp;
  struct stat fileinfo;
  u8 *filebuf;

  if (stat (line_buf, &fileinfo) < 0)
    return 0;

  if (hc_fopen (&fp, line_buf, "rb") == false)
    return 0;

  filebuf = hcmalloc (fileinfo.st_size + 1);

  if (hc_fread (filebuf, 1, fileinfo.st_size, &fp) < (size_t) fileinfo.st_size)
  {
    hc_fclose (&fp);
    hcfree (filebuf);

    return PARSER_FILE_SIZE;
  }

  hc_fclose (&fp);

  filebuf[fileinfo.st_size] = '\0';

  char cipher_name[HC_PEM_MAX_CIPHER_NAME_LENGTH] = { 0 };
  u8 saltbytes[MAX(HC_PEM_SALT_LENGTH, HC_PEM_MAX_BLOCK_SIZE)];
  int err;

  if ((err = parse_pem_key_data ((char *) filebuf, cipher_name, saltbytes, (u8 *) pem->data, &pem->data_len)) < 0)
  {
    hcfree (filebuf);

    return err;
  }

  u32 *saltwords = (u32 *) saltbytes;

  for (u32 i = 0; i < HC_PEM_SALT_LENGTH / 4; i++)
  {
    pem->salt_iv[i] = saltwords[i];
  }

  hc_pem_cipher_t *candidate_cipher = pem_ciphers, *chosen_cipher = NULL;

  while (candidate_cipher->name)
  {
    if (strcasecmp (cipher_name, candidate_cipher->name) == 0)
    {
      chosen_cipher = candidate_cipher;
      break;
    }
    else
    {
      candidate_cipher++;
    }
  }

  if (chosen_cipher == NULL)
  {
    hcfree (filebuf);

    return PARSER_CIPHER;
  }

  if (chosen_cipher->block_size > HC_PEM_MAX_BLOCK_SIZE)
  {
    hcfree (filebuf);

    return PARSER_BLOCK_SIZE;
  }

  if (pem->data_len % chosen_cipher->block_size)
  {
    hcfree (filebuf);

    return PARSER_HASH_LENGTH;
  }

  if (chosen_cipher->key_length > HC_PEM_MAX_KEY_LENGTH)
  {
    // Nope nope nopety nope
    return PARSER_KEY_SIZE;
  }

  pem->chosen_cipher = chosen_cipher;

  memcpy (salt->salt_buf, pem->salt_iv, MIN (HC_PEM_SALT_LENGTH, 64 * 4));
  salt->salt_iter = 1;

  return 1;
}

void *module_benchmark_esalt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  pem_t *pem = (pem_t *) hcmalloc (sizeof (pem_t));

  pem->chosen_cipher = &pem_ciphers[0];
  hex_decode ((u8 *) "7CC48DB27D461D30", 16, (u8 *) pem->salt_iv);
  pem->data_len = base64_decode (base64_to_int, (u8 *) "ysVmp6tkcZXRqHyy3YMk5zd4bsT9D97kFcDIKkD2g5o/OBgc0pGQ/iSwJm/V+A2IkwgQlwvLW1OfKkAWdjcSFNKhmiWApVQB", 96, (u8 *) pem->data);

  return pem;
}

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_iter = 1;
  hex_decode ((u8 *) "7CC48DB27D461D30", 16, (u8 *) salt->salt_buf);

  return salt;
}

u64 module_kern_type_dynamic (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t * salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t * hash_info)
{
  const pem_t *pem = (const pem_t *) esalt_buf;

  u64 kern_type = 22900;

  kern_type += pem->chosen_cipher->cipher_type * 10;
  kern_type += pem->chosen_cipher->cipher_mode;

  return kern_type;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pem_t);

  return esalt_size;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t * hashconfig, MAYBE_UNUSED const user_options_t * user_options, MAYBE_UNUSED const user_options_extra_t * user_options_extra, MAYBE_UNUSED const hashes_t * hashes, MAYBE_UNUSED const hc_device_param_t * device_param)
{
  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D _unroll");

  return jit_build_options;
}

void module_init (module_ctx_t * module_ctx)
{
  module_ctx->module_context_size = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec = module_attack_exec;
  module_ctx->module_benchmark_esalt = module_benchmark_esalt;
  module_ctx->module_benchmark_hook_salt = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt = module_benchmark_salt;
  module_ctx->module_build_plain_postprocess = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0 = module_dgst_pos0;
  module_ctx->module_dgst_pos1 = module_dgst_pos1;
  module_ctx->module_dgst_pos2 = module_dgst_pos2;
  module_ctx->module_dgst_pos3 = module_dgst_pos3;
  module_ctx->module_dgst_size = module_dgst_size;
  module_ctx->module_dictstat_disable = MODULE_DEFAULT;
  module_ctx->module_esalt_size = module_esalt_size;
  module_ctx->module_extra_buffer_size = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count = module_hash_binary_count;
  module_ctx->module_hash_binary_parse = module_hash_binary_parse;
  module_ctx->module_hash_binary_save = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash = MODULE_DEFAULT;
  module_ctx->module_hash_decode = module_hash_decode;
  module_ctx->module_hash_encode_status = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile = MODULE_DEFAULT;
  module_ctx->module_hash_encode = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest = MODULE_DEFAULT;
  module_ctx->module_hash_mode = MODULE_DEFAULT;
  module_ctx->module_hash_category = module_hash_category;
  module_ctx->module_hash_name = module_hash_name;
  module_ctx->module_hashes_count_min = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable = MODULE_DEFAULT;
  module_ctx->module_hook12 = MODULE_DEFAULT;
  module_ctx->module_hook23 = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size = MODULE_DEFAULT;
  module_ctx->module_hook_size = MODULE_DEFAULT;
  module_ctx->module_jit_build_options = module_jit_build_options;
  module_ctx->module_jit_cache_disable = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min = MODULE_DEFAULT;
  module_ctx->module_kern_type = module_kern_type;
  module_ctx->module_kern_type_dynamic = module_kern_type_dynamic;
  module_ctx->module_opti_type = module_opti_type;
  module_ctx->module_opts_type = module_opts_type;
  module_ctx->module_outfile_check_disable = module_outfile_check_disable;
  module_ctx->module_outfile_check_nocomp = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check = MODULE_DEFAULT;
  module_ctx->module_potfile_disable = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes = MODULE_DEFAULT;
  module_ctx->module_pwdump_column = MODULE_DEFAULT;
  module_ctx->module_pw_max = module_pw_max;
  module_ctx->module_pw_min = MODULE_DEFAULT;
  module_ctx->module_salt_max = MODULE_DEFAULT;
  module_ctx->module_salt_min = MODULE_DEFAULT;
  module_ctx->module_salt_type = module_salt_type;
  module_ctx->module_separator = MODULE_DEFAULT;
  module_ctx->module_st_hash = module_st_hash;
  module_ctx->module_st_pass = module_st_pass;
  module_ctx->module_tmp_size = MODULE_DEFAULT;
  module_ctx->module_unstable_warning = MODULE_DEFAULT;
  module_ctx->module_warmup_disable = MODULE_DEFAULT;
}
