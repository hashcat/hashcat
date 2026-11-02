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
#include "filehandling.h"
#include "path.h"
#include "memory.h"
#include "cpu_crc32.h"
#include "keyboard_layout.h"
#include "truecrypt_veracrypt_common.c"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_32;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "VeraCrypt SHA256 + XTS 1536 bit + boot-mode (legacy)";
static const u64   KERN_TYPE      = 13753;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP
                                  | OPTI_TYPE_REGISTER_LIMIT;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_BINARY_HASHFILE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_KEYBOARD_MAPPING
                                  | OPTS_TYPE_COPY_TMPS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_EXTENDED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "f95b222552195378a228d932f7df38ca459b6d812899be43944ba2e9bf47967ba35da17bf69cc3f424521983989a66fd3c7865af6dd8ac2aeb82e10c92cae66f62c89b7053d2ba18ee5adcebcf426cc7720f029f7ea5409b3b7182593afbee99f6a3828887d9da6438fafd766589c35c210de60b013d9f816f9a1c8e7e76159347611c3dba00f433aa419dcb9eaf59af6886fccd7d12ae09c2b3d7a8a6102c511e8a34b4c39df8b1938dd5fe037d7087cf2a33b5410df9a6d83d218819b32bc13999c2dd7e96eb740902699ffe5fbaa47270cf1a7e3488198495059e1520ad4ad8beec0c63827286c300555a30febfe29a359d7e364c0b52613d9cff9348152f6871b6210681ab8cfdf24b96c4793c546083197d6e5377a59d7fcab9aa679fddf550ac1ab04249d0d679e8a39ddcca26f9b8b21f7f8b71d64a0ad3d9e3ed9e2e41abd6a9b4ff4d4a7ab29c27882487909fb1118a91de8e2e2d0dea7501a63b7553fd4ff26a5f64964031c9aa3fabbc09e3f58b09ce42bbf3f05afe0f9ea18331c7ba1a887afe307fedc2be93568fe80def12e97d5e129c373814a560573ee6350f59b329352e28137aa31688c499ae1c20b25c91506c520cae56c969790204de1ba46773197fb6a72fd4742712375e89cb5ee41f3ec8b64f3322ba389c947e671b0414e981fe582898af8a5bab09e094f03cb4cab047e7547313a7d1ddba7b70";

#include "hooks_common.c"

u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

#define VC_SALT_LEN       (               64)
#define VC_DATA_LEN       (              448)
#define VC_HEADER_LEN     (              512)
#define VC_HEADER_HEX_LEN (VC_HEADER_LEN * 2)

typedef struct vc_tmp
{
  u32 ipad[16];
  u32 opad[16];

  u32 dgst[64];
  u32 out[64];

  u32 pim_key[64];
  int pim; // marker for cracked
  int pim_check; // marker for _extended kernel

} vc_tmp_t;

typedef struct vc
{
  u32 data_buf[VC_DATA_LEN / 4];
  u32 keyfile_buf16[16];
  u32 keyfile_buf32[32];
  u32 keyfile_enabled;
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

  int pim_multi; // 2048 for boot (not SHA-512 or Whirlpool), 1000 for others
  int pim_start;
  int pim_stop;

} vc_t;

static const int   ROUNDS_VERACRYPT_200000     = 200000;
static const float MIN_SUFFICIENT_ENTROPY_FILE = 7.0f;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == true)
    {
      if (strncmp (device_param->device_name, "Intel", 5) == 0)
      {
        // Intel Iris Graphics, Metal Version 244.303: failed to create 'm13753_comp' pipeline, timeout reached
        return true;
      }
    }
  }

  return false;
}

int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const void *tmps, const u32 *src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 *dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  const vc_t *vc = (const vc_t *) hashes->esalts_buf;

  u32 tmp_buf[64] = { 0 };

  memcpy (tmp_buf, src_buf, src_len);

  execute_keyboard_layout_mapping (tmp_buf, src_len, vc->keyboard_layout_mapping_buf, vc->keyboard_layout_mapping_cnt);

  const vc_tmp_t *vc_tmp = (const vc_tmp_t *) tmps;

  if (vc_tmp->pim == 0)
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s", (char *) tmp_buf);
  }
  else
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s   (PIM=%d)", (char *) tmp_buf, vc_tmp->pim);
  }
}

bool module_potfile_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool potfile_disable = true;

  return potfile_disable;
}

bool module_outfile_check_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool outfile_check_disable = true;

  return outfile_check_disable;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (vc_t);

  return esalt_size;
}

u32 module_hashes_count_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 hashes_count_max = 1;

  return hashes_count_max;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (vc_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is selected
  // IOW, even in optimized kernel mode it support length 64

  const u32 pw_max = 64;

  return pw_max;
}

int module_hash_init_selftest (MAYBE_UNUSED const hashconfig_t *hashconfig, hash_t *hash)
{
  char header[VC_HEADER_LEN + 1] = { 0 };

  hex_decode ((const u8 *) hashconfig->st_hash, VC_HEADER_HEX_LEN, (u8 *) header);

  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, header, VC_HEADER_LEN);

  return parser_status;
}

int module_hash_binary_parse (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, hashes_t *hashes)
{
  // note: if module_hash_binary_parse exists, then module_hash_decode is not called

  HCFILE fp;

  if (hc_fopen (&fp, hashes->hashfile, "rb") == false) return (PARSER_HAVE_ERRNO);

  char *in = (char *) hcmalloc (VC_HEADER_LEN);

  const size_t n = hc_fread (in, 1, VC_HEADER_LEN, &fp);

  hc_fclose (&fp);

  if (n != VC_HEADER_LEN)
  {
    hcfree (in);

    return (PARSER_VC_FILE_SIZE);
  }

  hash_t *hashes_buf = hashes->hashes_buf;

  hash_t *hash = &hashes_buf[0];

  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, in, VC_HEADER_LEN);

  if (parser_status != PARSER_OK)
  {
    hcfree (in);

    return 0;
  }

  hcfree (in);

  // keyfiles

  vc_t *vc = (vc_t *) hash->esalt;

  const char *veracrypt_keyfiles = module_option_str (user_options, OPTION_VERACRYPT_KEYFILES);

  if (veracrypt_keyfiles)
  {
    char *keyfiles = hcstrdup (veracrypt_keyfiles);

    char *saveptr = NULL;

    char *keyfile = strtok_r (keyfiles, ",", &saveptr);

    while (keyfile)
    {
      if (hc_path_read (keyfile))
      {
        cpu_crc32 (keyfile, (u8 *) vc->keyfile_buf16,  64);
        cpu_crc32 (keyfile, (u8 *) vc->keyfile_buf32, 128);
      }

      keyfile = strtok_r ((char *) NULL, ",", &saveptr);
    }

    hcfree (keyfiles);

    vc->keyfile_enabled = 1;
  }

  // keyboard layout mapping

  const char *keyboard_layout_mapping = module_option_str (user_options, OPTION_KEYBOARD_LAYOUT_MAPPING);

  if (keyboard_layout_mapping)
  {
    if (hc_path_read (keyboard_layout_mapping))
    {
      initialize_keyboard_layout_mapping (keyboard_layout_mapping, vc->keyboard_layout_mapping_buf, &vc->keyboard_layout_mapping_cnt);
    }
  }

  // veracrypt PIM

  salt_t *salt = hash->salt;

  if ((module_option_given (user_options, OPTION_VERACRYPT_PIM_START) == true) && (module_option_given (user_options, OPTION_VERACRYPT_PIM_STOP) == true))
  {
    vc->pim_start = module_option_u32 (user_options, OPTION_VERACRYPT_PIM_START);
    vc->pim_stop  = module_option_u32 (user_options, OPTION_VERACRYPT_PIM_STOP);

    salt->salt_iter = vc->pim_stop * 2048 - 1;
  }

  return 1;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  vc_t *vc = (vc_t *) esalt_buf;

  // entropy

  const float entropy = get_entropy ((const u8 *) line_buf, line_len);

  if (entropy < MIN_SUFFICIENT_ENTROPY_FILE) return (PARSER_INSUFFICIENT_ENTROPY);

  // salt

  memcpy (salt->salt_buf, line_buf, VC_SALT_LEN);

  salt->salt_len = VC_SALT_LEN;

  // iter

  salt->salt_iter = ROUNDS_VERACRYPT_200000 - 1;

  // pim

  vc->pim_multi = 2048;
  vc->pim_start = 0;
  vc->pim_stop  = 0;

  // data

  memcpy (vc->data_buf, line_buf + VC_SALT_LEN, VC_DATA_LEN);

  // signature

  vc->signature = 0x41524556; // "VERA"

  // fake digest

  memcpy (digest, vc->data_buf, VC_DATA_LEN / 4);

  return (PARSER_OK);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_build_plain_postprocess  = module_build_plain_postprocess;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_binary_parse        = module_hash_binary_parse;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_init_selftest       = module_hash_init_selftest;
  module_ctx->module_hashes_count_max         = module_hashes_count_max;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_outfile_check_disable    = module_outfile_check_disable;
  module_ctx->module_potfile_disable          = module_potfile_disable;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_register_options         = veracrypt_keyboard_module_register_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
}
