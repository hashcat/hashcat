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
#include "cpu_crc32.h"
#include "keyboard_layout.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_32;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "VeraCrypt RIPEMD160 + XTS 1024 bit (legacy)";
static const u64   KERN_TYPE      = 13712;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_BINARY_HASHFILE
                                  | OPTS_TYPE_LOOP_EXTENDED
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_COPY_TMPS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001cdf025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346";

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

#define VC_SALT_LEN   64
#define VC_DATA_LEN   448
#define VC_HEADER_LEN 512

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
  u32 data_buf[112];
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

static const int   ROUNDS_VERACRYPT_655331     = 655331;
static const float MIN_SUFFICIENT_ENTROPY_FILE = 7.0f;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // AMD Radeon Pro W5700X Compute Engine; 1.2 (Apr 22 2021 21:54:44); 11.3.1; 20E241
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->is_metal == false)
    {
      return true;
    }
  }

  return false;
}

int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const void *tmps, const u32 *src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 *dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  const vc_tmp_t *vc_tmp = (const vc_tmp_t *) tmps;

  if (vc_tmp->pim == 0)
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s", (char *) src_buf);
  }
  else
  {
    return snprintf ((char *) dst_buf, dst_sz, "%s   (PIM=%d)", (char *) src_buf, vc_tmp->pim - 15);
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

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (vc_tmp_t);

  return tmp_size;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 1000; // lowest PIM multiplier

  return kernel_loops_max;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is selected
  // IOW, even in optimized kernel mode it support length 64

  const u32 pw_max = 64; // VC nowadays support 128, but RipeMD160 for container were removed before update from 64->128

  return pw_max;
}

int module_hash_init_selftest (MAYBE_UNUSED const hashconfig_t *hashconfig, hash_t *hash)
{
  const size_t st_hash_len = strlen (hashconfig->st_hash);

  char *tmpdata = (char *) hcmalloc (st_hash_len / 2);

  for (size_t i = 0, j = 0; j < st_hash_len; i += 1, j += 2)
  {
    const u8 c = hex_to_u8 ((const u8 *) hashconfig->st_hash + j);

    tmpdata[i] = c;
  }

  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, tmpdata, st_hash_len / 2);

  hcfree (tmpdata);

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

  if (n != VC_HEADER_LEN) return (PARSER_VC_FILE_SIZE);

  hash_t *hashes_buf = hashes->hashes_buf;

  hash_t *hash = &hashes_buf[0];

  const int parser_status = module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, in, VC_HEADER_LEN);

  if (parser_status != PARSER_OK) return 0;

  hcfree (in);

  // keyfiles

  vc_t *vc = (vc_t *) hash->esalt;

  if (user_options->veracrypt_keyfiles)
  {
    char *keyfiles = hcstrdup (user_options->veracrypt_keyfiles);

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

  if (user_options->keyboard_layout_mapping)
  {
    if (hc_path_read (user_options->keyboard_layout_mapping))
    {
      initialize_keyboard_layout_mapping (user_options->keyboard_layout_mapping, vc->keyboard_layout_mapping_buf, &vc->keyboard_layout_mapping_cnt);
    }
  }

  // veracrypt PIM

  salt_t *salt = hash->salt;

  if ((user_options->veracrypt_pim_start_chgd == true) && (user_options->veracrypt_pim_stop_chgd == true))
  {
    vc->pim_start = 15 + user_options->veracrypt_pim_start;
    vc->pim_stop  = 15 + user_options->veracrypt_pim_stop;

    salt->salt_iter = vc->pim_stop * 1000 - 1;
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

  salt->salt_iter = ROUNDS_VERACRYPT_655331 - 1;

  // pim

  vc->pim_multi = 1000;
  vc->pim_start = 0;
  vc->pim_stop  = 0;

  // data

  memcpy (vc->data_buf, line_buf + VC_SALT_LEN, VC_DATA_LEN);

  // signature

  vc->signature = 0x41524556; // "VERA"

  // fake digest

  memcpy (digest, vc->data_buf, 112);

  return (PARSER_OK);
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
  module_ctx->module_build_plain_postprocess  = module_build_plain_postprocess;
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
  module_ctx->module_hash_binary_parse        = module_hash_binary_parse;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = module_hash_init_selftest;
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
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = module_outfile_check_disable;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = module_potfile_disable;
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
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
