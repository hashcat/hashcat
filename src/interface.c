/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"
#include "memory.h"
#include "convert.h"
#include "event.h"
#include "shared.h"
#include "opencl.h"
#include "interface.h"
#include "filehandling.h"
#include "modules.h"
#include "dynloader.h"

/**
 * parser
 */

static int sort_by_src_len (const void *p1, const void *p2)
{
  const keyboard_layout_mapping_t *k1 = (const keyboard_layout_mapping_t *) p1;
  const keyboard_layout_mapping_t *k2 = (const keyboard_layout_mapping_t *) p2;

  return k1->src_len < k2->src_len;
}

bool initialize_keyboard_layout_mapping (hashcat_ctx_t *hashcat_ctx, const char *filename, keyboard_layout_mapping_t *keyboard_layout_mapping, int *keyboard_layout_mapping_cnt)
{
  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  FILE *fp = fopen (filename, "r");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

    return false;
  }

  int maps_cnt = 0;

  while (!feof (fp))
  {
    const size_t line_len = fgetl (fp, line_buf);

    if (line_len == 0) continue;

    token_t token;

    token.token_cnt  = 2;

    token.len_min[0] = 1;
    token.len_max[0] = 4;
    token.sep[0]     = 0x09;
    token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.len_min[1] = 0;
    token.len_max[1] = 4;
    token.sep[1]     = 0x09;
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, (const int) line_len, &token);

    if (rc_tokenizer != PARSER_OK)
    {
      event_log_error (hashcat_ctx, "%s: Syntax error: %s", filename, line_buf);

      fclose (fp);

      free (line_buf);

      return false;
    }

    memcpy (&keyboard_layout_mapping[maps_cnt].src_char, token.buf[0], token.len[0]);
    memcpy (&keyboard_layout_mapping[maps_cnt].dst_char, token.buf[1], token.len[1]);

    keyboard_layout_mapping[maps_cnt].src_len = token.len[0];
    keyboard_layout_mapping[maps_cnt].dst_len = token.len[1];

    if (maps_cnt == 256)
    {
      event_log_error (hashcat_ctx, "%s: too many entries", filename);

      fclose (fp);

      free (line_buf);

      return false;
    }

    maps_cnt++;
  }

  *keyboard_layout_mapping_cnt = maps_cnt;

  fclose (fp);

  free (line_buf);

  // we need to sort this by length to ensure the largest blocks come first in mapping

  qsort (keyboard_layout_mapping, maps_cnt, sizeof (keyboard_layout_mapping_t), sort_by_src_len);

  return true;
}

int find_keyboard_layout_map (const u32 search, const int search_len, keyboard_layout_mapping_t *s_keyboard_layout_mapping, const int keyboard_layout_mapping_cnt)
{
  for (int idx = 0; idx < keyboard_layout_mapping_cnt; idx++)
  {
    const u32 src_char = s_keyboard_layout_mapping[idx].src_char;
    const int src_len  = s_keyboard_layout_mapping[idx].src_len;

    if (src_len == search_len)
    {
      const u32 mask = 0xffffffff >> ((4 - search_len) * 8);

      if ((src_char & mask) == (search & mask)) return idx;
    }
  }

  return -1;
}

int execute_keyboard_layout_mapping (u32 plain_buf[64], const int plain_len, keyboard_layout_mapping_t *s_keyboard_layout_mapping, const int keyboard_layout_mapping_cnt)
{
  u32 out_buf[16] = { 0 };

  u8 *out_ptr = (u8 *) out_buf;

  int out_len = 0;

  u8 *plain_ptr = (u8 *) plain_buf;

  int plain_pos = 0;

  while (plain_pos < plain_len)
  {
    u32 src0 = 0;
    u32 src1 = 0;
    u32 src2 = 0;
    u32 src3 = 0;

    const int rem = MIN (plain_len - plain_pos, 4);

    if (rem > 0) src0 = plain_ptr[plain_pos + 0];
    if (rem > 1) src1 = plain_ptr[plain_pos + 1];
    if (rem > 2) src2 = plain_ptr[plain_pos + 2];
    if (rem > 3) src3 = plain_ptr[plain_pos + 3];

    const u32 src = (src0 <<  0)
                  | (src1 <<  8)
                  | (src2 << 16)
                  | (src3 << 24);

    int src_len;

    for (src_len = rem; src_len > 0; src_len--)
    {
      const int idx = find_keyboard_layout_map (src, src_len, s_keyboard_layout_mapping, keyboard_layout_mapping_cnt);

      if (idx == -1) continue;

      u32 dst_char = s_keyboard_layout_mapping[idx].dst_char;
      int dst_len  = s_keyboard_layout_mapping[idx].dst_len;

      switch (dst_len)
      {
        case 1:
          out_ptr[out_len++] = (dst_char >>  0) & 0xff;
          break;
        case 2:
          out_ptr[out_len++] = (dst_char >>  0) & 0xff;
          out_ptr[out_len++] = (dst_char >>  8) & 0xff;
          break;
        case 3:
          out_ptr[out_len++] = (dst_char >>  0) & 0xff;
          out_ptr[out_len++] = (dst_char >>  8) & 0xff;
          out_ptr[out_len++] = (dst_char >> 16) & 0xff;
          break;
        case 4:
          out_ptr[out_len++] = (dst_char >>  0) & 0xff;
          out_ptr[out_len++] = (dst_char >>  8) & 0xff;
          out_ptr[out_len++] = (dst_char >> 16) & 0xff;
          out_ptr[out_len++] = (dst_char >> 24) & 0xff;
          break;
      }

      plain_pos += src_len;

      break;
    }

    // not matched, keep original

    if (src_len == 0)
    {
      out_ptr[out_len] = plain_ptr[plain_pos];

      out_len++;

      plain_pos++;
    }
  }

  plain_buf[ 0] = out_buf[ 0];
  plain_buf[ 1] = out_buf[ 1];
  plain_buf[ 2] = out_buf[ 2];
  plain_buf[ 3] = out_buf[ 3];
  plain_buf[ 4] = out_buf[ 4];
  plain_buf[ 5] = out_buf[ 5];
  plain_buf[ 6] = out_buf[ 6];
  plain_buf[ 7] = out_buf[ 7];
  plain_buf[ 8] = out_buf[ 8];
  plain_buf[ 9] = out_buf[ 9];
  plain_buf[10] = out_buf[10];
  plain_buf[11] = out_buf[11];
  plain_buf[12] = out_buf[12];
  plain_buf[13] = out_buf[13];
  plain_buf[14] = out_buf[14];
  plain_buf[15] = out_buf[15];

  return out_len;
}

/**
 * parsing
 */

int ascii_digest (const hashconfig_t *hashconfig, const hashes_t *hashes, const module_ctx_t *module_ctx, char *out_buf, const int out_size, const u32 salt_pos, const u32 digest_pos)
{
  void        *digests_buf = hashes->digests_buf;
  salt_t      *salts_buf   = hashes->salts_buf;
  void        *esalts_buf  = hashes->esalts_buf;
  hashinfo_t **hash_info   = hashes->hash_info;
  const char  *hashfile    = hashes->hashfile;

  const u32 dgst_size  = hashconfig->dgst_size;
  const u64 esalt_size = hashconfig->esalt_size;

  //const u32 hash_type  = hashconfig->hash_type;
  //const u32 hash_mode  = hashconfig->hash_mode;
  //const u32 salt_type  = hashconfig->salt_type;

  //u8 datax[256] = { 0 };

  //u64 *digest_buf64 = (u64 *) datax;
  //u32 *digest_buf   = (u32 *) datax;

  char *digests_buf_ptr = (char *) digests_buf;

  //memcpy (digest_buf, digests_buf_ptr + (salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size), dgst_size);

  char *esalts_buf_ptr = (char *) esalts_buf;

  //salt_t salt;

  /*

  const bool isSalted = ((hashconfig->salt_type == SALT_TYPE_GENERIC)
                      |  (hashconfig->salt_type == SALT_TYPE_EMBEDDED));

  if (isSalted == true)
  {
    memcpy (&salt, &salts_buf[salt_pos], sizeof (salt_t));

    char *ptr = (char *) salt.salt_buf;

    if (opti_type & OPTI_TYPE_PRECOMPUTE_PERMUT)
    {
      switch (hash_type)
      {
        case HASH_TYPE_NETNTLM:

          salt.salt_buf[0] = rotr32 (salt.salt_buf[0], 3);
          salt.salt_buf[1] = rotr32 (salt.salt_buf[1], 3);

          u32 tt;

          FP (salt.salt_buf[1], salt.salt_buf[0], tt);

          break;
      }
    }

    u32 salt_len = salt.salt_len;

    if (opts_type & OPTS_TYPE_ST_UTF16LE)
    {
      for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
      {
        ptr[i] = ptr[j];
      }

      salt_len = salt_len / 2;
    }

    if (opts_type & OPTS_TYPE_ST_GENERATE_LE)
    {
      u32 max = salt.salt_len / 4;

      if (salt_len % 4) max++;

      for (u32 i = 0; i < max; i++)
      {
        salt.salt_buf[i] = byte_swap_32 (salt.salt_buf[i]);
      }
    }

    if (opts_type & OPTS_TYPE_ST_HEX)
    {
      char tmp[64] = { 0 };

      for (u32 i = 0, j = 0; i < salt_len; i += 1, j += 2)
      {
        sprintf (tmp + j, "%02x", (unsigned char) ptr[i]);
      }

      salt_len = salt_len * 2;

      memcpy (ptr, tmp, salt_len);
    }

    u32 memset_size = ((SALT_MAX - (int) salt_len) > 0) ? (SALT_MAX - salt_len) : 0;

    memset (ptr + salt_len, 0, memset_size);

    salt.salt_len = salt_len;
  }
  else
  {
    memset (&salt, 0, sizeof (salt_t));
  }
  */

  //
  // some modes require special encoding
  //

  //u32 out_buf_plain[256] = { 0 };
  //u32 out_buf_salt[256]  = { 0 };

  //char tmp_buf[1024] = { 0 };

  //char *ptr_plain = (char *) out_buf_plain;
  //u8   *ptr_salt  = (u8 *)   out_buf_salt;

  const u32 digest_cur = salts_buf[salt_pos].digests_offset + digest_pos;

  hashinfo_t *hash_info_ptr = NULL;

  if (hash_info) hash_info_ptr = hash_info[digest_cur];

  const int out_len = module_ctx->module_hash_encode
  (
    hashconfig,
    digests_buf_ptr + (digest_cur * dgst_size),
    salts_buf + salt_pos,
    esalts_buf_ptr + (digest_cur * esalt_size),
    hash_info_ptr,
    out_buf,
    out_size
  );

  return out_len;
}

int module_filename (const folder_config_t *folder_config, const int hash_mode, char *out_buf, const size_t out_size)
{
  // cross compiled
  #if defined (__x86_64__)
  #if defined (_WIN)
  const int out_len = snprintf (out_buf, out_size, "%s/modules/module64_%05d.dll", folder_config->shared_dir, hash_mode);
  #else
  const int out_len = snprintf (out_buf, out_size, "%s/modules/module64_%05d.so", folder_config->shared_dir, hash_mode);
  #endif
  #else
  #if defined (_WIN)
  const int out_len = snprintf (out_buf, out_size, "%s/modules/module32_%05d.dll", folder_config->shared_dir, hash_mode);
  #else
  const int out_len = snprintf (out_buf, out_size, "%s/modules/module32_%05d.so", folder_config->shared_dir, hash_mode);
  #endif
  #endif

  if (hc_path_exist (out_buf) == true) return out_len;

  // native compiled
  #if defined (_WIN)
  return snprintf (out_buf, out_size, "%s/modules/module_%05d.dll", folder_config->shared_dir, hash_mode);
  #else
  return snprintf (out_buf, out_size, "%s/modules/module_%05d.so", folder_config->shared_dir, hash_mode);
  #endif
}

bool module_load (hashcat_ctx_t *hashcat_ctx, module_ctx_t *module_ctx, const u32 hash_mode)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  memset (module_ctx, 0, sizeof (module_ctx_t));

  char *module_file = (char *) hcmalloc (HCBUFSIZ_TINY);

  module_filename (folder_config, hash_mode, module_file, HCBUFSIZ_TINY);

  module_ctx->module_handle = hc_dlopen (module_file);

  if (module_ctx->module_handle == NULL)
  {
    #if defined (_WIN)
    event_log_error (hashcat_ctx, "Cannot load module %s", module_file); // todo: maybe there's a dlerror () equivalent
    #else
    event_log_error (hashcat_ctx, "%s", dlerror ());
    #endif

    return false;
  }

  module_ctx->module_init = (MODULE_INIT) hc_dlsym (module_ctx->module_handle, "module_init");

  if (module_ctx->module_init == NULL)
  {
    event_log_error (hashcat_ctx, "Cannot load symbol 'module_init' in module %s", module_file);

    return false;
  }

  hcfree (module_file);

  return true;
}

void module_unload (module_ctx_t *module_ctx)
{
  if (module_ctx->module_handle)
  {
    hc_dlclose (module_ctx->module_handle);
  }
}

int hashconfig_init (hashcat_ctx_t *hashcat_ctx)
{
  const folder_config_t      *folder_config      = hashcat_ctx->folder_config;
        hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
        module_ctx_t         *module_ctx         = hashcat_ctx->module_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // set some boring defaults

  hashconfig->benchmark_mask          = default_benchmark_mask          (hashconfig, user_options, user_options_extra);
  hashconfig->dictstat_disable        = default_dictstat_disable        (hashconfig, user_options, user_options_extra);
  hashconfig->esalt_size              = default_esalt_size              (hashconfig, user_options, user_options_extra);
  hashconfig->forced_outfile_format   = default_forced_outfile_format   (hashconfig, user_options, user_options_extra);
  hashconfig->hash_mode               = default_hash_mode               (hashconfig, user_options, user_options_extra);
  hashconfig->hlfmt_disable           = default_hlfmt_disable           (hashconfig, user_options, user_options_extra);
  hashconfig->hook_salt_size          = default_hook_salt_size          (hashconfig, user_options, user_options_extra);
  hashconfig->hook_size               = default_hook_size               (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_accel_min        = default_kernel_accel_min        (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_accel_max        = default_kernel_accel_max        (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_loops_min        = default_kernel_loops_min        (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_loops_max        = default_kernel_loops_max        (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_threads_min      = default_kernel_threads_min      (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_threads_max      = default_kernel_threads_max      (hashconfig, user_options, user_options_extra);
  hashconfig->outfile_check_disable   = default_outfile_check_disable   (hashconfig, user_options, user_options_extra);
  hashconfig->outfile_check_nocomp    = default_outfile_check_nocomp    (hashconfig, user_options, user_options_extra);
  hashconfig->potfile_disable         = default_potfile_disable         (hashconfig, user_options, user_options_extra);
  hashconfig->potfile_keep_all_hashes = default_potfile_keep_all_hashes (hashconfig, user_options, user_options_extra);
  hashconfig->pwdump_column           = default_pwdump_column           (hashconfig, user_options, user_options_extra);
  hashconfig->separator               = default_separator               (hashconfig, user_options, user_options_extra);
  hashconfig->tmp_size                = default_tmp_size                (hashconfig, user_options, user_options_extra);
  hashconfig->unstable_warning        = default_unstable_warning        (hashconfig, user_options, user_options_extra);
  hashconfig->warmup_disable          = default_warmup_disable          (hashconfig, user_options, user_options_extra);

  // finally, the real stuff

  const bool rc_load = module_load (hashcat_ctx, module_ctx, user_options->hash_mode);

  if (rc_load == false) return -1;

  module_ctx->module_init (module_ctx);

  if (module_ctx->module_context_size != MODULE_CONTEXT_SIZE_CURRENT)
  {
    event_log_error (hashcat_ctx, "module context size is invalid. Old template?");

    return -1;
  }

  if (module_ctx->module_interface_version < MODULE_INTERFACE_VERSION_MINIMUM)
  {
    event_log_error (hashcat_ctx, "module interface version is outdated, please compile");

    return -1;
  }

  // check for missing pointer assignements

  #define CHECK_DEFINED(func)                                                       \
    if (func == NULL)                                                               \
    {                                                                               \
      event_log_error (hashcat_ctx, "Missing symbol definitions. Old template?'");  \
                                                                                    \
      return -1;                                                                    \
    }

  CHECK_DEFINED (module_ctx->module_attack_exec);
  CHECK_DEFINED (module_ctx->module_benchmark_esalt);
  CHECK_DEFINED (module_ctx->module_benchmark_hook_salt);
  CHECK_DEFINED (module_ctx->module_benchmark_mask);
  CHECK_DEFINED (module_ctx->module_benchmark_salt);
  CHECK_DEFINED (module_ctx->module_dictstat_disable);
  CHECK_DEFINED (module_ctx->module_dgst_pos0);
  CHECK_DEFINED (module_ctx->module_dgst_pos1);
  CHECK_DEFINED (module_ctx->module_dgst_pos2);
  CHECK_DEFINED (module_ctx->module_dgst_pos3);
  CHECK_DEFINED (module_ctx->module_dgst_size);
  CHECK_DEFINED (module_ctx->module_esalt_size);
  CHECK_DEFINED (module_ctx->module_forced_outfile_format);
  CHECK_DEFINED (module_ctx->module_hash_category);
  CHECK_DEFINED (module_ctx->module_hash_name);
  CHECK_DEFINED (module_ctx->module_hash_mode);
  CHECK_DEFINED (module_ctx->module_hash_type);
  CHECK_DEFINED (module_ctx->module_hlfmt_disable);
  CHECK_DEFINED (module_ctx->module_hook_salt_size);
  CHECK_DEFINED (module_ctx->module_hook_size);
  CHECK_DEFINED (module_ctx->module_kernel_accel_min);
  CHECK_DEFINED (module_ctx->module_kernel_accel_max);
  CHECK_DEFINED (module_ctx->module_kernel_loops_min);
  CHECK_DEFINED (module_ctx->module_kernel_loops_max);
  CHECK_DEFINED (module_ctx->module_kernel_threads_min);
  CHECK_DEFINED (module_ctx->module_kernel_threads_max);
  CHECK_DEFINED (module_ctx->module_kern_type);
  CHECK_DEFINED (module_ctx->module_opti_type);
  CHECK_DEFINED (module_ctx->module_opts_type);
  CHECK_DEFINED (module_ctx->module_outfile_check_disable);
  CHECK_DEFINED (module_ctx->module_outfile_check_nocomp);
  CHECK_DEFINED (module_ctx->module_potfile_disable);
  CHECK_DEFINED (module_ctx->module_potfile_keep_all_hashes);
  CHECK_DEFINED (module_ctx->module_pwdump_column);
  CHECK_DEFINED (module_ctx->module_pw_min);
  CHECK_DEFINED (module_ctx->module_pw_max);
  CHECK_DEFINED (module_ctx->module_salt_min);
  CHECK_DEFINED (module_ctx->module_salt_max);
  CHECK_DEFINED (module_ctx->module_salt_type);
  CHECK_DEFINED (module_ctx->module_separator);
  CHECK_DEFINED (module_ctx->module_st_hash);
  CHECK_DEFINED (module_ctx->module_st_pass);
  CHECK_DEFINED (module_ctx->module_tmp_size);
  CHECK_DEFINED (module_ctx->module_unstable_warning);
  CHECK_DEFINED (module_ctx->module_warmup_disable);
  CHECK_DEFINED (module_ctx->module_hash_binary_count);
  CHECK_DEFINED (module_ctx->module_hash_binary_parse);
  CHECK_DEFINED (module_ctx->module_hash_binary_save);
  CHECK_DEFINED (module_ctx->module_hash_binary_verify);
  CHECK_DEFINED (module_ctx->module_hash_decode_outfile);
  CHECK_DEFINED (module_ctx->module_hash_decode_zero_hash);
  CHECK_DEFINED (module_ctx->module_hash_decode);
  CHECK_DEFINED (module_ctx->module_hash_encode_status);
  CHECK_DEFINED (module_ctx->module_hash_encode);
  CHECK_DEFINED (module_ctx->module_extra_buffer_size);
  CHECK_DEFINED (module_ctx->module_jit_build_options);
  CHECK_DEFINED (module_ctx->module_deep_comp_kernel);
  CHECK_DEFINED (module_ctx->module_hash_init_selftest);
  CHECK_DEFINED (module_ctx->module_hook12);
  CHECK_DEFINED (module_ctx->module_hook23);
  CHECK_DEFINED (module_ctx->module_build_plain_postprocess);

  #undef CHECK_DEFINED

  // mandatory functions check

  #define CHECK_MANDATORY(func)                                                 \
    if (func == MODULE_DEFAULT)                                                 \
    {                                                                           \
      event_log_error (hashcat_ctx, "Missing mandatory symbol definitions.'");  \
                                                                                \
      return -1;                                                                \
    }

  CHECK_MANDATORY (module_ctx->module_attack_exec);
  CHECK_MANDATORY (module_ctx->module_dgst_pos0);
  CHECK_MANDATORY (module_ctx->module_dgst_pos1);
  CHECK_MANDATORY (module_ctx->module_dgst_pos2);
  CHECK_MANDATORY (module_ctx->module_dgst_pos3);
  CHECK_MANDATORY (module_ctx->module_dgst_size);
  CHECK_MANDATORY (module_ctx->module_hash_decode);
  CHECK_MANDATORY (module_ctx->module_hash_encode);
  CHECK_MANDATORY (module_ctx->module_hash_category);
  CHECK_MANDATORY (module_ctx->module_hash_name);
  CHECK_MANDATORY (module_ctx->module_hash_type);
  CHECK_MANDATORY (module_ctx->module_kern_type);
  CHECK_MANDATORY (module_ctx->module_opti_type);
  CHECK_MANDATORY (module_ctx->module_opts_type);
  CHECK_MANDATORY (module_ctx->module_salt_type);
  CHECK_MANDATORY (module_ctx->module_st_hash);
  CHECK_MANDATORY (module_ctx->module_st_pass);

  #undef CHECK_MANDATORY

  if (module_ctx->module_attack_exec              != MODULE_DEFAULT) hashconfig->attack_exec             = module_ctx->module_attack_exec              (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_benchmark_mask           != MODULE_DEFAULT) hashconfig->benchmark_mask          = module_ctx->module_benchmark_mask           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_pos0                != MODULE_DEFAULT) hashconfig->dgst_pos0               = module_ctx->module_dgst_pos0                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_pos1                != MODULE_DEFAULT) hashconfig->dgst_pos1               = module_ctx->module_dgst_pos1                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_pos2                != MODULE_DEFAULT) hashconfig->dgst_pos2               = module_ctx->module_dgst_pos2                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_pos3                != MODULE_DEFAULT) hashconfig->dgst_pos3               = module_ctx->module_dgst_pos3                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dgst_size                != MODULE_DEFAULT) hashconfig->dgst_size               = module_ctx->module_dgst_size                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dictstat_disable         != MODULE_DEFAULT) hashconfig->dictstat_disable        = module_ctx->module_dictstat_disable         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_esalt_size               != MODULE_DEFAULT) hashconfig->esalt_size              = module_ctx->module_esalt_size               (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_forced_outfile_format    != MODULE_DEFAULT) hashconfig->forced_outfile_format   = module_ctx->module_forced_outfile_format    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_category            != MODULE_DEFAULT) hashconfig->hash_category           = module_ctx->module_hash_category            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_mode                != MODULE_DEFAULT) hashconfig->hash_mode               = module_ctx->module_hash_mode                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_name                != MODULE_DEFAULT) hashconfig->hash_name               = module_ctx->module_hash_name                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_type                != MODULE_DEFAULT) hashconfig->hash_type               = module_ctx->module_hash_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hlfmt_disable            != MODULE_DEFAULT) hashconfig->hlfmt_disable           = module_ctx->module_hlfmt_disable            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_salt_size           != MODULE_DEFAULT) hashconfig->hook_salt_size          = module_ctx->module_hook_salt_size           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_size                != MODULE_DEFAULT) hashconfig->hook_size               = module_ctx->module_hook_size                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_accel_min         != MODULE_DEFAULT) hashconfig->kernel_accel_min        = module_ctx->module_kernel_accel_min         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_accel_max         != MODULE_DEFAULT) hashconfig->kernel_accel_max        = module_ctx->module_kernel_accel_max         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_loops_min         != MODULE_DEFAULT) hashconfig->kernel_loops_min        = module_ctx->module_kernel_loops_min         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_loops_max         != MODULE_DEFAULT) hashconfig->kernel_loops_max        = module_ctx->module_kernel_loops_max         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_threads_min       != MODULE_DEFAULT) hashconfig->kernel_threads_min      = module_ctx->module_kernel_threads_min       (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_threads_max       != MODULE_DEFAULT) hashconfig->kernel_threads_max      = module_ctx->module_kernel_threads_max       (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kern_type                != MODULE_DEFAULT) hashconfig->kern_type               = module_ctx->module_kern_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_opti_type                != MODULE_DEFAULT) hashconfig->opti_type               = module_ctx->module_opti_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_opts_type                != MODULE_DEFAULT) hashconfig->opts_type               = module_ctx->module_opts_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_outfile_check_disable    != MODULE_DEFAULT) hashconfig->outfile_check_disable   = module_ctx->module_outfile_check_disable    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_outfile_check_nocomp     != MODULE_DEFAULT) hashconfig->outfile_check_nocomp    = module_ctx->module_outfile_check_nocomp     (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_potfile_disable          != MODULE_DEFAULT) hashconfig->potfile_disable         = module_ctx->module_potfile_disable          (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_potfile_keep_all_hashes  != MODULE_DEFAULT) hashconfig->potfile_keep_all_hashes = module_ctx->module_potfile_keep_all_hashes  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_pwdump_column            != MODULE_DEFAULT) hashconfig->pwdump_column           = module_ctx->module_pwdump_column            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_salt_type                != MODULE_DEFAULT) hashconfig->salt_type               = module_ctx->module_salt_type                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_separator                != MODULE_DEFAULT) hashconfig->separator               = module_ctx->module_separator                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_st_hash                  != MODULE_DEFAULT) hashconfig->st_hash                 = module_ctx->module_st_hash                  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_st_pass                  != MODULE_DEFAULT) hashconfig->st_pass                 = module_ctx->module_st_pass                  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_tmp_size                 != MODULE_DEFAULT) hashconfig->tmp_size                = module_ctx->module_tmp_size                 (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_unstable_warning         != MODULE_DEFAULT) hashconfig->unstable_warning        = module_ctx->module_unstable_warning         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_warmup_disable           != MODULE_DEFAULT) hashconfig->warmup_disable          = module_ctx->module_warmup_disable           (hashconfig, user_options, user_options_extra);

  if (user_options->keyboard_layout_mapping)
  {
    if ((hashconfig->opts_type & OPTS_TYPE_KEYBOARD_MAPPING) == 0)
    {
      event_log_error (hashcat_ctx, "Parameter --keyboard-layout-mapping not valid for hash-type %u", hashconfig->hash_mode);

      return -1;
    }
  }

  if (user_options->hex_salt)
  {
    if (hashconfig->salt_type == SALT_TYPE_GENERIC)
    {
      hashconfig->opts_type |= OPTS_TYPE_ST_HEX;
    }
    else
    {
      event_log_error (hashcat_ctx, "Parameter --hex-salt not valid for hash-type %u", hashconfig->hash_mode);

      return -1;
    }
  }

  if (user_options->keep_guessing)
  {
    hashconfig->opts_type |= OPTS_TYPE_PT_NEVERCRACK;
  }

  hashconfig->has_optimized_kernel  = false;
  hashconfig->has_pure_kernel       = false;

  if (hashconfig->kern_type == (u32) -1)
  {
    // some hash modes tell hashcat about their exact hash-mode inside the parser (eg. luks and jwt)
  }
  else
  {
    // some kernels do not have an optimized kernel, simply because they do not need them
    // or because they are not yet converted, for them we should switch off optimized mode

    char source_file[256] = { 0 };

    generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, hashconfig->kern_type, false, folder_config->shared_dir, source_file);

    hashconfig->has_pure_kernel = hc_path_read (source_file);

    generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, hashconfig->kern_type, true, folder_config->shared_dir, source_file);

    hashconfig->has_optimized_kernel = hc_path_read (source_file);

    if (user_options->example_hashes == false)
    {
      if (user_options->optimized_kernel_enable == true)
      {
        if (hashconfig->has_optimized_kernel == false)
        {
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "%s: Optimized OpenCL kernel requested but not needed - falling back to pure OpenCL kernel", source_file);
        }
        else
        {
          hashconfig->opti_type |= OPTI_TYPE_OPTIMIZED_KERNEL;
        }
      }
      else
      {
        if (hashconfig->has_pure_kernel == false)
        {
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "%s: Pure OpenCL kernel not found, falling back to optimized OpenCL kernel", source_file);

          hashconfig->opti_type |= OPTI_TYPE_OPTIMIZED_KERNEL;
        }
        else
        {
          // nothing to do
        }
      }
    }
  }

  if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0)
  {
    hashconfig->opts_type &= ~OPTS_TYPE_PT_UTF16LE;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_UTF16BE;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD01;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD02;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD06;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD80;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADDBITS14;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADDBITS15;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_UTF16LE;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_UTF16BE;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD01;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD02;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD80;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS14;
    hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS15;

    hashconfig->opti_type &= ~OPTI_TYPE_PRECOMPUTE_INIT;
    hashconfig->opti_type &= ~OPTI_TYPE_PRECOMPUTE_MERKLE;
    hashconfig->opti_type &= ~OPTI_TYPE_MEET_IN_MIDDLE;
    hashconfig->opti_type &= ~OPTI_TYPE_PREPENDED_SALT;
    hashconfig->opti_type &= ~OPTI_TYPE_APPENDED_SALT;
  }

  const bool is_salted = ((hashconfig->salt_type == SALT_TYPE_GENERIC)
                       |  (hashconfig->salt_type == SALT_TYPE_EMBEDDED)
                       |  (hashconfig->salt_type == SALT_TYPE_VIRTUAL));

  hashconfig->is_salted = is_salted;

  // those depend on some previously defined values

  hashconfig->pw_max    = default_pw_max    (hashconfig, user_options, user_options_extra);
  hashconfig->pw_min    = default_pw_min    (hashconfig, user_options, user_options_extra);
  hashconfig->salt_max  = default_salt_max  (hashconfig, user_options, user_options_extra);
  hashconfig->salt_min  = default_salt_min  (hashconfig, user_options, user_options_extra);

  if (module_ctx->module_pw_max   != MODULE_DEFAULT) hashconfig->pw_max    = module_ctx->module_pw_max   (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_pw_min   != MODULE_DEFAULT) hashconfig->pw_min    = module_ctx->module_pw_min   (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_salt_max != MODULE_DEFAULT) hashconfig->salt_max  = module_ctx->module_salt_max (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_salt_min != MODULE_DEFAULT) hashconfig->salt_min  = module_ctx->module_salt_min (hashconfig, user_options, user_options_extra);

  return 0;
}

void hashconfig_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  module_ctx_t *module_ctx = hashcat_ctx->module_ctx;

  module_unload (module_ctx);

  memset (hashconfig, 0, sizeof (hashconfig_t));
}

/**
 * default functions
 */

const char *default_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?b?b?b?b?b?b?b";

  return mask;
}

u32 default_hash_mode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 hash_mode = user_options->hash_mode;

  return hash_mode;
}

u64 default_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = 4;

  return tmp_size;
}

u64 default_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = 0;

  return esalt_size;
}

u32 default_kernel_accel_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_accel_min = KERNEL_ACCEL_MIN;

  return kernel_accel_min;
}

u32 default_kernel_accel_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_accel_max = KERNEL_ACCEL_MAX;

  return kernel_accel_max;
}

u32 default_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = KERNEL_LOOPS_MIN;

  return kernel_loops_min;
}

u32 default_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = KERNEL_LOOPS_MAX;

  return kernel_loops_max;
}

u32 default_kernel_threads_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_min = KERNEL_THREADS_MIN;

  return kernel_threads_min;
}

u32 default_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_max = KERNEL_THREADS_MAX;

  return kernel_threads_max;
}

u32 default_forced_outfile_format (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 forced_outfile_format = user_options->outfile_format;

  return forced_outfile_format;
}

u64 default_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_salt_size = 0;

  return hook_salt_size;
}

u64 default_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_size = 4;

  return hook_size;
}

char default_separator (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return user_options->separator;
}

bool default_dictstat_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool dictstat_disable = false;

  return dictstat_disable;
}

bool default_warmup_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool warmup_disable = false;

  return warmup_disable;
}

bool default_outfile_check_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool outfile_check_disable = false;

  return outfile_check_disable;
}

bool default_outfile_check_nocomp (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool outfile_check_nocomp = false;

  return outfile_check_nocomp;
}

bool default_hlfmt_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool hlfmt_disable = false;

  return hlfmt_disable;
}

bool default_potfile_keep_all_hashes (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  bool potfile_keep_all_hashes = false;

  // keep all hashes if --username was combined with --left or --show

  if (user_options->username == true)
  {
    if ((user_options->show == true) || (user_options->left == true))
    {
      potfile_keep_all_hashes = true;
    }
  }

  return potfile_keep_all_hashes;
}

u32 default_pwdump_column (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pwdump_column = PWDUMP_COLUMN_INVALID;

  return pwdump_column;
}

bool default_potfile_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool potfile_disable = false;

  return potfile_disable;
}

bool default_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool unstable_warning = false;

  return unstable_warning;
}

u32 default_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // pw_min : algo specific hard min length

  u32 pw_min = PW_MIN;

  if (optimized_kernel == true)
  {
    // unused case
  }

  return pw_min;
}

u32 default_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // pw_max : some algo suffer from support for long passwords,
  //          the user need to add -L to enable support for them

  u32 pw_max = PW_MAX;

  if (optimized_kernel == true)
  {
    pw_max = PW_MAX_OLD;

    if ((hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE) || (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE))
    {
      pw_max /= 2;
    }

    #define PW_DICTMAX 31

    if ((user_options->rp_files_cnt > 0) || (user_options->rp_gen > 0))
    {
      if (user_options->slow_candidates == true)
      {
        pw_max = MIN (pw_max, PW_DICTMAX);
      }
      else
      {
        switch (user_options_extra->attack_kern)
        {
          case ATTACK_KERN_STRAIGHT:  pw_max = MIN (pw_max, PW_DICTMAX);
                                      break;
          case ATTACK_KERN_COMBI:     pw_max = MIN (pw_max, PW_DICTMAX);
                                      break;
        }
      }
    }
    else
    {
      if (user_options->slow_candidates == true)
      {
        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          pw_max = MIN (pw_max, PW_DICTMAX);
        }
        else
        {
          // If we have a NOOP rule then we can process words from wordlists > PW_DICTMAX for slow hashes
        }
      }
      else
      {
        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          switch (user_options_extra->attack_kern)
          {
            case ATTACK_KERN_STRAIGHT:  pw_max = MIN (pw_max, PW_DICTMAX);
                                        break;
            case ATTACK_KERN_COMBI:     pw_max = MIN (pw_max, PW_DICTMAX);
                                        break;
          }
        }
        else
        {
          // If we have a NOOP rule then we can process words from wordlists > PW_DICTMAX for slow hashes
        }
      }
    }
  }

  return pw_max;
}

u32 default_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // salt_min : this limit is only interessting for generic hash types that support a salt

  u32 salt_min = SALT_MIN;

  if (hashconfig->salt_type == SALT_TYPE_GENERIC)
  {
    if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
    {
      salt_min *= 2;
    }
  }

  return salt_min;
}

u32 default_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  // salt_max : this limit is only interessting for generic hash types that support a salt

  u32 salt_max = SALT_MAX;

  if (optimized_kernel == true)
  {
    salt_max = SALT_MAX_OLD;

    if ((hashconfig->opts_type & OPTS_TYPE_ST_UTF16LE) || (hashconfig->opts_type & OPTS_TYPE_ST_UTF16BE))
    {
      salt_max /= 2;
    }
  }

  if (hashconfig->salt_type == SALT_TYPE_GENERIC)
  {
    if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
    {
      salt_max *= 2;
    }
  }

  return salt_max;
}
