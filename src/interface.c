/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "backend.h"
#include "modules.h"
#include "dynloader.h"
#include "interface.h"

/**
 * parsing
 */

int module_filename (const folder_config_t *folder_config, const int hash_mode, char *out_buf, const size_t out_size)
{
  // native compiled
  #if defined (_WIN) || defined (__CYGWIN__)
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
  hashconfig->hashes_count_min        = default_hashes_count_min        (hashconfig, user_options, user_options_extra);
  hashconfig->hashes_count_max        = default_hashes_count_max        (hashconfig, user_options, user_options_extra);
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

  #define CHECK_DEFINED(func)                                                     \
    if ((func) == NULL)                                                             \
    {                                                                             \
      event_log_error (hashcat_ctx, "Missing symbol definitions. Old template?"); \
                                                                                  \
      return -1;                                                                  \
    }

  CHECK_DEFINED (module_ctx->module_attack_exec);
  CHECK_DEFINED (module_ctx->module_benchmark_esalt);
  CHECK_DEFINED (module_ctx->module_benchmark_hook_salt);
  CHECK_DEFINED (module_ctx->module_benchmark_mask);
  CHECK_DEFINED (module_ctx->module_benchmark_salt);
  CHECK_DEFINED (module_ctx->module_build_plain_postprocess);
  CHECK_DEFINED (module_ctx->module_deep_comp_kernel);
  CHECK_DEFINED (module_ctx->module_dgst_pos0);
  CHECK_DEFINED (module_ctx->module_dgst_pos1);
  CHECK_DEFINED (module_ctx->module_dgst_pos2);
  CHECK_DEFINED (module_ctx->module_dgst_pos3);
  CHECK_DEFINED (module_ctx->module_dgst_size);
  CHECK_DEFINED (module_ctx->module_dictstat_disable);
  CHECK_DEFINED (module_ctx->module_esalt_size);
  CHECK_DEFINED (module_ctx->module_extra_buffer_size);
  CHECK_DEFINED (module_ctx->module_extra_tmp_size);
  CHECK_DEFINED (module_ctx->module_forced_outfile_format);
  CHECK_DEFINED (module_ctx->module_hash_binary_count);
  CHECK_DEFINED (module_ctx->module_hash_binary_parse);
  CHECK_DEFINED (module_ctx->module_hash_binary_save);
  CHECK_DEFINED (module_ctx->module_hash_category);
  CHECK_DEFINED (module_ctx->module_hash_decode);
  CHECK_DEFINED (module_ctx->module_hash_decode_potfile);
  CHECK_DEFINED (module_ctx->module_hash_decode_zero_hash);
  CHECK_DEFINED (module_ctx->module_hash_encode);
  CHECK_DEFINED (module_ctx->module_hash_encode_potfile);
  CHECK_DEFINED (module_ctx->module_hash_encode_status);
  CHECK_DEFINED (module_ctx->module_hash_init_selftest);
  CHECK_DEFINED (module_ctx->module_hash_mode);
  CHECK_DEFINED (module_ctx->module_hash_name);
  CHECK_DEFINED (module_ctx->module_hashes_count_max);
  CHECK_DEFINED (module_ctx->module_hashes_count_min);
  CHECK_DEFINED (module_ctx->module_hlfmt_disable);
  CHECK_DEFINED (module_ctx->module_hook12);
  CHECK_DEFINED (module_ctx->module_hook23);
  CHECK_DEFINED (module_ctx->module_hook_salt_size);
  CHECK_DEFINED (module_ctx->module_hook_size);
  CHECK_DEFINED (module_ctx->module_jit_build_options);
  CHECK_DEFINED (module_ctx->module_jit_cache_disable);
  CHECK_DEFINED (module_ctx->module_kern_type);
  CHECK_DEFINED (module_ctx->module_kern_type_dynamic);
  CHECK_DEFINED (module_ctx->module_kernel_accel_max);
  CHECK_DEFINED (module_ctx->module_kernel_accel_min);
  CHECK_DEFINED (module_ctx->module_kernel_loops_max);
  CHECK_DEFINED (module_ctx->module_kernel_loops_min);
  CHECK_DEFINED (module_ctx->module_kernel_threads_max);
  CHECK_DEFINED (module_ctx->module_kernel_threads_min);
  CHECK_DEFINED (module_ctx->module_opti_type);
  CHECK_DEFINED (module_ctx->module_opts_type);
  CHECK_DEFINED (module_ctx->module_outfile_check_disable);
  CHECK_DEFINED (module_ctx->module_outfile_check_nocomp);
  CHECK_DEFINED (module_ctx->module_potfile_custom_check);
  CHECK_DEFINED (module_ctx->module_potfile_disable);
  CHECK_DEFINED (module_ctx->module_potfile_keep_all_hashes);
  CHECK_DEFINED (module_ctx->module_pw_max);
  CHECK_DEFINED (module_ctx->module_pw_min);
  CHECK_DEFINED (module_ctx->module_pwdump_column);
  CHECK_DEFINED (module_ctx->module_salt_max);
  CHECK_DEFINED (module_ctx->module_salt_min);
  CHECK_DEFINED (module_ctx->module_salt_type);
  CHECK_DEFINED (module_ctx->module_separator);
  CHECK_DEFINED (module_ctx->module_st_hash);
  CHECK_DEFINED (module_ctx->module_st_pass);
  CHECK_DEFINED (module_ctx->module_tmp_size);
  CHECK_DEFINED (module_ctx->module_unstable_warning);
  CHECK_DEFINED (module_ctx->module_warmup_disable);

  #undef CHECK_DEFINED

  // mandatory functions check

  #define CHECK_MANDATORY(func)                                               \
    if ((func) == MODULE_DEFAULT)                                               \
    {                                                                         \
      event_log_error (hashcat_ctx, "Missing mandatory symbol definitions");  \
                                                                              \
      return -1;                                                              \
    }

  CHECK_MANDATORY (module_ctx->module_attack_exec);
  CHECK_MANDATORY (module_ctx->module_dgst_pos0);
  CHECK_MANDATORY (module_ctx->module_dgst_pos1);
  CHECK_MANDATORY (module_ctx->module_dgst_pos2);
  CHECK_MANDATORY (module_ctx->module_dgst_pos3);
  CHECK_MANDATORY (module_ctx->module_dgst_size);
  CHECK_MANDATORY (module_ctx->module_hash_decode);
  // CHECK_MANDATORY (module_ctx->module_hash_encode); we do that one later
  CHECK_MANDATORY (module_ctx->module_hash_category);
  CHECK_MANDATORY (module_ctx->module_hash_name);
  CHECK_MANDATORY (module_ctx->module_kern_type);
  CHECK_MANDATORY (module_ctx->module_opti_type);
  CHECK_MANDATORY (module_ctx->module_opts_type);
  CHECK_MANDATORY (module_ctx->module_salt_type);
  CHECK_MANDATORY (module_ctx->module_st_hash);
  CHECK_MANDATORY (module_ctx->module_st_pass);

  hashconfig->attack_exec   = module_ctx->module_attack_exec    (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_pos0     = module_ctx->module_dgst_pos0      (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_pos1     = module_ctx->module_dgst_pos1      (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_pos2     = module_ctx->module_dgst_pos2      (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_pos3     = module_ctx->module_dgst_pos3      (hashconfig, user_options, user_options_extra);
  hashconfig->dgst_size     = module_ctx->module_dgst_size      (hashconfig, user_options, user_options_extra);
  hashconfig->hash_category = module_ctx->module_hash_category  (hashconfig, user_options, user_options_extra);
  hashconfig->hash_name     = module_ctx->module_hash_name      (hashconfig, user_options, user_options_extra);
  hashconfig->kern_type     = module_ctx->module_kern_type      (hashconfig, user_options, user_options_extra);
  hashconfig->opti_type     = module_ctx->module_opti_type      (hashconfig, user_options, user_options_extra);
  hashconfig->opts_type     = module_ctx->module_opts_type      (hashconfig, user_options, user_options_extra);
  hashconfig->salt_type     = module_ctx->module_salt_type      (hashconfig, user_options, user_options_extra);
  hashconfig->st_hash       = module_ctx->module_st_hash        (hashconfig, user_options, user_options_extra);
  hashconfig->st_pass       = module_ctx->module_st_pass        (hashconfig, user_options, user_options_extra);

  if ((hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE) == 0)
  {
    CHECK_MANDATORY (module_ctx->module_hash_encode);
  }

  #undef CHECK_MANDATORY

  if (module_ctx->module_benchmark_mask           != MODULE_DEFAULT) hashconfig->benchmark_mask          = module_ctx->module_benchmark_mask           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_dictstat_disable         != MODULE_DEFAULT) hashconfig->dictstat_disable        = module_ctx->module_dictstat_disable         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_esalt_size               != MODULE_DEFAULT) hashconfig->esalt_size              = module_ctx->module_esalt_size               (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_forced_outfile_format    != MODULE_DEFAULT) hashconfig->forced_outfile_format   = module_ctx->module_forced_outfile_format    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_mode                != MODULE_DEFAULT) hashconfig->hash_mode               = module_ctx->module_hash_mode                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hashes_count_min         != MODULE_DEFAULT) hashconfig->hashes_count_min        = module_ctx->module_hashes_count_min         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hashes_count_max         != MODULE_DEFAULT) hashconfig->hashes_count_max        = module_ctx->module_hashes_count_max         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hlfmt_disable            != MODULE_DEFAULT) hashconfig->hlfmt_disable           = module_ctx->module_hlfmt_disable            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_salt_size           != MODULE_DEFAULT) hashconfig->hook_salt_size          = module_ctx->module_hook_salt_size           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_size                != MODULE_DEFAULT) hashconfig->hook_size               = module_ctx->module_hook_size                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_accel_min         != MODULE_DEFAULT) hashconfig->kernel_accel_min        = module_ctx->module_kernel_accel_min         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_accel_max         != MODULE_DEFAULT) hashconfig->kernel_accel_max        = module_ctx->module_kernel_accel_max         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_loops_min         != MODULE_DEFAULT) hashconfig->kernel_loops_min        = module_ctx->module_kernel_loops_min         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_loops_max         != MODULE_DEFAULT) hashconfig->kernel_loops_max        = module_ctx->module_kernel_loops_max         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_threads_min       != MODULE_DEFAULT) hashconfig->kernel_threads_min      = module_ctx->module_kernel_threads_min       (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_threads_max       != MODULE_DEFAULT) hashconfig->kernel_threads_max      = module_ctx->module_kernel_threads_max       (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_outfile_check_disable    != MODULE_DEFAULT) hashconfig->outfile_check_disable   = module_ctx->module_outfile_check_disable    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_outfile_check_nocomp     != MODULE_DEFAULT) hashconfig->outfile_check_nocomp    = module_ctx->module_outfile_check_nocomp     (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_potfile_disable          != MODULE_DEFAULT) hashconfig->potfile_disable         = module_ctx->module_potfile_disable          (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_potfile_keep_all_hashes  != MODULE_DEFAULT) hashconfig->potfile_keep_all_hashes = module_ctx->module_potfile_keep_all_hashes  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_pwdump_column            != MODULE_DEFAULT) hashconfig->pwdump_column           = module_ctx->module_pwdump_column            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_separator                != MODULE_DEFAULT) hashconfig->separator               = module_ctx->module_separator                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_tmp_size                 != MODULE_DEFAULT) hashconfig->tmp_size                = module_ctx->module_tmp_size                 (hashconfig, user_options, user_options_extra);
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
  else
  {
    if (hashconfig->opti_type & OPTS_TYPE_SUGGEST_KG)
    {
      if (user_options->quiet == false)
      {
        event_log_warning (hashcat_ctx, "This hash-mode is known to emit multiple valid password candidates for the same hash.");
        event_log_warning (hashcat_ctx, "Use --keep-guessing to prevent hashcat from shutdown after the hash has been cracked.");
        event_log_warning (hashcat_ctx, NULL);
      }
    }
  }

  hashconfig->has_optimized_kernel  = false;
  hashconfig->has_pure_kernel       = false;

  if (module_ctx->module_kern_type_dynamic != MODULE_DEFAULT)
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
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "%s: Optimized kernel requested but not needed - falling back to pure kernel", source_file);
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
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "%s: Pure kernel not found, falling back to optimized kernel", source_file);

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

u32 default_hashes_count_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 hashes_count_min = 1;

  return hashes_count_min;
}

u32 default_hashes_count_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 hashes_count_max = 0xffffffff;

  return hashes_count_max;
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
