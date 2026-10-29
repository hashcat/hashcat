/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "path.h"
#include "backend.h"
#include "modules.h"
#include "dynloader.h"
#include "interface.h"
#include "hlfmt.h"
#include "recipe.h"
#include "module_options.h"

// The name that says which plugin interface this core implements is defined in src/plugin_abi.c. It
// is the first thing a plugin has to get past, and the checks below are what catch a plugin that
// got past it.

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

// Hash-modes defined only by a stored recipe are numbered in the range reserved for them, see
// docs/hashcat-hash-recipe.md. Each pair maps the number such a hash-mode had outside that range to
// its number inside it, so that -m still accepts the old number. module_load () opens the module of
// the new number, and user_options->hash_mode keeps the number that was given, which is the number a
// run reports. The listings skip every old number, even where an earlier build or install left a
// module file under it. A number in this table can never get a module of its own, because
// module_load () would not open it.

typedef struct module_alias
{
  u32 hash_mode_old;
  u32 hash_mode_new;

} module_alias_t;

static const module_alias_t MODULE_ALIASES[] =
{
  {  1310, 40009 },
  {  1320, 40010 },
  {  5200, 40011 },
  {  5720, 40012 },
  {  6050, 40013 },
  {  6060, 40014 },
  {  6400, 40015 },
  {  6500, 40016 },
  {  6700, 40017 },
  {  7100, 40018 },
  {  7200, 40019 },
  {  7900, 40020 },
  {  9200, 40021 },
  { 10000, 40022 },
  { 10300, 40023 },
  { 10900, 40024 },
  { 10901, 40025 },
  { 11000, 40026 },
  { 11750, 40027 },
  { 11760, 40028 },
  { 11850, 40029 },
  { 11860, 40030 },
  { 11900, 40031 },
  { 12000, 40032 },
  { 12001, 40033 },
  { 12100, 40034 },
  { 12150, 40035 },
  { 12300, 40036 },
  { 12800, 40037 },
  { 15100, 40038 },
  { 18500, 40039 },
  { 18800, 40040 },
  { 19210, 40041 },
  { 20200, 40042 },
  { 20300, 40043 },
  { 20400, 40044 },
  { 20600, 40045 },
  { 20720, 40046 },
  { 20730, 40047 },
  { 21300, 40048 },
  { 21420, 40049 },
  { 21600, 40050 },
  { 22800, 40051 },
  { 23200, 40052 },
  { 24200, 40053 },
  { 26300, 40054 },
  { 28600, 40055 },
  { 29100, 40056 },
  { 32000, 40057 },
  { 32010, 40058 },
  { 32020, 40059 },
  { 32030, 40060 },
  { 32031, 40061 },
  { 32040, 40062 },
  { 32041, 40063 },
  { 32050, 40064 },
  { 32060, 40065 },
  { 32070, 40066 },
  { 32410, 40067 },
  { 32420, 40068 },
  { 32600, 40069 },
  { 32900, 40070 },
  { 33100, 40071 },
  { 33300, 40072 },
  { 33650, 40073 },
  { 33660, 40074 },
  { 33900, 40075 },
  { 34400, 40076 },
  { 34500, 40077 },
  { 35000, 40078 },
  { 35700, 40079 },
  { 36500, 40080 },
  { 37300, 40081 },
  { 37301, 40082 },
};

u32 module_hash_mode_resolve (const u32 hash_mode)
{
  const u32 aliases_cnt = sizeof (MODULE_ALIASES) / sizeof (MODULE_ALIASES[0]);

  u32 hash_mode_resolved = hash_mode;

  for (u32 i = 0; i < aliases_cnt; i++)
  {
    if (MODULE_ALIASES[i].hash_mode_old != hash_mode) continue;

    hash_mode_resolved = MODULE_ALIASES[i].hash_mode_new;

    break;
  }

  return hash_mode_resolved;
}

bool module_load (hashcat_ctx_t *hashcat_ctx, module_ctx_t *module_ctx, const u32 hash_mode)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  memset (module_ctx, 0, sizeof (module_ctx_t));

  char *module_file = (char *) hcmalloc (HCBUFSIZ_TINY);

  module_filename (folder_config, module_hash_mode_resolve (hash_mode), module_file, HCBUFSIZ_TINY);

  struct stat s;

  memset (&s, 0, sizeof (struct stat));

  if (stat (module_file, &s) == -1)
  {
    event_log_warning (hashcat_ctx, "Either the specified hash mode does not exist in the official repository,");
    event_log_warning (hashcat_ctx, "or the file(s) could not be found. Please check that the hash mode number is");
    event_log_warning (hashcat_ctx, "correct and that the files are in the correct place.");
    event_log_warning (hashcat_ctx, NULL);
  }

  module_ctx->module_handle = hc_dlopen (module_file);

  if (module_ctx->module_handle == NULL)
  {
    // a plugin built against an interface this core no longer carries is the usual reason, and the
    // file says which one it was built against, so that is reported rather than the loader's own
    // words. The Unix loader names the symbol it could not resolve. The Windows loader says only
    // that a procedure was not found, which reads as a broken install.

    const int plugin_abi = hc_dlplugin_abi (module_file);

    if ((plugin_abi != -1) && (plugin_abi != HC_PLUGIN_ABI_VERSION))
    {
      event_log_error (hashcat_ctx, "Module %s was built for plugin interface %d, this hashcat provides %d", module_file, plugin_abi, HC_PLUGIN_ABI_VERSION);
    }
    else
    {
      #if defined (_WIN)
      event_log_error (hashcat_ctx, "Cannot load module %s: %s", module_file, hc_dlerror ());
      #else
      event_log_error (hashcat_ctx, "%s", hc_dlerror ());
      #endif
    }

    hcfree (module_file);

    return false;
  }

  module_ctx->module_init = (MODULE_INIT) hc_dlsym (module_ctx->module_handle, "module_init");

  if (module_ctx->module_init == NULL)
  {
    event_log_error (hashcat_ctx, "Cannot load symbol 'module_init' in module %s", module_file);

    hcfree (module_file);

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
  const backend_ctx_t        *backend_ctx        = hashcat_ctx->backend_ctx;
  const bridge_ctx_t         *bridge_ctx         = hashcat_ctx->bridge_ctx;
  const folder_config_t      *folder_config      = hashcat_ctx->folder_config;
        hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
        module_ctx_t         *module_ctx         = hashcat_ctx->module_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // set some boring defaults

  hashconfig->benchmark_mask          = default_benchmark_mask          (hashconfig, user_options, user_options_extra);
  hashconfig->benchmark_charset       = default_benchmark_charset       (hashconfig, user_options, user_options_extra);
  hashconfig->esalt_size              = default_esalt_size              (hashconfig, user_options, user_options_extra);
  hashconfig->forced_outfile_format   = default_forced_outfile_format   (hashconfig, user_options, user_options_extra);
  hashconfig->hash_mode               = default_hash_mode               (hashconfig, user_options, user_options_extra);
  hashconfig->hashes_count_min        = default_hashes_count_min        (hashconfig, user_options, user_options_extra);
  hashconfig->hashes_count_max        = default_hashes_count_max        (hashconfig, user_options, user_options_extra);
  hashconfig->hlfmt_disable           = default_hlfmt_disable           (hashconfig, user_options, user_options_extra);
  hashconfig->hook_salt_size          = default_hook_salt_size          (hashconfig, user_options, user_options_extra);
  hashconfig->hook_size               = default_hook_size               (hashconfig, user_options, user_options_extra);
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

  // What a hash tells us about whoever chose the password. A module that says nothing gets the answer
  // that works for every mode, which is the account name in front of the hash cut into words, and a
  // module that knows better says so and is not overwritten. -m 22000 is the example: its salt is the
  // network name and its esalt holds two MAC addresses, and no general rule could find those.
  //
  // Installed here rather than tested for at every call site, so that a reader has a pointer to call
  // either way and the question "did this module define one" is asked once.

  if (module_ctx->module_hash_hints == MODULE_DEFAULT) module_ctx->module_hash_hints = default_hash_hints;

  if (module_ctx->module_context_size != MODULE_CONTEXT_SIZE_CURRENT)
  {
    event_log_error (hashcat_ctx, "Module context size in 'module_init()' for hash-mode '%d' is invalid. Is this module based on an old template?", user_options->hash_mode);

    return -1;
  }

  if (module_ctx->module_interface_version < MODULE_INTERFACE_VERSION_MINIMUM)
  {
    event_log_error (hashcat_ctx, "Interface version in module context in 'module_init()' for hash-mode '%d' is outdated. Please recompile.", user_options->hash_mode);

    return -1;
  }

  // check for missing pointer assignments

  #define CHECK_DEFINED(module_ctx, func)                                         \
    if ((module_ctx)->func == NULL)                                               \
    {                                                                             \
      event_log_error (hashcat_ctx, "Module context missing field '%s' in 'module_init()' for hash-mode '%d'. Is this module based on an old template?", #func, user_options->hash_mode); \
                                                                                  \
      return -1;                                                                  \
    }

  CHECK_DEFINED (module_ctx, module_attack_exec);
  CHECK_DEFINED (module_ctx, module_benchmark_esalt);
  CHECK_DEFINED (module_ctx, module_benchmark_hook_salt);
  CHECK_DEFINED (module_ctx, module_benchmark_mask);
  CHECK_DEFINED (module_ctx, module_benchmark_charset);
  CHECK_DEFINED (module_ctx, module_benchmark_salt);
  CHECK_DEFINED (module_ctx, module_benchmark_cost);
  CHECK_DEFINED (module_ctx, module_bridge_name);
  CHECK_DEFINED (module_ctx, module_bridge_type);
  CHECK_DEFINED (module_ctx, module_build_plain_postprocess);
  CHECK_DEFINED (module_ctx, module_deep_comp_kernel);
  CHECK_DEFINED (module_ctx, module_deprecated_notice);
  CHECK_DEFINED (module_ctx, module_usage_notice);
  CHECK_DEFINED (module_ctx, module_advice_notice);
  CHECK_DEFINED (module_ctx, module_length_sort);
  CHECK_DEFINED (module_ctx, module_dgst_pos0);
  CHECK_DEFINED (module_ctx, module_dgst_pos1);
  CHECK_DEFINED (module_ctx, module_dgst_pos2);
  CHECK_DEFINED (module_ctx, module_dgst_pos3);
  CHECK_DEFINED (module_ctx, module_dgst_size);
  CHECK_DEFINED (module_ctx, module_esalt_size);
  CHECK_DEFINED (module_ctx, module_extra_buffer_size);
  CHECK_DEFINED (module_ctx, module_extra_tmp_size);
  CHECK_DEFINED (module_ctx, module_extra_tuningdb_block);
  CHECK_DEFINED (module_ctx, module_forced_outfile_format);
  CHECK_DEFINED (module_ctx, module_hash_binary_count);
  CHECK_DEFINED (module_ctx, module_hash_binary_parse);
  CHECK_DEFINED (module_ctx, module_hash_binary_save);
  CHECK_DEFINED (module_ctx, module_hash_category);
  CHECK_DEFINED (module_ctx, module_hash_decode);
  CHECK_DEFINED (module_ctx, module_hash_decode_postprocess);
  CHECK_DEFINED (module_ctx, module_hash_decode_potfile);
  CHECK_DEFINED (module_ctx, module_hash_decode_zero_hash);
  CHECK_DEFINED (module_ctx, module_hash_encode);
  CHECK_DEFINED (module_ctx, module_hash_encode_potfile);
  CHECK_DEFINED (module_ctx, module_hash_encode_status);
  CHECK_DEFINED (module_ctx, module_hash_hints);
  CHECK_DEFINED (module_ctx, module_hash_init_selftest);
  CHECK_DEFINED (module_ctx, module_hash_mode);
  CHECK_DEFINED (module_ctx, module_hash_name);
  CHECK_DEFINED (module_ctx, module_hash_recipe);
  CHECK_DEFINED (module_ctx, module_hashes_count_max);
  CHECK_DEFINED (module_ctx, module_hashes_count_min);
  CHECK_DEFINED (module_ctx, module_hlfmt_disable);
  CHECK_DEFINED (module_ctx, module_hook_extra_param_size);
  CHECK_DEFINED (module_ctx, module_hook_extra_param_init);
  CHECK_DEFINED (module_ctx, module_hook_extra_param_term);
  CHECK_DEFINED (module_ctx, module_hook12);
  CHECK_DEFINED (module_ctx, module_hook23);
  CHECK_DEFINED (module_ctx, module_hook_salt_size);
  CHECK_DEFINED (module_ctx, module_hook_size);
  CHECK_DEFINED (module_ctx, module_jit_build_options);
  CHECK_DEFINED (module_ctx, module_jit_cache_disable);
  CHECK_DEFINED (module_ctx, module_kern_bits);
  CHECK_DEFINED (module_ctx, module_kern_type);
  CHECK_DEFINED (module_ctx, module_kern_type_dynamic);
  CHECK_DEFINED (module_ctx, module_kernel_accel_max);
  CHECK_DEFINED (module_ctx, module_kernel_accel_min);
  CHECK_DEFINED (module_ctx, module_kernel_loops_max);
  CHECK_DEFINED (module_ctx, module_kernel_loops_min);
  CHECK_DEFINED (module_ctx, module_kernel_threads_max);
  CHECK_DEFINED (module_ctx, module_kernel_threads_min);
  CHECK_DEFINED (module_ctx, module_opti_type);
  CHECK_DEFINED (module_ctx, module_opts_type);
  CHECK_DEFINED (module_ctx, module_outfile_check_disable);
  CHECK_DEFINED (module_ctx, module_outfile_check_nocomp);
  CHECK_DEFINED (module_ctx, module_potfile_custom_check);
  CHECK_DEFINED (module_ctx, module_potfile_disable);
  CHECK_DEFINED (module_ctx, module_potfile_keep_all_hashes);
  CHECK_DEFINED (module_ctx, module_pw_max);
  CHECK_DEFINED (module_ctx, module_pw_min);
  CHECK_DEFINED (module_ctx, module_pwdump_column);
  CHECK_DEFINED (module_ctx, module_register_options);
  CHECK_DEFINED (module_ctx, module_salt_max);
  CHECK_DEFINED (module_ctx, module_salt_min);
  CHECK_DEFINED (module_ctx, module_salt_type);
  CHECK_DEFINED (module_ctx, module_separator);
  CHECK_DEFINED (module_ctx, module_st_hash);
  CHECK_DEFINED (module_ctx, module_st_pass);
  CHECK_DEFINED (module_ctx, module_tmp_size);
  CHECK_DEFINED (module_ctx, module_unstable_warning);
  CHECK_DEFINED (module_ctx, module_warmup_disable);

  #undef CHECK_DEFINED

  // mandatory functions check

  #define CHECK_MANDATORY(module_ctx, func)                                   \
    if ((module_ctx)->func == MODULE_DEFAULT)                                 \
    {                                                                         \
      event_log_error (hashcat_ctx, "Module context field '%s' in 'module_init()' for hash-mode '%d' is set to MODULE_DEFAULT, but must be explicitly set.", #func, user_options->hash_mode); \
                                                                              \
      return -1;                                                              \
    }

  CHECK_MANDATORY (module_ctx, module_attack_exec);
  CHECK_MANDATORY (module_ctx, module_dgst_pos0);
  CHECK_MANDATORY (module_ctx, module_dgst_pos1);
  CHECK_MANDATORY (module_ctx, module_dgst_pos2);
  CHECK_MANDATORY (module_ctx, module_dgst_pos3);
  CHECK_MANDATORY (module_ctx, module_dgst_size);
  CHECK_MANDATORY (module_ctx, module_hash_decode);
  // CHECK_MANDATORY (module_ctx, module_hash_encode); we do that one later
  CHECK_MANDATORY (module_ctx, module_hash_category);
  CHECK_MANDATORY (module_ctx, module_hash_name);
  CHECK_MANDATORY (module_ctx, module_kern_type);
  CHECK_MANDATORY (module_ctx, module_opti_type);
  CHECK_MANDATORY (module_ctx, module_opts_type);
  CHECK_MANDATORY (module_ctx, module_salt_type);
  CHECK_MANDATORY (module_ctx, module_st_hash);
  CHECK_MANDATORY (module_ctx, module_st_pass);

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

  // Mode 4000 uses the recipe to parse its hash lines and determine the encoding of the hash.

  hashconfig->hash_recipe_option = user_options->hash_recipe;

  // A recipe replaces only the pure kernels and -O still runs the module's optimized ones, so the
  // probes for those below use the kern_type the module declares.

  const u32 optimized_kern_type = hashconfig->kern_type;

  // A mode whose module names a recipe runs mode 4000's pure kernels, built from that recipe. Option
  // -O selects the mode's optimized kernels when available. Otherwise, the fallback below uses the
  // recipe kernels. These read candidates as little endian words, so a mode that generates them big
  // endian for its optimized kernels generates them little endian here. Validate the recipe now to
  // report the parser's error instead of a kernel build error. See docs/hashcat-hash-recipe.md.

  if (module_ctx->module_hash_recipe != MODULE_DEFAULT)
  {
    bool use_recipe = true;

    if (user_options->optimized_kernel == true)
    {
      char optimized_file[KERNEL_PATH_SZ] = { 0 };

      generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, hashconfig->kern_type, true, folder_config->shared_dir, optimized_file);

      if (kernel_path_fits (hashcat_ctx, optimized_file) == false) return -1;

      if (hc_path_read (optimized_file) == true) use_recipe = false;
    }

    if (use_recipe == true)
    {
      const char *recipe = module_ctx->module_hash_recipe (hashconfig, user_options, user_options_extra);

      recipe_prog_t prog;

      if (recipe_compile_stored (&prog, recipe) == false)
      {
        event_log_error (hashcat_ctx, "Recipe of hash-mode %d is invalid at position %u: %s", hashconfig->hash_mode, prog.error_pos, prog.error);

        return -1;
      }

      // A recipe with pbkdf2 or a loop runs in mode 4000's slow kernel and can replace only a slow
      // mode's kernels. A fast recipe can replace only a fast mode's kernels. For pbkdf2, each work
      // item in the loop kernel processes VECT_SIZE candidates. For a for loop, it processes one
      // candidate per work item.

      const bool mode_slow = (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL);

      if (mode_slow != (prog.slow == 1))
      {
        event_log_error (hashcat_ctx, "Recipe of hash-mode %d is a %s hash, but the mode is a %s one", hashconfig->hash_mode, (prog.slow == 1) ? "slow" : "fast", (mode_slow == true) ? "slow" : "fast");

        return -1;
      }

      hashconfig->hash_recipe = recipe;
      hashconfig->kern_type   = RECIPE_KERN_TYPE;

      hashconfig->opts_type &= ~OPTS_TYPE_PT_GENERATE_BE;
      hashconfig->opts_type |=  OPTS_TYPE_PT_GENERATE_LE;

      if (prog.kdf_blocks > 0)
      {
        hashconfig->opti_type |= OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
      }
      else if (prog.slow == 1)
      {
        hashconfig->opti_type &= ~OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
      }
    }
  }

  // The optional kernels a mode provides. hashcat adds the ones every slow hash needs further down.

  if (module_ctx->module_kern_bits != MODULE_DEFAULT)
  {
    hashconfig->kern_bits = module_ctx->module_kern_bits (hashconfig, user_options, user_options_extra);
  }
  hashconfig->salt_type     = module_ctx->module_salt_type      (hashconfig, user_options, user_options_extra);
  hashconfig->st_hash       = module_ctx->module_st_hash        (hashconfig, user_options, user_options_extra);
  hashconfig->st_pass       = module_ctx->module_st_pass        (hashconfig, user_options, user_options_extra);

  if ((hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE) == 0)
  {
    CHECK_MANDATORY (module_ctx, module_hash_encode);
  }

  // check deep comp kernel requirements
  if (hashconfig->opts_type & OPTS_TYPE_DEEP_COMP_KERNEL)
  {
    CHECK_MANDATORY (module_ctx, module_deep_comp_kernel);
  }

  #undef CHECK_MANDATORY

  // Whether this mode takes a module option at all is decided by the option table, see
  // option_table_check_module (). The checks a module attaches to a value, such as a file it cannot
  // read, run here, because this is the first point with the module loaded.

  if (module_options_check (hashcat_ctx) == -1) return -1;

  if (user_options->multiply_accel == false)
  {
    hashconfig->opts_type |= OPTS_TYPE_MP_MULTI_DISABLE;
  }

  if (user_options->self_test == false)
  {
    hashconfig->opts_type |= OPTS_TYPE_SELF_TEST_DISABLE;
  }

  if (user_options->hex_charset)
  {
    hashconfig->opts_type |= OPTS_TYPE_MT_HEX;
  }

  if (user_options->hex_wordlist)
  {
    hashconfig->opts_type |= OPTS_TYPE_PT_HEX;
  }

  if ((user_options->hex_salt == true) && (hashconfig->salt_type == SALT_TYPE_GENERIC)) hashconfig->opts_type |= OPTS_TYPE_ST_HEX;

  if (user_options->keep_guessing)
  {
    hashconfig->opts_type |= OPTS_TYPE_PT_NEVERCRACK;
  }
  else
  {
    if (hashconfig->opts_type & OPTS_TYPE_SUGGEST_KG)
    {
      if (user_options->quiet == false && user_options->autodetect == false)
      {
        event_log_warning (hashcat_ctx, "This hash-mode is known to emit multiple valid candidates for the same hash.");
        event_log_warning (hashcat_ctx, "Use --keep-guessing to continue attack after finding the first crack.");
        event_log_warning (hashcat_ctx, NULL);
      }
    }
  }

  if (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL)
  {
    hashconfig->kern_bits |= KERN_BIT_INIT | KERN_BIT_LOOP | KERN_BIT_COMP;
  }

  hashconfig->has_optimized_kernel  = false;
  hashconfig->has_pure_kernel       = false;

  // some kernels do not have an optimized kernel, simply because they do not need them
  // or because they are not yet converted, for them we should switch off optimized mode
  //
  // a mode that tells hashcat its exact hash-mode inside the parser (eg. luks and jwt) is answered
  // from the kern_type it declares, because backend.c only asks it for the real one once a hash has
  // been read, and hashconfig_init () runs before that

  char source_file[KERNEL_PATH_SZ] = { 0 };

  // A path cut to fit is not a kernel that is missing, and a probe cannot tell the difference. It
  // would report a mode with no kernels at all, and the run would then fail on something that reads
  // like a problem with the mode. So a cut path is refused here too, not only where a build uses it.

  generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, hashconfig->kern_type, false, folder_config->shared_dir, source_file);

  if (kernel_path_fits (hashcat_ctx, source_file) == false) return -1;

  hashconfig->has_pure_kernel = hc_path_read (source_file);

  generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, optimized_kern_type, true, folder_config->shared_dir, source_file);

  if (kernel_path_fits (hashcat_ctx, source_file) == false) return -1;

  hashconfig->has_optimized_kernel = hc_path_read (source_file);

  if (user_options->hash_info == 0 || user_options->hash_info > 1)
  {
    if (user_options->optimized_kernel == true)
    {
      if (hashconfig->has_optimized_kernel == false)
      {
        if (user_options->quiet == false)
        {
          event_log_warning (hashcat_ctx, "Kernel %s:", source_file);
          event_log_warning (hashcat_ctx, "Optimized kernel requested, but not available or not required");
          event_log_warning (hashcat_ctx, "Falling back to pure kernel");
          event_log_warning (hashcat_ctx, NULL);
        }
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

  if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0)
  {
    hashconfig->opts_type &= ~OPTS_TYPE_PT_UTF16LE;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_UTF16BE;
    hashconfig->opts_type &= ~OPTS_TYPE_PT_ADD01;
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

  // In hash-info mode there is no attack to run, so what a reader is asking is which kernel types the
  // mode has at all rather than which it has for the attack-mode that happens to be the default. The
  // probe above uses the selected attack_kern, so a mode whose only kernel serves one attack-mode
  // reports no kernel type, and test.py --edge reads that line and concludes there is nothing to
  // test. -m 37000 is the first mode of that shape, a 4 byte key recovery that only brute-force drives.
  //
  // This sits after opti_type and opts_type have had their say above, so it changes what is reported
  // and nothing else. ATTACK_KERN_PCFG is left out on purpose: the device engine has only the pure
  // kernel and generate_source_kernel_filename () names a file for it that is not meant to exist.

  if (user_options->hash_info > 0)
  {
    const u32 attack_kerns[]  = { ATTACK_KERN_STRAIGHT, ATTACK_KERN_COMBI, ATTACK_KERN_BF };

    const u32 attack_kerns_cnt = sizeof (attack_kerns) / sizeof (attack_kerns[0]);

    // a recipe mode's pure kernels are the recipe ones, also when -O left the module's kern_type

    const u32 pure_kern_type = (module_ctx->module_hash_recipe != MODULE_DEFAULT) ? RECIPE_KERN_TYPE : hashconfig->kern_type;

    for (u32 i = 0; i < attack_kerns_cnt; i++)
    {
      generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, attack_kerns[i], pure_kern_type, false, folder_config->shared_dir, source_file);

      if (kernel_path_fits (hashcat_ctx, source_file) == false) return -1;

      if (hc_path_read (source_file) == true) hashconfig->has_pure_kernel = true;

      generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, attack_kerns[i], optimized_kern_type, true, folder_config->shared_dir, source_file);

      if (kernel_path_fits (hashcat_ctx, source_file) == false) return -1;

      if (hc_path_read (source_file) == true) hashconfig->has_optimized_kernel = true;
    }
  }

  const bool is_salted = ((hashconfig->salt_type == SALT_TYPE_GENERIC)
                       |  (hashconfig->salt_type == SALT_TYPE_EMBEDDED)
                       |  (hashconfig->salt_type == SALT_TYPE_VIRTUAL));

  hashconfig->is_salted = is_salted;

  if (module_ctx->module_benchmark_mask           != MODULE_DEFAULT) hashconfig->benchmark_mask          = module_ctx->module_benchmark_mask           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_benchmark_charset        != MODULE_DEFAULT) hashconfig->benchmark_charset       = module_ctx->module_benchmark_charset        (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_esalt_size               != MODULE_DEFAULT) hashconfig->esalt_size              = module_ctx->module_esalt_size               (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_forced_outfile_format    != MODULE_DEFAULT) hashconfig->forced_outfile_format   = module_ctx->module_forced_outfile_format    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hash_mode                != MODULE_DEFAULT) hashconfig->hash_mode               = module_ctx->module_hash_mode                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hashes_count_min         != MODULE_DEFAULT) hashconfig->hashes_count_min        = module_ctx->module_hashes_count_min         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hashes_count_max         != MODULE_DEFAULT) hashconfig->hashes_count_max        = module_ctx->module_hashes_count_max         (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hlfmt_disable            != MODULE_DEFAULT) hashconfig->hlfmt_disable           = module_ctx->module_hlfmt_disable            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_extra_param_size    != MODULE_DEFAULT) hashconfig->hook_extra_param_size   = module_ctx->module_hook_extra_param_size    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_salt_size           != MODULE_DEFAULT) hashconfig->hook_salt_size          = module_ctx->module_hook_salt_size           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_hook_size                != MODULE_DEFAULT) hashconfig->hook_size               = module_ctx->module_hook_size                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_length_sort              != MODULE_DEFAULT) hashconfig->length_sort             = module_ctx->module_length_sort              (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_outfile_check_disable    != MODULE_DEFAULT) hashconfig->outfile_check_disable   = module_ctx->module_outfile_check_disable    (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_outfile_check_nocomp     != MODULE_DEFAULT) hashconfig->outfile_check_nocomp    = module_ctx->module_outfile_check_nocomp     (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_potfile_disable          != MODULE_DEFAULT) hashconfig->potfile_disable         = module_ctx->module_potfile_disable          (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_potfile_keep_all_hashes  != MODULE_DEFAULT) hashconfig->potfile_keep_all_hashes = module_ctx->module_potfile_keep_all_hashes  (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_pwdump_column            != MODULE_DEFAULT) hashconfig->pwdump_column           = module_ctx->module_pwdump_column            (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_separator                != MODULE_DEFAULT) hashconfig->separator               = module_ctx->module_separator                (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_tmp_size                 != MODULE_DEFAULT) hashconfig->tmp_size                = module_ctx->module_tmp_size                 (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_warmup_disable           != MODULE_DEFAULT) hashconfig->warmup_disable          = module_ctx->module_warmup_disable           (hashconfig, user_options, user_options_extra);

  // A stored recipe running as a slow hash keeps its pbkdf2 state or carried variables in
  // the tmps. Their layout must match mode 4000's slow kernel, rather than the layout used
  // by the mode's own kernels.

  if (hashconfig->hash_recipe != NULL)
  {
    recipe_prog_t prog;

    if ((recipe_compile_stored (&prog, hashconfig->hash_recipe) == true) && (prog.slow == 1)) hashconfig->tmp_size = recipe_tmp_size (&prog);
  }

  // those depend on some previously defined values

  hashconfig->pw_max              = default_pw_max              (hashconfig, user_options, user_options_extra);
  hashconfig->pw_min              = default_pw_min              (hashconfig, user_options, user_options_extra);
  hashconfig->salt_max            = default_salt_max            (hashconfig, user_options, user_options_extra);
  hashconfig->salt_min            = default_salt_min            (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_accel_min    = default_kernel_accel_min    (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_accel_max    = default_kernel_accel_max    (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_loops_min    = default_kernel_loops_min    (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_loops_max    = default_kernel_loops_max    (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_threads_min  = default_kernel_threads_min  (hashconfig, user_options, user_options_extra);
  hashconfig->kernel_threads_max  = default_kernel_threads_max  (hashconfig, user_options, user_options_extra);

  if (module_ctx->module_pw_max             != MODULE_DEFAULT) hashconfig->pw_max             = module_ctx->module_pw_max             (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_pw_min             != MODULE_DEFAULT) hashconfig->pw_min             = module_ctx->module_pw_min             (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_salt_max           != MODULE_DEFAULT) hashconfig->salt_max           = module_ctx->module_salt_max           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_salt_min           != MODULE_DEFAULT) hashconfig->salt_min           = module_ctx->module_salt_min           (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_accel_min   != MODULE_DEFAULT) hashconfig->kernel_accel_min   = module_ctx->module_kernel_accel_min   (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_accel_max   != MODULE_DEFAULT) hashconfig->kernel_accel_max   = module_ctx->module_kernel_accel_max   (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_loops_min   != MODULE_DEFAULT) hashconfig->kernel_loops_min   = module_ctx->module_kernel_loops_min   (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_loops_max   != MODULE_DEFAULT) hashconfig->kernel_loops_max   = module_ctx->module_kernel_loops_max   (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_threads_min != MODULE_DEFAULT) hashconfig->kernel_threads_min = module_ctx->module_kernel_threads_min (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_kernel_threads_max != MODULE_DEFAULT) hashconfig->kernel_threads_max = module_ctx->module_kernel_threads_max (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_bridge_name        != MODULE_DEFAULT) hashconfig->bridge_name        = module_ctx->module_bridge_name        (hashconfig, user_options, user_options_extra);
  if (module_ctx->module_bridge_type        != MODULE_DEFAULT) hashconfig->bridge_type        = module_ctx->module_bridge_type        (hashconfig, user_options, user_options_extra);

  if (hashconfig->hook_extra_param_size)
  {
    const int hook_threads = (int) user_options->hook_threads;

    module_ctx->hook_extra_params = hccalloc (hook_threads, sizeof (void *));

    for (int i = 0; i < hook_threads; i++)
    {
      module_ctx->hook_extra_params[i] = hcmalloc (hashconfig->hook_extra_param_size);
    }
  }
  else
  {
    module_ctx->hook_extra_params = hccalloc (1, sizeof (void *));

    module_ctx->hook_extra_params[0] = hcmalloc (1);
  }

  if (module_ctx->module_hook_extra_param_init != MODULE_DEFAULT)
  {
    const int hook_threads = (int) user_options->hook_threads;

    for (int i = 0; i < hook_threads; i++)
    {
      const bool rc_hook_extra_param_init = module_ctx->module_hook_extra_param_init (hashcat_ctx, hashconfig, user_options, user_options_extra, folder_config, backend_ctx, module_ctx->hook_extra_params[i]);

      if (rc_hook_extra_param_init == false) return -1;
    }
  }

  // bridges have some serious impact on hashconfig
  if (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP)
  {
    hashconfig->kern_bits &= ~KERN_BIT_LOOP;

    hashconfig->bridge_type |= BRIDGE_TYPE_LAUNCH_LOOP;
  }

  if (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP2)
  {
    hashconfig->kern_bits &= ~KERN_BIT_LOOP2;

    hashconfig->bridge_type |= BRIDGE_TYPE_LAUNCH_LOOP2;
  }

  // selftest bridge update
  if (hashconfig->bridge_type & BRIDGE_TYPE_UPDATE_SELFTEST)
  {
    if (bridge_ctx->st_update_hash) hashconfig->st_hash = bridge_ctx->st_update_hash (hashcat_ctx, bridge_ctx->platform_context);
    if (bridge_ctx->st_update_pass) hashconfig->st_pass = bridge_ctx->st_update_pass (hashcat_ctx, bridge_ctx->platform_context);
  }

  return 0;
}

// Which kernels the session runs, for the decisions that are not settled when hashconfig_init ()
// runs. attack_kern is one of them, and the feed is what settles it: generic_instance_init () holds
// the only assignment of ATTACK_KERN_PCFG in the tree, and makes it only once the device engine is
// known to have base words. is_opti_kernel_no_pcfg () returns the wrong value before that, so this
// is called after generic_ctx_init (), and from here on the backend only asks whether a bit is set.

void hashconfig_kern_bits_init (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t       *hashconfig       = hashcat_ctx->hashconfig;
  const user_options_t *user_options   = hashcat_ctx->user_options;

  // A fast hash hashes in the cracking kernel itself. An optimized build splits that over the three
  // length-bounded kernels and a pure build does it all in one.

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (is_opti_kernel_no_pcfg (hashcat_ctx) == true)
    {
      hashconfig->kern_bits |= KERN_BIT_04 | KERN_BIT_08 | KERN_BIT_16;
    }
    else
    {
      hashconfig->kern_bits |= KERN_BIT_XX;
    }
  }

  // The mask kernel only has a table to build when hashcat expands the mask itself.

  if (user_options->slow_candidates == true)
  {
    hashconfig->kern_bits &= ~KERN_BIT_TM;
  }

  if (user_options->attack_mode != ATTACK_MODE_BF)
  {
    hashconfig->kern_bits &= ~KERN_BIT_TM;
  }
}

void hashconfig_destroy (hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t        *backend_ctx        = hashcat_ctx->backend_ctx;
  const folder_config_t      *folder_config      = hashcat_ctx->folder_config;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  module_ctx_t *module_ctx = hashcat_ctx->module_ctx;

  // A module that never got as far as module_init () has every function pointer still at NULL, because
  // module_load () memsets the context and then returns early when the file cannot be opened or has no
  // module_init symbol. MODULE_DEFAULT is (void *) -1 rather than NULL, so each "was this one set" test
  // below is true for a module that was never loaded, and the first of them calls through a null
  // pointer.
  //
  // Autodetect is where this bites. It walks every hash-mode in turn and destroys the context after
  // each one whether the load succeeded or not, so a single plugin that will not load takes the whole
  // sweep down with it rather than being skipped.

  if (module_ctx->module_init == NULL)
  {
    module_unload (module_ctx);

    memset (hashconfig, 0, sizeof (hashconfig_t));

    return;
  }

  if (module_ctx->module_hook_extra_param_term != MODULE_DEFAULT)
  {
    const int hook_threads = (int) user_options->hook_threads;

    for (int i = 0; i < hook_threads; i++)
    {
      module_ctx->module_hook_extra_param_term (hashcat_ctx, hashconfig, user_options, user_options_extra, folder_config, backend_ctx, module_ctx->hook_extra_params[i]);
    }
  }

  if (module_ctx->hook_extra_params)
  {
    if (hashconfig->hook_extra_param_size)
    {
      const int hook_threads = (int) user_options->hook_threads;

      for (int i = 0; i < hook_threads; i++)
      {
        hcfree (module_ctx->hook_extra_params[i]);
      }
    }
    else
    {
      hcfree (module_ctx->hook_extra_params[0]);
    }

    hcfree (module_ctx->hook_extra_params);
  }

  module_unload (module_ctx);

  memset (hashconfig, 0, sizeof (hashconfig_t));
}

/**
 * default functions
 */

const char *default_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?a?a?a?a?a?a?a";

  return mask;
}

const char *default_benchmark_charset (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return NULL;
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
  return user_options_extra->separator;
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

// What a hash carries about whoever chose the password, when the module has nothing of its own.
//
// The one thing true of every hash mode is that a hash file may carry the account name in front of the
// hash, so that is what this answers with. A passwd file carries two more fields that describe the
// person rather than the account, the real name out of the gecos field and the home directory, and both
// are taken as well. A module whose salt or esalt holds something better, a network name or a principal
// or a MAC address, defines its own and is not overwritten.

u32 default_hash_hints (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, const hashinfo_t *hash_info, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size)
{
  if (hash_info == NULL) return 0;

  const user_t *user = hash_info->user;

  if (user == NULL) return 0;

  const u32 cnt = hlfmt_account_hints (user->user_name, user->user_len, user->user_gecos, user->user_gecos_len, user->user_home, user->user_home_len, out_words, out_max, scratch, scratch_size);

  return cnt;
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
  //
  // -a 9 is not here, although it splits its hash file the same way. The potfile is turned off for the
  // whole attack mode in user_options_preprocess (), so nothing reads one, and every answer this steers
  // is inside potfile handling that never runs. A term for it would read as though --show worked there,
  // and --show for -a 9 prints nothing at all.

  if ((user_options->username == true) || (user_options->dynamic_x == true))
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
  // salt_min : this limit is only interesting for generic hash types that support a salt

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

  // salt_max : this limit is only interesting for generic hash types that support a salt

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
