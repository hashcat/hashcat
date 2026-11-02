/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_MODULE_OPTIONS_H
#define HC_MODULE_OPTIONS_H

// One option a module registered. The row is a copy, because the module it came from is unloaded
// again once every module has been asked. The hash-modes are the ones that registered it, in
// ascending order, and the value is what the command line or a library caller gave. file is the
// module that registered the row first. When modules register the name with different rows,
// conflict is set, file_conflict names the first module of another row, and no hash-mode takes the
// option, see module_options_conflicts ().

typedef struct module_option_entry
{
  module_option_t  row;

  u32             *modes;
  u32              modes_cnt;

  bool             given;
  u64              value;
  const char      *str;

  char            *file;
  char            *file_conflict;
  bool             conflict;

} module_option_entry_t;

#define MODULE_OPTIONS_MAX 0x100

// broken holds the hash-modes whose module could not be loaded when the options were collected.
// cache_file is the cache the rows were read from or written to, see src/module_options_cache.c.

typedef struct module_options
{
  module_option_entry_t *entries;
  u32                    entries_cnt;

  u32                   *broken;
  u32                    broken_cnt;

  char                  *cache_file;
  bool                   cache_read;
  bool                   cache_written;

  bool                   guessed;

} module_options_t;

HC_API int  module_options_init         (hashcat_ctx_t *hashcat_ctx, const char *install_folder, const char *shared_folder, const char *version, const int comptime);
HC_API void module_options_destroy      (hashcat_ctx_t *hashcat_ctx);
HC_API int  module_options_cache_report (hashcat_ctx_t *hashcat_ctx);
HC_API int  module_option_set           (hashcat_ctx_t *hashcat_ctx, const char *name, const char *value);

HC_PLUGIN_API bool        module_option_given (const user_options_t *user_options, const char *name);
HC_PLUGIN_API u32         module_option_u32   (const user_options_t *user_options, const char *name);
HC_PLUGIN_API const char *module_option_str   (const user_options_t *user_options, const char *name);

module_option_entry_t *module_option_find (const module_options_t *module_options, const char *name);

bool module_option_registered (const module_option_entry_t *entry, const u32 hash_mode);
bool module_options_broken    (const user_options_t *user_options, const u32 hash_mode);
int  module_options_check     (hashcat_ctx_t *hashcat_ctx);
void module_options_usage     (const user_options_t *user_options);
void module_options_logger    (hashcat_ctx_t *hashcat_ctx);

#endif // HC_MODULE_OPTIONS_H
