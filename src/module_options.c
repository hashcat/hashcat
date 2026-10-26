/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "shared.h"
#include "convert.h"
#include "folder.h"
#include "logfile.h"
#include "modules.h"
#include "dynloader.h"
#include "interface.h"
#include "module_options.h"
#include "module_options_cache.h"
#include "user_options_table.h"
#include "path.h"
#include "status_rc.h"

#include <inttypes.h>

// The options only some hash-modes read belong to the modules that read them. The hook of every
// module is called once, before the command line is parsed, so that a single parse covers every option
// and --help can list them. An option is then in scope for exactly the hash-modes that registered it,
// and the module reads the value back through module_option_given (), module_option_u32 () and
// module_option_str (). Those read it out of user_options, never out of a variable here, because under
// SHARED=0 every module links its own copy of src/module_options_value.c, where they are.

static char *module_option_strdup (const char *s)
{
  if (s == NULL) return NULL;

  char *copy = hcstrdup (s);

  return copy;
}

static const char *const core_option_names[] =
{
  #define OPTION(id, name, letter, idx, arg) name,
  #include "options.def"
  #undef OPTION
  NULL
};

static bool module_option_strings_equal (const char *a, const char *b)
{
  if ((a == NULL) && (b == NULL)) return true;

  if ((a == NULL) || (b == NULL)) return false;

  const bool equal = (strcmp (a, b) == 0);

  return equal;
}

// Two rows define the same option when everything the table and the module read is the same. The
// help text and the check callback are left out, the callback lives at a different address in each
// module.

static bool module_option_rows_equal (const module_option_t *a, const module_option_t *b)
{
  if (a->type       != b->type)       return false;
  if (a->flags      != b->flags)      return false;
  if (a->min        != b->min)        return false;
  if (a->max        != b->max)        return false;
  if (a->def        != b->def)        return false;
  if (a->brain_slot != b->brain_slot) return false;

  if (module_option_strings_equal (a->alias,    b->alias)    == false) return false;
  if (module_option_strings_equal (a->le,       b->le)       == false) return false;
  if (module_option_strings_equal (a->requires, b->requires) == false) return false;
  if (module_option_strings_equal (a->excludes, b->excludes) == false) return false;

  return true;
}

static void module_option_entry_free (const module_option_entry_t *entry)
{
  hcfree ((char *) entry->row.name);
  hcfree ((char *) entry->row.alias);
  hcfree ((char *) entry->row.le);
  hcfree ((char *) entry->row.requires);
  hcfree ((char *) entry->row.excludes);
  hcfree ((char *) entry->row.help_type);
  hcfree ((char *) entry->row.help);
  hcfree ((char *) entry->row.help_example);

  hcfree (entry->modes);
  hcfree (entry->file);
  hcfree (entry->file_conflict);
}

static void module_options_add (hashcat_ctx_t *hashcat_ctx, module_options_t *module_options, const module_option_t *rows, const u32 hash_mode, const char *module_file)
{
  for (u32 i = 0; rows[i].name != NULL; i++)
  {
    const module_option_t *row = &rows[i];

    if ((row->type != MODULE_OPTION_TYPE_FLAG) && (row->type != MODULE_OPTION_TYPE_U32) && (row->type != MODULE_OPTION_TYPE_STR)) continue;

    // getopt would only ever return the core option of that name

    bool core = false;

    for (u32 j = 0; core_option_names[j] != NULL; j++)
    {
      if (strcmp (core_option_names[j], row->name) != 0) continue;

      core = true;

      break;
    }

    if (core == true)
    {
      event_log_error (hashcat_ctx, "Module %s registers --%s, which is a hashcat option. The module's option is left out.", module_file, row->name);

      continue;
    }

    // A check is called with the value as text, which a flag does not have. A brain slot is filled
    // with a number, which a string option does not have either, and one module filling a slot twice
    // would leave the value to the order of its rows.

    if ((row->check != NULL) && (row->type == MODULE_OPTION_TYPE_FLAG))
    {
      event_log_error (hashcat_ctx, "Module %s registers a check for --%s, which takes no value. The module's option is left out.", module_file, row->name);

      continue;
    }

    bool slot_valid = (row->brain_slot <= BRAIN_SLOTS_MAX);

    if ((row->brain_slot != 0) && (row->type == MODULE_OPTION_TYPE_STR)) slot_valid = false;

    for (u32 j = 0; j < i; j++)
    {
      if (row->brain_slot == 0) break;

      if (strcmp (rows[j].name, row->name) == 0) continue;

      if (rows[j].brain_slot == row->brain_slot) slot_valid = false;
    }

    if (slot_valid == false)
    {
      event_log_error (hashcat_ctx, "Module %s gives --%s brain slot %u. A slot is 1 to %d, holds a number and belongs to one option of a module. The module's option is left out.", module_file, row->name, row->brain_slot, BRAIN_SLOTS_MAX);

      continue;
    }

    // Modules that register the same row share one entry. A shared option comes from one helper the
    // related modules all include, so their rows agree. A row that differs from every row of that name
    // so far starts an entry of its own, and module_options_conflicts () settles the name once every
    // module has been asked.

    module_option_entry_t *entry = NULL;

    for (u32 j = 0; j < module_options->entries_cnt; j++)
    {
      if (strcmp (module_options->entries[j].row.name, row->name) != 0) continue;

      if (module_option_rows_equal (&module_options->entries[j].row, row) == false) continue;

      entry = &module_options->entries[j];

      break;
    }

    // the getopt values the table hands out run from IDX_MODULE_OPTION up to the core ones

    if ((entry == NULL) && (module_options->entries_cnt >= MODULE_OPTIONS_MAX))
    {
      event_log_error (hashcat_ctx, "Module %s registers --%s, but %d module options are registered already. The module's option is left out.", module_file, row->name, MODULE_OPTIONS_MAX);

      continue;
    }

    if (entry == NULL)
    {
      module_options->entries = (module_option_entry_t *) hcrealloc (module_options->entries, module_options->entries_cnt * sizeof (module_option_entry_t), sizeof (module_option_entry_t));

      entry = &module_options->entries[module_options->entries_cnt];

      module_options->entries_cnt++;

      memset (entry, 0, sizeof (module_option_entry_t));

      entry->row = *row;

      entry->row.name         = module_option_strdup (row->name);
      entry->row.alias        = module_option_strdup (row->alias);
      entry->row.le           = module_option_strdup (row->le);
      entry->row.requires     = module_option_strdup (row->requires);
      entry->row.excludes     = module_option_strdup (row->excludes);
      entry->row.help_type    = module_option_strdup (row->help_type);
      entry->row.help         = module_option_strdup (row->help);
      entry->row.help_example = module_option_strdup (row->help_example);

      entry->file = module_option_strdup (module_file);

      // the check belongs to the loaded module and is asked for again once one is loaded

      entry->row.check = NULL;

      entry->value = row->def;
    }

    // a module that lists a name twice is one hash-mode, not two

    if ((entry->modes_cnt > 0) && (entry->modes[entry->modes_cnt - 1] == hash_mode)) continue;

    entry->modes = (u32 *) hcrealloc (entry->modes, entry->modes_cnt * sizeof (u32), sizeof (u32));

    entry->modes[entry->modes_cnt] = hash_mode;

    entry->modes_cnt++;
  }
}

// An alias has to name an option of its own type that is not an alias itself, or a value given for it
// would go nowhere or arrive as the wrong kind. A row that does not is dropped. An alias of an option
// that modules register differently stays, so that it is refused the same way the option is.

static void module_options_drop_aliases (module_options_t *module_options)
{
  u32 kept = 0;

  for (u32 i = 0; i < module_options->entries_cnt; i++)
  {
    const module_option_entry_t *entry = &module_options->entries[i];

    bool valid = true;

    if (entry->row.alias != NULL)
    {
      valid = false;

      for (u32 j = 0; j < module_options->entries_cnt; j++)
      {
        const module_option_entry_t *target = &module_options->entries[j];

        if (strcmp (target->row.name, entry->row.alias) != 0) continue;

        if ((target->row.alias == NULL) && ((target->conflict == true) || (target->row.type == entry->row.type))) valid = true;

        break;
      }
    }

    if (valid == false)
    {
      module_option_entry_free (entry);

      continue;
    }

    module_options->entries[kept] = *entry;

    kept++;
  }

  module_options->entries_cnt = kept;
}

static int sort_by_mode (const void *p1, const void *p2)
{
  const u32 m1 = *((const u32 *) p1);
  const u32 m2 = *((const u32 *) p2);

  if (m1 > m2) return  1;
  if (m1 < m2) return -1;

  return 0;
}

// Two modules that register one name with different rows cannot both be right, and keeping either
// row would make the result depend on the module numbers. So neither is kept. The entries of that
// name become one entry that no hash-mode takes, with the hash-modes of every row, and the option
// table refuses the option in a run of any of them. What is left of the row is the same whichever
// module came first: it takes a value, as text, when either row takes one, and nothing else is
// checked.

static void module_options_conflicts (hashcat_ctx_t *hashcat_ctx, module_options_t *module_options)
{
  for (u32 i = 0; i < module_options->entries_cnt; i++)
  {
    module_option_entry_t *entry = &module_options->entries[i];

    bool takes_value = (entry->row.type != MODULE_OPTION_TYPE_FLAG);

    u32 j = i + 1;

    while (j < module_options->entries_cnt)
    {
      module_option_entry_t *other = &module_options->entries[j];

      if (strcmp (other->row.name, entry->row.name) != 0)
      {
        j++;

        continue;
      }

      if (strcmp (other->file, entry->file) == 0)
      {
        event_log_error (hashcat_ctx, "Module %s registers --%s twice, differently. The option is left out for every hash-mode that registers it.", entry->file, entry->row.name);
      }
      else
      {
        event_log_error (hashcat_ctx, "Modules %s and %s register --%s differently. The option is left out for every hash-mode that registers it.", entry->file, other->file, entry->row.name);
      }

      if (other->row.type != MODULE_OPTION_TYPE_FLAG) takes_value = true;

      entry->modes = (u32 *) hcrealloc (entry->modes, entry->modes_cnt * sizeof (u32), other->modes_cnt * sizeof (u32));

      memcpy (&entry->modes[entry->modes_cnt], other->modes, other->modes_cnt * sizeof (u32));

      entry->modes_cnt += other->modes_cnt;

      if (entry->file_conflict == NULL)
      {
        entry->file_conflict = other->file;

        other->file = NULL;
      }

      module_option_entry_free (other);

      const u32 rest = module_options->entries_cnt - j - 1;

      memmove (&module_options->entries[j], &module_options->entries[j + 1], rest * sizeof (module_option_entry_t));

      module_options->entries_cnt--;
    }

    if (entry->file_conflict == NULL) continue;

    qsort (entry->modes, entry->modes_cnt, sizeof (u32), sort_by_mode);

    hcfree ((char *) entry->row.alias);
    hcfree ((char *) entry->row.le);
    hcfree ((char *) entry->row.requires);
    hcfree ((char *) entry->row.excludes);

    entry->row.type       = (takes_value == true) ? MODULE_OPTION_TYPE_STR : MODULE_OPTION_TYPE_FLAG;
    entry->row.flags      = MODULE_OPTION_FLAG_HIDDEN;
    entry->row.min        = 0;
    entry->row.max        = 0;
    entry->row.def        = 0;
    entry->row.brain_slot = 0;
    entry->row.alias      = NULL;
    entry->row.le         = NULL;
    entry->row.requires   = NULL;
    entry->row.excludes   = NULL;

    entry->value    = 0;
    entry->conflict = true;
  }
}

static const char *file_base (const char *path)
{
  size_t base = strlen (path);

  while ((base > 0) && (path[base - 1] != '/') && (path[base - 1] != '\\')) base--;

  const char *name = &path[base];

  return name;
}

// The hash-mode of a module file, or -1 for a file that is not one: its name has to be the one
// module_filename () gives for the number in it.

static int module_file_mode (const folder_config_t *folder_config, const char *path)
{
  const char *base = file_base (path);

  static const char prefix[] = "module_";

  const size_t prefix_len = strlen (prefix);

  if (strncmp (base, prefix, prefix_len) != 0) return -1;

  u32 mode = 0;

  for (u32 i = 0; i < 5; i++)
  {
    const char c = base[prefix_len + i];

    if ((c < '0') || (c > '9')) return -1;

    mode = (mode * 10) + (u32) (c - '0');
  }

  char expected[HCBUFSIZ_TINY];

  module_filename (folder_config, (int) mode, expected, sizeof (expected));

  if (strcmp (file_base (expected), base) != 0) return -1;

  const int rc = (int) mode;

  return rc;
}

// module_init () fills a module_ctx_t of the size the module was built with, before the size check
// below can turn the module away. Every file in modules/ is loaded on every start, so one built
// against a later interface would write past this build's struct each time. The struct it writes into
// is therefore twice the size and on the heap.

#define MODULE_CTX_SCRATCH_SIZE (2 * sizeof (module_ctx_t))

static void module_options_collect (hashcat_ctx_t *hashcat_ctx, module_options_t *module_options, module_ctx_t *module_ctx, const char *module_file, const u32 hash_mode, module_cache_writer_t *writer, const module_cache_id_t *id)
{
  const hc_dynlib_t handle = hc_dlopen (module_file);

  // A module that cannot be loaded is skipped with one warning, and what lists every hash-mode leaves
  // it out, see module_options_broken (). A run of its hash-mode still stops with the reason when it
  // loads it.

  if (handle == NULL)
  {
    const int plugin_abi = hc_dlplugin_abi (module_file);

    if ((plugin_abi != -1) && (plugin_abi != HC_PLUGIN_ABI_VERSION))
    {
      event_log_warning (hashcat_ctx, "Module %s was built for plugin interface %d, this hashcat provides %d.", module_file, plugin_abi, HC_PLUGIN_ABI_VERSION);
    }
    else
    {
      event_log_warning (hashcat_ctx, "Cannot load module %s: %s", module_file, hc_dlerror ());
    }

    module_options->broken = (u32 *) hcrealloc (module_options->broken, module_options->broken_cnt * sizeof (u32), sizeof (u32));

    module_options->broken[module_options->broken_cnt] = hash_mode;

    module_options->broken_cnt++;

    return;
  }

  const MODULE_INIT module_init = (MODULE_INIT) hc_dlsym (handle, "module_init");

  const module_option_t *rows = NULL;

  if (module_init != NULL)
  {
    memset (module_ctx, 0, MODULE_CTX_SCRATCH_SIZE);

    module_init (module_ctx);

    const bool current = (module_ctx->module_context_size == MODULE_CONTEXT_SIZE_CURRENT) && (module_ctx->module_interface_version >= MODULE_INTERFACE_VERSION_MINIMUM);

    if ((current == true) && (module_ctx->module_register_options != MODULE_DEFAULT) && (module_ctx->module_register_options != NULL))
    {
      rows = module_ctx->module_register_options ();
    }
  }

  if (rows != NULL) module_options_add (hashcat_ctx, module_options, rows, hash_mode, module_file);

  // the rows belong to the module, so they are written before it is unloaded

  if (writer != NULL) module_cache_write_rows (writer, file_base (module_file), id, rows);

  hc_dlclose (handle);
}

// The rows of every module out of the cache in dir, if it holds exactly the module files there are
// now: the same names in the same order, none of them added, removed, rebuilt or touched since. Each
// module's rows then go through module_options_add () as if the module had been loaded.

static bool module_options_replay (hashcat_ctx_t *hashcat_ctx, module_options_t *module_options, const folder_config_t *folder_config, const char *dir, const char *version, const int comptime, const u32 *modes, const module_cache_id_t *ids, const u32 modes_cnt)
{
  module_cache_t *cache = module_cache_load (dir, version, comptime);

  if (cache == NULL) return false;

  bool same = (cache->modules_cnt == modes_cnt);

  char *module_file = (char *) hcmalloc (HCBUFSIZ_TINY);

  for (u32 i = 0; i < modes_cnt; i++)
  {
    if (same == false) break;

    const module_cache_module_t *module = &cache->modules[i];

    module_filename (folder_config, (int) modes[i], module_file, HCBUFSIZ_TINY);

    if (strcmp (module->base, file_base (module_file)) != 0) same = false;

    if (module->id.size       != ids[i].size)       same = false;
    if (module->id.mtime_sec  != ids[i].mtime_sec)  same = false;
    if (module->id.mtime_nsec != ids[i].mtime_nsec) same = false;
  }

  if (same == true)
  {
    for (u32 i = 0; i < modes_cnt; i++)
    {
      if (cache->modules[i].rows_cnt == 0) continue;

      module_filename (folder_config, (int) modes[i], module_file, HCBUFSIZ_TINY);

      module_options_add (hashcat_ctx, module_options, cache->modules[i].rows, modes[i], module_file);
    }
  }

  hcfree (module_file);

  module_cache_free (cache);

  return same;
}

static bool module_cache_disabled (void)
{
  const char *env = getenv ("HASHCAT_MODULE_CACHE_DISABLE");

  if (env == NULL) return false;

  const bool disabled = (env[0] >= '1') && (env[0] <= '9');

  return disabled;
}

int module_options_init (hashcat_ctx_t *hashcat_ctx, const char *install_folder, const char *shared_folder, const char *version, const int comptime)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  // A catalog collected without the folders guesses them, and an installed hashcat keeps its modules
  // somewhere else. So it is collected again once hashcat_session_init () has the folders, unless a
  // command line was parsed against it or a value was set in it already.

  if (user_options->module_options != NULL)
  {
    const module_options_t *guess = user_options->module_options;

    if (guess->guessed == false) return 0;

    if ((install_folder == NULL) && (shared_folder == NULL)) return 0;

    if (user_options->option_table != NULL) return 0;

    for (u32 i = 0; i < guess->entries_cnt; i++)
    {
      if (guess->entries[i].given == true) return 0;
    }

    module_options_destroy (hashcat_ctx);
  }

  module_options_t *module_options = (module_options_t *) hccalloc (1, sizeof (module_options_t));

  user_options->module_options = module_options;

  module_options->guessed = (install_folder == NULL) && (shared_folder == NULL);

  // Without a folder there are no modules and so no module options. The session reports the missing
  // module once it loads the one it needs.

  char *shared_dir = NULL;
  char *cache_dir  = NULL;

  if (folder_early_dirs (install_folder, shared_folder, user_options->cache_path, &shared_dir, &cache_dir) == -1) return 0;

  folder_config_t folder_config;

  memset (&folder_config, 0, sizeof (folder_config));

  folder_config.shared_dir = shared_dir;

  char *modules_dir = NULL;

  hc_asprintf (&modules_dir, "%s/modules", shared_dir);

  char **files = scan_directory (modules_dir);

  hcfree (modules_dir);

  const int files_cnt = count_dictionaries (files);

  u32 *modes = (u32 *) hccalloc (files_cnt + 1, sizeof (u32));

  u32 modes_cnt = 0;

  for (int i = 0; i < files_cnt; i++)
  {
    const int mode = module_file_mode (&folder_config, files[i]);

    if (mode == -1) continue;

    // an old number loads the module of its new number, so a file left under it would register twice

    if (module_hash_mode_resolve ((u32) mode) != (u32) mode) continue;

    modes[modes_cnt] = (u32) mode;

    modes_cnt++;
  }

  for (int i = 0; i < files_cnt; i++) hcfree (files[i]);

  hcfree (files);

  // in the order of the hash-modes, so that --help lists the options in one order

  qsort (modes, modes_cnt, sizeof (u32), sort_by_mode);

  char *module_file = (char *) hcmalloc (HCBUFSIZ_TINY);

  // What the cache compares with: every module file there is now, by name, size and modification
  // time. A caller that does not name the build it is, as a program using libhashcat may not, scans
  // the modules every time, and so does HASHCAT_MODULE_CACHE_DISABLE.

  module_cache_id_t *ids = (module_cache_id_t *) hccalloc (modes_cnt + 1, sizeof (module_cache_id_t));

  bool cache_on = (version != NULL) && (module_cache_disabled () == false);

  for (u32 i = 0; i < modes_cnt; i++)
  {
    if (cache_on == false) break;

    module_filename (&folder_config, (int) modes[i], module_file, HCBUFSIZ_TINY);

    if (module_cache_identity (module_file, &ids[i]) == false) cache_on = false;
  }

  // The cache directory first, then the file an install put beside the modules. A rebuild asked for
  // on the command line reads neither.

  const char *replayed_dir = NULL;

  if ((cache_on == true) && (user_options->module_cache_rebuild == false))
  {
    if ((cache_dir != NULL) && (module_options_replay (hashcat_ctx, module_options, &folder_config, cache_dir, version, comptime, modes, ids, modes_cnt) == true))
    {
      replayed_dir = cache_dir;
    }
    else if (module_options_replay (hashcat_ctx, module_options, &folder_config, shared_dir, version, comptime, modes, ids, modes_cnt) == true)
    {
      replayed_dir = shared_dir;
    }
  }

  const bool replayed = (replayed_dir != NULL);

  if (replayed == false)
  {
    module_cache_writer_t *writer = ((cache_on == true) && (cache_dir != NULL)) ? module_cache_write_begin (version, comptime) : NULL;

    module_ctx_t *module_ctx = (module_ctx_t *) hcmalloc (MODULE_CTX_SCRATCH_SIZE);

    for (u32 i = 0; i < modes_cnt; i++)
    {
      module_filename (&folder_config, (int) modes[i], module_file, HCBUFSIZ_TINY);

      module_options_collect (hashcat_ctx, module_options, module_ctx, module_file, modes[i], writer, &ids[i]);
    }

    hcfree (module_ctx);

    // A module that could not be loaded leaves no file, so the next start tries every module again
    // rather than trust a list that was incomplete.

    if (writer != NULL) module_options->cache_written = module_cache_write_end (writer, cache_dir, (user_options->cache_path == NULL), (module_options->broken_cnt == 0));
  }

  module_options->cache_read = replayed;

  if (cache_dir != NULL) hc_asprintf (&module_options->cache_file, "%s/%s", cache_dir, MODULE_CACHE_FILE);

  // with HASHCAT_OPTION_DEBUG, where the rows came from: a cache file read, the modules scanned and the
  // cache written, or the modules scanned alone

  const char *debug = getenv ("HASHCAT_OPTION_DEBUG");

  if ((debug != NULL) && (debug[0] >= '1') && (debug[0] <= '9'))
  {
    if (replayed == true)
    {
      fprintf (stderr, "OPTION-CACHE read %s/%s\n", replayed_dir, MODULE_CACHE_FILE);
    }
    else if (module_options->cache_written == true)
    {
      fprintf (stderr, "OPTION-CACHE written %s\n", module_options->cache_file);
    }
    else
    {
      fprintf (stderr, "OPTION-CACHE scanned %s\n", (module_options->cache_file == NULL) ? "-" : module_options->cache_file);
    }
  }

  hcfree (ids);
  hcfree (module_file);
  hcfree (modes);
  hcfree (cache_dir);
  hcfree (shared_dir);

  module_options_conflicts (hashcat_ctx, module_options);

  module_options_drop_aliases (module_options);

  return 0;
}

// What --module-cache-rebuild reports once module_options_init () has scanned every module and
// written the cache for it. Success is silent, because make runs it as a build step.

int module_options_cache_report (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t   *user_options   = hashcat_ctx->user_options;
  const module_options_t *module_options = user_options->module_options;

  if (module_cache_disabled () == true)
  {
    event_log_warning (hashcat_ctx, "HASHCAT_MODULE_CACHE_DISABLE is set, so there is no module option cache to write.");

    return 0;
  }

  if ((module_options == NULL) || (module_options->cache_file == NULL))
  {
    event_log_error (hashcat_ctx, "There is no cache directory to write the module option cache to.");

    return -1;
  }

  if (module_options->broken_cnt > 0)
  {
    event_log_error (hashcat_ctx, "%s is not written, because a module could not be loaded.", module_options->cache_file);

    return -1;
  }

  if (module_options->cache_written == false)
  {
    event_log_error (hashcat_ctx, "%s could not be written.", module_options->cache_file);

    return -1;
  }

  return 0;
}

void module_options_destroy (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  module_options_t *module_options = user_options->module_options;

  if (module_options == NULL) return;

  // the option table names the module options by the strings freed below, so it goes first

  option_table_destroy (hashcat_ctx);

  for (u32 i = 0; i < module_options->entries_cnt; i++) module_option_entry_free (&module_options->entries[i]);

  hcfree (module_options->entries);
  hcfree (module_options->broken);
  hcfree (module_options->cache_file);

  hcfree (module_options);

  user_options->module_options = NULL;
}

// Whether the module of a hash-mode could not be loaded when the options were collected. That was
// reported then, so what lists every hash-mode, or loads one only to check the install, leaves it out
// rather than stop at it.

bool module_options_broken (const user_options_t *user_options, const u32 hash_mode)
{
  const module_options_t *module_options = user_options->module_options;

  if (module_options == NULL) return false;

  for (u32 i = 0; i < module_options->broken_cnt; i++)
  {
    if (module_options->broken[i] == hash_mode) return true;
  }

  return false;
}

// For a program that fills user_options itself rather than handing hashcat a command line, once
// module_options_init () has collected the options. The value is checked by hashcat_session_init ()
// together with every other option. A string is not copied, so it has to stay valid until the session
// is destroyed, the same as the strings a caller puts into user_options.

int module_option_set (hashcat_ctx_t *hashcat_ctx, const char *name, const char *value)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  module_option_entry_t *entry = module_option_find (user_options->module_options, name);

  if (entry == NULL)
  {
    event_log_error (hashcat_ctx, "--%s is not an option any module registered.", name);

    return -1;
  }

  if (entry->row.type == MODULE_OPTION_TYPE_FLAG)
  {
    entry->value = 1;
  }
  else if (entry->row.type == MODULE_OPTION_TYPE_U32)
  {
    if ((value == NULL) || (hc_string_is_digit (value) == false))
    {
      event_log_error (hashcat_ctx, "--%s takes a number.", entry->row.name);

      return -1;
    }

    entry->value = hc_strtoull (value, NULL, 10);
  }
  else
  {
    if (value == NULL)
    {
      event_log_error (hashcat_ctx, "--%s needs a value.", entry->row.name);

      return -1;
    }

    entry->str = value;
  }

  entry->given = true;

  return 0;
}

// The checks a module attached to its options, run once it is loaded. hashconfig_init () calls this
// once the module has passed its interface checks, so under autodetect a mode whose check fails is
// skipped silently, the same as a mode that cannot parse the hash.

static rc_final_t module_option_files_rc (const char *value)
{
  char *list = hcstrdup (value);

  char *saveptr = NULL;

  rc_final_t rc_error = RC_FINAL_ERROR_TASK;

  for (char *name = strtok_r (list, ",", &saveptr); name != NULL; name = strtok_r (NULL, ",", &saveptr))
  {
    if (hc_path_exist (name) == false)
    {
      const int path_errno = errno;

      rc_error = path_missing_rc (path_errno);

      break;
    }

    if (hc_path_read (name) == false) rc_error = RC_FINAL_ERROR;
  }

  hcfree (list);

  return rc_error;
}

int module_options_check (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const module_ctx_t   *module_ctx   = hashcat_ctx->module_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->module_options == NULL) return 0;

  if (module_ctx->module_register_options == MODULE_DEFAULT) return 0;

  const module_option_t *rows = module_ctx->module_register_options ();

  if (rows == NULL) return 0;

  // an old hash-mode number loads the module of its new number, which is the one that registered

  const u32 hash_mode = module_hash_mode_resolve (hashconfig->hash_mode);

  for (u32 i = 0; rows[i].name != NULL; i++)
  {
    const module_option_t *row = &rows[i];

    if (row->check == NULL) continue;

    const module_option_entry_t *entry = module_option_find (user_options->module_options, row->name);

    if (entry == NULL) continue;

    if (entry->given == false) continue;

    // An option that modules register differently is left out. The option table refuses it on this
    // mode, with a clearer message than this module's check would give.

    if (module_option_registered (entry, hash_mode) == false) continue;

    char number[24];

    const char *value = entry->str;

    if (entry->row.type == MODULE_OPTION_TYPE_U32)
    {
      snprintf (number, sizeof (number), "%" PRIu64, entry->value);

      value = number;
    }

    if (value == NULL) continue;

    char err[512];

    err[0] = 0;

    if (row->check (value, err, sizeof (err)) == true) continue;

    if (err[0] == 0) snprintf (err, sizeof (err), "--%s %s cannot be used with hash-type %u.", row->name, value, hashconfig->hash_mode);

    if (user_options->autodetect == false) event_log_error (hashcat_ctx, "%s", err);

    // A value that names files that exist and can be read, such as a keyboard mapping or keyfiles the
    // module cannot use, is the task's. A file that is not there, or anything else the module refused,
    // is the command's. One that is there and may not be read is the machine's and stays -1. A comma
    // separates the files of a keyfile list.

    if (user_options->autodetect == false) status_set_rc_error (hashcat_ctx, module_option_files_rc (value));

    return -1;
  }

  return 0;
}

// The rows go into --help where the table in usage.c leaves room for them, in the same columns.

void module_options_usage (const user_options_t *user_options)
{
  const module_options_t *module_options = user_options->module_options;

  if (module_options == NULL) return;

  for (u32 i = 0; i < module_options->entries_cnt; i++)
  {
    const module_option_t *row = &module_options->entries[i].row;

    if ((row->flags & MODULE_OPTION_FLAG_HIDDEN) != 0) continue;

    const char *help_type    = (row->help_type    == NULL) ? "" : row->help_type;
    const char *help         = (row->help         == NULL) ? "" : row->help;
    const char *help_example = (row->help_example == NULL) ? "" : row->help_example;

    if (help_example[0] == 0)
    {
      printf ("     --%-25s| %-4s | %-52s |", row->name, help_type, help);
    }
    else
    {
      printf ("     --%-25s| %-4s | %-52s | %s", row->name, help_type, help, help_example);
    }

    fwrite (EOL, strlen (EOL), 1, stdout);
  }
}

void module_options_logger (hashcat_ctx_t *hashcat_ctx)
{
  const user_options_t *user_options = hashcat_ctx->user_options;
  const logfile_ctx_t  *logfile_ctx  = hashcat_ctx->logfile_ctx;

  const module_options_t *module_options = user_options->module_options;

  if (module_options == NULL) return;

  for (u32 i = 0; i < module_options->entries_cnt; i++)
  {
    const module_option_entry_t *entry = &module_options->entries[i];

    if (entry->row.alias != NULL) continue;

    if (entry->conflict == true) continue;

    if (entry->row.type == MODULE_OPTION_TYPE_STR)
    {
      if (entry->given == true) logfile_top_var_string (entry->row.name, entry->str);
    }
    else
    {
      logfile_top_var_uint (entry->row.name, entry->value);
    }
  }
}
