/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "module_options.h"

// What a module calls to read back the value of an option it registered. These are kept apart from
// src/module_options.c because under SHARED=0 every module links in its own copy of what it calls, and
// reading a value needs nothing but the struct user_options points at.

module_option_entry_t *module_option_find (const module_options_t *module_options, const char *name)
{
  if (module_options == NULL) return NULL;

  for (u32 i = 0; i < module_options->entries_cnt; i++)
  {
    module_option_entry_t *entry = &module_options->entries[i];

    if (strcmp (entry->row.name, name) != 0) continue;

    // a module reads an option by its own name, never by an alias, but a library caller may set one

    if (entry->row.alias != NULL)
    {
      module_option_entry_t *target = module_option_find (module_options, entry->row.alias);

      return target;
    }

    return entry;
  }

  return NULL;
}

// An option that modules register differently is left out for every hash-mode, so a module reads it
// the way it reads a name nobody registered.

bool module_option_given (const user_options_t *user_options, const char *name)
{
  const module_option_entry_t *entry = module_option_find (user_options->module_options, name);

  if (entry == NULL) return false;

  if (entry->conflict == true) return false;

  return entry->given;
}

u32 module_option_u32 (const user_options_t *user_options, const char *name)
{
  const module_option_entry_t *entry = module_option_find (user_options->module_options, name);

  if (entry == NULL) return 0;

  if (entry->conflict == true) return 0;

  const u32 value = (u32) entry->value;

  return value;
}

const char *module_option_str (const user_options_t *user_options, const char *name)
{
  const module_option_entry_t *entry = module_option_find (user_options->module_options, name);

  if (entry == NULL) return NULL;

  if (entry->conflict == true) return NULL;

  if (entry->given == false) return NULL;

  return entry->str;
}

bool module_option_registered (const module_option_entry_t *entry, const u32 hash_mode)
{
  if (entry->conflict == true) return false;

  for (u32 i = 0; i < entry->modes_cnt; i++)
  {
    if (entry->modes[i] == hash_mode) return true;
  }

  return false;
}
