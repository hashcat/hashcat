/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"
#include "filehandling.h"
#include "folder.h"
#include "shared.h"
#include "tuningdb.h"

int sort_by_tuning_db_alias (const void *v1, const void *v2)
{
  const tuning_db_alias_t *t1 = (const tuning_db_alias_t *) v1;
  const tuning_db_alias_t *t2 = (const tuning_db_alias_t *) v2;

  const int res1 = strcmp (t1->device_name, t2->device_name);

  if (res1 != 0) return (res1);

  return 0;
}

int sort_by_tuning_db_entry (const void *v1, const void *v2)
{
  const tuning_db_entry_t *t1 = (const tuning_db_entry_t *) v1;
  const tuning_db_entry_t *t2 = (const tuning_db_entry_t *) v2;

  const int res1 = strcmp (t1->device_name, t2->device_name);

  if (res1 != 0) return (res1);

  const int res2 = t1->attack_mode
                 - t2->attack_mode;

  if (res2 != 0) return (res2);

  const int res3 = t1->hash_mode
                 - t2->hash_mode;

  if (res3 != 0) return (res3);

  return 0;
}

int tuning_db_init (hashcat_ctx_t *hashcat_ctx)
{
  tuning_db_t     *tuning_db      = hashcat_ctx->tuning_db;
  user_options_t  *user_options   = hashcat_ctx->user_options;
  folder_config_t *folder_config  = hashcat_ctx->folder_config;

  tuning_db->enabled = false;

  if (user_options->hash_info    == true) return 0;
  if (user_options->keyspace     == true) return 0;
  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->usage        == true) return 0;
  if (user_options->version      == true) return 0;
  if (user_options->identify     == true) return 0;
  if (user_options->backend_info  > 0)    return 0;

  tuning_db->enabled = true;

  char *tuning_db_folder = NULL;

  hc_asprintf (&tuning_db_folder, "%s/tunings", folder_config->shared_dir);

  char **tuning_db_files = scan_directory (tuning_db_folder);

  for (int i = 0; tuning_db_files[i] != NULL; i++)
  {
    char *tuning_db_file = tuning_db_files[i];

    const size_t suflen = strlen (TUNING_DB_SUFFIX);

    const size_t dblen = strlen (tuning_db_file);

    if (dblen < suflen) continue; // make sure to not do any out-of-boundary reads

    if (memcmp (tuning_db_file + dblen - suflen, TUNING_DB_SUFFIX, suflen) != 0) continue;

    HCFILE fp;

    if (hc_fopen (&fp, tuning_db_file, "rb") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", tuning_db_file, strerror (errno));

      return -1;
    }

    hcfree (tuning_db_file);

    int line_num = 0;

    char *buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

    while (!hc_feof (&fp))
    {
      char *line_buf = hc_fgets (buf, HCBUFSIZ_LARGE - 1, &fp);

      if (line_buf == NULL) break;

      line_num++;

      const size_t line_len = in_superchop (line_buf);

      if (line_len == 0) continue;

      if (line_buf[0] == '#') continue;

      tuning_db_process_line (hashcat_ctx, line_buf, line_num);
    }

    hcfree (buf);

    hc_fclose (&fp);
  }

  hcfree (tuning_db_files);

  // todo: print loaded 'cnt' message

  // sort the database

  qsort (tuning_db->alias_buf, tuning_db->alias_cnt, sizeof (tuning_db_alias_t), sort_by_tuning_db_alias);
  qsort (tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

  return 0;
}

void tuning_db_destroy (hashcat_ctx_t *hashcat_ctx)
{
  tuning_db_t *tuning_db = hashcat_ctx->tuning_db;

  if (tuning_db->enabled == false) return;

  int i;

  for (i = 0; i < tuning_db->alias_cnt; i++)
  {
    tuning_db_alias_t *alias = &tuning_db->alias_buf[i];

    hcfree (alias->device_name);
    hcfree (alias->alias_name);
  }

  for (i = 0; i < tuning_db->entry_cnt; i++)
  {
    tuning_db_entry_t *entry = &tuning_db->entry_buf[i];

    hcfree ((void *)entry->device_name);
  }

  hcfree (tuning_db->alias_buf);
  hcfree (tuning_db->entry_buf);

  memset (tuning_db, 0, sizeof (tuning_db_t));
}

bool tuning_db_process_line (hashcat_ctx_t *hashcat_ctx, const char *line_buf, const int line_num)
{
  tuning_db_t           *tuning_db          = hashcat_ctx->tuning_db;
  user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  #define ADD_DB_ENTRIES 1

  if (tuning_db->alias_cnt == tuning_db->alias_alloc)
  {
    tuning_db->alias_buf    = (tuning_db_alias_t *) hcrealloc (tuning_db->alias_buf, tuning_db->alias_alloc * sizeof (tuning_db_alias_t), ADD_DB_ENTRIES * sizeof (tuning_db_alias_t));
    tuning_db->alias_alloc += ADD_DB_ENTRIES;
  }

  if (tuning_db->entry_cnt == tuning_db->entry_alloc)
  {
    tuning_db->entry_buf    = (tuning_db_entry_t *) hcrealloc (tuning_db->entry_buf, tuning_db->entry_alloc * sizeof (tuning_db_entry_t), ADD_DB_ENTRIES * sizeof (tuning_db_entry_t));
    tuning_db->entry_alloc += ADD_DB_ENTRIES;
  }

  char *buf = hcstrdup (line_buf);

  char *token_ptr[7] = { NULL };

  int token_cnt = 0;

  char *saveptr = NULL;

  char *next = strtok_r (buf, "\t ", &saveptr);

  token_ptr[token_cnt] = next;

  token_cnt++;

  while ((next = strtok_r ((char *) NULL, "\t ", &saveptr)) != NULL)
  {
    token_ptr[token_cnt] = next;

    token_cnt++;
  }

  if (token_cnt == 2)
  {
    char *device_name = token_ptr[0];
    char *alias_name  = token_ptr[1];

    tuning_db_alias_t *alias = &tuning_db->alias_buf[tuning_db->alias_cnt];

    alias->device_name = hcstrdup (device_name);
    alias->alias_name  = hcstrdup (alias_name);

    tuning_db->alias_cnt++;
  }
  else if (token_cnt == 6)
  {
    if ((token_ptr[1][0] != '0') &&
        (token_ptr[1][0] != '1') &&
        (token_ptr[1][0] != '3') &&
        (token_ptr[1][0] != '9') &&
        (token_ptr[1][0] != '*'))
    {
      event_log_warning (hashcat_ctx, "Tuning-db: Invalid attack_mode '%c' in Line '%d'", token_ptr[1][0], line_num);

      hcfree (buf);

      return false;
    }

    if ((token_ptr[3][0] != '1') &&
        (token_ptr[3][0] != '2') &&
        (token_ptr[3][0] != '4') &&
        (token_ptr[3][0] != '8') &&
        (token_ptr[3][0] != 'N'))
    {
      event_log_warning (hashcat_ctx, "Tuning-db: Invalid vector_width '%c' in Line '%d'", token_ptr[3][0], line_num);

      hcfree (buf);

      return false;
    }

    char *device_name = token_ptr[0];

    int hash_mode     = -1;
    int attack_mode   = -1;
    int vector_width  = -1;
    int kernel_accel  = -1;
    int kernel_loops  = -1;

    if (token_ptr[1][0] != '*') attack_mode   = (int) strtol (token_ptr[1], NULL, 10);
    if (token_ptr[2][0] != '*') hash_mode     = (int) strtol (token_ptr[2], NULL, 10);
    if (token_ptr[3][0] != 'N') vector_width  = (int) strtol (token_ptr[3], NULL, 10);

    if (token_ptr[4][0] == 'A')
    {
      kernel_accel = 0;
    }
    else if (token_ptr[4][0] == 'M')
    {
      kernel_accel = 1024;
    }
    else if (token_ptr[4][0] == 'N')
    {
      kernel_accel = -1;
    }
    else
    {
      kernel_accel = (int) strtol (token_ptr[4], NULL, 10);

      if ((kernel_accel < 1) || (kernel_accel > 1024))
      {
        event_log_warning (hashcat_ctx, "Tuning-db: Invalid kernel_accel '%d' in Line '%d'", kernel_accel, line_num);

        hcfree (buf);

        return false;
      }
    }

    if (token_ptr[5][0] == 'A')
    {
      kernel_loops = 0;
    }
    else if (token_ptr[5][0] == 'M')
    {
      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        kernel_loops = KERNEL_RULES;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        kernel_loops = KERNEL_COMBS;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
      {
        kernel_loops = KERNEL_BFS;
      }
    }
    else
    {
      kernel_loops = (int) strtol (token_ptr[5], NULL, 10);

      if (kernel_loops < 1)
      {
        event_log_warning (hashcat_ctx, "Tuning-db: Invalid kernel_loops '%d' in Line '%d'", kernel_loops, line_num);

        hcfree (buf);

        return false;
      }

      if ((user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) && (kernel_loops > KERNEL_RULES))
      {
        event_log_warning (hashcat_ctx, "Tuning-db: Invalid kernel_loops '%d' in Line '%d'", kernel_loops, line_num);

        hcfree (buf);

        return false;
      }

      if ((user_options_extra->attack_kern == ATTACK_KERN_COMBI) && (kernel_loops > KERNEL_COMBS))
      {
        event_log_warning (hashcat_ctx, "Tuning-db: Invalid kernel_loops '%d' in Line '%d'", kernel_loops, line_num);

        hcfree (buf);

        return false;
      }

      if ((user_options_extra->attack_kern == ATTACK_KERN_BF) && (kernel_loops > KERNEL_BFS))
      {
        event_log_warning (hashcat_ctx, "Tuning-db: Invalid kernel_loops '%d' in Line '%d'", kernel_loops, line_num);

        hcfree (buf);

        return false;
      }
    }

    tuning_db_entry_t *entry = &tuning_db->entry_buf[tuning_db->entry_cnt];

    entry->device_name  = hcstrdup (device_name);
    entry->attack_mode  = attack_mode;
    entry->hash_mode    = hash_mode;
    entry->vector_width = vector_width;
    entry->kernel_accel = kernel_accel;
    entry->kernel_loops = kernel_loops;

    tuning_db->entry_cnt++;
  }
  else
  {
    event_log_warning (hashcat_ctx, "Tuning-db: Invalid number of token in Line '%d'", line_num);

    hcfree (buf);

    return false;
  }

  hcfree (buf);

  return true;
}

tuning_db_entry_t *tuning_db_search_real (hashcat_ctx_t *hashcat_ctx, const char *device_name, const cl_device_type device_type, int attack_mode, const int hash_mode)
{
  tuning_db_t *tuning_db = hashcat_ctx->tuning_db;

  static tuning_db_entry_t s;

  // first we need to convert all spaces in the device_name to underscore

  char *device_name_nospace = hcstrdup (device_name);

  const size_t device_name_length = strlen (device_name_nospace);

  size_t i;

  for (i = 0; i < device_name_length; i++)
  {
    if (device_name_nospace[i] == ' ') device_name_nospace[i] = '_';
  }

  // find out if there's an alias configured

  char *device_name_nospace2 = hcstrdup (device_name_nospace);

  tuning_db_alias_t a;

  a.device_name = device_name_nospace2;

  char *alias_name = NULL;

  for (i = device_name_length; i >= 1; i--)
  {
    device_name_nospace2[i] = 0;

    tuning_db_alias_t *alias = (tuning_db_alias_t *) bsearch (&a, tuning_db->alias_buf, tuning_db->alias_cnt, sizeof (tuning_db_alias_t), sort_by_tuning_db_alias);

    if (alias == NULL) continue;

    alias_name = alias->alias_name;

    break;
  }

  hcfree (device_name_nospace2);

  // attack-mode 6 and 7 are attack-mode 1 basically

  if (attack_mode == 6) attack_mode = 1;
  if (attack_mode == 7) attack_mode = 1;

  // bsearch is not ideal but fast enough

  s.device_name = device_name_nospace;
  s.attack_mode = attack_mode;
  s.hash_mode   = hash_mode;

  tuning_db_entry_t *entry = NULL;

  // this will produce all 2^3 combinations required

  for (i = 0; i < 8; i++)
  {
    s.device_name = (i & 1) ? "*" : device_name_nospace;
    s.attack_mode = (i & 2) ?  -1 : attack_mode;
    s.hash_mode   = (i & 4) ?  -1 : hash_mode;

    entry = (tuning_db_entry_t *) bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

    if (entry != NULL) break;

    // in non-wildcard mode do some additional checks:

    if ((i & 1) == 0)
    {
      // in case we have an alias-name

      if (alias_name != NULL)
      {
        s.device_name = alias_name;

        entry = (tuning_db_entry_t *) bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

        if (entry != NULL) break;
      }

      // or by device type

      if (device_type & CL_DEVICE_TYPE_CPU)
      {
        s.device_name = "DEVICE_TYPE_CPU";
      }
      else if (device_type & CL_DEVICE_TYPE_GPU)
      {
        s.device_name = "DEVICE_TYPE_GPU";
      }
      else if (device_type & CL_DEVICE_TYPE_ACCELERATOR)
      {
        s.device_name = "DEVICE_TYPE_ACCELERATOR";
      }

      entry = (tuning_db_entry_t *) bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

      if (entry != NULL) break;
    }
  }

  // free converted device_name

  hcfree (device_name_nospace);

  return entry;
}

tuning_db_entry_t *tuning_db_search (hashcat_ctx_t *hashcat_ctx, const char *device_name, const cl_device_type device_type, int attack_mode, const int hash_mode)
{
  tuning_db_entry_t *entry = NULL;

  const char *NV_prefix = (const char *) "NVIDIA ";

  if (strncmp (device_name, NV_prefix, strlen (NV_prefix)) == 0)
  {
    entry = tuning_db_search_real (hashcat_ctx, device_name + strlen (NV_prefix), device_type, attack_mode, hash_mode);

    if (entry) return entry;
  }

  const char *AMD_prefix = (const char *) "AMD ";

  if (strncmp (device_name, AMD_prefix, strlen (AMD_prefix)) == 0)
  {
    entry = tuning_db_search_real (hashcat_ctx, device_name + strlen (AMD_prefix), device_type, attack_mode, hash_mode);

    if (entry) return entry;
  }

  entry = tuning_db_search_real (hashcat_ctx, device_name, device_type, attack_mode, hash_mode);

  return entry;
}
