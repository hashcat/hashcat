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

// A device resolves to at most two aliases: the one the tuning file names for it, and the one derived
// from its vendor.

#define TUNING_DB_ALIAS_MAX 2

int sort_by_tuning_db_entry (const void *v1, const void *v2)
{
  const tuning_db_entry_t *t1 = (const tuning_db_entry_t *) v1;
  const tuning_db_entry_t *t2 = (const tuning_db_entry_t *) v2;

  const int res1 = strcmp (t1->device_name, t2->device_name);

  if (res1 != 0) return (res1);

  const int res2 = t1->attack_kern
                 - t2->attack_kern;

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

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->keyspace     == true) return 0;
  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->version      == true) return 0;
  if (user_options->identify     == true) return 0;

  tuning_db->enabled = true;

  char *tuning_db_folder = NULL;

  hc_asprintf (&tuning_db_folder, "%s/tunings", folder_config->shared_dir);

  char **tuning_db_files = scan_directory (tuning_db_folder);

  hcfree (tuning_db_folder);

  for (int i = 0; tuning_db_files[i] != NULL; i++)
  {
    char *tuning_db_file = tuning_db_files[i];

    const size_t suflen = strlen (TUNING_DB_SUFFIX);

    const size_t dblen = strlen (tuning_db_file);

    if (dblen < suflen)
    {
      hcfree (tuning_db_file);

      continue; // make sure to not do any out-of-boundary reads
    }

    if (memcmp (tuning_db_file + dblen - suflen, TUNING_DB_SUFFIX, suflen) != 0)
    {
      hcfree (tuning_db_file);

      continue;
    }

    HCFILE fp;

    if (hc_fopen (&fp, tuning_db_file, "rb") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", tuning_db_file, hc_fopen_strerror ());

      for (int j = 0; tuning_db_files[j] != NULL; j++) hcfree (tuning_db_files[j]);

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
    // a line with more fields than the table holds is none of the shapes below, and storing the
    // extra pointers walks off the end of the array

    if (token_cnt == (int) (sizeof (token_ptr) / sizeof (token_ptr[0]))) break;

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
        (token_ptr[1][0] != '4') &&
        (token_ptr[1][0] != '*'))
    {
      event_log_warning (hashcat_ctx, "Tuning-db: Invalid attack_kern '%c' in Line '%d'", token_ptr[1][0], line_num);

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
    int attack_kern   = -1;
    int vector_width  = -1;
    int kernel_accel  = -1;
    int kernel_loops  = -1;

    if (token_ptr[1][0] != '*') attack_kern   = (int) strtol (token_ptr[1], NULL, 10);

    // The column is the attack kern type, which is also the kernel suffix and the -a value that
    // reaches it: 0, 1, 3 and 4 are the _a0, _a1, _a3 and _a4 kernels. There is no _a2.
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
    entry->attack_kern  = attack_kern;
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

// Which vendor's rows a device should fall back on, worked out from what the backend recorded rather
// than from a list of card names. CUDA, HIP and Metal each hardcode their vendor id at enumeration and
// an OpenCL device gets one mapped from its vendor string, so this one field answers for every backend.
//
// GPU only. The vendor rows were all measured on discrete cards, and an AMD or an Intel CPU reports its
// maker's vendor id exactly as its GPUs do, so without this gate a Ryzen would start taking tuning
// meant for a Radeon.
//
// Three ids are deliberately absent. VENDOR_ID_AMD_USE_INTEL is the string GenuineIntel, an Intel CPU
// seen through AMD's runtime, so the name is the opposite of what it is. VENDOR_ID_MESA does not say
// whose silicon is underneath. Metal reports VENDOR_ID_APPLE for every device it drives, including an
// AMD card in an Intel Mac, so an Apple alias derived here could not tell those apart.

static const char *tuning_db_vendor_alias (const cl_device_type device_type, const cl_uint device_vendor_id, const char *device_name)
{
  if ((device_type & CL_DEVICE_TYPE_GPU) == 0) return NULL;

  switch (device_vendor_id)
  {
    case VENDOR_ID_NV:          return "ALIAS_NV";
    case VENDOR_ID_AMD:         return "ALIAS_AMD";
    case VENDOR_ID_AMD_USE_HIP: return "ALIAS_AMD";
    case VENDOR_ID_INTEL_SDK:   return "ALIAS_INTEL";
  }

  // Two runtimes do not say whose silicon they are driving. Metal reports Apple for every device it
  // has, including a Radeon in an Intel Mac, and Mesa reports itself. Both still put the vendor in the
  // device name, and a handful of vendor prefixes is a far smaller thing to keep current than a list
  // of every card that vendor ever shipped.

  if (strncmp (device_name, "NVIDIA ", 7) == 0) return "ALIAS_NV";
  if (strncmp (device_name, "AMD ",    4) == 0) return "ALIAS_AMD";
  if (strncmp (device_name, "Intel",   5) == 0) return "ALIAS_INTEL";

  return NULL;
}

static tuning_db_entry_t *tuning_db_search_real (hashcat_ctx_t *hashcat_ctx, const char *device_name, const cl_device_type device_type, const char *vendor_alias, const int attack_kern, const int hash_mode)
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

  char *alias_names[TUNING_DB_ALIAS_MAX];

  int alias_cnt = 0;

  for (i = device_name_length; i >= 1; i--)
  {
    device_name_nospace2[i] = 0;

    tuning_db_alias_t *alias = (tuning_db_alias_t *) bsearch (&a, tuning_db->alias_buf, tuning_db->alias_cnt, sizeof (tuning_db_alias_t), sort_by_tuning_db_alias);

    if (alias == NULL) continue;

    alias_names[alias_cnt] = alias->alias_name;

    alias_cnt++;

    break;
  }

  hcfree (device_name_nospace2);

  // The tuning file cannot name a card that did not exist when it was written, and that is the one
  // card most likely to be missing a tuning. The vendor alias is therefore derived rather than looked
  // up, from what the backend already worked out at enumeration. It goes behind the file's own alias,
  // so a row written for a narrower group still wins.

  if ((vendor_alias != NULL) && (alias_cnt < TUNING_DB_ALIAS_MAX))
  {
    bool have_it = false;

    for (int j = 0; j < alias_cnt; j++)
    {
      if (strcmp (alias_names[j], vendor_alias) == 0) have_it = true;
    }

    if (have_it == false)
    {
      alias_names[alias_cnt] = (char *) vendor_alias;

      alias_cnt++;
    }
  }

  // bsearch is not ideal but fast enough

  s.device_name = device_name_nospace;
  s.attack_kern = attack_kern;
  s.hash_mode   = hash_mode;

  tuning_db_entry_t *entry = NULL;

  // this will produce all 2^3 combinations required

  for (i = 0; i < 8; i++)
  {
    s.device_name = (i & 1) ? "*" : device_name_nospace;
    s.attack_kern = (i & 2) ?  -1 : attack_kern;
    s.hash_mode   = (i & 4) ?  -1 : hash_mode;

    entry = (tuning_db_entry_t *) bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

    if (entry != NULL) break;

    // in non-wildcard mode do some additional checks:

    if ((i & 1) == 0)
    {
      // in case we have an alias-name

      for (int j = 0; j < alias_cnt; j++)
      {
        s.device_name = alias_names[j];

        entry = (tuning_db_entry_t *) bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

        if (entry != NULL) break;
      }

      if (entry != NULL) break;

      // or by device type

      if (device_type & CL_DEVICE_TYPE_CPU)
      {
        s.device_name = "DEVICE_TYPE_CPU";
      }
      else if (device_type & CL_DEVICE_TYPE_GPU)
      {
        s.device_name = "DEVICE_TYPE_GPU";
      }

      entry = (tuning_db_entry_t *) bsearch (&s, tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);

      if (entry != NULL) break;
    }
  }

  // free converted device_name

  hcfree (device_name_nospace);

  return entry;
}

tuning_db_entry_t *tuning_db_search (hashcat_ctx_t *hashcat_ctx, const char *device_name, const cl_device_type device_type, const cl_uint device_vendor_id, const int attack_kern, const int hash_mode)
{
  // Worked out once, and from the name exactly as the device reported it, because the searches below
  // retry with a vendor prefix stripped off the front and that prefix is one of the things it reads.

  const char *vendor_alias = tuning_db_vendor_alias (device_type, device_vendor_id, device_name);

  tuning_db_entry_t *entry = NULL;

  const char *NV_prefix = (const char *) "NVIDIA ";

  if (strncmp (device_name, NV_prefix, strlen (NV_prefix)) == 0)
  {
    entry = tuning_db_search_real (hashcat_ctx, device_name + strlen (NV_prefix), device_type, vendor_alias, attack_kern, hash_mode);

    if (entry) return entry;
  }

  const char *AMD_prefix = (const char *) "AMD ";

  if (strncmp (device_name, AMD_prefix, strlen (AMD_prefix)) == 0)
  {
    entry = tuning_db_search_real (hashcat_ctx, device_name + strlen (AMD_prefix), device_type, vendor_alias, attack_kern, hash_mode);

    if (entry) return entry;
  }

  entry = tuning_db_search_real (hashcat_ctx, device_name, device_type, vendor_alias, attack_kern, hash_mode);

  if (entry) return entry;

  return NULL;
}
