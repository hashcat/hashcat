/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "folder.h"
#include "induct.h"

static int sort_by_mtime (const void *p1, const void *p2)
{
  const char **f1 = (const char **) p1;
  const char **f2 = (const char **) p2;

  struct stat s1; stat (*f1, &s1);
  struct stat s2; stat (*f2, &s2);

  return s2.st_mtime - s1.st_mtime;
}

int induct_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  induct_ctx_t    *induct_ctx    = hashcat_ctx->induct_ctx;
  status_ctx_t    *status_ctx    = hashcat_ctx->status_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  induct_ctx->enabled = false;

  if (user_options->benchmark   == true) return 0;
  if (user_options->keyspace    == true) return 0;
  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->stdout_flag == true) return 0;
  if (user_options->speed_only  == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  if (user_options->attack_mode == ATTACK_MODE_BF)    return 0;
  if (user_options->attack_mode == ATTACK_MODE_COMBI) return 0;

  induct_ctx->enabled = true;

  if (user_options->induction_dir == NULL)
  {
    char *root_directory = (char *) hcmalloc (hashcat_ctx, HCBUFSIZ_TINY); VERIFY_PTR (root_directory);

    snprintf (root_directory, HCBUFSIZ_TINY - 1, "%s/%s.%s", folder_config->session_dir, user_options->session, INDUCT_DIR);

    if (rmdir (root_directory) == -1)
    {
      if (errno == ENOENT)
      {
        // good, we can ignore
      }
      else if (errno == ENOTEMPTY)
      {
        char *root_directory_mv = (char *) hcmalloc (hashcat_ctx, HCBUFSIZ_TINY); VERIFY_PTR (root_directory_mv);

        snprintf (root_directory_mv, HCBUFSIZ_TINY - 1, "%s/%s.induct.%d", folder_config->session_dir, user_options->session, (int) status_ctx->proc_start);

        if (rename (root_directory, root_directory_mv) != 0)
        {
          event_log_error (hashcat_ctx, "Rename directory %s to %s: %s", root_directory, root_directory_mv, strerror (errno));

          return -1;
        }
      }
      else
      {
        event_log_error (hashcat_ctx, "%s: %s", root_directory, strerror (errno));

        return -1;
      }
    }

    if (hc_mkdir (root_directory, 0700) == -1)
    {
      event_log_error (hashcat_ctx, "%s: %s", root_directory, strerror (errno));

      return -1;
    }

    induct_ctx->root_directory = root_directory;
  }
  else
  {
    induct_ctx->root_directory = hcstrdup (hashcat_ctx, user_options->induction_dir);
  }

  return 0;
}

void induct_ctx_scan (hashcat_ctx_t *hashcat_ctx)
{
  induct_ctx_t *induct_ctx = hashcat_ctx->induct_ctx;

  if (induct_ctx->enabled == false) return;

  induct_ctx->induction_dictionaries = scan_directory (hashcat_ctx, induct_ctx->root_directory);

  induct_ctx->induction_dictionaries_cnt = count_dictionaries (induct_ctx->induction_dictionaries);

  qsort (induct_ctx->induction_dictionaries, (size_t) induct_ctx->induction_dictionaries_cnt, sizeof (char *), sort_by_mtime);
}

void induct_ctx_cleanup (hashcat_ctx_t *hashcat_ctx)
{
  induct_ctx_t *induct_ctx = hashcat_ctx->induct_ctx;

  if (induct_ctx->enabled == false) return;

  for (int file_pos = 0; file_pos < induct_ctx->induction_dictionaries_cnt; file_pos++)
  {
    struct stat induct_stat;

    if (stat (induct_ctx->induction_dictionaries[file_pos], &induct_stat) == 0)
    {
      unlink (induct_ctx->induction_dictionaries[file_pos]);
    }
  }
}

void induct_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  induct_ctx_t *induct_ctx = hashcat_ctx->induct_ctx;

  if (induct_ctx->enabled == false) return;

  if (rmdir (induct_ctx->root_directory) == -1)
  {
    if (errno == ENOENT)
    {
      // good, we can ignore
    }
    else if (errno == ENOTEMPTY)
    {
      // good, we can ignore
    }
    else
    {
      event_log_error (hashcat_ctx, "%s: %s", induct_ctx->root_directory, strerror (errno));

      //return -1;
    }
  }

  hcfree (induct_ctx->root_directory);

  memset (induct_ctx, 0, sizeof (induct_ctx_t));
}
