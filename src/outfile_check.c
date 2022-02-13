/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "filehandling.h"
#include "folder.h"
#include "hashes.h"
#include "shared.h"
#include "thread.h"
#include "outfile_check.h"

static int sort_by_salt_buf (const void *v1, const void *v2, MAYBE_UNUSED void * v3)
{
  return sort_by_salt (v1, v2);
}

static int outfile_remove (hashcat_ctx_t *hashcat_ctx)
{
  // some hash-dependent constants

  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  module_ctx_t   *module_ctx   = hashcat_ctx->module_ctx;
  outcheck_ctx_t *outcheck_ctx = hashcat_ctx->outcheck_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  const size_t dgst_size = hashconfig->dgst_size;
  const bool   is_salted = hashconfig->is_salted;
  const char   separator = hashconfig->separator;

  salt_t    *salts_buf   = hashes->salts_buf;
  const u32  salts_cnt   = hashes->salts_cnt;

  char      *digests_buf = (char *) hashes->digests_buf;

  char *root_directory      = outcheck_ctx->root_directory;
  u32   outfile_check_timer = user_options->outfile_check_timer;

  // buffers
  hash_t hash_buf;

  hash_buf.digest    = hcmalloc (dgst_size);
  hash_buf.salt      = NULL;
  hash_buf.esalt     = NULL;
  hash_buf.hook_salt = NULL;
  hash_buf.cracked   = 0;
  hash_buf.hash_info = NULL;
  hash_buf.pw_buf    = NULL;
  hash_buf.pw_len    = 0;

  if (hashconfig->is_salted == true)
  {
    hash_buf.salt = (salt_t *) hcmalloc (sizeof (salt_t));
  }

  if (hashconfig->esalt_size > 0)
  {
    hash_buf.esalt = hcmalloc (hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hash_buf.hook_salt = hcmalloc (hashconfig->hook_salt_size);
  }

  outfile_data_t *out_info = NULL;

  char **out_files = NULL;

  time_t folder_mtime = 0;

  int out_cnt = 0;

  u32 check_left = outfile_check_timer; // or 1 if we want to check it at startup

  while (status_ctx->shutdown_inner == false)
  {
    sleep (1);

    if (status_ctx->devices_status != STATUS_RUNNING) continue;

    check_left--;

    if (check_left != 0) continue;

    check_left = outfile_check_timer;

    if (hc_path_exist (root_directory) == false) continue;

    const bool is_dir = hc_path_is_directory (root_directory);

    if (is_dir == false) continue;

    struct stat outfile_check_stat;

    if (stat (root_directory, &outfile_check_stat) == -1)
    {
      event_log_error (hashcat_ctx, "%s: %s", root_directory, strerror (errno));

      hcfree (out_files);
      hcfree (out_info);

      return -1;
    }

    if (outfile_check_stat.st_mtime > folder_mtime)
    {
      char **out_files_new = scan_directory (root_directory);

      int out_cnt_new = count_dictionaries (out_files_new);

      outfile_data_t *out_info_new = NULL;

      if (out_cnt_new > 0)
      {
        out_info_new = (outfile_data_t *) hccalloc (out_cnt_new, sizeof (outfile_data_t));

        for (int i = 0; i < out_cnt_new; i++)
        {
          out_info_new[i].file_name = out_files_new[i];

          // check if there are files that we have seen/checked before (and not changed)

          for (int j = 0; j < out_cnt; j++)
          {
            if (strcmp (out_info[j].file_name, out_info_new[i].file_name) != 0) continue;

            struct stat outfile_stat;

            if (stat (out_info_new[i].file_name, &outfile_stat) != 0) continue;

            if (outfile_stat.st_ctime != out_info[j].ctime) continue;

            out_info_new[i].ctime = out_info[j].ctime;
            out_info_new[i].seek  = out_info[j].seek;
          }
        }
      }

      hcfree (out_info);
      hcfree (out_files);

      out_files = out_files_new;
      out_cnt   = out_cnt_new;
      out_info  = out_info_new;

      folder_mtime = outfile_check_stat.st_mtime;
    }

    for (int j = 0; j < out_cnt; j++)
    {
      HCFILE fp;

      if (hc_fopen (&fp, out_info[j].file_name, "rb") == false) continue;

      //hc_thread_mutex_lock (status_ctx->mux_display);

      struct stat outfile_stat;

      if (hc_fstat (&fp, &outfile_stat))
      {
        hc_fclose (&fp);

        continue;
      }

      if (outfile_stat.st_ctime > out_info[j].ctime)
      {
        out_info[j].ctime = outfile_stat.st_ctime;
        out_info[j].seek  = 0;
      }

      hc_fseek (&fp, out_info[j].seek, SEEK_SET);

      char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

      // large portion of the following code is the same as in potfile_remove_parse
      // maybe subject of a future optimization

      while (!hc_feof (&fp))
      {
        size_t line_len = fgetl (&fp, line_buf, HCBUFSIZ_LARGE);

        if (line_len == 0) continue;

        // this fake separator is used to enable loading outfiles without password

        line_buf[line_len] = separator;

        line_len++;

        for (int tries = 0; tries < PW_MAX; tries++)
        {
          char *last_separator = strrchr (line_buf, separator);

          if (last_separator == NULL) break;

          char *line_hash_buf = line_buf;

          int line_hash_len = last_separator - line_buf;

          line_hash_buf[line_hash_len] = 0;

          if (line_hash_len == 0) continue;

          if (hash_buf.salt)
          {
            memset (hash_buf.salt, 0, sizeof (salt_t));
          }

          if (hash_buf.esalt)
          {
            memset (hash_buf.esalt, 0, hashconfig->esalt_size);
          }

          if (hash_buf.hook_salt)
          {
            memset (hash_buf.hook_salt, 0, hashconfig->hook_salt_size);
          }

          int parser_status = module_ctx->module_hash_decode (hashconfig, hash_buf.digest, hash_buf.salt, hash_buf.esalt, hash_buf.hook_salt, hash_buf.hash_info, line_buf, line_hash_len);

          if (parser_status != PARSER_OK) continue;

          salt_t *salt_buf = salts_buf;

          if (is_salted == true)
          {
            salt_buf = (salt_t *) hc_bsearch_r (hash_buf.salt, salts_buf, salts_cnt, sizeof (salt_t), sort_by_salt_buf, (void *) hashconfig);
          }

          if (salt_buf == NULL) continue;

          const u32 salt_pos = salt_buf - salts_buf; // the offset from the start of the array (unit: sizeof (salt_t))

          if (hashes->salts_shown[salt_pos] == 1) break; // already marked as cracked (no action needed)

          u32 idx = salt_buf->digests_offset;

          bool cracked = false;

          if (hashconfig->outfile_check_nocomp == true)
          {
            cracked = true;
          }
          else
          {
            char *digests_buf_ptr = digests_buf + (salt_buf->digests_offset * dgst_size);
            u32   digests_buf_cnt = salt_buf->digests_cnt;

            char *digest_buf = (char *) hc_bsearch_r (hash_buf.digest, digests_buf_ptr, digests_buf_cnt, dgst_size, sort_by_digest_p0p1, (void *) hashconfig);

            if (digest_buf != NULL)
            {
              idx += (digest_buf - digests_buf_ptr) / dgst_size;

              if (hashes->digests_shown[idx] == 1) break;

              cracked = true;
            }
          }

          if (cracked == true)
          {
            hashes->digests_shown[idx] = 1;

            hashes->digests_done++;

            salt_buf->digests_done++;

            if (salt_buf->digests_done == salt_buf->digests_cnt)
            {
              hashes->salts_shown[salt_pos] = 1;

              hashes->salts_done++;

              if (hashes->salts_done == salts_cnt) mycracked (hashcat_ctx);
            }

            break;
          }

          if (status_ctx->shutdown_inner == true) break;
        }
      }

      hcfree (line_buf);

      out_info[j].seek = hc_ftell (&fp);

      //hc_thread_mutex_unlock (status_ctx->mux_display);

      hc_fclose (&fp);

      if (status_ctx->shutdown_inner == true) break;
    }
  }

  hcfree (hash_buf.esalt);
  hcfree (hash_buf.hook_salt);

  hcfree (hash_buf.salt);

  hcfree (hash_buf.digest);

  hcfree (out_info);

  hcfree (out_files);

  return 0;
}

HC_API_CALL void *thread_outfile_remove (void *p)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) p;

  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const outcheck_ctx_t *outcheck_ctx = hashcat_ctx->outcheck_ctx;

  if (hashconfig->outfile_check_disable == true) return NULL;

  if (outcheck_ctx->enabled == false) return NULL;

  const int rc = outfile_remove (hashcat_ctx);

  if (rc == -1) return NULL;

  return NULL;
}

int outcheck_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;
  const hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;
        outcheck_ctx_t  *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
  const user_options_t  *user_options  = hashcat_ctx->user_options;

  outcheck_ctx->enabled = false;

  if (user_options->keyspace      == true) return 0;
  if (user_options->benchmark     == true) return 0;
  if (user_options->hash_info     == true) return 0;
  if (user_options->speed_only    == true) return 0;
  if (user_options->progress_only == true) return 0;
  if (user_options->identify      == true) return 0;
  if (user_options->backend_info   > 0)    return 0;

  if (hashconfig->outfile_check_disable == true) return 0;
  if (user_options->outfile_check_timer == 0)    return 0;

  if (user_options->outfile_check_dir == NULL)
  {
    hc_asprintf (&outcheck_ctx->root_directory, "%s/%s.%s", folder_config->session_dir, user_options->session, OUTFILES_DIR);
  }
  else
  {
    outcheck_ctx->root_directory = user_options->outfile_check_dir;
  }

  outcheck_ctx->enabled = true;

  if (hc_path_exist (outcheck_ctx->root_directory) == false)
  {
    if (hc_mkdir (outcheck_ctx->root_directory, 0700) == -1)
    {
      event_log_error (hashcat_ctx, "%s: %s", outcheck_ctx->root_directory, strerror (errno));

      return -1;
    }
  }

  return 0;
}

void outcheck_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  outcheck_ctx_t *outcheck_ctx = hashcat_ctx->outcheck_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (outcheck_ctx->enabled == false)            return;
  if (hashconfig->outfile_check_disable == true) return;

  if (rmdir (outcheck_ctx->root_directory) == -1)
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
      event_log_error (hashcat_ctx, "%s: %s", outcheck_ctx->root_directory, strerror (errno));

      //return -1;
    }
  }

  if (user_options->outfile_check_dir == NULL)
  {
    hcfree (outcheck_ctx->root_directory);
  }

  memset (outcheck_ctx, 0, sizeof (outcheck_ctx_t));
}
