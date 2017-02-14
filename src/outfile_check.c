/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "outfile_check.h"

#include "convert.h"
#include "folder.h"
#include "hashes.h"
#include "interface.h"
#include "shared.h"
#include "thread.h"

static int outfile_remove (hashcat_ctx_t *hashcat_ctx)
{
  // some hash-dependent constants

  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  outcheck_ctx_t *outcheck_ctx = hashcat_ctx->outcheck_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  u32  dgst_size      = hashconfig->dgst_size;
  u32  is_salted      = hashconfig->is_salted;
  u32  esalt_size     = hashconfig->esalt_size;
  u32  hook_salt_size = hashconfig->hook_salt_size;
  u32  hash_mode      = hashconfig->hash_mode;
  char separator      = hashconfig->separator;

  char *root_directory      = outcheck_ctx->root_directory;
  u32   outfile_check_timer = user_options->outfile_check_timer;

  // buffers
  hash_t hash_buf = { 0, 0, 0, 0, 0, 0, NULL, 0 };

  hash_buf.digest = hcmalloc (dgst_size);

  if (is_salted)      hash_buf.salt      = (salt_t *) hcmalloc (sizeof (salt_t));
  if (esalt_size)     hash_buf.esalt     = (void   *) hcmalloc (esalt_size);
  if (hook_salt_size) hash_buf.hook_salt = (void   *) hcmalloc (hook_salt_size);

  u32 digest_buf[64] = { 0 };

  outfile_data_t *out_info = NULL;

  char **out_files = NULL;

  time_t folder_mtime = 0;

  int out_cnt = 0;

  u32 check_left = outfile_check_timer; // or 1 if we want to check it at startup

  while (status_ctx->shutdown_inner == false)
  {
    hc_sleep (1);

    if (status_ctx->devices_status != STATUS_RUNNING) continue;

    check_left--;

    if (check_left == 0)
    {
      if (hc_path_exist (root_directory) == true)
      {
        const bool is_dir = hc_path_is_directory (root_directory);

        if (is_dir == true)
        {
          hc_stat_t outfile_check_stat;

          if (hc_stat (root_directory, &outfile_check_stat) == -1)
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
                  if (strcmp (out_info[j].file_name, out_info_new[i].file_name) == 0)
                  {
                    hc_stat_t outfile_stat;

                    if (hc_stat (out_info_new[i].file_name, &outfile_stat) == 0)
                    {
                      if (outfile_stat.st_ctime == out_info[j].ctime)
                      {
                        out_info_new[i].ctime = out_info[j].ctime;
                        out_info_new[i].seek  = out_info[j].seek;
                      }
                    }
                  }
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
            FILE *fp = fopen (out_info[j].file_name, "rb");

            if (fp != NULL)
            {
              //hc_thread_mutex_lock (status_ctx->mux_display);

              hc_stat_t outfile_stat;

              if (hc_fstat (fileno (fp), &outfile_stat))
              {
                fclose (fp);

                continue;
              }

              if (outfile_stat.st_ctime > out_info[j].ctime)
              {
                out_info[j].ctime = outfile_stat.st_ctime;
                out_info[j].seek  = 0;
              }

              fseeko (fp, out_info[j].seek, SEEK_SET);

              char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

              while (!feof (fp))
              {
                char *ptr = fgets (line_buf, HCBUFSIZ_LARGE - 1, fp);

                if (ptr == NULL) break;

                size_t line_len = strlen (line_buf);

                if (line_len == 0) continue;

                size_t iter = 1;

                for (size_t i = line_len - 1; i && iter; i--, line_len--)
                {
                  if (line_buf[i] != separator) continue;

                  iter--;

                  int parser_status = PARSER_OK;

                  if ((hash_mode != 2500) && (hash_mode != 6800))
                  {
                    parser_status = hashconfig->parse_func ((u8 *) line_buf, line_len - 1, &hash_buf, hashconfig);
                  }

                  u32 found = 0;

                  if (parser_status == PARSER_OK)
                  {
                    for (u32 salt_pos = 0; (found == 0) && (salt_pos < hashes->salts_cnt); salt_pos++)
                    {
                      if (hashes->salts_shown[salt_pos] == 1) continue;

                      salt_t *salt_buf = &hashes->salts_buf[salt_pos];

                      for (u32 digest_pos = 0; (found == 0) && (digest_pos < salt_buf->digests_cnt); digest_pos++)
                      {
                        u32 idx = salt_buf->digests_offset + digest_pos;

                        if (hashes->digests_shown[idx] == 1) continue;

                        u32 cracked = 0;

                        if (hash_mode == 6800)
                        {
                          if (i == salt_buf->salt_len)
                          {
                            cracked = (memcmp (line_buf, salt_buf->salt_buf, salt_buf->salt_len) == 0);
                          }
                        }
                        else if (hash_mode == 2500)
                        {
                          // this comparison is a bit inaccurate as we compare only ESSID
                          // call it a bug, but it's good enough for a special case used in a special case
                          // in this case all essid will be marked as cracked that match the essid

                          if (i == salt_buf->salt_len)
                          {
                            cracked = (memcmp (line_buf, salt_buf->salt_buf, salt_buf->salt_len) == 0);
                          }
                        }
                        else
                        {
                          char *digests_buf_ptr = (char *) hashes->digests_buf;

                          memcpy (digest_buf, digests_buf_ptr + (hashes->salts_buf[salt_pos].digests_offset * dgst_size) + (digest_pos * dgst_size), dgst_size);

                          cracked = (sort_by_digest_p0p1 (digest_buf, hash_buf.digest, hashconfig) == 0);
                        }

                        if (cracked == 1)
                        {
                          found = 1;

                          hashes->digests_shown[idx] = 1;

                          hashes->digests_done++;

                          salt_buf->digests_done++;

                          if (salt_buf->digests_done == salt_buf->digests_cnt)
                          {
                            hashes->salts_shown[salt_pos] = 1;

                            hashes->salts_done++;

                            if (hashes->salts_done == hashes->salts_cnt) mycracked (hashcat_ctx);
                          }
                        }
                      }

                      if (status_ctx->devices_status == STATUS_CRACKED) break;
                    }
                  }

                  if (found) break;

                  if (status_ctx->devices_status == STATUS_CRACKED) break;
                }

                if (status_ctx->devices_status == STATUS_CRACKED) break;
              }

              hcfree (line_buf);

              out_info[j].seek = ftello (fp);

              //hc_thread_mutex_unlock (status_ctx->mux_display);

              fclose (fp);
            }
          }
        }
      }

      check_left = outfile_check_timer;
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

void *thread_outfile_remove (void *p)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) p;

  const int rc = outfile_remove (hashcat_ctx);

  if (rc == -1) return NULL;

  return NULL;
}

int outcheck_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  outcheck_ctx_t  *outcheck_ctx  = hashcat_ctx->outcheck_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  outcheck_ctx->enabled = false;

  if (user_options->keyspace      == true) return 0;
  if (user_options->benchmark     == true) return 0;
  if (user_options->speed_only    == true) return 0;
  if (user_options->progress_only == true) return 0;
  if (user_options->opencl_info   == true) return 0;

  if (user_options->outfile_check_timer == 0) return 0;

  if ((user_options->hash_mode ==  5200) ||
     ((user_options->hash_mode >=  6200) && (user_options->hash_mode <=  6299)) ||
     ((user_options->hash_mode >= 13700) && (user_options->hash_mode <= 13799)) ||
      (user_options->hash_mode ==  9000)) return 0;

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
  outcheck_ctx_t *outcheck_ctx = hashcat_ctx->outcheck_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (outcheck_ctx->enabled == false) return;

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
