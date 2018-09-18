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
#include "bitops.h"

static int outfile_remove (hashcat_ctx_t *hashcat_ctx)
{
  // some hash-dependent constants

  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  outcheck_ctx_t *outcheck_ctx = hashcat_ctx->outcheck_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  size_t dgst_size      = hashconfig->dgst_size;
  bool   is_salted      = hashconfig->is_salted;
  size_t esalt_size     = hashconfig->esalt_size;
  size_t hook_salt_size = hashconfig->hook_salt_size;
  u32    hash_mode      = hashconfig->hash_mode;
  char   separator      = hashconfig->separator;

  salt_t    *salts_buf   = hashes->salts_buf;
  const u32  salts_cnt   = hashes->salts_cnt;

  char      *digests_buf = hashes->digests_buf;

  char *root_directory      = outcheck_ctx->root_directory;
  u32   outfile_check_timer = user_options->outfile_check_timer;

  // buffers
  hash_t hash_buf = { 0, 0, 0, 0, 0, 0, NULL, 0 };

  hash_buf.digest = hcmalloc (dgst_size);

  if (is_salted == true)  hash_buf.salt      = (salt_t *) hcmalloc (sizeof (salt_t));
  if (esalt_size > 0)     hash_buf.esalt     = hcmalloc (esalt_size);
  if (hook_salt_size > 0) hash_buf.hook_salt = hcmalloc (hook_salt_size);

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
      FILE *fp = fopen (out_info[j].file_name, "rb");

      if (fp == NULL) continue;

      //hc_thread_mutex_lock (status_ctx->mux_display);

      struct stat outfile_stat;

      if (fstat (fileno (fp), &outfile_stat))
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

        size_t cut_tries = 5;

        for (size_t i = line_len - 1; i && cut_tries; i--, line_len--)
        {
          if (line_buf[i] != separator) continue;

          cut_tries--;

          if (is_salted == true) memset (hash_buf.salt, 0, sizeof (salt_t)); // needed ? (let's play it safe!)

          int parser_status = PARSER_HASH_LENGTH;

          if ((hash_mode == 2500) || (hash_mode == 2501)) // special case WPA/WPA2
          {
            // fake the parsing of the salt

            u32 identifier_len = 32 + 1 + 12 + 1 + 12 + 1; // format is [ID_MD5]:[MAC1]:[MAC2]:$salt:$pass

            if ((line_len - 1) < identifier_len) continue;

            hash_buf.salt->salt_len = line_len - 1 - identifier_len;

            memcpy (hash_buf.salt->salt_buf, line_buf + identifier_len, hash_buf.salt->salt_len);

            // fake the parsing of the digest

            if (is_valid_hex_string ((u8 *) line_buf, 32) == false) break;

            u32 *digest = (u32 *) hash_buf.digest;

            digest[0] = hex_to_u32 ((u8 *) line_buf +  0);
            digest[1] = hex_to_u32 ((u8 *) line_buf +  8);
            digest[2] = hex_to_u32 ((u8 *) line_buf + 16);
            digest[3] = hex_to_u32 ((u8 *) line_buf + 24);

            digest[0] = byte_swap_32 (digest[0]);
            digest[1] = byte_swap_32 (digest[1]);
            digest[2] = byte_swap_32 (digest[2]);
            digest[3] = byte_swap_32 (digest[3]);

            parser_status = PARSER_OK;
          }
          else if (hash_mode == 6800) // special case LastPass (only email address in outfile/potfile)
          {
            // fake the parsing of the hash/salt

            hash_buf.salt->salt_len = line_len - 1;

            memcpy (hash_buf.salt->salt_buf, line_buf, line_len - 1);

            parser_status = PARSER_OK;
          }
          else // "normal" case: hash in the outfile is the same as the hash in the original hash file
          {
            parser_status = hashconfig->parse_func ((u8 *) line_buf, (u32) line_len - 1, &hash_buf, hashconfig);
          }

          if (parser_status != PARSER_OK) continue;


          salt_t *salt_buf = salts_buf;

          if (is_salted == true)
          {
            salt_buf = (salt_t *) hc_bsearch_r (hash_buf.salt, salts_buf, salts_cnt, sizeof (salt_t), sort_by_salt_buf, (void *) hashconfig);
          }

          if (salt_buf == NULL) continue;

          u32 salt_pos = salt_buf - salts_buf; // the offset from the start of the array (unit: sizeof (salt_t))

          if (hashes->salts_shown[salt_pos] == 1) break; // already marked as cracked (no action needed)

          u32 idx = salt_buf->digests_offset;

          bool cracked = false;

          if (hash_mode == 6800)
          {
            // the comparison with only matching salt is a bit inaccurate
            // call it a bug, but it's good enough for a special case used in a special case

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

        if (status_ctx->shutdown_inner == true) break;
      }

      hcfree (line_buf);

      out_info[j].seek = ftello (fp);

      //hc_thread_mutex_unlock (status_ctx->mux_display);

      fclose (fp);

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

  if (user_options->keyspace       == true) return 0;
  if (user_options->benchmark      == true) return 0;
  if (user_options->example_hashes == true) return 0;
  if (user_options->speed_only     == true) return 0;
  if (user_options->progress_only  == true) return 0;
  if (user_options->opencl_info    == true) return 0;

  if (user_options->outfile_check_timer == 0) return 0;

  if ((user_options->hash_mode ==  5200) ||
     ((user_options->hash_mode >=  6200) && (user_options->hash_mode <=  6299)) ||
      (user_options->hash_mode ==  9000) ||
     ((user_options->hash_mode >= 13700) && (user_options->hash_mode <= 13799)) ||
      (user_options->hash_mode == 14600)) return 0;

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
