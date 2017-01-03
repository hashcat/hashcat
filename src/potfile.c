/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "convert.h"
#include "memory.h"
#include "event.h"
#include "interface.h"
#include "filehandling.h"
#include "loopback.h"
#include "outfile.h"
#include "potfile.h"
#include "locking.h"
#include "shared.h"

// get rid of this later
int sort_by_hash         (const void *v1, const void *v2, void *v3);
int sort_by_hash_no_salt (const void *v1, const void *v2, void *v3);
// get rid of this later

int sort_by_hash_t_salt (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  // testphase: this should work
  u32 n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  /* original code, seems buggy since salt_len can be very big (had a case with 131 len)
     also it thinks salt_buf[x] is a char but its a u32 so salt_len should be / 4
  if (s1->salt_len > s2->salt_len) return ( 1);
  if (s1->salt_len < s2->salt_len) return -1;

  u32 n = s1->salt_len;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }
  */

  return 0;
}

int sort_by_hash_t_salt_hccap (const void *v1, const void *v2)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  // last 2: salt_buf[10] and salt_buf[11] contain the digest (skip them)

  u32 n = 9; // 9 * 4 = 36 bytes (max length of ESSID)

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  return 0;
}

int potfile_init (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  potfile_ctx_t   *potfile_ctx   = hashcat_ctx->potfile_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  potfile_ctx->enabled = false;

  if (user_options->benchmark       == true) return 0;
  if (user_options->keyspace        == true) return 0;
  if (user_options->opencl_info     == true) return 0;
  if (user_options->stdout_flag     == true) return 0;
  if (user_options->speed_only      == true) return 0;
  if (user_options->progress_only   == true) return 0;
  if (user_options->usage           == true) return 0;
  if (user_options->version         == true) return 0;
  if (user_options->potfile_disable == true) return 0;

  potfile_ctx->enabled = true;

  if (user_options->potfile_path == NULL)
  {
    potfile_ctx->fp       = NULL;

    hc_asprintf (&potfile_ctx->filename, "%s/hashcat.potfile", folder_config->profile_dir);
  }
  else
  {
    potfile_ctx->filename = hcstrdup (user_options->potfile_path);
    potfile_ctx->fp       = NULL;
  }

  const int rc = potfile_write_open (hashcat_ctx);

  if (rc == -1) return -1;

  potfile_write_close (hashcat_ctx);

  // starting from here, we should allocate some scratch buffer for later use

  u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  potfile_ctx->out_buf = out_buf;

  // we need two buffers in parallel

  u8 *tmp_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  potfile_ctx->tmp_buf = tmp_buf;

  // old potfile detection

  if (user_options->potfile_path == NULL)
  {
    char *potfile_old;

    hc_asprintf (&potfile_old, "%s/hashcat.pot", folder_config->profile_dir);

    hc_stat_t st;

    if (hc_stat (potfile_old, &st) == 0)
    {
      event_log_warning (hashcat_ctx, "Old potfile detected: %s", potfile_old);
      event_log_warning (hashcat_ctx, "New potfile is: %s ", potfile_ctx->filename);
      event_log_warning (hashcat_ctx, "");
    }

    hcfree (potfile_old);
  }

  return 0;
}

void potfile_destroy (hashcat_ctx_t *hashcat_ctx)
{
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return;

  hcfree (potfile_ctx->out_buf);
  hcfree (potfile_ctx->tmp_buf);

  memset (potfile_ctx, 0, sizeof (potfile_ctx_t));
}

int potfile_read_open (hashcat_ctx_t *hashcat_ctx)
{
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return 0;

  potfile_ctx->fp = fopen (potfile_ctx->filename, "rb");

  if (potfile_ctx->fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %m", potfile_ctx->filename);

    return -1;
  }

  return 0;
}

void potfile_read_close (hashcat_ctx_t *hashcat_ctx)
{
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return;

  if (potfile_ctx->fp == NULL) return;

  fclose (potfile_ctx->fp);
}

int potfile_write_open (hashcat_ctx_t *hashcat_ctx)
{
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return 0;

  FILE *fp = fopen (potfile_ctx->filename, "ab");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %m", potfile_ctx->filename);

    return -1;
  }

  potfile_ctx->fp = fp;

  return 0;
}

void potfile_write_close (hashcat_ctx_t *hashcat_ctx)
{
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return;

  fclose (potfile_ctx->fp);
}

void potfile_write_append (hashcat_ctx_t *hashcat_ctx, const char *out_buf, u8 *plain_ptr, unsigned int plain_len)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const potfile_ctx_t  *potfile_ctx  = hashcat_ctx->potfile_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (potfile_ctx->enabled == false) return;

  u8 *tmp_buf = potfile_ctx->tmp_buf;

  int tmp_len = 0;

  if (1)
  {
    const size_t out_len = strlen (out_buf);

    memcpy (tmp_buf + tmp_len, out_buf, out_len);

    tmp_len += out_len;

    tmp_buf[tmp_len] = hashconfig->separator;

    tmp_len += 1;
  }

  if (1)
  {
    const bool always_ascii = (hashconfig->hash_type & OPTS_TYPE_PT_ALWAYS_ASCII) ? true : false;

    if ((user_options->outfile_autohex == true) && (need_hexify (plain_ptr, plain_len, hashconfig->separator, always_ascii) == true))
    {
      tmp_buf[tmp_len++] = '$';
      tmp_buf[tmp_len++] = 'H';
      tmp_buf[tmp_len++] = 'E';
      tmp_buf[tmp_len++] = 'X';
      tmp_buf[tmp_len++] = '[';

      exec_hexify ((const u8 *) plain_ptr, plain_len, (u8 *) tmp_buf + tmp_len);

      tmp_len += plain_len * 2;

      tmp_buf[tmp_len++] = ']';
    }
    else
    {
      memcpy (tmp_buf + tmp_len, plain_ptr, plain_len);

      tmp_len += plain_len;
    }
  }

  tmp_buf[tmp_len] = 0;

  lock_file (potfile_ctx->fp);

  fprintf (potfile_ctx->fp, "%s" EOL, tmp_buf);

  fflush (potfile_ctx->fp);

  unlock_file (potfile_ctx->fp);
}

int potfile_remove_parse (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const loopback_ctx_t *loopback_ctx = hashcat_ctx->loopback_ctx;
  const potfile_ctx_t  *potfile_ctx  = hashcat_ctx->potfile_ctx;

  if (potfile_ctx->enabled == false) return 0;

  hash_t *hashes_buf = hashes->hashes_buf;
  u32     hashes_cnt = hashes->hashes_cnt;

  // no solution for these special hash types (for instane because they use hashfile in output etc)

  if  (hashconfig->hash_mode ==  5200)  return 0;
  if ((hashconfig->hash_mode >=  6200)
   && (hashconfig->hash_mode <=  6299)) return 0;
  if  (hashconfig->hash_mode ==  9000)  return 0;
  if ((hashconfig->hash_mode >= 13700)
   && (hashconfig->hash_mode <= 13799)) return 0;

  hash_t hash_buf;

  hash_buf.digest    = hcmalloc (hashconfig->dgst_size);
  hash_buf.salt      = NULL;
  hash_buf.esalt     = NULL;
  hash_buf.hash_info = NULL;
  hash_buf.cracked   = 0;

  if (hashconfig->is_salted)
  {
    hash_buf.salt = (salt_t *) hcmalloc (sizeof (salt_t));
  }

  if (hashconfig->esalt_size)
  {
    hash_buf.esalt = hcmalloc (hashconfig->esalt_size);
  }

  // this is usually detected by weak-hash-check
  // but not if bitslice

  if (hashconfig->hash_mode == 3000)
  {
    int parser_status = hashconfig->parse_func ((u8 *) LM_WEAK_HASH, 16, &hash_buf, hashconfig);

    if (parser_status == PARSER_OK)
    {
      hash_t *found = (hash_t *) hc_bsearch_r (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_no_salt, (void *) hashconfig);

      if (found)
      {
        found->pw_buf = "";
        found->pw_len = 0;

        found->cracked = 1;
      }
    }
  }

  const int rc = potfile_read_open (hashcat_ctx);

  if (rc == -1) return -1;

  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  while (!feof (potfile_ctx->fp))
  {
    int line_len = fgetl (potfile_ctx->fp, line_buf);

    if (line_len == 0) continue;

    char *last_separator = strrchr (line_buf, hashconfig->separator);

    if (last_separator == NULL) continue; // ??

    char *line_pw_buf = last_separator + 1;

    int line_pw_len = line_buf + line_len - line_pw_buf;

    char *line_hash_buf = line_buf;

    int line_hash_len = last_separator - line_buf;

    line_hash_buf[line_hash_len] = 0;

    if (line_hash_len == 0) continue;

    // we should allow length 0 passwords (detected by weak hash check)
    //if (line_pw_len == 0) continue;

    if (hashconfig->is_salted)
    {
      memset (hash_buf.salt, 0, sizeof (salt_t));
    }

    if (hashconfig->esalt_size)
    {
      memset (hash_buf.esalt, 0, hashconfig->esalt_size);
    }

    hash_t *found = NULL;

    if (hashconfig->hash_mode == 6800)
    {
      if (line_hash_len < 64) // 64 = 16 * u32 in salt_buf[]
      {
        // manipulate salt_buf
        memcpy (hash_buf.salt->salt_buf, line_hash_buf, line_hash_len);

        hash_buf.salt->salt_len = line_hash_len;

        found = (hash_t *) bsearch (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_t_salt);
      }
    }
    else if (hashconfig->hash_mode == 2500)
    {
      if (line_hash_len < 64) // 64 = 16 * u32 in salt_buf[]
      {
        // here we have in line_hash_buf: ESSID:MAC1:MAC2   (without the plain)

        char *mac2_pos = strrchr (line_hash_buf, ':');

        if (mac2_pos == NULL) continue;

        mac2_pos[0] = 0;
        mac2_pos++;

        if (strlen (mac2_pos) != 12) continue;

        char *mac1_pos = strrchr (line_hash_buf, ':');

        if (mac1_pos == NULL) continue;

        mac1_pos[0] = 0;
        mac1_pos++;

        if (strlen (mac1_pos) != 12) continue;

        u32 essid_length = mac1_pos - line_hash_buf - 1;

        if (hashconfig->is_salted)
        {
          // this should be always true, but we need it to make scan-build happy

          memcpy (hash_buf.salt->salt_buf, line_hash_buf, essid_length);

          hash_buf.salt->salt_len = essid_length;
        }

        found = (hash_t *) bsearch (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_t_salt_hccap);

        if (found)
        {
          wpa_t *wpa = (wpa_t *) found->esalt;

          // compare hex string(s) vs binary MAC address(es)

          for (u32 mac_idx = 0, orig_mac_idx = 0; mac_idx < 6; mac_idx += 1, orig_mac_idx += 2)
          {
            if (wpa->orig_mac1[mac_idx] != hex_to_u8 ((const u8 *) &mac1_pos[orig_mac_idx]))
            {
              found = NULL;

              break;
            }

            if (wpa->orig_mac2[mac_idx] != hex_to_u8 ((const u8 *) &mac2_pos[orig_mac_idx]))
            {
              found = NULL;

              break;
            }
          }
        }
      }
    }
    else
    {
      int parser_status = hashconfig->parse_func ((u8 *) line_hash_buf, line_hash_len, &hash_buf, hashconfig);

      if (parser_status == PARSER_OK)
      {
        if (hashconfig->is_salted)
        {
          found = (hash_t *) hc_bsearch_r (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash, (void *) hashconfig);
        }
        else
        {
          found = (hash_t *) hc_bsearch_r (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_no_salt, (void *) hashconfig);
        }
      }
    }

    if (found == NULL) continue;

    char *pw_buf = line_pw_buf;
    int   pw_len = line_pw_len;

    found->pw_buf = (char *) hcmalloc (pw_len + 1);
    found->pw_len = pw_len;

    memcpy (found->pw_buf, pw_buf, pw_len);

    found->pw_buf[found->pw_len] = 0;

    found->cracked = 1;

    // if enabled, update also the loopback file

    if (loopback_ctx->fp != NULL)
    {
      loopback_write_append (hashcat_ctx, (u8 *) pw_buf, (unsigned int) pw_len);
    }
  }

  hcfree (line_buf);

  potfile_read_close (hashcat_ctx);

  if (hashconfig->esalt_size)
  {
    hcfree (hash_buf.esalt);
  }

  if (hashconfig->is_salted)
  {
    hcfree (hash_buf.salt);
  }

  hcfree (hash_buf.digest);

  return 0;
}

int potfile_handle_show (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t      *hashes      = hashcat_ctx->hashes;
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  hash_t *hashes_buf  = hashes->hashes_buf;

  u32     salts_cnt = hashes->salts_cnt;
  salt_t *salts_buf = hashes->salts_buf;

  for (u32 salt_idx = 0; salt_idx < salts_cnt; salt_idx++)
  {
    salt_t *salt_buf = salts_buf + salt_idx;

    u32 digests_cnt = salt_buf->digests_cnt;

    for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
    {
      const u32 hashes_idx = salt_buf->digests_offset + digest_idx;

      u32 *digests_shown = hashes->digests_shown;

      if (digests_shown[hashes_idx] == 0) continue;

      u8 *out_buf = potfile_ctx->out_buf;

      out_buf[0] = 0;

      ascii_digest (hashcat_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salt_idx, digest_idx);

      hash_t *hash = &hashes_buf[hashes_idx];

      // user
      unsigned char *username = NULL;

      u32 user_len = 0;

      if (hash->hash_info != NULL)
      {
        user_t *user = hash->hash_info->user;

        if (user)
        {
          username = (unsigned char *) (user->user_name);

          user_len = user->user_len;

          username[user_len] = 0;
        }
      }

      u8 *tmp_buf = potfile_ctx->tmp_buf;

      tmp_buf[0] = 0;

      const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, (u8 *) hash->pw_buf, hash->pw_len, 0, username, user_len, (char *) tmp_buf);

      EVENT_DATA (EVENT_POTFILE_HASH_SHOW, tmp_buf, tmp_len);
    }
  }

  return 0;
}

int potfile_handle_left (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t      *hashes      = hashcat_ctx->hashes;
  potfile_ctx_t *potfile_ctx = hashcat_ctx->potfile_ctx;

  hash_t *hashes_buf = hashes->hashes_buf;

  u32     salts_cnt = hashes->salts_cnt;
  salt_t *salts_buf = hashes->salts_buf;

  for (u32 salt_idx = 0; salt_idx < salts_cnt; salt_idx++)
  {
    salt_t *salt_buf = salts_buf + salt_idx;

    u32 digests_cnt = salt_buf->digests_cnt;

    for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
    {
      const u32 hashes_idx = salt_buf->digests_offset + digest_idx;

      u32 *digests_shown = hashes->digests_shown;

      if (digests_shown[hashes_idx] == 1) continue;

      u8 *out_buf = potfile_ctx->out_buf;

      out_buf[0] = 0;

      ascii_digest (hashcat_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salt_idx, digest_idx);

      hash_t *hash = &hashes_buf[hashes_idx];

      // user
      unsigned char *username = NULL;

      u32 user_len = 0;

      if (hash->hash_info != NULL)
      {
        user_t *user = hash->hash_info->user;

        if (user)
        {
          username = (unsigned char *) (user->user_name);

          user_len = user->user_len;

          username[user_len] = 0;
        }
      }

      u8 *tmp_buf = potfile_ctx->tmp_buf;

      tmp_buf[0] = 0;

      const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, NULL, 0, 0, username, user_len, (char *) tmp_buf);

      EVENT_DATA (EVENT_POTFILE_HASH_LEFT, tmp_buf, tmp_len);
    }
  }

  return 0;
}
