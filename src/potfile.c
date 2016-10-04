/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "convert.h"
#include "memory.h"
#include "logging.h"
#include "interface.h"
#include "filehandling.h"
#include "outfile.h"
#include "potfile.h"

#if defined (_WIN)
#define __WINDOWS__
#endif
#include "sort_r.h"
#if defined (_WIN)
#undef __WINDOWS__
#endif

// get rid of this later
int sort_by_hash         (const void *v1, const void *v2, void *v3);
int sort_by_hash_no_salt (const void *v1, const void *v2, void *v3);
// get rid of this later

int sort_by_pot (const void *v1, const void *v2, void *v3)
{
  const pot_t *p1 = (const pot_t *) v1;
  const pot_t *p2 = (const pot_t *) v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  return sort_by_hash (h1, h2, v3);
}

int sort_by_salt_buf (const void *v1, const void *v2, void *v3)
{
  if (v3 == NULL) v3 = NULL; // make compiler happy

  const pot_t *p1 = (const pot_t *) v1;
  const pot_t *p2 = (const pot_t *) v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  u32 n = 16;

  while (n--)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return ( 1);
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  return 0;
}

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

void hc_qsort_r (void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg)
{
  sort_r (base, nmemb, size, compar, arg);
}

void *hc_bsearch_r (const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg)
{
  for (size_t l = 0, r = nmemb; r; r >>= 1)
  {
    const size_t m = r >> 1;

    const size_t c = l + m;

    const void *next = base + (c * size);

    const int cmp = (*compar) (key, next, arg);

    if (cmp > 0)
    {
      l += m + 1;

      r--;
    }

    if (cmp == 0) return ((void *) next);
  }

  return (NULL);
}

void potfile_init (potfile_ctx_t *potfile_ctx, const user_options_t *user_options, const folder_config_t *folder_config)
{
  potfile_ctx->enabled = false;

  if (user_options->benchmark       == true) return;
  if (user_options->keyspace        == true) return;
  if (user_options->opencl_info     == true) return;
  if (user_options->stdout_flag     == true) return;
  if (user_options->usage           == true) return;
  if (user_options->version         == true) return;
  if (user_options->potfile_disable == true) return;

  potfile_ctx->enabled = true;

  if (user_options->potfile_path == NULL)
  {
    potfile_ctx->filename = (char *) mymalloc (HCBUFSIZ_TINY);
    potfile_ctx->fp       = NULL;

    snprintf (potfile_ctx->filename, HCBUFSIZ_TINY - 1, "%s/hashcat.potfile", folder_config->profile_dir);
  }
  else
  {
    potfile_ctx->filename = mystrdup (user_options->potfile_path);
    potfile_ctx->fp       = NULL;
  }

  potfile_ctx->pot              = NULL;
  potfile_ctx->pot_cnt          = 0;
  potfile_ctx->pot_avail        = 0;
  potfile_ctx->pot_hashes_avail = 0;
}

void potfile_destroy (potfile_ctx_t *potfile_ctx)
{
  if (potfile_ctx->enabled == false) return;

  memset (potfile_ctx, 0, sizeof (potfile_ctx_t));
}

void potfile_format_plain (potfile_ctx_t *potfile_ctx, const unsigned char *plain_ptr, const u32 plain_len)
{
  if (potfile_ctx->enabled == false) return;

  bool needs_hexify = false;

  for (u32 i = 0; i < plain_len; i++)
  {
    if (plain_ptr[i] < 0x20)
    {
      needs_hexify = true;

      break;
    }

    if (plain_ptr[i] > 0x7f)
    {
      needs_hexify = true;

      break;
    }
  }

  if (needs_hexify == true)
  {
    fprintf (potfile_ctx->fp, "$HEX[");

    for (u32 i = 0; i < plain_len; i++)
    {
      fprintf (potfile_ctx->fp, "%02x", plain_ptr[i]);
    }

    fprintf (potfile_ctx->fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, potfile_ctx->fp);
  }
}

int potfile_read_open (potfile_ctx_t *potfile_ctx)
{
  if (potfile_ctx->enabled == false) return 0;

  potfile_ctx->fp = fopen (potfile_ctx->filename, "rb");

  if (potfile_ctx->fp == NULL)
  {
    //log_error ("ERROR: %s: %s", potfile_ctx->filename, strerror (errno));

    return -1;
  }

  return 0;
}

void potfile_read_parse (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig)
{
  if (potfile_ctx->enabled == false) return;

  if (potfile_ctx->fp == NULL) return;

  potfile_ctx->pot_avail = count_lines (potfile_ctx->fp);

  potfile_ctx->pot = (pot_t *) mycalloc (potfile_ctx->pot_avail, sizeof (pot_t));

  rewind (potfile_ctx->fp);

  char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  for (u32 line_num = 0; line_num < potfile_ctx->pot_avail; line_num++)
  {
    int line_len = fgetl (potfile_ctx->fp, line_buf);

    if (line_len == 0) continue;

    pot_t *pot_ptr = &potfile_ctx->pot[potfile_ctx->pot_cnt];

    // we do not initialize all hashes_buf->digest etc at the beginning, since many lines may not be
    // valid lines of this specific hash type (otherwise it would be more waste of memory than gain)

    if (potfile_ctx->pot_cnt == potfile_ctx->pot_hashes_avail)
    {
      potfile_hash_alloc (potfile_ctx, hashconfig, INCR_POT);
    }

    int parser_status;

    int iter = MAX_CUT_TRIES;

    hash_t *hashes_buf = &pot_ptr->hash;

    char *plain_buf = line_buf + line_len;

    int plain_len = 0;

    do
    {
      for (int i = line_len - 1; i; i--, plain_len++, plain_buf--, line_len--)
      {
        if (line_buf[i] == ':')
        {
          line_len--;

          break;
        }
      }

      if (hashconfig->hash_mode != 2500)
      {
        parser_status = hashconfig->parse_func (line_buf, line_len, hashes_buf, hashconfig);
      }
      else
      {
        int max_salt_size = sizeof (hashes_buf->salt->salt_buf);

        if (line_len > max_salt_size)
        {
          parser_status = PARSER_GLOBAL_LENGTH;
        }
        else
        {
          memset (&hashes_buf->salt->salt_buf, 0, max_salt_size);

          memcpy (&hashes_buf->salt->salt_buf, line_buf, line_len);

          hashes_buf->salt->salt_len = line_len;

          parser_status = PARSER_OK;
        }
      }

      // if NOT parsed without error, we add the ":" to the plain

      if (parser_status == PARSER_GLOBAL_LENGTH || parser_status == PARSER_HASH_LENGTH || parser_status == PARSER_SALT_LENGTH)
      {
        plain_len++;
        plain_buf--;
      }

    } while ((parser_status == PARSER_GLOBAL_LENGTH || parser_status == PARSER_HASH_LENGTH || parser_status == PARSER_SALT_LENGTH) && --iter);

    if (parser_status < PARSER_GLOBAL_ZERO)
    {
      // log_info ("WARNING: Potfile '%s' in line %u (%s): %s", potfile, line_num, line_buf, strparser (parser_status));

      continue;
    }

    if (plain_len >= HCBUFSIZ_TINY) continue;

    memcpy (pot_ptr->plain_buf, plain_buf, plain_len);

    pot_ptr->plain_len = plain_len;

    potfile_ctx->pot_cnt++;
  }

  myfree (line_buf);

  hc_qsort_r (potfile_ctx->pot, potfile_ctx->pot_cnt, sizeof (pot_t), sort_by_pot, (void *) hashconfig);
}

void potfile_read_close (potfile_ctx_t *potfile_ctx)
{
  if (potfile_ctx->enabled == false) return;

  if (potfile_ctx->fp == NULL) return;

  fclose (potfile_ctx->fp);
}

int potfile_write_open (potfile_ctx_t *potfile_ctx)
{
  if (potfile_ctx->enabled == false) return 0;

  potfile_ctx->fp = fopen (potfile_ctx->filename, "ab");

  if (potfile_ctx->fp == NULL)
  {
    log_error ("ERROR: %s: %s", potfile_ctx->filename, strerror (errno));

    return -1;
  }

  return 0;
}

void potfile_write_close (potfile_ctx_t *potfile_ctx)
{
  if (potfile_ctx->enabled == false) return;

  fclose (potfile_ctx->fp);
}

void potfile_write_append (potfile_ctx_t *potfile_ctx, const char *out_buf, u8 *plain_ptr, unsigned int plain_len)
{
  if (potfile_ctx->enabled == false) return;

  FILE *fp = potfile_ctx->fp;

  fprintf (fp, "%s:", out_buf);

  potfile_format_plain (potfile_ctx, plain_ptr, plain_len);

  fputc ('\n', fp);

  fflush (fp);
}

void potfile_hash_alloc (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, const u32 num)
{
  if (potfile_ctx->enabled == false) return;

  u32 pos = 0;

  for (pos = 0; pos < num; pos++)
  {
    if ((potfile_ctx->pot_cnt + pos) >= potfile_ctx->pot_avail) break;

    pot_t *tmp_pot = &potfile_ctx->pot[potfile_ctx->pot_cnt + pos];

    hash_t *tmp_hash = &tmp_pot->hash;

    tmp_hash->digest = mymalloc (hashconfig->dgst_size);

    if (hashconfig->is_salted)
    {
      tmp_hash->salt = (salt_t *) mymalloc (sizeof (salt_t));
    }

    if (hashconfig->esalt_size)
    {
      tmp_hash->esalt = mymalloc (hashconfig->esalt_size);
    }

    potfile_ctx->pot_hashes_avail++;
  }
}

void potfile_hash_free (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig)
{
  if (potfile_ctx->enabled == false) return;

  for (u32 i = 0; i < potfile_ctx->pot_cnt; i++)
  {
    pot_t *pot_ptr = &potfile_ctx->pot[i];

    hash_t *hashes_buf = &pot_ptr->hash;

    myfree (hashes_buf->digest);

    if (hashconfig->is_salted)
    {
      myfree (hashes_buf->salt);
    }

    if (hashconfig->esalt_size)
    {
      myfree (hashes_buf->esalt);
    }
  }

  myfree (potfile_ctx->pot);
}

void potfile_show_request (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, outfile_ctx_t *outfile_ctx, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *, void *))
{
  if (potfile_ctx->enabled == false) return;

  pot_t pot_key;

  pot_key.hash.salt   = hashes_buf->salt;
  pot_key.hash.digest = hashes_buf->digest;

  pot_t *pot_ptr = (pot_t *) hc_bsearch_r (&pot_key, potfile_ctx->pot, potfile_ctx->pot_cnt, sizeof (pot_t), sort_by_pot, (void *) hashconfig);

  if (pot_ptr)
  {
    log_info_nn ("");

    input_buf[input_len] = 0;

    // user
    unsigned char *username = NULL;
    u32 user_len = 0;

    if (hashes_buf->hash_info)
    {
      user_t *user = hashes_buf->hash_info->user;

      if (user)
      {
        username = (unsigned char *) (user->user_name);

        user_len = user->user_len;
      }
    }

    // do output the line

    outfile_write (outfile_ctx, input_buf, (const unsigned char *) pot_ptr->plain_buf, pot_ptr->plain_len, 0, username, user_len, hashconfig);
  }
}

void potfile_left_request (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, outfile_ctx_t *outfile_ctx, char *input_buf, int input_len, hash_t *hashes_buf, int (*sort_by_pot) (const void *, const void *, void *))
{
  if (potfile_ctx->enabled == false) return;

  pot_t pot_key;

  memcpy (&pot_key.hash, hashes_buf, sizeof (hash_t));

  pot_t *pot_ptr = (pot_t *) hc_bsearch_r (&pot_key, potfile_ctx->pot, potfile_ctx->pot_cnt, sizeof (pot_t), sort_by_pot, (void *) hashconfig);

  if (pot_ptr == NULL)
  {
    log_info_nn ("");

    input_buf[input_len] = 0;

    outfile_write (outfile_ctx, input_buf, NULL, 0, 0, NULL, 0, hashconfig);
  }
}

void potfile_show_request_lm (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, outfile_ctx_t *outfile_ctx, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *, void *))
{
  if (potfile_ctx->enabled == false) return;

  // left

  pot_t pot_left_key;

  pot_left_key.hash.salt   = hash_left->salt;
  pot_left_key.hash.digest = hash_left->digest;

  pot_t *pot_left_ptr = (pot_t *) hc_bsearch_r (&pot_left_key, potfile_ctx->pot, potfile_ctx->pot_cnt, sizeof (pot_t), sort_by_pot, (void *) hashconfig);

  // right

  u32 weak_hash_found = 0;

  pot_t pot_right_key;

  pot_right_key.hash.salt   = hash_right->salt;
  pot_right_key.hash.digest = hash_right->digest;

  pot_t *pot_right_ptr = (pot_t *) hc_bsearch_r (&pot_right_key, potfile_ctx->pot, potfile_ctx->pot_cnt, sizeof (pot_t), sort_by_pot, (void *) hashconfig);

  if (pot_right_ptr == NULL)
  {
    // special case, if "weak hash"

    if (memcmp (hash_right->digest, LM_WEAK_HASH, 8) == 0)
    {
      weak_hash_found = 1;

      pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

      // in theory this is not needed, but we are paranoia:

      memset (pot_right_ptr->plain_buf, 0, sizeof (pot_right_ptr->plain_buf));
      pot_right_ptr->plain_len = 0;
    }
  }

  if ((pot_left_ptr == NULL) && (pot_right_ptr == NULL))
  {
    if (weak_hash_found == 1) myfree (pot_right_ptr); // this shouldn't happen at all: if weak_hash_found == 1, than pot_right_ptr is not NULL for sure

    return;
  }

  // at least one half was found:

  log_info_nn ("");

  input_buf[input_len] = 0;

  // user

  unsigned char *username = NULL;
  u32 user_len = 0;

  if (hash_left->hash_info)
  {
    user_t *user = hash_left->hash_info->user;

    if (user)
    {
      username = (unsigned char *) (user->user_name);

      user_len = user->user_len;
    }
  }

  // mask the part which was not found

  u32 left_part_masked  = 0;
  u32 right_part_masked = 0;

  u32 mask_plain_len = strlen (LM_MASKED_PLAIN);

  if (pot_left_ptr == NULL)
  {
    left_part_masked = 1;

    pot_left_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

    memset (pot_left_ptr->plain_buf, 0, sizeof (pot_left_ptr->plain_buf));

    memcpy (pot_left_ptr->plain_buf, LM_MASKED_PLAIN, mask_plain_len);
    pot_left_ptr->plain_len = mask_plain_len;
  }

  if (pot_right_ptr == NULL)
  {
    right_part_masked = 1;

    pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));

    memset (pot_right_ptr->plain_buf, 0, sizeof (pot_right_ptr->plain_buf));

    memcpy (pot_right_ptr->plain_buf, LM_MASKED_PLAIN, mask_plain_len);
    pot_right_ptr->plain_len = mask_plain_len;
  }

  // create the pot_ptr out of pot_left_ptr and pot_right_ptr

  pot_t pot_ptr;

  pot_ptr.plain_len = pot_left_ptr->plain_len + pot_right_ptr->plain_len;

  memcpy (pot_ptr.plain_buf, pot_left_ptr->plain_buf, pot_left_ptr->plain_len);

  memcpy (pot_ptr.plain_buf + pot_left_ptr->plain_len, pot_right_ptr->plain_buf, pot_right_ptr->plain_len);

  // do output the line

  outfile_write (outfile_ctx, input_buf, (unsigned char *) pot_ptr.plain_buf, pot_ptr.plain_len, 0, username, user_len, hashconfig);

  if (weak_hash_found == 1) myfree (pot_right_ptr);

  if (left_part_masked  == 1) myfree (pot_left_ptr);
  if (right_part_masked == 1) myfree (pot_right_ptr);
}

void potfile_left_request_lm (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, outfile_ctx_t *outfile_ctx, char *input_buf, int input_len, hash_t *hash_left, hash_t *hash_right, int (*sort_by_pot) (const void *, const void *, void *))
{
  if (potfile_ctx->enabled == false) return;

  // left

  pot_t pot_left_key;

  memcpy (&pot_left_key.hash, hash_left, sizeof (hash_t));

  pot_t *pot_left_ptr = (pot_t *) hc_bsearch_r (&pot_left_key, potfile_ctx->pot, potfile_ctx->pot_cnt, sizeof (pot_t), sort_by_pot, (void *) hashconfig);

  // right

  pot_t pot_right_key;

  memcpy (&pot_right_key.hash, hash_right, sizeof (hash_t));

  pot_t *pot_right_ptr = (pot_t *) hc_bsearch_r (&pot_right_key, potfile_ctx->pot, potfile_ctx->pot_cnt, sizeof (pot_t), sort_by_pot, (void *) hashconfig);

  u32 weak_hash_found = 0;

  if (pot_right_ptr == NULL)
  {
    // special case, if "weak hash"

    if (memcmp (hash_right->digest, LM_WEAK_HASH, 8) == 0)
    {
      weak_hash_found = 1;

      // we just need that pot_right_ptr is not a NULL pointer

      pot_right_ptr = (pot_t *) mycalloc (1, sizeof (pot_t));
    }
  }

  if ((pot_left_ptr != NULL) && (pot_right_ptr != NULL))
  {
    if (weak_hash_found == 1) myfree (pot_right_ptr);

    return;
  }

  // ... at least one part was not cracked

  log_info_nn ("");

  input_buf[input_len] = 0;

  // only show the hash part which is still not cracked

  u32 user_len = (u32)input_len - 32u;

  char *hash_output = (char *) mymalloc (33);

  memcpy (hash_output, input_buf, input_len);

  if (pot_left_ptr != NULL)
  {
    // only show right part (because left part was already found)

    memcpy (hash_output + user_len, input_buf + user_len + 16, 16);

    hash_output[user_len + 16] = 0;
  }

  if (pot_right_ptr != NULL)
  {
    // only show left part (because right part was already found)

    memcpy (hash_output + user_len, input_buf + user_len, 16);

    hash_output[user_len + 16] = 0;
  }

  outfile_write (outfile_ctx, hash_output, NULL, 0, 0, NULL, 0, hashconfig);

  myfree (hash_output);

  if (weak_hash_found == 1) myfree (pot_right_ptr);
}

int potfile_remove_parse (potfile_ctx_t *potfile_ctx, const hashconfig_t *hashconfig, const hashes_t *hashes)
{
  if (potfile_ctx->enabled == false) return 0;

  hash_t *hashes_buf = hashes->hashes_buf;
  u32    hashes_cnt = hashes->hashes_cnt;

  // no solution for these special hash types (for instane because they use hashfile in output etc)

  if  (hashconfig->hash_mode == 5200)
    return 0;

  if ((hashconfig->hash_mode >= 6200) && (hashconfig->hash_mode <= 6299))
    return 0;

  if  (hashconfig->hash_mode == 9000)
    return 0;

  if ((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode <= 13799))
    return 0;

  hash_t hash_buf;

  hash_buf.digest    = mymalloc (hashconfig->dgst_size);
  hash_buf.salt      = NULL;
  hash_buf.esalt     = NULL;
  hash_buf.hash_info = NULL;
  hash_buf.cracked   = 0;

  if (hashconfig->is_salted)
  {
    hash_buf.salt = (salt_t *) mymalloc (sizeof (salt_t));
  }

  if (hashconfig->esalt_size)
  {
    hash_buf.esalt = mymalloc (hashconfig->esalt_size);
  }

  const int rc = potfile_read_open (potfile_ctx);

  if (rc == -1) return 0;

  int potfile_remove_cracks = 0;

  char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  // to be safe work with a copy (because of line_len loop, i etc)
  // moved up here because it's easier to handle continue case
  // it's just 64kb

  char *line_buf_cpy = (char *) mymalloc (HCBUFSIZ_LARGE);

  while (!feof (potfile_ctx->fp))
  {
    char *ptr = fgets (line_buf, HCBUFSIZ_LARGE - 1, potfile_ctx->fp);

    if (ptr == NULL) break;

    int line_len = strlen (line_buf);

    if (line_len == 0) continue;

    int iter = MAX_CUT_TRIES;

    for (int i = line_len - 1; i && iter; i--, line_len--)
    {
      if (line_buf[i] != ':') continue;

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
        if (i < 64) // 64 = 16 * u32 in salt_buf[]
        {
          // manipulate salt_buf
          memcpy (hash_buf.salt->salt_buf, line_buf, i);

          hash_buf.salt->salt_len = i;

          found = (hash_t *) bsearch (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_t_salt);
        }
      }
      else if (hashconfig->hash_mode == 2500)
      {
        if (i < 64) // 64 = 16 * u32 in salt_buf[]
        {
          // here we have in line_buf: ESSID:MAC1:MAC2   (without the plain)
          // manipulate salt_buf

          memset (line_buf_cpy, 0, HCBUFSIZ_LARGE);
          memcpy (line_buf_cpy, line_buf, i);

          char *mac2_pos = strrchr (line_buf_cpy, ':');

          if (mac2_pos == NULL) continue;

          mac2_pos[0] = 0;
          mac2_pos++;

          if (strlen (mac2_pos) != 12) continue;

          char *mac1_pos = strrchr (line_buf_cpy, ':');

          if (mac1_pos == NULL) continue;

          mac1_pos[0] = 0;
          mac1_pos++;

          if (strlen (mac1_pos) != 12) continue;

          u32 essid_length = mac1_pos - line_buf_cpy - 1;

          // here we need the ESSID
          memcpy (hash_buf.salt->salt_buf, line_buf_cpy, essid_length);

          hash_buf.salt->salt_len = essid_length;

          found = (hash_t *) bsearch (&hash_buf, hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_t_salt_hccap);

          if (found)
          {
            wpa_t *wpa = (wpa_t *) found->esalt;

            // compare hex string(s) vs binary MAC address(es)

            for (u32 i = 0, j = 0; i < 6; i++, j += 2)
            {
              if (wpa->orig_mac1[i] != hex_to_u8 ((const u8 *) &mac1_pos[j]))
              {
                found = NULL;

                break;
              }
            }

            // early skip ;)
            if (!found) continue;

            for (u32 i = 0, j = 0; i < 6; i++, j += 2)
            {
              if (wpa->orig_mac2[i] != hex_to_u8 ((const u8 *) &mac2_pos[j]))
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
        int parser_status = hashconfig->parse_func (line_buf, line_len - 1, &hash_buf, hashconfig);

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

      if (!found->cracked) potfile_remove_cracks++;

      found->cracked = 1;

      if (found) break;

      iter--;
    }
  }

  myfree (line_buf_cpy);

  myfree (line_buf);

  potfile_read_close (potfile_ctx);

  if (hashconfig->esalt_size)
  {
    myfree (hash_buf.esalt);
  }

  if (hashconfig->is_salted)
  {
    myfree (hash_buf.salt);
  }

  myfree (hash_buf.digest);

  return potfile_remove_cracks;
}
