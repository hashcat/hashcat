/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "interface.h"
#include "filehandling.h"
#include "potfile.h"

// get rid of this later
int sort_by_hash (const void *v1, const void *v2);
void format_plain (FILE *fp, unsigned char *plain_ptr, uint plain_len, uint outfile_autohex);
// get rid of this later

int sort_by_pot (const void *v1, const void *v2)
{
  const pot_t *p1 = (const pot_t *) v1;
  const pot_t *p2 = (const pot_t *) v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  return sort_by_hash (h1, h2);
}

void potfile_init (potfile_ctx_t *potfile_ctx, const char *profile_dir, const char *potfile_path)
{
  potfile_ctx->fp = NULL;

  potfile_ctx->filename = (char *) mymalloc (HCBUFSIZ_TINY);

  if (potfile_path == NULL)
  {
    snprintf (potfile_ctx->filename, HCBUFSIZ_TINY - 1, "%s/hashcat.potfile", profile_dir);
  }
  else
  {
    strncpy (potfile_ctx->filename, potfile_path, HCBUFSIZ_TINY - 1);
  }

  potfile_ctx->pot              = NULL;
  potfile_ctx->pot_cnt          = 0;
  potfile_ctx->pot_avail        = 0;
  potfile_ctx->pot_hashes_avail = 0;
}

int potfile_read_open (potfile_ctx_t *potfile_ctx)
{
  potfile_ctx->fp = fopen (potfile_ctx->filename, "rb");

  if (potfile_ctx->fp == NULL)
  {
    //log_error ("ERROR: %s: %s", potfile_ctx->filename, strerror (errno));

    return -1;
  }

  return 0;
}

void potfile_read_parse (potfile_ctx_t *potfile_ctx, hashconfig_t *hashconfig)
{
  potfile_ctx->pot_avail = count_lines (potfile_ctx->fp);

  potfile_ctx->pot = (pot_t *) mycalloc (potfile_ctx->pot_avail, sizeof (pot_t));

  rewind (potfile_ctx->fp);

  char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  for (uint line_num = 0; line_num < potfile_ctx->pot_avail; line_num++)
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

  qsort (potfile_ctx->pot, potfile_ctx->pot_cnt, sizeof (pot_t), sort_by_pot);
}

void potfile_read_close (potfile_ctx_t *potfile_ctx)
{
  fclose (potfile_ctx->fp);
}

int potfile_write_open (potfile_ctx_t *potfile_ctx)
{
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
  fclose (potfile_ctx->fp);
}

void potfile_write_append (potfile_ctx_t *potfile_ctx, const char *out_buf, u8 *plain_ptr, unsigned int plain_len)
{
  FILE *fp = potfile_ctx->fp;

  fprintf (fp, "%s:", out_buf);

  format_plain (fp, plain_ptr, plain_len, 1);

  fputc ('\n', fp);

  fflush (fp);
}

void potfile_hash_alloc (potfile_ctx_t *potfile_ctx, hashconfig_t *hashconfig, const uint num)
{
  uint pos = 0;

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

void potfile_hash_free (potfile_ctx_t *potfile_ctx, hashconfig_t *hashconfig)
{
  for (uint i = 0; i < potfile_ctx->pot_cnt; i++)
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
}

void potfile_destroy (potfile_ctx_t *potfile_ctx)
{
  myfree (potfile_ctx->filename);
}


