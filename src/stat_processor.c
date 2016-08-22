#include <types.h>
#include <logging.h>
#include <hc_global_data_t.h>
#include <hc_global.h>

/**
* statprocessor
*/

u64 sp_get_sum(uint start, uint stop, cs_t *root_css_buf)
{
  u64 sum = 1;

  uint i;

  for (i = start; i < stop; i++)
  {
    sum *= root_css_buf[i].cs_len;
  }

  return (sum);
}

void sp_exec(u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint start, uint stop)
{
  u64 v = ctx;

  cs_t *cs = &root_css_buf[start];

  uint i;

  for (i = start; i < stop; i++)
  {
    const u64 m = v % cs->cs_len;
    const u64 d = v / cs->cs_len;

    v = d;

    const uint k = cs->cs_buf[m];

    pw_buf[i - start] = (char)k;

    cs = &markov_css_buf[(i * CHARSIZ) + k];
  }
}

int sp_comp_val(const void *p1, const void *p2)
{
  hcstat_table_t *b1 = (hcstat_table_t *)p1;
  hcstat_table_t *b2 = (hcstat_table_t *)p2;

  return b2->val - b1->val;
}

void sp_setup_tbl(const char *shared_dir, char *hcstat, uint disable, uint classic, hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf)
{
  uint i;
  uint j;
  uint k;

  /**
  * Initialize hcstats
  */

  u64 *root_stats_buf = (u64 *)mycalloc(SP_ROOT_CNT, sizeof(u64));

  u64 *root_stats_ptr = root_stats_buf;

  u64 *root_stats_buf_by_pos[SP_PW_MAX];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    root_stats_buf_by_pos[i] = root_stats_ptr;

    root_stats_ptr += CHARSIZ;
  }

  u64 *markov_stats_buf = (u64 *)mycalloc(SP_MARKOV_CNT, sizeof(u64));

  u64 *markov_stats_ptr = markov_stats_buf;

  u64 *markov_stats_buf_by_key[SP_PW_MAX][CHARSIZ];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      markov_stats_buf_by_key[i][j] = markov_stats_ptr;

      markov_stats_ptr += CHARSIZ;
    }
  }

  /**
  * Load hcstats File
  */

  if (hcstat == NULL)
  {
    char hcstat_tmp[256] = { 0 };

    snprintf(hcstat_tmp, sizeof(hcstat_tmp) - 1, "%s/%s", shared_dir, SP_HCSTAT);

    hcstat = hcstat_tmp;
  }

  FILE *fd = fopen(hcstat, "rb");

  if (fd == NULL)
  {
    log_error("%s: %s", hcstat, strerror(errno));

    exit(-1);
  }

  if (fread(root_stats_buf, sizeof(u64), SP_ROOT_CNT, fd) != SP_ROOT_CNT)
  {
    log_error("%s: Could not load data", hcstat);

    fclose(fd);

    exit(-1);
  }

  if (fread(markov_stats_buf, sizeof(u64), SP_MARKOV_CNT, fd) != SP_MARKOV_CNT)
  {
    log_error("%s: Could not load data", hcstat);

    fclose(fd);

    exit(-1);
  }

  fclose(fd);

  /**
  * Markov modifier of hcstat_table on user request
  */

  if (disable)
  {
    memset(root_stats_buf, 0, SP_ROOT_CNT   * sizeof(u64));
    memset(markov_stats_buf, 0, SP_MARKOV_CNT * sizeof(u64));
  }

  if (classic)
  {
    /* Add all stats to first position */

    for (i = 1; i < SP_PW_MAX; i++)
    {
      u64 *out = root_stats_buf_by_pos[0];
      u64 *in = root_stats_buf_by_pos[i];

      for (j = 0; j < CHARSIZ; j++)
      {
        *out++ += *in++;
      }
    }

    for (i = 1; i < SP_PW_MAX; i++)
    {
      u64 *out = markov_stats_buf_by_key[0][0];
      u64 *in = markov_stats_buf_by_key[i][0];

      for (j = 0; j < CHARSIZ; j++)
      {
        for (k = 0; k < CHARSIZ; k++)
        {
          *out++ += *in++;
        }
      }
    }

    /* copy them to all pw_positions */

    for (i = 1; i < SP_PW_MAX; i++)
    {
      memcpy(root_stats_buf_by_pos[i], root_stats_buf_by_pos[0], CHARSIZ * sizeof(u64));
    }

    for (i = 1; i < SP_PW_MAX; i++)
    {
      memcpy(markov_stats_buf_by_key[i][0], markov_stats_buf_by_key[0][0], CHARSIZ * CHARSIZ * sizeof(u64));
    }
  }
  /**
  * Initialize tables
  */

  hcstat_table_t *root_table_ptr = root_table_buf;

  hcstat_table_t *root_table_buf_by_pos[SP_PW_MAX];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    root_table_buf_by_pos[i] = root_table_ptr;

    root_table_ptr += CHARSIZ;
  }

  hcstat_table_t *markov_table_ptr = markov_table_buf;

  hcstat_table_t *markov_table_buf_by_key[SP_PW_MAX][CHARSIZ];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      markov_table_buf_by_key[i][j] = markov_table_ptr;

      markov_table_ptr += CHARSIZ;
    }
  }

  /**
  * Convert hcstat to tables
  */

  for (i = 0; i < SP_ROOT_CNT; i++)
  {
    uint key = i % CHARSIZ;

    root_table_buf[i].key = key;
    root_table_buf[i].val = root_stats_buf[i];
  }

  for (i = 0; i < SP_MARKOV_CNT; i++)
  {
    uint key = i % CHARSIZ;

    markov_table_buf[i].key = key;
    markov_table_buf[i].val = markov_stats_buf[i];
  }

  myfree(root_stats_buf);
  myfree(markov_stats_buf);

  /**
  * Finally sort them
  */

  for (i = 0; i < SP_PW_MAX; i++)
  {
    qsort(root_table_buf_by_pos[i], CHARSIZ, sizeof(hcstat_table_t), sp_comp_val);
  }

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      qsort(markov_table_buf_by_key[i][j], CHARSIZ, sizeof(hcstat_table_t), sp_comp_val);
    }
  }
}

void sp_tbl_to_css(hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint threshold, uint uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  /**
  * Convert tables to css
  */

  for (uint i = 0; i < SP_ROOT_CNT; i++)
  {
    uint pw_pos = i / CHARSIZ;

    cs_t *cs = &root_css_buf[pw_pos];

    if (cs->cs_len == threshold) continue;

    uint key = root_table_buf[i].key;

    if (uniq_tbls[pw_pos][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  /**
  * Convert table to css
  */

  for (uint i = 0; i < SP_MARKOV_CNT; i++)
  {
    uint c = i / CHARSIZ;

    cs_t *cs = &markov_css_buf[c];

    if (cs->cs_len == threshold) continue;

    uint pw_pos = c / CHARSIZ;

    uint key = markov_table_buf[i].key;

    if ((pw_pos + 1) < SP_PW_MAX) if (uniq_tbls[pw_pos + 1][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  /*
  for (uint i = 0; i < 8; i++)
  {
  for (uint j = 0x20; j < 0x80; j++)
  {
  cs_t *ptr = &markov_css_buf[(i * CHARSIZ) + j];

  printf ("pos:%u key:%u len:%u\n", i, j, ptr->cs_len);

  for (uint k = 0; k < 10; k++)
  {
  printf ("  %u\n",  ptr->cs_buf[k]);
  }
  }
  }
  */
}

void sp_stretch_root(hcstat_table_t *in, hcstat_table_t *out)
{
  for (uint i = 0; i < SP_PW_MAX; i += 2)
  {
    memcpy(out, in, CHARSIZ * sizeof(hcstat_table_t));

    out += CHARSIZ;
    in += CHARSIZ;

    out->key = 0;
    out->val = 1;

    out++;

    for (uint j = 1; j < CHARSIZ; j++)
    {
      out->key = j;
      out->val = 0;

      out++;
    }
  }
}

void sp_stretch_markov(hcstat_table_t *in, hcstat_table_t *out)
{
  for (uint i = 0; i < SP_PW_MAX; i += 2)
  {
    memcpy(out, in, CHARSIZ * CHARSIZ * sizeof(hcstat_table_t));

    out += CHARSIZ * CHARSIZ;
    in += CHARSIZ * CHARSIZ;

    for (uint j = 0; j < CHARSIZ; j++)
    {
      out->key = 0;
      out->val = 1;

      out++;

      for (uint k = 1; k < CHARSIZ; k++)
      {
        out->key = k;
        out->val = 0;

        out++;
      }
    }
  }
}
