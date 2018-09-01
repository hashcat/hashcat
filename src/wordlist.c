/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "dictstat.h"
#include "thread.h"
#include "rp.h"
#include "rp_cpu.h"
#include "shared.h"
#include "wordlist.h"

size_t convert_from_hex (hashcat_ctx_t *hashcat_ctx, char *line_buf, const size_t line_len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (line_len & 1) return (line_len); // not in hex

  if (user_options->hex_wordlist == true)
  {
    size_t i, j;

    for (i = 0, j = 0; j < line_len; i += 1, j += 2)
    {
      line_buf[i] = hex_to_u8 ((const u8 *) &line_buf[j]);
    }

    memset (line_buf + i, 0, line_len - i);

    return (i);
  }

  if (user_options->wordlist_autohex_disable == false)
  {
    if (is_hexify ((const u8 *) line_buf, line_len) == true)
    {
      const size_t new_len = exec_unhexify ((const u8 *) line_buf, line_len, (u8 *) line_buf, line_len);

      return new_len;
    }
  }

  return (line_len);
}

int load_segment (hashcat_ctx_t *hashcat_ctx, FILE *fd)
{
  wl_data_t *wl_data = hashcat_ctx->wl_data;

  // NOTE: use (never changing) ->incr here instead of ->avail otherwise the buffer gets bigger and bigger

  wl_data->pos = 0;

  wl_data->cnt = hc_fread (wl_data->buf, 1, wl_data->incr - 1000, fd);

  wl_data->buf[wl_data->cnt] = 0;

  if (wl_data->cnt == 0) return 0;

  if (wl_data->buf[wl_data->cnt - 1] == '\n') return 0;

  while (!feof (fd))
  {
    if (wl_data->cnt == wl_data->avail)
    {
      wl_data->buf = (char *) hcrealloc (wl_data->buf, wl_data->avail, wl_data->incr);

      wl_data->avail += wl_data->incr;
    }

    const int c = fgetc (fd);

    if (c == EOF) break;

    wl_data->buf[wl_data->cnt] = (char) c;

    wl_data->cnt++;

    if (c == '\n') break;
  }

  // ensure stream ends with a newline

  if (wl_data->buf[wl_data->cnt - 1] != '\n')
  {
    wl_data->cnt++;

    wl_data->buf[wl_data->cnt - 1] = '\n';
  }

  return 0;
}

void get_next_word_lm (char *buf, u64 sz, u64 *len, u64 *off)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr >= 'a' && *ptr <= 'z') *ptr -= 0x20;

    if (i == 7)
    {
      *off = i;
      *len = i;

      return;
    }

    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    *len = i;

    return;
  }

  *off = sz;
  *len = sz;
}

void get_next_word_uc (char *buf, u64 sz, u64 *len, u64 *off)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr >= 'a' && *ptr <= 'z') *ptr -= 0x20;

    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    *len = i;

    return;
  }

  *off = sz;
  *len = sz;
}

void get_next_word_std (char *buf, u64 sz, u64 *len, u64 *off)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    *len = i;

    return;
  }

  *off = sz;
  *len = sz;
}

void get_next_word (hashcat_ctx_t *hashcat_ctx, FILE *fd, char **out_buf, u32 *out_len)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  wl_data_t            *wl_data            = hashcat_ctx->wl_data;

  while (wl_data->pos < wl_data->cnt)
  {
    u64 off;
    u64 len;

    char *ptr = wl_data->buf + wl_data->pos;

    wl_data->func (ptr, wl_data->cnt - wl_data->pos, &len, &off);

    wl_data->pos += off;

    // do the on-the-fly encoding

    if (wl_data->iconv_enabled == true)
    {
      char  *iconv_ptr = wl_data->iconv_tmp;
      size_t iconv_sz  = HCBUFSIZ_TINY;

      size_t ptr_len = len;

      const size_t iconv_rc = iconv (wl_data->iconv_ctx, &ptr, &ptr_len, &iconv_ptr, &iconv_sz);

      if (iconv_rc == (size_t) -1) continue;

      ptr = wl_data->iconv_tmp;
      len = HCBUFSIZ_TINY - iconv_sz;
    }

    if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l))
    {
      if (len >= RP_PASSWORD_SIZE) continue;

      char rule_buf_out[RP_PASSWORD_SIZE];

      memset (rule_buf_out, 0, sizeof (rule_buf_out));

      const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, user_options_extra->rule_len_l, ptr, (u32) len, rule_buf_out);

      if (rule_len_out < 0) continue;
    }

    if (len >= PW_MAX) continue;

    *out_buf = ptr;
    *out_len = (u32) len;

    return;
  }

  if (feof (fd))
  {
    fprintf (stderr, "BUG feof()!!\n");

    return;
  }

  load_segment (hashcat_ctx, fd);

  get_next_word (hashcat_ctx, fd, out_buf, out_len);
}

void pw_pre_add (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len, const u8 *base_buf, const int base_len, const int rule_idx)
{
  if (device_param->pws_pre_cnt < device_param->kernel_power)
  {
    pw_pre_t *pw_pre = device_param->pws_pre_buf + device_param->pws_pre_cnt;

    memcpy (pw_pre->pw_buf, pw_buf, pw_len);

    pw_pre->pw_len = pw_len;

    if (base_buf != NULL)
    {
      memcpy (pw_pre->base_buf, base_buf, base_len);

      pw_pre->base_len = base_len;
    }

    pw_pre->rule_idx = rule_idx;

    device_param->pws_pre_cnt++;
  }
  else
  {
    fprintf (stdout, "BUG pw_pre_add()!!\n");

    return;
  }
}

void pw_base_add (hc_device_param_t *device_param, pw_pre_t *pw_pre)
{
  if (device_param->pws_base_cnt < device_param->kernel_power)
  {
    memcpy (device_param->pws_base_buf + device_param->pws_base_cnt, pw_pre, sizeof (pw_pre_t));

    device_param->pws_base_cnt++;
  }
  else
  {
    fprintf (stderr, "BUG pw_base_add()!!\n");

    return;
  }
}

void pw_add (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len)
{
  if (device_param->pws_cnt < device_param->kernel_power)
  {
    pw_idx_t *pw_idx = device_param->pws_idx + device_param->pws_cnt;

    const u32 pw_len4 = (pw_len + 3) & ~3; // round up to multiple of 4

    const u32 pw_len4_cnt = pw_len4 / 4;

    pw_idx->cnt = pw_len4_cnt;
    pw_idx->len = pw_len;

    u8 *dst = (u8 *) (device_param->pws_comp + pw_idx->off);

    memcpy (dst, pw_buf, pw_len);

    memset (dst + pw_len, 0, pw_len4 - pw_len);

    // prepare next element

    pw_idx_t *pw_idx_next = pw_idx + 1;

    pw_idx_next->off = pw_idx->off + pw_idx->cnt;

    device_param->pws_cnt++;
  }
  else
  {
    fprintf (stderr, "BUG pw_add()!!\n");

    return;
  }
}

int count_words (hashcat_ctx_t *hashcat_ctx, FILE *fd, const char *dictfile, u64 *result)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  wl_data_t            *wl_data            = hashcat_ctx->wl_data;

  //hc_signal (NULL);

  dictstat_t d;

  d.cnt = 0;

  if (fstat (fileno (fd), &d.stat))
  {
    *result = 0;

    return 0;
  }

  d.stat.st_mode    = 0;
  d.stat.st_nlink   = 0;
  d.stat.st_uid     = 0;
  d.stat.st_gid     = 0;
  d.stat.st_rdev    = 0;
  d.stat.st_atime   = 0;

  #if defined (STAT_NANOSECONDS_ACCESS_TIME)
  d.stat.STAT_NANOSECONDS_ACCESS_TIME = 0;
  #endif

  #if defined (_POSIX)
  d.stat.st_blksize = 0;
  d.stat.st_blocks  = 0;
  #endif

  memset (d.encoding_from, 0, sizeof (d.encoding_from));
  memset (d.encoding_to,   0, sizeof (d.encoding_to));

  strncpy (d.encoding_from, user_options->encoding_from, sizeof (d.encoding_from));
  strncpy (d.encoding_to,   user_options->encoding_to,   sizeof (d.encoding_to));

  if (d.stat.st_size == 0)
  {
    *result = 0;

    return 0;
  }

  const u64 cached_cnt = dictstat_find (hashcat_ctx, &d);

  if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l) == 0)
  {
    if (cached_cnt)
    {
      u64 keyspace = cached_cnt;

      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        if (overflow_check_u64_mul (keyspace, straight_ctx->kernel_rules_cnt) == false) return -1;

        keyspace *= straight_ctx->kernel_rules_cnt;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        if (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (user_options->attack_mode == ATTACK_MODE_HYBRID2))
        {
          if (overflow_check_u64_mul (keyspace, mask_ctx->bfs_cnt) == false) return -1;

          keyspace *= mask_ctx->bfs_cnt;
        }
        else
        {
          if (overflow_check_u64_mul (keyspace, combinator_ctx->combs_cnt) == false) return -1;

          keyspace *= combinator_ctx->combs_cnt;
        }
      }

      cache_hit_t cache_hit;

      cache_hit.dictfile      = dictfile;
      cache_hit.stat.st_size  = d.stat.st_size;
      cache_hit.cached_cnt    = cached_cnt;
      cache_hit.keyspace      = keyspace;

      EVENT_DATA (EVENT_WORDLIST_CACHE_HIT, &cache_hit, sizeof (cache_hit));

      *result = keyspace;

      return 0;
    }
  }

  time_t rt_start;

  time (&rt_start);

  time_t now  = 0;
  time_t prev = 0;

  u64 comp = 0;
  u64 cnt  = 0;
  u64 cnt2 = 0;

  while (!feof (fd))
  {
    load_segment (hashcat_ctx, fd);

    comp += wl_data->cnt;

    u64 i = 0;

    while (i < wl_data->cnt)
    {
      u64 len;
      u64 off;

      char *ptr = wl_data->buf + i;

      wl_data->func (ptr, wl_data->cnt - i, &len, &off);

      i += off;

      // do the on-the-fly encoding

      if (wl_data->iconv_enabled == true)
      {
        char  *iconv_ptr = wl_data->iconv_tmp;
        size_t iconv_sz  = HCBUFSIZ_TINY;

        size_t ptr_len = len;

        const size_t iconv_rc = iconv (wl_data->iconv_ctx, &ptr, &ptr_len, &iconv_ptr, &iconv_sz);

        if (iconv_rc == (size_t) -1) continue;

        ptr = wl_data->iconv_tmp;
        len = HCBUFSIZ_TINY - iconv_sz;
      }

      if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l))
      {
        if (len >= RP_PASSWORD_SIZE) continue;

        char rule_buf_out[RP_PASSWORD_SIZE];

        memset (rule_buf_out, 0, sizeof (rule_buf_out));

        const int rule_len_out = _old_apply_rule (user_options->rule_buf_l, user_options_extra->rule_len_l, ptr, (u32) len, rule_buf_out);

        if (rule_len_out < 0) continue;
      }

      cnt2++;

      if (len >= PW_MAX) continue;

      d.cnt++;

      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        if (overflow_check_u64_add (cnt, straight_ctx->kernel_rules_cnt) == false) return -1;

        cnt += straight_ctx->kernel_rules_cnt;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        if (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (user_options->attack_mode == ATTACK_MODE_HYBRID2))
        {
          if (overflow_check_u64_add (cnt, mask_ctx->bfs_cnt) == false) return -1;

          cnt += mask_ctx->bfs_cnt;
        }
        else
        {
          if (overflow_check_u64_add (cnt, combinator_ctx->combs_cnt) == false) return -1;

          cnt += combinator_ctx->combs_cnt;
        }
      }
    }

    time (&now);

    if ((now - prev) == 0) continue;

    time (&prev);

    double percent = ((double) comp / (double) d.stat.st_size) * 100;

    if (percent < 100)
    {
      cache_generate_t cache_generate;

      cache_generate.dictfile    = dictfile;
      cache_generate.comp        = comp;
      cache_generate.percent     = percent;
      cache_generate.cnt         = cnt;
      cache_generate.cnt2        = cnt2;

      EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));
    }
  }

  time_t rt_stop;

  time (&rt_stop);

  cache_generate_t cache_generate;

  cache_generate.dictfile    = dictfile;
  cache_generate.comp        = comp;
  cache_generate.percent     = 100;
  cache_generate.cnt         = cnt;
  cache_generate.cnt2        = cnt2;
  cache_generate.runtime     = rt_stop - rt_start;

  EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));

  dictstat_append (hashcat_ctx, &d);

  //hc_signal (sigHandler_default);

  *result = cnt;

  return 0;
}

int wl_data_init (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;
  wl_data_t      *wl_data      = hashcat_ctx->wl_data;

  wl_data->enabled = false;

  if (user_options->benchmark      == true) return 0;
  if (user_options->example_hashes == true) return 0;
  if (user_options->left           == true) return 0;
  if (user_options->opencl_info    == true) return 0;
  if (user_options->usage          == true) return 0;
  if (user_options->version        == true) return 0;

  wl_data->enabled = true;

  wl_data->buf   = (char *) hcmalloc (user_options->segment_size);
  wl_data->avail = user_options->segment_size;
  wl_data->incr  = user_options->segment_size;
  wl_data->cnt   = 0;
  wl_data->pos   = 0;

  /**
   * choose dictionary parser
   */

  wl_data->func = get_next_word_std;

  if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
  {
    wl_data->func = get_next_word_uc;
  }

  if (hashconfig->hash_mode == 3000) // yes that's fine that way
  {
    wl_data->func = get_next_word_lm;
  }

  /**
   * iconv
   */

  if (strcmp (user_options->encoding_from, user_options->encoding_to) != 0)
  {
    wl_data->iconv_enabled = true;

    wl_data->iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

    if (wl_data->iconv_ctx == (iconv_t) -1) return -1;

    wl_data->iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);
  }

  return 0;
}

void wl_data_destroy (hashcat_ctx_t *hashcat_ctx)
{
  wl_data_t *wl_data = hashcat_ctx->wl_data;

  if (wl_data->enabled == false) return;

  hcfree (wl_data->buf);

  if (wl_data->iconv_enabled == true)
  {
    iconv_close (wl_data->iconv_ctx);

    wl_data->iconv_enabled = false;

    hcfree (wl_data->iconv_tmp);
  }

  memset (wl_data, 0, sizeof (wl_data_t));
}
