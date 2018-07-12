/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "interface.h"
#include "hashes.h"
#include "mpsp.h"
#include "rp.h"
#include "rp_kernel_on_cpu.h"
#include "rp_kernel_on_cpu_optimized.h"
#include "opencl.h"
#include "shared.h"
#include "outfile.h"
#include "locking.h"

int build_plain (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u32 *plain_buf, int *out_len)
{
  const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
  const hashconfig_t     *hashconfig     = hashcat_ctx->hashconfig;
  const hashes_t         *hashes         = hashcat_ctx->hashes;
  const mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
  const straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;
  const user_options_t   *user_options   = hashcat_ctx->user_options;

  const u64 gidvid = plain->gidvid;
  const u32 il_pos = plain->il_pos;

  int plain_len = 0;

  u8 *plain_ptr = (u8 *) plain_buf;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    pw_t pw;

    const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

    if (rc == -1) return -1;

    const u64 off = device_param->innerloop_pos + il_pos;

    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      for (int i = 0; i < 8; i++)
      {
        plain_buf[i] = pw.i[i];
      }

      plain_len = apply_rules_optimized (straight_ctx->kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], pw.pw_len);
    }
    else
    {
      for (int i = 0; i < 64; i++)
      {
        plain_buf[i] = pw.i[i];
      }

      plain_len = apply_rules (straight_ctx->kernel_rules_buf[off].cmds, plain_buf, pw.pw_len);
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    pw_t pw;

    const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

    if (rc == -1) return -1;

    for (int i = 0; i < 64; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = (int) pw.pw_len;

    char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
    u32   comb_len =          device_param->combs_buf[il_pos].pw_len;

    if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      memcpy (plain_ptr + plain_len, comb_buf, (size_t) comb_len);
    }
    else
    {
      memmove (plain_ptr + comb_len, plain_ptr, (size_t) plain_len);

      memcpy (plain_ptr, comb_buf, comb_len);
    }

    plain_len += comb_len;
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
    u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

    u32 l_start = device_param->kernel_params_mp_l_buf32[5];
    u32 r_start = device_param->kernel_params_mp_r_buf32[5];

    u32 l_stop = device_param->kernel_params_mp_l_buf32[4];
    u32 r_stop = device_param->kernel_params_mp_r_buf32[4];

    sp_exec (l_off, (char *) plain_ptr + l_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, l_start, l_start + l_stop);
    sp_exec (r_off, (char *) plain_ptr + r_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, r_start, r_start + r_stop);

    plain_len = (int) mask_ctx->css_cnt;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    pw_t pw;

    const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

    if (rc == -1) return -1;

    for (int i = 0; i < 64; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = (int) pw.pw_len;

    u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

    u32 start = 0;
    u32 stop  = device_param->kernel_params_mp_buf32[4];

    sp_exec (off, (char *) plain_ptr + plain_len, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

    plain_len += start + stop;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      pw_t pw;

      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1) return -1;

      for (int i = 0; i < 64; i++)
      {
        plain_buf[i] = pw.i[i];
      }

      plain_len = (int) pw.pw_len;

      u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

      u32 start = 0;
      u32 stop  = device_param->kernel_params_mp_buf32[4];

      memmove (plain_ptr + stop, plain_ptr, plain_len);

      sp_exec (off, (char *) plain_ptr, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

      plain_len += start + stop;
    }
    else
    {
      pw_t pw;

      const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

      if (rc == -1) return -1;

      u64 off = device_param->kernel_params_mp_buf64[3] + gidvid;

      u32 start = 0;
      u32 stop  = device_param->kernel_params_mp_buf32[4];

      sp_exec (off, (char *) plain_ptr, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

      plain_len = stop;

      char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
      u32   comb_len =          device_param->combs_buf[il_pos].pw_len;

      memcpy (plain_ptr + plain_len, comb_buf, comb_len);

      plain_len += comb_len;
    }
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (hashconfig->opti_type & OPTI_TYPE_BRUTE_FORCE) // lots of optimizations can happen here
    {
      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          plain_len = plain_len - hashes->salts_buf[0].salt_len;
        }
      }

      if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE)
      {
        for (int i = 0, j = 0; i < plain_len; i += 2, j += 1)
        {
          plain_ptr[j] = plain_ptr[i];
        }

        plain_len = plain_len / 2;
      }
      else if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE)
      {
        for (int i = 1, j = 0; i < plain_len; i += 2, j += 1)
        {
          plain_ptr[j] = plain_ptr[i];
        }

        plain_len = plain_len / 2;
      }
    }
  }

  const u32 pw_max = hashconfig_get_pw_max (hashcat_ctx, false);

  if (plain_len > (int) hashconfig->pw_max) plain_len = MIN (plain_len, (int) pw_max);

  plain_ptr[plain_len] = 0;

  *out_len = plain_len;

  return 0;
}

int build_crackpos (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u64 *out_pos)
{
  const combinator_ctx_t      *combinator_ctx     = hashcat_ctx->combinator_ctx;
  const mask_ctx_t            *mask_ctx           = hashcat_ctx->mask_ctx;
  const straight_ctx_t        *straight_ctx       = hashcat_ctx->straight_ctx;
  const user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  const u64 gidvid = plain->gidvid;
  const u32 il_pos = plain->il_pos;

  u64 crackpos = device_param->words_off;

  if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
  {
    crackpos += gidvid;
    crackpos *= straight_ctx->kernel_rules_cnt;
    crackpos += device_param->innerloop_pos + il_pos;
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
  {
    crackpos += gidvid;
    crackpos *= combinator_ctx->combs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;
  }
  else if (user_options_extra->attack_kern == ATTACK_MODE_BF)
  {
    crackpos += gidvid;
    crackpos *= mask_ctx->bfs_cnt;
    crackpos += device_param->innerloop_pos + il_pos;
  }

  *out_pos = crackpos;

  return 0;
}

int build_debugdata (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u8 *debug_rule_buf, int *debug_rule_len, u8 *debug_plain_ptr, int *debug_plain_len)
{
  const debugfile_ctx_t *debugfile_ctx = hashcat_ctx->debugfile_ctx;
  const straight_ctx_t  *straight_ctx  = hashcat_ctx->straight_ctx;
  const user_options_t  *user_options  = hashcat_ctx->user_options;

  const u64 gidvid = plain->gidvid;
  const u32 il_pos = plain->il_pos;

  if (user_options->attack_mode != ATTACK_MODE_STRAIGHT) return 0;

  const u32 debug_mode = debugfile_ctx->mode;

  if (debug_mode == 0) return 0;

  pw_t pw;

  const int rc = gidd_to_pw_t (hashcat_ctx, device_param, gidvid, &pw);

  if (rc == -1) return -1;

  int plain_len = (int) pw.pw_len;

  const u64 off = device_param->innerloop_pos + il_pos;

  // save rule
  if ((debug_mode == 1) || (debug_mode == 3) || (debug_mode == 4))
  {
    const int len = kernel_rule_to_cpu_rule ((char *) debug_rule_buf, &straight_ctx->kernel_rules_buf[off]);

    debug_rule_buf[len] = 0;

    *debug_rule_len = len;
  }

  // save plain
  if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
  {
    memcpy (debug_plain_ptr, (char *) pw.i, (size_t) plain_len);

    debug_plain_ptr[plain_len] = 0;

    *debug_plain_len = plain_len;
  }

  return 0;
}

int outfile_init (hashcat_ctx_t *hashcat_ctx)
{
  outfile_ctx_t  *outfile_ctx  = hashcat_ctx->outfile_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  outfile_ctx->fp               = NULL;
  outfile_ctx->filename         = user_options->outfile;
  outfile_ctx->outfile_format   = user_options->outfile_format;
  outfile_ctx->outfile_autohex  = user_options->outfile_autohex;

  return 0;
}

void outfile_destroy (hashcat_ctx_t *hashcat_ctx)
{
  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  memset (outfile_ctx, 0, sizeof (outfile_ctx_t));
}

int outfile_write_open (hashcat_ctx_t *hashcat_ctx)
{
  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  if (outfile_ctx->filename == NULL) return 0;

  FILE *fp = fopen (outfile_ctx->filename, "ab");

  if (fp == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", outfile_ctx->filename, strerror (errno));

    return -1;
  }

  if (lock_file (fp) == -1)
  {
    fclose (fp);

    event_log_error (hashcat_ctx, "%s: %s", outfile_ctx->filename, strerror (errno));

    return -1;
  }

  outfile_ctx->fp = fp;

  return 0;
}

void outfile_write_close (hashcat_ctx_t *hashcat_ctx)
{
  outfile_ctx_t *outfile_ctx = hashcat_ctx->outfile_ctx;

  if (outfile_ctx->fp == NULL) return;

  fclose (outfile_ctx->fp);
}

int outfile_write (hashcat_ctx_t *hashcat_ctx, const char *out_buf, const unsigned char *plain_ptr, const u32 plain_len, const u64 crackpos, const unsigned char *username, const u32 user_len, char tmp_buf[HCBUFSIZ_LARGE])
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const outfile_ctx_t  *outfile_ctx  = hashcat_ctx->outfile_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  int tmp_len = 0;

  if (user_len > 0)
  {
    if (username != NULL)
    {
      memcpy (tmp_buf + tmp_len, username, user_len);

      tmp_len += user_len;

      if (outfile_ctx->outfile_format & (OUTFILE_FMT_HASH | OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
      {
        tmp_buf[tmp_len] = hashconfig->separator;

        tmp_len += 1;
      }
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_HASH)
  {
    const size_t out_len = strlen (out_buf);

    memcpy (tmp_buf + tmp_len, out_buf, out_len);

    tmp_len += out_len;

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      tmp_buf[tmp_len] = hashconfig->separator;

      tmp_len += 1;
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_PLAIN)
  {
    bool convert_to_hex = false;

    if (user_options->show == false)
    {
      if (user_options->outfile_autohex == true)
      {
        const bool always_ascii = (hashconfig->hash_type & OPTS_TYPE_PT_ALWAYS_ASCII) ? true : false;

        convert_to_hex = need_hexify (plain_ptr, plain_len, hashconfig->separator, always_ascii);
      }
    }

    if (convert_to_hex)
    {
      tmp_buf[tmp_len++] = '$';
      tmp_buf[tmp_len++] = 'H';
      tmp_buf[tmp_len++] = 'E';
      tmp_buf[tmp_len++] = 'X';
      tmp_buf[tmp_len++] = '[';

      exec_hexify (plain_ptr, plain_len, (u8 *) tmp_buf + tmp_len);

      tmp_len += plain_len * 2;

      tmp_buf[tmp_len++] = ']';
    }
    else
    {
      memcpy (tmp_buf + tmp_len, plain_ptr, plain_len);

      tmp_len += plain_len;
    }

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      tmp_buf[tmp_len] = hashconfig->separator;

      tmp_len += 1;
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_HEXPLAIN)
  {
    exec_hexify (plain_ptr, plain_len, (u8 *) tmp_buf + tmp_len);

    tmp_len += plain_len * 2;

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_CRACKPOS))
    {
      tmp_buf[tmp_len] = hashconfig->separator;

      tmp_len += 1;
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_CRACKPOS)
  {
    tmp_len += snprintf (tmp_buf + tmp_len, HCBUFSIZ_LARGE - tmp_len, "%" PRIu64, crackpos);
  }

  tmp_buf[tmp_len] = 0;

  if (outfile_ctx->fp != NULL)
  {
    hc_fwrite (tmp_buf, tmp_len,      1, outfile_ctx->fp);
    hc_fwrite (EOL,     strlen (EOL), 1, outfile_ctx->fp);
  }

  return tmp_len;
}
