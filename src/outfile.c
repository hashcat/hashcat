/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "interface.h"
#include "hashes.h"
#include "mpsp.h"
#include "rp.h"
#include "rp_kernel_on_cpu.h"
#include "opencl.h"
#include "outfile.h"

void build_plain (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u32 *plain_buf, int *out_len)
{
  combinator_ctx_t      *combinator_ctx     = hashcat_ctx->combinator_ctx;
  hashconfig_t          *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t              *hashes             = hashcat_ctx->hashes;
  mask_ctx_t            *mask_ctx           = hashcat_ctx->mask_ctx;
  opencl_ctx_t          *opencl_ctx         = hashcat_ctx->opencl_ctx;
  straight_ctx_t        *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_t        *user_options       = hashcat_ctx->user_options;

  const u32 gidvid      = plain->gidvid;
  const u32 il_pos      = plain->il_pos;

  int plain_len = 0;

  u8 *plain_ptr = (u8 *) plain_buf;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    pw_t pw;

    gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = (int) pw.pw_len;

    const u32 off = device_param->innerloop_pos + il_pos;

    plain_len = (int) apply_rules (straight_ctx->kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], (u32) plain_len);

    if (plain_len > (int) hashconfig->pw_max) plain_len = (int) hashconfig->pw_max;
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    pw_t pw;

    gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
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

    if (hashconfig->pw_max != PW_DICTMAX1)
    {
      if (plain_len > (int) hashconfig->pw_max) plain_len = (int) hashconfig->pw_max;
    }
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

    gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
    {
      plain_buf[i] = pw.i[i];
    }

    plain_len = (int) pw.pw_len;

    u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

    u32 start = 0;
    u32 stop  = device_param->kernel_params_mp_buf32[4];

    sp_exec (off, (char *) plain_ptr + plain_len, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

    plain_len += start + stop;

    if (hashconfig->pw_max != PW_DICTMAX1)
    {
      if (plain_len > (int) hashconfig->pw_max) plain_len = (int) hashconfig->pw_max;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    pw_t pw;

    gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

    for (int i = 0; i < 16; i++)
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

    if (hashconfig->pw_max != PW_DICTMAX1)
    {
      if (plain_len > (int) hashconfig->pw_max) plain_len = (int) hashconfig->pw_max;
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

      if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
      {
        for (int i = 0, j = 0; i < plain_len; i += 2, j += 1)
        {
          plain_ptr[j] = plain_ptr[i];
        }

        plain_len = plain_len / 2;
      }
    }
  }

  *out_len = plain_len;
}

void build_crackpos (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u64 *out_pos)
{
  combinator_ctx_t      *combinator_ctx     = hashcat_ctx->combinator_ctx;
  mask_ctx_t            *mask_ctx           = hashcat_ctx->mask_ctx;
  straight_ctx_t        *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  const u32 gidvid      = plain->gidvid;
  const u32 il_pos      = plain->il_pos;

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
}

void build_debugdata (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain, u8 *debug_rule_buf, int *debug_rule_len, u8 *debug_plain_ptr, int *debug_plain_len)
{
  debugfile_ctx_t       *debugfile_ctx      = hashcat_ctx->debugfile_ctx;
  opencl_ctx_t          *opencl_ctx         = hashcat_ctx->opencl_ctx;
  straight_ctx_t        *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_t        *user_options       = hashcat_ctx->user_options;

  const u32 gidvid      = plain->gidvid;
  const u32 il_pos      = plain->il_pos;

  if (user_options->attack_mode != ATTACK_MODE_STRAIGHT) return;

  const u32 debug_mode = debugfile_ctx->mode;

  if (debug_mode == 0) return;

  pw_t pw;

  gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

  int plain_len = (int) pw.pw_len;

  const u32 off = device_param->innerloop_pos + il_pos;

  // save rule
  if ((debug_mode == 1) || (debug_mode == 3) || (debug_mode == 4))
  {
    *debug_rule_len = kernel_rule_to_cpu_rule ((char *) debug_rule_buf, &straight_ctx->kernel_rules_buf[off]);
  }

  // save plain
  if ((debug_mode == 2) || (debug_mode == 3) || (debug_mode == 4))
  {
    memcpy (debug_plain_ptr, (char *) pw.i, (size_t) plain_len);

    *debug_plain_len = plain_len;
  }
}

void outfile_init (outfile_ctx_t *outfile_ctx, const user_options_t *user_options)
{
  if (user_options->outfile == NULL)
  {
    outfile_ctx->fp       = stdout;
    outfile_ctx->filename = NULL;
  }
  else
  {
    outfile_ctx->fp       = NULL;
    outfile_ctx->filename = user_options->outfile;
  }

  outfile_ctx->outfile_format   = user_options->outfile_format;
  outfile_ctx->outfile_autohex  = user_options->outfile_autohex;
}

void outfile_destroy (outfile_ctx_t *outfile_ctx)
{
  memset (outfile_ctx, 0, sizeof (outfile_ctx_t));
}

void outfile_format_plain (outfile_ctx_t *outfile_ctx, const unsigned char *plain_ptr, const u32 plain_len)
{
  bool needs_hexify = false;

  if (outfile_ctx->outfile_autohex == true)
  {
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
  }

  if (needs_hexify == true)
  {
    fprintf (outfile_ctx->fp, "$HEX[");

    for (u32 i = 0; i < plain_len; i++)
    {
      fprintf (outfile_ctx->fp, "%02x", plain_ptr[i]);
    }

    fprintf (outfile_ctx->fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, outfile_ctx->fp);
  }
}

void outfile_write_open (outfile_ctx_t *outfile_ctx)
{
  if (outfile_ctx->filename == NULL) return;

  outfile_ctx->fp = fopen (outfile_ctx->filename, "ab");

  if (outfile_ctx->fp == NULL)
  {
    log_error ("ERROR: %s: %s", outfile_ctx->filename, strerror (errno));

    outfile_ctx->fp       = stdout;
    outfile_ctx->filename = NULL;
  }
}

void outfile_write_close (outfile_ctx_t *outfile_ctx)
{
  if (outfile_ctx->fp == stdout) return;

  fclose (outfile_ctx->fp);
}

void outfile_write (outfile_ctx_t *outfile_ctx, const char *out_buf, const unsigned char *plain_ptr, const u32 plain_len, const u64 crackpos, const unsigned char *username, const u32 user_len, const hashconfig_t *hashconfig)
{
  if (outfile_ctx->outfile_format & OUTFILE_FMT_HASH)
  {
    fprintf (outfile_ctx->fp, "%s", out_buf);

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      fputc (hashconfig->separator, outfile_ctx->fp);
    }
  }
  else if (user_len)
  {
    if (username != NULL)
    {
      for (u32 i = 0; i < user_len; i++)
      {
        fprintf (outfile_ctx->fp, "%c", username[i]);
      }

      if (outfile_ctx->outfile_format & (OUTFILE_FMT_PLAIN | OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
      {
        fputc (hashconfig->separator, outfile_ctx->fp);
      }
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_PLAIN)
  {
    outfile_format_plain (outfile_ctx, plain_ptr, plain_len);

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_HEXPLAIN | OUTFILE_FMT_CRACKPOS))
    {
      fputc (hashconfig->separator, outfile_ctx->fp);
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_HEXPLAIN)
  {
    for (u32 i = 0; i < plain_len; i++)
    {
      fprintf (outfile_ctx->fp, "%02x", plain_ptr[i]);
    }

    if (outfile_ctx->outfile_format & (OUTFILE_FMT_CRACKPOS))
    {
      fputc (hashconfig->separator, outfile_ctx->fp);
    }
  }

  if (outfile_ctx->outfile_format & OUTFILE_FMT_CRACKPOS)
  {
    fprintf (outfile_ctx->fp, "%" PRIu64, crackpos);
  }

  fputs (EOL, outfile_ctx->fp);
}

int outfile_and_hashfile (outfile_ctx_t *outfile_ctx, const char *hashfile)
{
  if (hashfile == NULL) return 0;

  char *outfile = outfile_ctx->filename;

  if (outfile == NULL) return 0;

  hc_stat tmpstat_outfile;
  hc_stat tmpstat_hashfile;

  FILE *tmp_outfile_fp = fopen (outfile, "r");

  if (tmp_outfile_fp)
  {
    #if defined (_POSIX)
    fstat (fileno (tmp_outfile_fp), &tmpstat_outfile);
    #endif

    #if defined (_WIN)
    _fstat64 (fileno (tmp_outfile_fp), &tmpstat_outfile);
    #endif

    fclose (tmp_outfile_fp);
  }

  FILE *tmp_hashfile_fp = fopen (hashfile, "r");

  if (tmp_hashfile_fp)
  {
    #if defined (_POSIX)
    fstat (fileno (tmp_hashfile_fp), &tmpstat_hashfile);
    #endif

    #if defined (_WIN)
    _fstat64 (fileno (tmp_hashfile_fp), &tmpstat_hashfile);
    #endif

    fclose (tmp_hashfile_fp);
  }

  if (tmp_outfile_fp && tmp_outfile_fp)
  {
    tmpstat_outfile.st_mode     = 0;
    tmpstat_outfile.st_nlink    = 0;
    tmpstat_outfile.st_uid      = 0;
    tmpstat_outfile.st_gid      = 0;
    tmpstat_outfile.st_rdev     = 0;
    tmpstat_outfile.st_atime    = 0;

    tmpstat_hashfile.st_mode    = 0;
    tmpstat_hashfile.st_nlink   = 0;
    tmpstat_hashfile.st_uid     = 0;
    tmpstat_hashfile.st_gid     = 0;
    tmpstat_hashfile.st_rdev    = 0;
    tmpstat_hashfile.st_atime   = 0;

    #if defined (_POSIX)
    tmpstat_outfile.st_blksize  = 0;
    tmpstat_outfile.st_blocks   = 0;

    tmpstat_hashfile.st_blksize = 0;
    tmpstat_hashfile.st_blocks  = 0;
    #endif

    if (memcmp (&tmpstat_outfile, &tmpstat_hashfile, sizeof (hc_stat)) == 0)
    {
      log_error ("ERROR: Hashfile and Outfile are not allowed to point to the same file");

      return -1;
    }
  }

  return 0;
}
