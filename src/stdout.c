/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "interface.h"
#include "timer.h"
#include "memory.h"
#include "convert.h"
#include "logging.h"
#include "logfile.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "tuningdb.h"
#include "thread.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "hash_management.h"
#include "locking.h"
#include "rp_cpu.h"
#include "rp_kernel_on_cpu.h"
#include "shared.h"
#include "mpsp.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"
#include "stdout.h"

extern hc_global_data_t data;

static void out_flush (out_t *out)
{
  fwrite (out->buf, 1, out->len, out->fp);

  out->len = 0;
}

static void out_push (out_t *out, const u8 *pw_buf, const int pw_len)
{
  char *ptr = out->buf + out->len;

  memcpy (ptr, pw_buf, pw_len);

  ptr[pw_len] = '\n';

  out->len += pw_len + 1;

  if (out->len >= BUFSIZ - 100)
  {
    out_flush (out);
  }
}

void process_stdout (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const user_options_t *user_options, const straight_ctx_t *straight_ctx, const combinator_ctx_t *combinator_ctx, const mask_ctx_t *mask_ctx, const uint pws_cnt)
{
  out_t out;

  out.fp = stdout;

  // i think this section can be optimized now that we have outfile_ctx

  char *filename = data.outfile_ctx->filename;

  if (filename != NULL)
  {
    if ((out.fp = fopen (filename, "ab")) != NULL)
    {
      lock_file (out.fp);
    }
    else
    {
      log_error ("ERROR: %s: %s", filename, strerror (errno));

      out.fp = stdout;
    }
  }

  out.len = 0;

  uint plain_buf[16] = { 0 };

  u8 *plain_ptr = (u8 *) plain_buf;

  uint plain_len = 0;

  const uint il_cnt = device_param->kernel_params_buf32[30]; // ugly, i know

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    pw_t pw;

    for (uint gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

      const uint pos = device_param->innerloop_pos;

      for (uint il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 8; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        plain_len = apply_rules (straight_ctx->kernel_rules_buf[pos + il_pos].cmds, &plain_buf[0], &plain_buf[4], plain_len);

        if (plain_len > data.pw_max) plain_len = data.pw_max;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    pw_t pw;

    for (uint gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

      for (uint il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 8; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
        uint  comb_len =          device_param->combs_buf[il_pos].pw_len;

        if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
        {
          memcpy (plain_ptr + plain_len, comb_buf, comb_len);
        }
        else
        {
          memmove (plain_ptr + comb_len, plain_ptr, plain_len);

          memcpy (plain_ptr, comb_buf, comb_len);
        }

        plain_len += comb_len;

        if (data.pw_max != PW_DICTMAX1)
        {
          if (plain_len > data.pw_max) plain_len = data.pw_max;
        }

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    for (uint gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      for (uint il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
        u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

        uint l_start = device_param->kernel_params_mp_l_buf32[5];
        uint r_start = device_param->kernel_params_mp_r_buf32[5];

        uint l_stop = device_param->kernel_params_mp_l_buf32[4];
        uint r_stop = device_param->kernel_params_mp_r_buf32[4];

        sp_exec (l_off, (char *) plain_ptr + l_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, l_start, l_start + l_stop);
        sp_exec (r_off, (char *) plain_ptr + r_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, r_start, r_start + r_stop);

        plain_len = mask_ctx->css_cnt;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    pw_t pw;

    for (uint gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

      for (uint il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 8; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

        uint start = 0;
        uint stop  = device_param->kernel_params_mp_buf32[4];

        sp_exec (off, (char *) plain_ptr + plain_len, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

        plain_len += start + stop;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    pw_t pw;

    for (uint gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      gidd_to_pw_t (opencl_ctx, device_param, gidvid, &pw);

      for (uint il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        for (int i = 0; i < 8; i++)
        {
          plain_buf[i] = pw.i[i];
        }

        plain_len = pw.pw_len;

        u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

        uint start = 0;
        uint stop  = device_param->kernel_params_mp_buf32[4];

        memmove (plain_ptr + stop, plain_ptr, plain_len);

        sp_exec (off, (char *) plain_ptr, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

        plain_len += start + stop;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }

  out_flush (&out);

  if (out.fp != stdout)
  {
    unlock_file (out.fp);

    fclose (out.fp);
  }
}
