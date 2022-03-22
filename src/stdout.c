/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "locking.h"
#include "emu_inc_rp.h"
#include "emu_inc_rp_optimized.h"
#include "mpsp.h"
#include "backend.h"
#include "shared.h"
#include "stdout.h"

static void out_flush (out_t *out)
{
  if (out->len == 0) return;

  hc_fwrite (out->buf, 1, out->len, &out->fp);

  out->len = 0;
}

static void out_push (out_t *out, const u8 *pw_buf, const int pw_len)
{
  char *ptr = out->buf + out->len;

  memcpy (ptr, pw_buf, pw_len);

  #if defined (_WIN)

  ptr[pw_len + 0] = '\r';
  ptr[pw_len + 1] = '\n';

  out->len += pw_len + 2;

  #else

  ptr[pw_len] = '\n';

  out->len += pw_len + 1;

  #endif

  if (out->len >= HCBUFSIZ_SMALL - 300)
  {
    out_flush (out);
  }
}

int process_stdout (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt)
{
  combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
  hashconfig_t     *hashconfig     = hashcat_ctx->hashconfig;
  mask_ctx_t       *mask_ctx       = hashcat_ctx->mask_ctx;
  outfile_ctx_t    *outfile_ctx    = hashcat_ctx->outfile_ctx;
  straight_ctx_t   *straight_ctx   = hashcat_ctx->straight_ctx;
  user_options_t   *user_options   = hashcat_ctx->user_options;

  char *filename = outfile_ctx->filename;

  out_t out;

  if (filename)
  {
    if (hc_fopen (&out.fp, filename, "ab") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

      return -1;
    }

    if (hc_lockfile (&out.fp) == -1)
    {
      hc_fclose (&out.fp);

      event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

      return -1;
    }
  }
  else
  {
    HCFILE *fp = &out.fp;

    fp->fd       = fileno (stdout);
    fp->pfp      = stdout;
    fp->gfp      = NULL;
    fp->ufp      = NULL;
    fp->bom_size = 0;
    fp->path     = NULL;
    fp->mode     = NULL;
  }

  out.len = 0;

  u32 plain_buf[64] = { 0 };

  u8 *plain_ptr = (u8 *) plain_buf;

  u32 plain_len = 0;

  const u32 il_cnt = device_param->kernel_param.il_cnt; // ugly, i know

  int rc = 0;

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    for (u64 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        u64 l_off = device_param->kernel_params_mp_l_buf64[3] + gidvid;
        u64 r_off = device_param->kernel_params_mp_r_buf64[3] + il_pos;

        u32 l_start = device_param->kernel_params_mp_l_buf32[5];
        u32 r_start = device_param->kernel_params_mp_r_buf32[5];

        u32 l_stop = device_param->kernel_params_mp_l_buf32[4];
        u32 r_stop = device_param->kernel_params_mp_r_buf32[4];

        sp_exec (l_off, (char *) plain_ptr + l_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, l_start, l_start + l_stop);
        sp_exec (r_off, (char *) plain_ptr + r_start, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, r_start, r_start + r_stop);

        plain_len = mask_ctx->css_cnt;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else if ((user_options->attack_mode == ATTACK_MODE_HYBRID2) && ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0))
  {
    for (u64 gidvid = 0; gidvid < pws_cnt; gidvid++)
    {
      for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
      {
        u64 off = device_param->kernel_params_mp_buf64[3] + gidvid;

        u32 start = 0;
        u32 stop  = device_param->kernel_params_mp_buf32[4];

        sp_exec (off, (char *) plain_ptr, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

        plain_len = stop;

        char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
        u32   comb_len =          device_param->combs_buf[il_pos].pw_len;

        memcpy (plain_ptr + plain_len, comb_buf, comb_len);

        plain_len += comb_len;

        if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

        out_push (&out, plain_ptr, plain_len);
      }
    }
  }
  else
  {
    // modes below require transferring pw index/buffer data from device to host

    const u64 blk_cnt_max = device_param->size_pws_idx / (sizeof (pw_idx_t));

    pw_idx_t *const pws_idx_blk  = device_param->pws_idx;
    u32      *const pws_comp_blk = device_param->pws_comp;

    u64 gidvid_blk = 0; // gidvid of first password in current block

    while (gidvid_blk < pws_cnt)
    {
      // copy the pw indexes from device for this block

      u64 remain  = pws_cnt - gidvid_blk;
      u64 blk_cnt = MIN (remain, blk_cnt_max);

      rc = copy_pws_idx (hashcat_ctx, device_param, gidvid_blk, blk_cnt, pws_idx_blk);

      if (rc == -1) break;

      const u32 off_blk = (blk_cnt > 0) ? pws_idx_blk[0].off : 0;

      const pw_idx_t *pw_idx      = device_param->pws_idx;
      const pw_idx_t *pw_idx_last = pw_idx + (blk_cnt - 1);

      // copy the pw buffer data from device for this block

      u32 copy_cnt = (pw_idx_last->off + pw_idx_last->cnt) - pws_idx_blk->off;

      rc = copy_pws_comp (hashcat_ctx, device_param, off_blk, copy_cnt, pws_comp_blk);

      if (rc == -1) break;

      if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
      {
        while (pw_idx <= pw_idx_last)
        {
          u32 *pw     = pws_comp_blk + (pw_idx->off - off_blk);
          u32  pw_len = pw_idx->len;

          pw_idx++;

          for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
          {
            const u32 off = device_param->innerloop_pos + il_pos;

            if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
            {
              for (int i = 0; i < 8; i++)
              {
                plain_buf[i] = pw[i];
              }

              plain_len = apply_rules_optimized (straight_ctx->kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], pw_len);
            }
            else
            {
              for (int i = 0; i < 64; i++)
              {
                plain_buf[i] = pw[i];
              }

              plain_len = apply_rules (straight_ctx->kernel_rules_buf[off].cmds, plain_buf, pw_len);
            }

            if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

            out_push (&out, plain_ptr, plain_len);
          }
        }
      }
      else if (user_options->attack_mode == ATTACK_MODE_COMBI)
      {
        while (pw_idx <= pw_idx_last)
        {
          u32 *pw     = pws_comp_blk + (pw_idx->off - off_blk);
          u32  pw_len = pw_idx->len;

          pw_idx++;

          for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
          {
            for (int i = 0; i < 64; i++)
            {
              plain_buf[i] = pw[i];
            }

            plain_len = pw_len;

            char *comb_buf = (char *) device_param->combs_buf[il_pos].i;
            u32   comb_len =          device_param->combs_buf[il_pos].pw_len;

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

            if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

            out_push (&out, plain_ptr, plain_len);
          }
        }
      }
      else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
      {
        while (pw_idx <= pw_idx_last)
        {
          u32 *pw     = pws_comp_blk + (pw_idx->off - off_blk);
          u32  pw_len = pw_idx->len;

          pw_idx++;

          for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
          {
            for (int i = 0; i < 64; i++)
            {
              plain_buf[i] = pw[i];
            }

            plain_len = pw_len;

            u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

            u32 start = 0;
            u32 stop  = device_param->kernel_params_mp_buf32[4];

            sp_exec (off, (char *) plain_ptr + plain_len, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

            plain_len += start + stop;

            out_push (&out, plain_ptr, plain_len);
          }
        }
      }
      else if ((user_options->attack_mode == ATTACK_MODE_HYBRID2) && (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL))
      {
        while (pw_idx <= pw_idx_last)
        {
          char *pw     = (char *) (pws_comp_blk + (pw_idx->off - off_blk));
          u32   pw_len =          (pw_idx->len);

          pw_idx++;

          for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
          {
            u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

            u32 start = 0;
            u32 stop  = device_param->kernel_params_mp_buf32[4];

            sp_exec (off, (char *) plain_ptr, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, start, start + stop);

            plain_len = stop;

            memcpy (plain_ptr + plain_len, pw, pw_len);

            plain_len += pw_len;

            if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

            out_push (&out, plain_ptr, plain_len);
          }
        }
      }

      gidvid_blk += blk_cnt; // prepare for next block
    }
  }

  out_flush (&out);

  if (filename)
  {
    hc_unlockfile (&out.fp);

    hc_fclose (&out.fp);
  }

  return rc;
}
