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
#include "filehandling.h"
#include "thread.h"
#include "memory.h"
#include "system.h"
#include "stdout.h"

static void out_flush (out_t *out)
{
  if (out->len == 0) return;

  // a short write here means candidates were lost, and losing them silently is worse than the
  // write failing, because the run still reports success

  const size_t nwrite = hc_fwrite (out->buf, 1, (size_t) out->len, &out->fp);

  if (nwrite != (size_t) out->len) out->write_failed = true;

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

  if (out->len >= STDOUT_BUFSIZ - 300)
  {
    out_flush (out);
  }
}

// Applying rules under --stdout is pure host work. One core assembles candidates while the rest of
// the machine sits idle, and because process_stdout () holds mux_outfile for the whole loop a second
// device does not help either: it waits instead of working.
//
// The output is word major and rule minor, so numbering every (word, rule) combination in that order
// gives an index space where a contiguous range is also contiguous in the output. Workers take one
// range each and are drained in range order, which means the bytes come out in exactly the order the
// serial loop produced them, whatever order the threads finish in.
//
// Work is done a round at a time so the buffers stay bounded. Each round is sized to a fixed byte
// budget from the longest candidate the mode can produce, so each worker can be given a buffer that
// its range cannot overrun and there is no growing to do while a rule is being applied.

#define STDOUT_RULE_THREADS_MAX  64
#define STDOUT_RULE_ROUND_BYTES  (128 * 1024 * 1024)
#define STDOUT_RULE_PARALLEL_MIN 65536

typedef struct stdout_rule_job
{
  const pw_idx_t      *pw_idx_base;
  const u32           *pws_comp_blk;
  u32                  off_blk;

  u64                  pair_first;
  u64                  pair_cnt;

  u32                  il_cnt;
  u64                  innerloop_pos;

  const kernel_rule_t *rules;
  bool                 optimized;
  u32                  pw_max;

  char                *buf;
  size_t               len;

} stdout_rule_job_t;

static HC_API_CALL void *stdout_rule_worker (void *p)
{
  stdout_rule_job_t *job = (stdout_rule_job_t *) p;

  u32 plain_buf[PW_MAX / sizeof (u32)];

  u8 *const plain_ptr = (u8 *) plain_buf;

  for (u64 i = 0; i < job->pair_cnt; i++)
  {
    const u64 pair = job->pair_first + i;

    const u64 word_idx = pair / job->il_cnt;
    const u32 il_pos   = (u32) (pair % job->il_cnt);

    const pw_idx_t *pw_idx = job->pw_idx_base + word_idx;

    const u32 *pw = job->pws_comp_blk + (pw_idx->off - job->off_blk);

    memset (plain_buf, 0, sizeof (plain_buf));

    for (u32 k = 0; k < pw_idx->cnt; k++) plain_buf[k] = pw[k];

    const u64 off = job->innerloop_pos + il_pos;

    int plain_len;

    if (job->optimized == true)
    {
      plain_len = apply_rules_optimized (job->rules[off].cmds, &plain_buf[0], &plain_buf[4], pw_idx->len);
    }
    else
    {
      plain_len = apply_rules (job->rules[off].cmds, plain_buf, pw_idx->len);
    }

    if (plain_len > (int) job->pw_max) plain_len = (int) job->pw_max;

    memcpy (job->buf + job->len, plain_ptr, (size_t) plain_len);

    job->len += (size_t) plain_len;

    #if defined (_WIN)
    job->buf[job->len + 0] = '\r';
    job->buf[job->len + 1] = '\n';

    job->len += 2;
    #else
    job->buf[job->len] = '\n';

    job->len += 1;
    #endif
  }

  return NULL;
}

int process_stdout (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  outfile_ctx_t        *outfile_ctx        = hashcat_ctx->outfile_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  // prevent wrong candidates in output when backend_ctx->backend_devices_active > 1

  hc_thread_mutex_lock (outfile_ctx->mux_outfile);

  char *filename = outfile_ctx->filename;

  out_t out;

  out.write_failed = false;

  if (filename)
  {
    if (hc_fopen (&out.fp, filename, "ab") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", filename, hc_fopen_strerror ());

      hc_thread_mutex_unlock (outfile_ctx->mux_outfile);

      return -1;
    }

    if (hc_lockfile (&out.fp) == -1)
    {
      hc_fclose (&out.fp);

      event_log_error (hashcat_ctx, "%s: %s", filename, strerror (errno));

      hc_thread_mutex_unlock (outfile_ctx->mux_outfile);

      return -1;
    }
  }
  else
  {
    HCFILE *fp = &out.fp;

    fp->fd       = fileno (stdout);
    fp->pfp      = stdout;
    fp->gfp      = NULL;
    fp->zfp      = NULL;
    fp->bom_size = 0;
    fp->path     = NULL;
    fp->mode     = NULL;
  }

  out.len = 0;

  #define BUF_SZ (PW_MAX / sizeof(u32))

  u32 plain_buf[BUF_SZ] = { 0 };

  u8 *const plain_ptr = (u8 *) plain_buf;

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
  // The base words are the mask and they exist only on the device, so there is no host word buffer to
  // copy and the candidate is put together from the outer loop position and the amplifier. That is
  // -a 7 under a pure kernel, and -a 12 under a pure kernel when its mask ends in ?w.

  else if ((user_options_extra->attack_kern == ATTACK_KERN_COMBI) && (user_options_extra->base_source == BASE_SOURCE_MASK))
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

      // Under --stdout no hash kernel runs, so nothing on the device has touched d_pws_idx or
      // d_pws_comp since run_copy () uploaded them from these very host buffers. pws_idx_blk and
      // pws_comp_blk are those host buffers, so reading the device back writes the same bytes where
      // they already are. Only the first block can skip it: a later one would have to be moved to
      // the front of the buffer, which is what the copy is for.

      const bool pws_already_on_host = (gidvid_blk == 0);

      if (pws_already_on_host == false)
      {
        rc = copy_pws_idx (hashcat_ctx, device_param, gidvid_blk, blk_cnt, pws_idx_blk);

        if (rc == -1) break;
      }

      const u32 off_blk = (blk_cnt > 0) ? pws_idx_blk[0].off : 0;

      const pw_idx_t *pw_idx      = device_param->pws_idx;
      const pw_idx_t *pw_idx_last = pw_idx + (blk_cnt - 1);

      // copy the pw buffer data from device for this block

      u32 copy_cnt = (pw_idx_last->off + pw_idx_last->cnt) - pws_idx_blk->off;

      if (pws_already_on_host == false)
      {
        rc = copy_pws_comp (hashcat_ctx, device_param, off_blk, copy_cnt, pws_comp_blk);

        if (rc == -1) break;
      }

      if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT) || (user_options->attack_mode == ATTACK_MODE_GENERIC) || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION))
      {
        bool done_parallel = false;

        const u64 word_cnt = (u64) (pw_idx_last - pw_idx) + 1;
        const u64 pair_cnt = word_cnt * il_cnt;

        u32 threads = hc_get_processor_count ();

        if (threads > STDOUT_RULE_THREADS_MAX) threads = STDOUT_RULE_THREADS_MAX;

        if (pair_cnt < STDOUT_RULE_PARALLEL_MIN) threads = 1;
        if ((u64) threads > pair_cnt)            threads = (u32) pair_cnt;

        if (threads > 1)
        {
          const size_t cand_max = (size_t) hashconfig->pw_max + 2;

          u64 pairs_per_round = STDOUT_RULE_ROUND_BYTES / cand_max;

          if (pairs_per_round < threads)  pairs_per_round = threads;

          // a short run must not reserve the whole budget for work it does not have

          if (pairs_per_round > pair_cnt)  pairs_per_round = pair_cnt;

          const u64    per_worker_max = CEILDIV (pairs_per_round, threads);
          const size_t worker_buf_sz  = (size_t) per_worker_max * cand_max;

          stdout_rule_job_t *jobs = (stdout_rule_job_t *) hcmalloc (threads * sizeof (stdout_rule_job_t));
          hc_thread_t       *tids = (hc_thread_t *)       hcmalloc (threads * sizeof (hc_thread_t));

          char *pool = (char *) hcmalloc ((size_t) threads * worker_buf_sz);

          if ((jobs != NULL) && (tids != NULL) && (pool != NULL))
          {
            // anything already buffered goes out first, or the workers' bytes would overtake it

            out_flush (&out);

            for (u64 base = 0; base < pair_cnt; base += pairs_per_round)
            {
              const u64 round_cnt = MIN (pairs_per_round, pair_cnt - base);
              const u64 round_end = base + round_cnt;
              const u64 per       = CEILDIV (round_cnt, threads);

              u32 live = 0;

              for (u32 t = 0; t < threads; t++)
              {
                const u64 first = base + ((u64) t * per);

                if (first >= round_end) break;

                jobs[t].pw_idx_base   = pw_idx;
                jobs[t].pws_comp_blk  = pws_comp_blk;
                jobs[t].off_blk       = off_blk;
                jobs[t].pair_first    = first;
                jobs[t].pair_cnt      = MIN (per, round_end - first);
                jobs[t].il_cnt        = il_cnt;
                jobs[t].innerloop_pos = device_param->innerloop_pos;
                jobs[t].rules         = straight_ctx->kernel_rules_buf;
                jobs[t].optimized     = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? true : false;
                jobs[t].pw_max        = hashconfig->pw_max;
                jobs[t].buf           = pool + ((size_t) t * worker_buf_sz);
                jobs[t].len           = 0;

                live++;
              }

              for (u32 t = 0; t < live; t++) hc_thread_create (tids[t], stdout_rule_worker, &jobs[t]);

              hc_thread_wait ((int) live, tids);

              // drained in range order, so the bytes land in the order the serial loop would produce

              for (u32 t = 0; t < live; t++)
              {
                if (jobs[t].len == 0) continue;

                const size_t nwrite = hc_fwrite (jobs[t].buf, 1, jobs[t].len, &out.fp);

                if (nwrite != jobs[t].len) out.write_failed = true;
              }
            }

            done_parallel = true;
          }

          hcfree (pool);
          hcfree (tids);
          hcfree (jobs);
        }

        while ((done_parallel == false) && (pw_idx <= pw_idx_last))
        {
          u32 *pw = pws_comp_blk + (pw_idx->off - off_blk);

          for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
          {
            const u64 off = device_param->innerloop_pos + il_pos;

            for (u32 i = 0; i < pw_idx->cnt; i++)
            {
              plain_buf[i] = pw[i];
            }

            if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
            {
              plain_len = apply_rules_optimized (straight_ctx->kernel_rules_buf[off].cmds, &plain_buf[0], &plain_buf[4], pw_idx->len);
            }
            else
            {
              plain_len = apply_rules (straight_ctx->kernel_rules_buf[off].cmds, plain_buf, pw_idx->len);
            }

            if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

            out_push (&out, plain_ptr, plain_len);

            memset (plain_ptr, 0, PW_MAX);
          }

          pw_idx++;
        }
      }
      else if (user_options->attack_mode == ATTACK_MODE_HYBRID)
      {
        char mask_buf[256];

        while (pw_idx <= pw_idx_last)
        {
          const u8 *pw = (const u8 *) (pws_comp_blk + (pw_idx->off - off_blk));

          for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
          {
            // Assembled by the same code the outfile uses, so the two cannot drift apart.

            if (device_param->combs_on_host == true)
            {
              plain_len = hybrid_amp_rebuild (hashcat_ctx, device_param, il_pos, plain_ptr, pw, pw_idx->len);
            }
            else
            {
              const u64 off = device_param->kernel_params_mp_buf64[3] + il_pos;

              hybrid_amp_mask (hashcat_ctx, off, mask_buf);

              plain_len = hybrid_assemble (hashcat_ctx, plain_ptr, mask_buf, pw, pw_idx->len, NULL, 0);
            }

            if (plain_len > hashconfig->pw_max) plain_len = hashconfig->pw_max;

            out_push (&out, plain_ptr, plain_len);
          }

          pw_idx++;
        }
      }
      gidvid_blk += blk_cnt; // prepare for next block
    }
  }

  out_flush (&out);

  if (out.write_failed == true)
  {
    event_log_error (hashcat_ctx, "Could not write all candidates to the output stream.");

    rc = -1;
  }

  if (filename)
  {
    hc_unlockfile (&out.fp);

    hc_fclose (&out.fp);
  }

  hc_thread_mutex_unlock (outfile_ctx->mux_outfile);

  return rc;
}
