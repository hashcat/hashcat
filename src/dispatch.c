/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"
#include "backend.h"
#include "wordlist.h"
#include "shared.h"
#include "thread.h"
#include "timer.h"
#include "pwpipe.h"
#include "filehandling.h"
#include "rp.h"
#include "rp_cpu.h"
#include "slow_candidates.h"
#include "generic.h"
#include "convert.h"
#include "pcfg_common.h"
#include "pcfg_cpu_random.h"
#include "pcfg_dispatch.h"
#include "dispatch.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

static u64 get_highest_words_done (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  u64 words_cur = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    const u64 words_done = device_param->words_done;

    if (words_done > words_cur) words_cur = words_done;
  }

  return words_cur;
}

static u64 get_lowest_words_done (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  u64 words_cur = 0xffffffffffffffff;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    const u64 words_done = device_param->words_done;

    if (words_done < words_cur) words_cur = words_done;
  }

  // It's possible that a device's workload isn't finished right after a restore-case.
  // In that case, this function would return 0 and overwrite the real restore point

  const status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  if (words_cur < status_ctx->words_cur) words_cur = status_ctx->words_cur;

  return words_cur;
}

static int set_kernel_power_final (hashcat_ctx_t *hashcat_ctx, const u64 kernel_power_final)
{
  EVENT (EVENT_SET_KERNEL_POWER_FINAL);

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  backend_ctx->kernel_power_final = kernel_power_final;

  return 0;
}

static u64 get_power (backend_ctx_t *backend_ctx, hc_device_param_t *device_param)
{
  const u64 kernel_power_final = backend_ctx->kernel_power_final;

  if (kernel_power_final)
  {
    const double device_factor = (double) device_param->hardware_power / backend_ctx->hardware_power_all;

    const u64 words_left_device = (u64) CEIL (kernel_power_final * device_factor);

    // work should be at least the hardware power available without any accelerator

    const u64 work = MAX (words_left_device, device_param->hardware_power);

    // we need to make sure the value is not larger than the regular kernel_power

    const u64 work_final = MIN (work, device_param->kernel_power);

    return work_final;
  }

  return device_param->kernel_power;
}

static u64 get_work (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 max)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  const u64 words_off  = status_ctx->words_off;
  const u64 words_base = (user_options->limit == 0) ? status_ctx->words_base : MIN (user_options->limit, status_ctx->words_base);

  device_param->words_off = words_off;

  const u64 kernel_power_all = backend_ctx->kernel_power_all;

  // words_off can start beyond the keyspace. The brain sets it to the highest position the session
  // has already reached, and a later run of the same attack can have a smaller keyspace: fewer rules,
  // a tighter --limit, a wordlist that shrank. Unsigned subtraction then wraps to about 1.8e19, work
  // never runs out and the attack never finishes.

  const u64 words_left = (words_off < words_base) ? words_base - words_off : 0;

  if (words_left < kernel_power_all)
  {
    if (backend_ctx->kernel_power_final == 0)
    {
      set_kernel_power_final (hashcat_ctx, words_left);
    }
  }

  const u64 kernel_power = get_power (backend_ctx, device_param);

  u64 work = MIN (words_left, kernel_power);

  work = MIN (work, max);

  status_ctx->words_off += work;

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  return work;
}

// Everything the stdin producer carries between batches.

typedef struct stdin_fill_state
{
  char *buf;

  bool    iconv_enabled;
  iconv_t iconv_ctx;
  char   *iconv_tmp;

} stdin_fill_state_t;

static int fill_stdin (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;

  stdin_fill_state_t *sf = (stdin_fill_state_t *) state;

  const u32 attack_mode = user_options->attack_mode;
  const u32 attack_kern = user_options_extra->attack_kern;

  hc_thread_mutex_lock (status_ctx->mux_dispatcher);

  if (feof (stdin) != 0)
  {
    hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

    return 0;
  }

  #define DISABLE_READ_TIMEOUT_AFTER 1000

  int selects_returned = 0;

  while (batch->pws_cnt < device_param->kernel_power)
  {
    if (selects_returned < DISABLE_READ_TIMEOUT_AFTER)
    {
      const int rc_select = select_read_timeout_console (1);

      if (rc_select == -1) break;

      if (rc_select == 0)
      {
        if (status_ctx->run_thread_level1 == false) break;

        status_ctx->stdin_read_timeout_cnt++;

        continue;
      }

      status_ctx->stdin_read_timeout_cnt = 0;

      selects_returned++;
    }

    char *line_buf = fgets (sf->buf, HCBUFSIZ_LARGE - 1, stdin);

    if (line_buf == NULL) break;

    size_t line_len = in_superchop (line_buf);

    line_len = convert_from_hex (hashcat_ctx, line_buf, (u32) line_len);

    // do the on-the-fly encoding

    if (sf->iconv_enabled == true)
    {
      char  *iconv_ptr = sf->iconv_tmp;
      size_t iconv_sz  = HCBUFSIZ_TINY;

      if (iconv (sf->iconv_ctx, &line_buf, &line_len, &iconv_ptr, &iconv_sz) == (size_t) -1) continue;

      line_buf = sf->iconv_tmp;
      line_len = HCBUFSIZ_TINY - iconv_sz;
    }

    // post-process rule engine

    char rule_buf_out[RP_PASSWORD_SIZE];

    int   rule_jk_len = (int)    user_options_extra->rule_len_l;
    const char *rule_jk_buf = user_options->rule_buf_l;

    if (attack_mode == ATTACK_MODE_HYBRID2)
    {
      rule_jk_len = (int)    user_options_extra->rule_len_r;
      rule_jk_buf = user_options->rule_buf_r;
    }

    if (run_rule_engine (rule_jk_len, rule_jk_buf))
    {
      if (line_len >= RP_PASSWORD_SIZE) continue;

      const int rule_len_out = _old_apply_rule (rule_jk_buf, rule_jk_len, line_buf, (int) line_len, rule_buf_out);

      if (rule_len_out < 0) continue;

      line_buf = rule_buf_out;
      line_len = (size_t) rule_len_out;
    }

    if (line_len > PW_MAX) continue;

    // hmm that's always the case, or?

    if (attack_kern == ATTACK_KERN_STRAIGHT)
    {
      if ((line_len < hashconfig->pw_min) || (line_len > hashconfig->pw_max))
      {
        batch->words_extra++;

        continue;
      }
    }

    pw_add (batch, device_param->kernel_power, (const u8 *) line_buf, (const int) line_len);

    if (status_ctx->run_thread_level1 == false) break;
  }

  hc_thread_mutex_unlock (status_ctx->mux_dispatcher);

  return 0;
}

static int calc_stdin (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  stdin_fill_state_t sf;

  sf.buf           = (char *) hcmalloc (HCBUFSIZ_LARGE);
  sf.iconv_enabled = false;
  sf.iconv_ctx     = NULL;
  sf.iconv_tmp     = NULL;

  if (strcmp (user_options->encoding_from, user_options->encoding_to) != 0)
  {
    sf.iconv_enabled = true;

    sf.iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

    if (sf.iconv_ctx == (iconv_t) -1)
    {
      hcfree (sf.buf);

      return -1;
    }

    sf.iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);
  }

  pw_pipe_t pipe;

  pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_stdin, &sf, false);

  int rc_final = 0;

  while (status_ctx->run_thread_level1 == true)
  {
    pw_batch_t *batch = pw_pipe_take (&pipe);

    if (batch == NULL) break;

    if (batch->words_extra > 0)
    {
      hc_thread_mutex_lock (status_ctx->mux_counter);

      for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        status_ctx->words_progress_rejected[salt_pos] += batch->words_extra * straight_ctx->kernel_rules_cnt;
      }

      hc_thread_mutex_unlock (status_ctx->mux_counter);
    }

    // flush

    device_param->pws_idx  = batch->pws_idx;
    device_param->pws_comp = batch->pws_comp;
    device_param->pws_cnt  = batch->pws_cnt;

    if (run_copy (hashcat_ctx, device_param, device_param->pws_cnt) == -1)
    {
      rc_final = -1;

      break;
    }

    if (run_cracker (hashcat_ctx, device_param, -1, device_param->pws_cnt) == -1) // no pws_pos?
    {
      rc_final = -1;

      break;
    }

    device_param->pws_cnt = 0;

    pw_pipe_release (&pipe, batch);

    if (status_ctx->run_thread_level1 == false) break;

    if (device_param->speed_only_finish == true) break;
  }

  pw_pipe_stop (&pipe);

  if (pw_pipe_failed (&pipe) == true) rc_final = -1;

  device_param->kernel_accel_prev   = device_param->kernel_accel;
  device_param->kernel_loops_prev   = device_param->kernel_loops;
  device_param->kernel_threads_prev = device_param->kernel_threads;

  device_param->kernel_accel   = 0;
  device_param->kernel_loops   = 0;
  device_param->kernel_threads = 0;

  if (sf.iconv_enabled == true)
  {
    iconv_close (sf.iconv_ctx);

    hcfree (sf.iconv_tmp);
  }

  hcfree (sf.buf);

  return rc_final;
}

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD thread_calc_stdin (void *p)
#else
HC_API_CALL void *thread_calc_stdin (void *p)
#endif
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  bridge_ctx_t  *bridge_ctx  = hashcat_ctx->bridge_ctx;
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  hashes_t      *hashes      = hashcat_ctx->hashes;

  if (backend_ctx->enabled == false) return 0;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped) return 0;
  if (device_param->skipped_warning == true) return 0;

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_init != BRIDGE_DEFAULT)
    {
      if (bridge_ctx->thread_init (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, hashes) == false) return 0;
    }
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return 0;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == -1) return 0;
  }

  if (calc_stdin (hashcat_ctx, device_param) == -1)
  {
    status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

    status_ctx->devices_status = STATUS_ERROR;
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return 0;
  }

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_term != BRIDGE_DEFAULT)
    {
      bridge_ctx->thread_term (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, hashes);
    }
  }

  return 0;
}

// Everything the slow-candidate producer carries between batches. The three slow-candidate modes
// build their candidates from different sources but drive them through the same loop, so they share
// one producer and hand it pointers into whichever extra_info struct they own.

typedef struct slow_fill_state
{
  hashcat_ctx_t *reader_ctx;   // owns the wordlist reader, where the mode has one
  void          *extra_info;

  u64       *pos;
  const u8  *out_buf;
  const u32 *out_len;

  const u8  *base_buf;         // NULL when the mode has no base word
  const u32 *base_len;
  const u64 *rule_pos;         // NULL when the mode applies no rule

  bool seek;                   // a generated candidate is addressed by index and needs no seek
  bool reject_len;             // a mask produces one fixed length, checked once by the caller
  bool keep_base;              // only the modes --debug-mode can report have to keep the base word

  const bool *reject;          // NULL when the mode can never refuse a candidate it was asked for

  u64 words_cur;

  #ifdef WITH_BRAIN
  u64 brain_highest;
  #endif

} slow_fill_state_t;

static int fill_slow (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  // every use of this is inside a WITH_BRAIN block, so a build without the brain has none

  MAYBE_UNUSED user_options_t *user_options = hashcat_ctx->user_options;

  slow_fill_state_t *sc = (slow_fill_state_t *) state;

  hc_timer_t timer_feed;

  pipe_mark (&timer_feed);

  u64 pre_rejects = -1;

  // this greatly reduces spam on hashcat console

  const u64 pre_rejects_ignore = get_power (backend_ctx, device_param) / 2;

  while (pre_rejects > pre_rejects_ignore)
  {
    u64 words_extra_total = 0;

    u64 words_extra = pre_rejects;

    pre_rejects = 0;

    #ifdef WITH_BRAIN
    u64 brain_rejects_attacks = 0;
    u64 brain_rejects_hashes  = 0;
    #endif

    memset (device_param->pws_pre_buf, 0, device_param->size_pws_pre);

    device_param->pws_pre_cnt = 0;

    while (words_extra)
    {
      u64 work = get_work (hashcat_ctx, device_param, words_extra);

      if (work == 0) break;

      // cleared here rather than after the brain block, so a reserve that skips part of the range can
      // set it and have this loop fetch that much again. Otherwise every skipped word is a word the
      // batch never gets back and the device runs a short batch.

      words_extra = 0;

      u64 words_off = device_param->words_off;

      #ifdef WITH_BRAIN
      if (user_options->brain_client == true)
      {
        if (device_param->brain_link_client_fd == -1)
        {
          const i64 passwords_max = device_param->hardware_power * device_param->kernel_accel;

          if (brain_client_connect (hashcat_ctx, device_param, status_ctx, user_options->brain_host, user_options->brain_port, user_options->brain_password, user_options->brain_session, user_options->brain_attack, passwords_max, &sc->brain_highest) == false)
          {
            brain_client_disconnect (device_param);
          }
        }

        if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_ATTACKS)
        {
          u64 overlap = 0;

          if (brain_client_reserve (device_param, status_ctx, words_off, work, &overlap) == false)
          {
            brain_client_disconnect (device_param);
          }

          words_extra        = overlap;
          words_extra_total += overlap;
          words_off         += overlap;
          work              -= overlap;

          brain_rejects_attacks += overlap;
        }
      }
      #endif

      const u64 words_fin = words_off + work;

      batch->words_fin = words_fin;

      if (sc->seek == true) slow_candidates_seek (sc->reader_ctx, sc->extra_info, sc->words_cur, words_off);

      sc->words_cur = words_off;

      for (u64 i = sc->words_cur; i < words_fin; i++)
      {
        sc->pos[0] = i;

        slow_candidates_next (sc->reader_ctx, sc->extra_info);

        // The source refused this one. It still occupies its offset, so the loop moves on rather
        // than fetching a replacement, and the caller counts it the way it counts a length reject.

        if ((sc->reject != NULL) && (*sc->reject == true))
        {
          pre_rejects++;

          continue;
        }

        if (sc->reject_len == true)
        {
          if ((sc->out_len[0] < hashconfig->pw_min) || (sc->out_len[0] > hashconfig->pw_max))
          {
            pre_rejects++;

            continue;
          }
        }

        #ifdef WITH_BRAIN
        if (user_options->brain_client == true)
        {
          u32 hash[2];

          brain_client_generate_hash ((u64 *) hash, (const char *) sc->out_buf, sc->out_len[0]);

          u32 *ptr = device_param->brain_link_out_buf;

          ptr[(device_param->pws_pre_cnt * 2) + 0] = hash[0];
          ptr[(device_param->pws_pre_cnt * 2) + 1] = hash[1];
        }
        #endif

        if (sc->base_buf)
        {
          pw_pre_add (device_param, sc->out_buf, sc->out_len[0], sc->base_buf, sc->base_len[0], (sc->rule_pos) ? (int) sc->rule_pos[0] : 0);
        }
        else
        {
          pw_pre_add (device_param, sc->out_buf, sc->out_len[0], NULL, 0, 0);
        }

        if (status_ctx->run_thread_level1 == false) break;
      }

      sc->words_cur = words_fin;

      if (status_ctx->run_thread_level1 == false) break;
    }

    #ifdef WITH_BRAIN
    if (user_options->brain_client == true)
    {
      if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_HASHES)
      {
        if (brain_client_lookup (device_param, status_ctx) == false)
        {
          brain_client_disconnect (device_param);
        }
      }

      const u64 pws_pre_cnt = device_param->pws_pre_cnt;

      for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
      {
        if (device_param->brain_link_in_buf[pws_pre_idx] == 1)
        {
          pre_rejects++;

          brain_rejects_hashes++;
        }
        else
        {
          pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

          if (sc->keep_base == true) pw_base_add (batch, device_param->kernel_power, pw_pre);

          pw_add (batch, device_param->kernel_power, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
        }
      }
    }
    else
    {
      const u64 pws_pre_cnt = device_param->pws_pre_cnt;

      for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
      {
        pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

        if (sc->keep_base == true) pw_base_add (batch, device_param->kernel_power, pw_pre);

        pw_add (batch, device_param->kernel_power, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
      }
    }
    #else
    const u64 pws_pre_cnt = device_param->pws_pre_cnt;

    for (u64 pws_pre_idx = 0; pws_pre_idx < pws_pre_cnt; pws_pre_idx++)
    {
      pw_pre_t *pw_pre = device_param->pws_pre_buf + pws_pre_idx;

      if (sc->keep_base == true) pw_base_add (batch, device_param->kernel_power, pw_pre);

      pw_add (batch, device_param->kernel_power, (const u8 *) pw_pre->pw_buf, (const int) pw_pre->pw_len);
    }
    #endif

    words_extra_total += pre_rejects;

    if (status_ctx->run_thread_level1 == false) break;

    if (words_extra_total > 0)
    {
      hc_thread_mutex_lock (status_ctx->mux_counter);

      for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        status_ctx->words_progress_rejected[salt_pos] += words_extra_total;
      }

      #ifdef WITH_BRAIN
      status_ctx->brain_rejects_attacks += brain_rejects_attacks;
      status_ctx->brain_rejects_hashes  += brain_rejects_hashes;
      #endif

      hc_thread_mutex_unlock (status_ctx->mux_counter);
    }
  }

  pipe_acc (PIPE_FEED, &timer_feed);

  return 0;
}


// Everything the wordlist producer carries between batches. It owns its own wordlist reader, because
// the reader keeps a buffer that only one thread may touch.

typedef struct wl_fill_state
{
  HCFILE fp;

  hashcat_ctx_t *hashcat_ctx_tmp;

  u64 words_cur;

} wl_fill_state_t;

// A producer that reads words gets its own hashcat_ctx with its own wl_data, because the reader keeps
// a segment buffer that only one thread may touch. Everything else in the context is shared on
// purpose: the copy is of the pointers, not of what they point at.
//
// Returns NULL on failure, having freed whatever it had taken. The caller still owns any file it
// opened before calling this.

static hashcat_ctx_t *wl_reader_create (hashcat_ctx_t *hashcat_ctx)
{
  hashcat_ctx_t *reader_ctx = (hashcat_ctx_t *) hcmalloc (sizeof (hashcat_ctx_t));

  memcpy (reader_ctx, hashcat_ctx, sizeof (hashcat_ctx_t)); // yes we actually want to copy these pointers

  reader_ctx->wl_data = (wl_data_t *) hcmalloc (sizeof (wl_data_t));

  if (wl_data_init (reader_ctx) == -1)
  {
    hcfree (reader_ctx->wl_data);
    hcfree (reader_ctx);

    return NULL;
  }

  return reader_ctx;
}

static void wl_reader_destroy (hashcat_ctx_t *reader_ctx)
{
  wl_data_destroy (reader_ctx);

  hcfree (reader_ctx->wl_data);
  hcfree (reader_ctx);
}

static int fill_wordlist (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  wl_fill_state_t *wl = (wl_fill_state_t *) state;

  const u32 attack_mode = user_options->attack_mode;
  const u32 attack_kern = user_options_extra->attack_kern;

  hc_timer_t timer_feed;

  pipe_mark (&timer_feed);

  u64 words_extra = -1U;

  while (words_extra)
  {
    const u64 work = get_work (hashcat_ctx, device_param, words_extra);

    if (work == 0) break;

    words_extra = 0;

    const u64 words_off = device_param->words_off;
    const u64 words_fin = words_off + work;

    batch->words_off = words_off;
    batch->words_fin = words_fin;

    char *line_buf;
    u32   line_len;

    char rule_buf_out[RP_PASSWORD_SIZE];

    for ( ; wl->words_cur < words_off; wl->words_cur++) get_next_word (wl->hashcat_ctx_tmp, &wl->fp, &line_buf, &line_len);

    for ( ; wl->words_cur < words_fin; wl->words_cur++)
    {
      get_next_word (wl->hashcat_ctx_tmp, &wl->fp, &line_buf, &line_len);

      // post-process rule engine

      int   rule_jk_len = (int)    user_options_extra->rule_len_l;
      const char *rule_jk_buf = user_options->rule_buf_l;

      if (attack_mode == ATTACK_MODE_HYBRID2)
      {
        rule_jk_len = (int)    user_options_extra->rule_len_r;
        rule_jk_buf = user_options->rule_buf_r;
      }

      if (run_rule_engine (rule_jk_len, rule_jk_buf))
      {
        if (line_len >= RP_PASSWORD_SIZE) continue;

        const int rule_len_out = _old_apply_rule (rule_jk_buf, rule_jk_len, line_buf, (int) line_len, rule_buf_out);

        if (rule_len_out < 0) continue;

        line_buf = rule_buf_out;
        line_len = (u32) rule_len_out;
      }

      // -a 9 does not reject on length, because that would bring the schedule out of sync

      if (attack_kern == ATTACK_KERN_STRAIGHT)
      {
        if (attack_mode == ATTACK_MODE_ASSOCIATION)
        {
          // do nothing, test fix for above scenario
        }
        else
        {
          if ((line_len < hashconfig->pw_min) || (line_len > hashconfig->pw_max))
          {
            words_extra++;

            continue;
          }
        }
      }
      else if (attack_kern == ATTACK_KERN_COMBI)
      {
        // do not check if minimum restriction is satisfied (line_len >= hashconfig->pw_min) here
        // since we still need to combine the plains

        if (line_len > hashconfig->pw_max)
        {
          words_extra++;

          continue;
        }
      }

      pw_add (batch, device_param->kernel_power, (const u8 *) line_buf, (const int) line_len);

      if (status_ctx->run_thread_level1 == false) break;
    }

    batch->words_extra += words_extra;

    if (status_ctx->run_thread_level1 == false) break;
  }

  pipe_acc (PIPE_FEED, &timer_feed);

  return 0;
}

// Everything the generic-feed producer carries between batches. The feed plugin keeps its own
// per-device cursor, so only one thread may drive it.

typedef struct generic_fill_state
{
  bool    iconv_enabled;
  iconv_t iconv_ctx;
  char   *iconv_tmp;

  int         rule_jk_len;
  const char *rule_jk_buf;

  bool rule_engine;
  bool wordlist_autohex;
  bool mods;

  // Driven by the hash mode rather than by the user or the plugin, so these apply whatever the feed
  // declared. They are what -a 0 does inside its own word reader, and a feed has no business
  // knowing about them.

  bool pt_uppercase;
  bool pt_hex;

  // The feed writes the candidate straight into the buffer that gets uploaded, which holds exactly
  // PW_MAX per candidate. That is what makes the feed zero copy and it is the whole reader advantage
  // over -a 0, so it has to stay the normal path.
  //
  // A hex wordlist, a $HEX[] wrapper and an encoding change all shorten a candidate, so one can
  // arrive too long for that buffer and still finish inside it: a 256 byte password written as hex
  // is a 512 byte line. When that happens the word is read a second time into scratch, which is
  // large enough, and only the finished candidate is copied over. It costs a seek and a re-read, and
  // it only happens for a candidate that would otherwise have been thrown away.

  bool  can_shrink;
  int   scratch_size;
  u8   *scratch;

  // Where the feed's own cursor is, so that a seek that would not move it can be skipped. A feed
  // that cannot seek has to implement seek by generating from the start again, which is the shape a
  // probabilistic generator has, and seeking it once per batch to the place it already sits turns a
  // linear attack into a quadratic one.

  bool seek_known;
  u64  seek_pos;

} generic_fill_state_t;

static int fill_generic (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  generic_fill_state_t *gf = (generic_fill_state_t *) state;

  hc_timer_t timer_feed;

  pipe_mark (&timer_feed);

  u64 words_extra = -1U;

  bool feed_dry = false;

  while (words_extra)
  {
    const u64 work_cnt = get_work (hashcat_ctx, device_param, words_extra);

    if (work_cnt == 0) break;

    words_extra = 0;

    const u64 words_off = device_param->words_off;

    batch->words_off = words_off;

    if ((gf->seek_known == false) || (gf->seek_pos != words_off))
    {
      if (generic_thread_seek (hashcat_ctx, device_param->device_id, words_off) != 0) return -1;

      gf->seek_known = true;
      gf->seek_pos   = words_off;
    }

    u64 work_cur = 0;

    for (work_cur = 0; work_cur < work_cnt; work_cur++)
    {
      pw_idx_t *pw_idx = batch->pws_idx + batch->pws_cnt;

      u8 *pw_buf = (u8 *) (batch->pws_comp + pw_idx->off);

      // the candidate lands in the upload buffer directly, which is what makes the feed zero copy

      u8 *work_buf = pw_buf;

      int pw_len = generic_thread_next (hashcat_ctx, device_param->device_id, pw_buf, PW_MAX);

      // the feed is dry. Whatever it produced before this call still has to be launched, so the
      // batch is finished rather than thrown away, and the pipeline is told on the next one

      if (pw_len == GENERIC_RC_EOF)
      {
        feed_dry = true;

        break;
      }

      // the feed failed. That is not the end of the attack, it is the end of the session, and it has
      // to reach the caller as an error or the run reports Exhausted and an exit status that says
      // everything went fine

      if (pw_len == GENERIC_RC_ERROR) return -1;

      gf->seek_pos++;

      // A feed reports the true length even when the candidate did not fit and it only wrote the
      // first PW_MAX bytes. If nothing in this run can shorten it then it is simply too long, and
      // -a 0 would have dropped it too.

      if (pw_len > PW_MAX)
      {
        if (gf->can_shrink == false)
        {
          batch->words_extra++;

          words_extra++;

          continue;
        }

        // It might still finish short enough, so read it again somewhere it fits. The feed is one
        // candidate past it now, so it has to be sent back.

        if (generic_thread_seek (hashcat_ctx, device_param->device_id, words_off + work_cur) != 0) return -1;

        pw_len = generic_thread_next (hashcat_ctx, device_param->device_id, gf->scratch, gf->scratch_size);

        if (pw_len == GENERIC_RC_EOF)
        {
          feed_dry = true;

          break;
        }

        if (pw_len == GENERIC_RC_ERROR) return -1;

        if (pw_len > gf->scratch_size)
        {
          batch->words_extra++;

          words_extra++;

          continue;
        }

        work_buf = gf->scratch;
      }

      // The hash mode's own transforms. -a 0 does these inside its word reader, so they have to
      // happen here for the same wordlist to produce the same candidates.

      if (gf->pt_uppercase == true) convert_to_uppercase ((char *) work_buf, pw_len);

      if (gf->pt_hex == true) pw_len = (int) convert_hex_wordlist ((char *) work_buf, pw_len);

      if (gf->mods == true)
      {
        if (gf->wordlist_autohex == true)
        {
          if (is_hexify ((const u8 *) work_buf, pw_len) == true)
          {
            pw_len = (int) exec_unhexify ((const u8 *) work_buf, (u32) pw_len, (u8 *) work_buf, (u32) pw_len);
          }
        }

        if (gf->iconv_enabled == true)
        {
          char  *iconv_ptr = gf->iconv_tmp;
          size_t iconv_sz  = HCBUFSIZ_TINY;

          char  *in_pw_buf = (char *) work_buf;
          size_t in_pw_len = pw_len;

          if (iconv (gf->iconv_ctx, &in_pw_buf, &in_pw_len, &iconv_ptr, &iconv_sz) == (size_t) -1)
          {
            batch->words_extra++;

            words_extra++;

            continue;
          }
          else
          {
            const size_t iconv_left = HCBUFSIZ_TINY - iconv_sz;

            if (iconv_left <= PW_MAX)
            {
              memcpy (work_buf, gf->iconv_tmp, iconv_left);

              pw_len = iconv_left;
            }
            else
            {
              batch->words_extra++;

              words_extra++;

              continue;
            }
          }
        }

        if (gf->rule_engine == true)
        {
          if (pw_len >= RP_PASSWORD_SIZE)
          {
            batch->words_extra++;

            words_extra++;

            continue;
          }

          char rule_buf_out[RP_PASSWORD_SIZE];

          const int rule_len_out = _old_apply_rule (gf->rule_jk_buf, gf->rule_jk_len, (char *) work_buf, (int) pw_len, rule_buf_out);

          if (rule_len_out < 0)
          {
            batch->words_extra++;

            words_extra++;

            continue;
          }

          memcpy (work_buf, rule_buf_out, rule_len_out);

          pw_len = rule_len_out;
        }
      }

      // Only now is the length final, so only now can it be judged. Rejecting before the transforms
      // would throw away a hex line that decodes to a candidate of a perfectly legal length: a 256
      // byte password written as hex arrives as 512 bytes.

      if (pw_len > PW_MAX)
      {
        batch->words_extra++;

        words_extra++;

        continue;
      }

      if (work_buf != pw_buf) memcpy (pw_buf, work_buf, pw_len);

      if ((pw_len < (int) hashconfig->pw_min) || (pw_len > (int) hashconfig->pw_max))
      {
        batch->words_extra++;

        words_extra++;

        continue;
      }

      pw_add_zerocopy (batch, device_param->kernel_power, pw_buf, pw_len);
    }

    // How far into the keyspace this batch reached. It is the restore point, so it has to be a
    // position and not a count of the words this one device happened to see.
    //
    // It is also what tells the pipeline whether the source is finished: a batch with no candidates
    // and no words_fin is the end. Leaving it at zero whenever nothing was accepted made a batch in
    // which every candidate was rejected on length look like the end of the feed, which ended the
    // attack and lost the rejects with it. Only a batch the feed refused to fill at all is the end.

    if (work_cur > 0) batch->words_fin = words_off + work_cur;

    if (feed_dry == true) break;

    if (status_ctx->run_thread_level1 == false) break;
  }

  pipe_acc (PIPE_FEED, &timer_feed);

  return 0;
}

// Take batches off the pipeline and launch them until the producer runs dry. Every attack mode does
// this the same way, which is what pwpipe.h means by the producer being a callback: the mode chooses
// what fills a batch, not what happens to it afterwards.
//
// Two things genuinely differ, and both are constant for a whole attack rather than per batch.
//
// slow_candidates rejects candidates the host has already built, so a device's words_done is not a
// prefix of the keyspace and the restore point has to come from the device that got furthest. It also
// passes no position to run_cracker, because the candidate was built on the host and the kernel is
// not deriving it from an offset. The fast path is the other way round on both counts.
//
// reject_amplifier is how many candidates one rejected base word stood for, so the rejects can be
// booked against the salts. A producer that books its own passes 0: fill_slow does, because only it
// knows how many words it had to skip to fill the batch.

static int pipe_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_pipe_t *pipe, const bool slow, const u64 reject_amplifier)
{
  hashes_t     *hashes     = hashcat_ctx->hashes;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // only read inside a WITH_BRAIN block, so a build without the brain has no use for it

  MAYBE_UNUSED user_options_t *user_options = hashcat_ctx->user_options;

  int rc_final = 0;

  while (status_ctx->run_thread_level1 == true)
  {
    pw_batch_t *batch = pw_pipe_take (pipe);

    if (batch == NULL) break;

    if ((reject_amplifier > 0) && (batch->words_extra > 0))
    {
      hc_thread_mutex_lock (status_ctx->mux_counter);

      for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        status_ctx->words_progress_rejected[salt_pos] += batch->words_extra * reject_amplifier;
      }

      hc_thread_mutex_unlock (status_ctx->mux_counter);
    }

    //
    // flush
    //

    const u64 pws_cnt   = batch->pws_cnt;
    const u64 words_off = batch->words_off;
    const u64 words_fin = batch->words_fin;

    device_param->pws_idx  = batch->pws_idx;
    device_param->pws_comp = batch->pws_comp;
    device_param->pws_cnt  = pws_cnt;

    if (slow == true) device_param->pws_base_buf = batch->pws_base;

    if (pws_cnt)
    {
      hc_timer_t timer_copy;

      if (slow == false) pipe_mark (&timer_copy);

      if (run_copy (hashcat_ctx, device_param, pws_cnt) == -1)
      {
        rc_final = -1;

        break;
      }

      if (slow == false) pipe_acc (PIPE_COPY, &timer_copy);

      const u64 pws_pos = (slow == true) ? (u64) -1 : words_off;

      if (run_cracker (hashcat_ctx, device_param, pws_pos, pws_cnt) == -1)
      {
        rc_final = -1;

        break;
      }

      #ifdef WITH_BRAIN
      if ((slow == true) && (user_options->brain_client == true))
      {
        if ((status_ctx->devices_status != STATUS_ABORTED)
         && (status_ctx->devices_status != STATUS_ABORTED_RUNTIME)
         && (status_ctx->devices_status != STATUS_QUIT)
         && (status_ctx->devices_status != STATUS_BYPASS)
         && (status_ctx->devices_status != STATUS_ERROR))
        {
          if (brain_client_commit (device_param, status_ctx) == false)
          {
            brain_client_disconnect (device_param);
          }
        }
      }
      #endif

      device_param->pws_cnt = 0;
    }

    // the launch is complete, so the slot may go back to the producer

    pw_pipe_release (pipe, batch);

    if (device_param->speed_only_finish == true) break;

    if (status_ctx->run_thread_level2 == true)
    {
      device_param->words_done = MAX (device_param->words_done, words_fin);

      status_ctx->words_cur = (slow == true) ? get_highest_words_done (hashcat_ctx) : get_lowest_words_done (hashcat_ctx);
    }

    if (status_ctx->run_thread_level1 == false) break;
  }

  pw_pipe_stop (pipe);

  if (pw_pipe_failed (pipe) == true) rc_final = -1;

  return rc_final;
}

static int calc (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  generic_ctx_t        *generic_ctx        = hashcat_ctx->generic_ctx;

  const u32 attack_mode = user_options->attack_mode;
  const u32 attack_kern = user_options_extra->attack_kern;

  // handling PCFG attack
  if (attack_mode == ATTACK_MODE_PCFG)
  {
    return calc_pcfg (hashcat_ctx, device_param);
  }

  if (user_options->slow_candidates == true)
  {
    #ifdef WITH_BRAIN
    const u32 brain_session = user_options->brain_session;
    const u32 brain_attack  = user_options->brain_attack;

    u64 highest = 0;

    brain_client_disconnect (device_param);

    if (user_options->brain_client == true)
    {
      const i64 passwords_max = device_param->hardware_power * device_param->kernel_accel;

      // this is the first connect of the run. A brain that is not there now means the whole attack
      // runs with no dedup at all, which is what the user asked for by passing -z, so it is an error
      // rather than a degradation. A link that drops later is different: the work already deduped
      // stays deduped, so that one only warns and keeps going.

      if (brain_client_connect (hashcat_ctx, device_param, status_ctx, user_options->brain_host, user_options->brain_port, user_options->brain_password, brain_session, brain_attack, passwords_max, &highest) == false)
      {
        brain_client_disconnect (device_param);

        return -1;
      }

      if (user_options->brain_client_features & BRAIN_CLIENT_FEATURE_ATTACKS)
      {
        hc_thread_mutex_lock (status_ctx->mux_dispatcher);

        if (status_ctx->words_off == 0)
        {
          status_ctx->words_off = highest;

          for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
          {
            status_ctx->words_progress_rejected[salt_pos] = status_ctx->words_off;
          }

          // the brain reported a contiguous prefix of the keyspace as already done, so the run starts
          // past it. Those words are rejected by the same mechanism as an overlap and belong in the
          // same counter, or the attacks total is short by the whole prefix on any resumed session.

          status_ctx->brain_rejects_attacks = status_ctx->words_off;
        }

        hc_thread_mutex_unlock (status_ctx->mux_dispatcher);
      }
    }
    #endif

    // attack modes from here

    if (attack_mode == ATTACK_MODE_STRAIGHT)
    {
      char *dictfile = straight_ctx->dict;

      extra_info_straight_t extra_info_straight;

      memset (&extra_info_straight, 0, sizeof (extra_info_straight));

      if (hc_fopen (&extra_info_straight.fp, dictfile, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile, strerror (errno));

        return -1;
      }

      hashcat_ctx_t *hashcat_ctx_tmp = wl_reader_create (hashcat_ctx);

      if (hashcat_ctx_tmp == NULL)
      {
        hc_fclose (&extra_info_straight.fp);

        return -1;
      }

      slow_fill_state_t sc;

      sc.reader_ctx = hashcat_ctx_tmp;
      sc.extra_info = &extra_info_straight;
      sc.pos        = &extra_info_straight.pos;
      sc.out_buf    = extra_info_straight.out_buf;
      sc.out_len    = &extra_info_straight.out_len;
      sc.base_buf   = extra_info_straight.base_buf;
      sc.base_len   = &extra_info_straight.base_len;
      sc.rule_pos   = &extra_info_straight.rule_pos_prev;
      sc.reject     = NULL;
      sc.seek       = true;
      sc.reject_len = true;
      sc.keep_base  = true;
      sc.words_cur  = 0;

      bool pipe_serial = false;

      #ifdef WITH_BRAIN
      sc.brain_highest = highest;

      pipe_serial = user_options->brain_client;
      #endif

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_slow, &sc, pipe_serial);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, true, 0);

      hc_fclose (&extra_info_straight.fp);

      wl_reader_destroy (hashcat_ctx_tmp);

      if (rc_final == -1) return -1;
    }
    else if (attack_mode == ATTACK_MODE_COMBI)
    {
      const u32 combs_mode = combinator_ctx->combs_mode;

      char *base_file;
      char *combs_file;

      if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
      {
        base_file  = combinator_ctx->dict1;
        combs_file = combinator_ctx->dict2;
      }
      else
      {
        base_file  = combinator_ctx->dict2;
        combs_file = combinator_ctx->dict1;
      }

      extra_info_combi_t extra_info_combi;

      memset (&extra_info_combi, 0, sizeof (extra_info_combi));

      if (hc_fopen (&extra_info_combi.base_fp, base_file, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", base_file, strerror (errno));

        return -1;
      }

      if (hc_fopen (&extra_info_combi.combs_fp, combs_file, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", combs_file, strerror (errno));

        hc_fclose (&extra_info_combi.base_fp);

        return -1;
      }

      extra_info_combi.scratch_buf = device_param->scratch_buf;

      hashcat_ctx_t *hashcat_ctx_tmp = wl_reader_create (hashcat_ctx);

      if (hashcat_ctx_tmp == NULL)
      {
        hc_fclose (&extra_info_combi.base_fp);
        hc_fclose (&extra_info_combi.combs_fp);

        return -1;
      }

      slow_fill_state_t sc;

      sc.reader_ctx = hashcat_ctx_tmp;
      sc.extra_info = &extra_info_combi;
      sc.pos        = &extra_info_combi.pos;
      sc.out_buf    = extra_info_combi.out_buf;
      sc.out_len    = &extra_info_combi.out_len;
      sc.base_buf   = NULL;
      sc.base_len   = NULL;
      sc.rule_pos   = NULL;
      sc.reject     = NULL;
      sc.seek       = true;
      sc.reject_len = true;
      sc.keep_base  = true;
      sc.words_cur  = 0;

      bool pipe_serial = false;

      #ifdef WITH_BRAIN
      sc.brain_highest = highest;

      pipe_serial = user_options->brain_client;
      #endif

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_slow, &sc, pipe_serial);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, true, 0);

      hc_fclose (&extra_info_combi.base_fp);
      hc_fclose (&extra_info_combi.combs_fp);

      wl_reader_destroy (hashcat_ctx_tmp);

      if (rc_final == -1) return -1;
    }
    else if (attack_mode == ATTACK_MODE_BF)
    {
      extra_info_mask_t extra_info_mask;

      memset (&extra_info_mask, 0, sizeof (extra_info_mask));

      extra_info_mask.out_len = mask_ctx->css_cnt;

      slow_fill_state_t sc;

      sc.reader_ctx = hashcat_ctx;
      sc.extra_info = &extra_info_mask;
      sc.pos        = &extra_info_mask.pos;
      sc.out_buf    = extra_info_mask.out_buf;
      sc.out_len    = &extra_info_mask.out_len;
      sc.base_buf   = NULL;
      sc.base_len   = NULL;
      sc.rule_pos   = NULL;
      sc.reject     = NULL;
      sc.seek       = false;
      sc.reject_len = false;
      sc.keep_base  = false;
      sc.words_cur  = 0;

      bool pipe_serial = false;

      #ifdef WITH_BRAIN
      sc.brain_highest = highest;

      pipe_serial = user_options->brain_client;
      #endif

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_slow, &sc, pipe_serial);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, true, 0);

      if (rc_final == -1) return -1;
    }
    else if (attack_mode == ATTACK_MODE_GENERIC)
    {
      extra_info_generic_t extra_info_generic;

      memset (&extra_info_generic, 0, sizeof (extra_info_generic));

      // The feed keeps one generator per device and hashcat addresses it by device id, so unlike the
      // wordlist reader there is no private copy of hashcat_ctx to make here.

      extra_info_generic.device_id = device_param->device_id;

      slow_fill_state_t sc;

      sc.reader_ctx = hashcat_ctx;
      sc.extra_info = &extra_info_generic;
      sc.pos        = &extra_info_generic.pos;
      sc.out_buf    = extra_info_generic.out_buf;
      sc.out_len    = &extra_info_generic.out_len;
      sc.base_buf   = extra_info_generic.base_buf;
      sc.base_len   = &extra_info_generic.base_len;
      sc.rule_pos   = &extra_info_generic.rule_pos_prev;
      sc.reject     = &extra_info_generic.reject;
      sc.seek       = true;
      sc.reject_len = true;
      sc.keep_base  = true;
      sc.words_cur  = 0;

      bool pipe_serial = false;

      #ifdef WITH_BRAIN
      sc.brain_highest = highest;

      pipe_serial = user_options->brain_client;
      #endif

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_slow, &sc, pipe_serial);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, true, 0);

      if (rc_final == -1) return -1;
    }

    #ifdef WITH_BRAIN
    if (user_options->brain_client == true)
    {
      brain_client_disconnect (device_param);
    }
    #endif
  }
  else
  {
    if ((attack_mode == ATTACK_MODE_BF) || (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (attack_mode == ATTACK_MODE_HYBRID2)))
    {
      if (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (attack_mode == ATTACK_MODE_HYBRID2))
      {
        char *dictfile = straight_ctx->dict;

        if (hc_fopen (&device_param->combs_fp, dictfile, "rb") == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", dictfile, strerror (errno));

          return -1;
        }
      }

      while (status_ctx->run_thread_level1 == true)
      {
        const u64 work = get_work (hashcat_ctx, device_param, -1);

        if (work == 0) break;

        const u64 words_off = device_param->words_off;
        const u64 words_fin = words_off + work;

        device_param->pws_cnt = work;

        if (run_copy    (hashcat_ctx, device_param, device_param->pws_cnt) == -1) return -1;
        if (run_cracker (hashcat_ctx, device_param, -1, device_param->pws_cnt) == -1) return -1;

        device_param->pws_cnt = 0;

        if (device_param->speed_only_finish == true) break;

        if (status_ctx->run_thread_level2 == true)
        {
          device_param->words_done = MAX (device_param->words_done, words_fin);

          status_ctx->words_cur = get_lowest_words_done (hashcat_ctx);
        }
      }
    }
    else if (attack_mode == ATTACK_MODE_GENERIC)
    {
      bool iconv_enabled = false;

      iconv_t iconv_ctx = NULL;

      char *iconv_tmp = NULL;

      if (generic_ctx->iconv_enable == true)
      {
        if (strcmp (user_options->encoding_from, user_options->encoding_to) != 0)
        {
          iconv_enabled = true;

          iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

          if (iconv_ctx == (iconv_t) -1)
          {
            event_log_error (hashcat_ctx, "iconv_open: %s", strerror (errno));

            return -1;
          }

          iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);
        }
      }

      generic_fill_state_t gf;

      gf.iconv_enabled = iconv_enabled;
      gf.iconv_ctx     = iconv_ctx;
      gf.iconv_tmp     = iconv_tmp;

      gf.rule_jk_len = (int) user_options_extra->rule_len_l;
      gf.rule_jk_buf =       user_options->rule_buf_l;

      gf.rule_engine      = generic_ctx->rules_enable && run_rule_engine (gf.rule_jk_len, gf.rule_jk_buf);
      gf.wordlist_autohex = generic_ctx->autohex_enable && user_options->wordlist_autohex;
      gf.mods             = gf.iconv_enabled | gf.rule_engine | gf.wordlist_autohex;

      gf.pt_uppercase = (hashconfig->opts_type & OPTS_TYPE_PT_UPPER) ? true : false;
      gf.pt_hex       = (hashconfig->opts_type & OPTS_TYPE_PT_HEX)   ? true : false;

      // Only these three can make a candidate come out shorter than it arrived. Without one of
      // them an over-length candidate is over-length for good and there is nothing to re-read.

      gf.can_shrink   = gf.pt_hex | gf.wordlist_autohex | gf.iconv_enabled;
      gf.scratch_size = HCBUFSIZ_TINY;
      gf.scratch      = (gf.can_shrink == true) ? (u8 *) hcmalloc (gf.scratch_size) : NULL;

      gf.seek_known = false;
      gf.seek_pos   = 0;

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_generic, &gf, false);

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, false, straight_ctx->kernel_rules_cnt);

      hcfree (gf.scratch);

      if (iconv_enabled == true)
      {
        iconv_close (iconv_ctx);

        hcfree (iconv_tmp);
      }

      if (rc_final == -1) return -1;
    }
    else
    {
      char *dictfile = straight_ctx->dict;

      if (attack_mode == ATTACK_MODE_COMBI)
      {
        if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
        {
          dictfile = combinator_ctx->dict1;
        }
        else
        {
          dictfile = combinator_ctx->dict2;
        }

        const u32 combs_mode = combinator_ctx->combs_mode;

        if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
        {
          const char *dictfilec = combinator_ctx->dict2;

          if (hc_fopen (&device_param->combs_fp, dictfilec, "rb") == false)
          {
            event_log_error (hashcat_ctx, "%s: %s", combinator_ctx->dict2, strerror (errno));

            return -1;
          }
        }
        else if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
        {
          const char *dictfilec = combinator_ctx->dict1;

          if (hc_fopen (&device_param->combs_fp, dictfilec, "rb") == false)
          {
            event_log_error (hashcat_ctx, "%s: %s", dictfilec, strerror (errno));

            return -1;
          }
        }
      }

      wl_fill_state_t wl_state;

      wl_state.words_cur = 0;

      if (hc_fopen (&wl_state.fp, dictfile, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", dictfile, strerror (errno));

        return -1;
      }

      hashcat_ctx_t *hashcat_ctx_tmp = wl_reader_create (hashcat_ctx);

      if (hashcat_ctx_tmp == NULL)
      {
        if (attack_mode == ATTACK_MODE_COMBI) hc_fclose (&device_param->combs_fp);

        hc_fclose (&wl_state.fp);

        return -1;
      }

      wl_state.hashcat_ctx_tmp = hashcat_ctx_tmp;

      pw_pipe_t pipe;

      pw_pipe_start (&pipe, hashcat_ctx, device_param, fill_wordlist, &wl_state, false);

      // One rejected base word stood for a whole amplifier's worth of candidates. Which amplifier
      // depends on the kernel, and it does not change during the attack, so it is resolved once here.

      u64 reject_amplifier = 0;

      if (attack_kern == ATTACK_KERN_STRAIGHT) reject_amplifier = straight_ctx->kernel_rules_cnt;
      if (attack_kern == ATTACK_KERN_COMBI)    reject_amplifier = combinator_ctx->combs_cnt;

      const int rc_final = pipe_run (hashcat_ctx, device_param, &pipe, false, reject_amplifier);

      if (attack_mode == ATTACK_MODE_COMBI) hc_fclose (&device_param->combs_fp);

      hc_fclose (&wl_state.fp);

      wl_reader_destroy (hashcat_ctx_tmp);

      if (rc_final == -1) return -1;
    }
  }

  device_param->kernel_accel_prev   = device_param->kernel_accel;
  device_param->kernel_loops_prev   = device_param->kernel_loops;
  device_param->kernel_threads_prev = device_param->kernel_threads;

  device_param->kernel_accel   = 0;
  device_param->kernel_loops   = 0;
  device_param->kernel_threads = 0;

  return 0;
}

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD thread_calc (void *p)
#else
HC_API_CALL void *thread_calc (void *p)
#endif
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  bridge_ctx_t  *bridge_ctx  = hashcat_ctx->bridge_ctx;
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;
  hashes_t      *hashes      = hashcat_ctx->hashes;

  if (backend_ctx->enabled == false) return 0;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped) return 0;
  if (device_param->skipped_warning == true) return 0;

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_init != BRIDGE_DEFAULT)
    {
      if (bridge_ctx->thread_init (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, hashes) == false) return 0;
    }
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return 0;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == -1) return 0;
  }

  if (calc (hashcat_ctx, device_param) == -1)
  {
    status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

    status_ctx->devices_status = STATUS_ERROR;
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return 0;
  }

  if (bridge_ctx->enabled == true)
  {
    if (bridge_ctx->thread_term != BRIDGE_DEFAULT)
    {
      bridge_ctx->thread_term (hashcat_ctx, bridge_ctx->platform_context, device_param, hashconfig, hashes);
    }
  }

  return 0;
}
