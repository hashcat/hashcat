/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"
#include "shared.h"
#include "thread.h"
#include "filehandling.h"
#include "folder.h"
#include "backend.h"
#include "straight.h"
#include "hashcat.h"
#include "pcfg.h"
#include "pcfg_trainer.h"
#include "pcfg_loopback.h"

// write a cracked password to the loopback pw file

void pcfg_loopback_write_pw (hashcat_ctx_t *hashcat_ctx, const u8 *pw, const u32 pw_len)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  if (pcfg_ctx->loopback_enabled == false) return;

  if (pcfg_ctx->loopback_fp.pfp == NULL) return;

  if (pw_len == 0) return;

  hc_thread_mutex_lock (pcfg_ctx->loopback_mutex);

  hc_fwrite (pw, pw_len, 1, &pcfg_ctx->loopback_fp);
  hc_fwrite ("\n", 1, 1, &pcfg_ctx->loopback_fp);
  hc_fflush (&pcfg_ctx->loopback_fp);

  hc_thread_mutex_unlock (pcfg_ctx->loopback_mutex);
}

// pcfg_loopback_ctx_init: early init during -a0 phase (before PCFG attack starts)

int pcfg_loopback_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  pcfg_ctx_t      *pcfg_ctx      = hashcat_ctx->pcfg_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;
  folder_config_t *folder_config = hashcat_ctx->folder_config;

  pcfg_ctx->loopback_enabled    = true;
  pcfg_ctx->loopback_generation = 0;

  // pw file in session directory (NOT induction dir, to avoid interference with induction cycle)
  hc_asprintf (&pcfg_ctx->loopback_pw_file, "%s/pcfg_loopback_pws.txt", folder_config->session_dir);

  // model file in session directory
  hc_asprintf (&pcfg_ctx->loopback_model_file, "%s/pcfg_loopback.model", folder_config->session_dir);

  // open pw file for writing
  if (hc_fopen (&pcfg_ctx->loopback_fp, pcfg_ctx->loopback_pw_file, "wb") == false)
  {
    event_log_error (hashcat_ctx, "PCFG loopback: %s: %s", pcfg_ctx->loopback_pw_file, strerror (errno));
    return -1;
  }

  hc_thread_mutex_init (pcfg_ctx->loopback_mutex);

  // if not running -a10 right now, return 1 to signal caller to return early
  if (user_options->attack_mode != ATTACK_MODE_PCFG) return 1;

  return 0;
}

// cleanup loopback resources

void pcfg_loopback_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  if (pcfg_ctx->loopback_fp.pfp != NULL)
  {
    hc_fclose (&pcfg_ctx->loopback_fp);
  }

  if (pcfg_ctx->loopback_pw_file != NULL)
  {
    unlink (pcfg_ctx->loopback_pw_file);
    hcfree (pcfg_ctx->loopback_pw_file);
    pcfg_ctx->loopback_pw_file = NULL;
  }

  if (pcfg_ctx->loopback_model_file != NULL)
  {
    unlink (pcfg_ctx->loopback_model_file);
    hcfree (pcfg_ctx->loopback_model_file);
    pcfg_ctx->loopback_model_file = NULL;
  }

  hc_thread_mutex_delete (pcfg_ctx->loopback_mutex);
}

// pcfg_loopback_sanity_check: validate --pcfg-loopback options

int pcfg_loopback_sanity_check (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
  {
    event_log_error (hashcat_ctx, "--pcfg-loopback is only allowed in attack mode 0 (straight).");
    return -1;
  }

  // set default pcfg_mode for loopback if user didn't explicitly set --pcfg-mode
  if (user_options->pcfg_mode_chgd == false)
  {
    user_options->pcfg_mode = PCFG_MODE_GPU_OMEN_BY_COST;
  }

  return 0;
}

// after -a0 completes, train PCFG model from cracked passwords and run -a10 loop

int pcfg_loopback_run (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t        *backend_ctx         = hashcat_ctx->backend_ctx;
  hashes_t             *hashes              = hashcat_ctx->hashes;
  pcfg_ctx_t           *pcfg_ctx            = hashcat_ctx->pcfg_ctx;
  status_ctx_t         *status_ctx          = hashcat_ctx->status_ctx;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  int rc = 0;

  // close pw file

  if (pcfg_ctx->loopback_fp.pfp != NULL)
  {
    hc_fclose (&pcfg_ctx->loopback_fp);
  }

  // check pw file has data

  struct stat pw_stat;

  if (stat (pcfg_ctx->loopback_pw_file, &pw_stat) != 0 || pw_stat.st_size == 0)
  {
    event_log_info (hashcat_ctx, "PCFG loopback: no cracked passwords, skipping PCFG phase.");

    return 0;
  }

  // count passwords (one per line)

  u32 pw_count = 0;

  HCFILE pw_count_fp;

  if (hc_fopen (&pw_count_fp, pcfg_ctx->loopback_pw_file, "rb") == true)
  {
    char buf[HCBUFSIZ_TINY];

    while (hc_fgets (buf, sizeof (buf), &pw_count_fp)) pw_count++;

    hc_fclose (&pw_count_fp);
  }

  event_log_info (hashcat_ctx, "\nPCFG loopback: %u cracked passwords collected, starting PCFG phase.", pw_count);

  // save original state, switch to PCFG mode

  const u32  saved_attack_mode      = user_options->attack_mode;
  const bool saved_train_af_disable = user_options->pcfg_train_af_disable;
  const bool saved_train_df_disable = user_options->pcfg_train_df_disable;

  user_options->attack_mode           = ATTACK_MODE_PCFG;
  user_options->pcfg_train_af_disable = true;   // disable AF: cracked pw set is small, all tokens matter
  user_options->pcfg_train_df_disable = true;   // disable DF: use cracked passwords as-is, no decomposition filtering

  // create model from cracked passwords

  init_char_types_lut ();

  if (user_options->pcfg_model_file != NULL)
  {
    // base model provided: update it with new data (same as --pcfg-model-update path)

    event_log_info (hashcat_ctx, "PCFG loopback: updating base model %s with cracked passwords...", user_options->pcfg_model_file);

    pcfg_model_t *base_model = pcfg_model_load_fast (hashcat_ctx, user_options->pcfg_model_file);

    if (!base_model) { rc = -1; goto cleanup; }

    u64 base_elements = pcfg_model_count_elements (base_model);

    pcfg_model_destroy (base_model);

    pcfg_trainer_t *trainer = pcfg_trainer_init (hashcat_ctx, pcfg_ctx->loopback_pw_file, base_elements);

    if (!trainer) { rc = -1; goto cleanup; }

    pcfg_trainer_import_from_file (hashcat_ctx, trainer, user_options->pcfg_model_file);

    if (pcfg_trainer_from_file (hashcat_ctx, trainer, pcfg_ctx->loopback_pw_file) != 0)
    {
      event_log_error (hashcat_ctx, "PCFG loopback: training failed");
      pcfg_trainer_destroy (trainer);
      rc = -1;
      goto cleanup;
    }

    if (!pcfg_trainer_export_to_file (hashcat_ctx, trainer, pcfg_ctx->loopback_model_file))
    {
      event_log_error (hashcat_ctx, "PCFG loopback: model export failed");
      pcfg_trainer_destroy (trainer);
      rc = -1;
      goto cleanup;
    }

    pcfg_trainer_destroy (trainer);
  }
  else
  {
    // no base model: create from scratch

    event_log_info (hashcat_ctx, "PCFG loopback: training new model from cracked passwords...");

    pcfg_trainer_t *trainer = pcfg_trainer_init (hashcat_ctx, pcfg_ctx->loopback_pw_file, 0);

    if (!trainer) { rc = -1; goto cleanup; }

    if (pcfg_trainer_from_file (hashcat_ctx, trainer, pcfg_ctx->loopback_pw_file) != 0)
    {
      event_log_error (hashcat_ctx, "PCFG loopback: training failed");
      pcfg_trainer_destroy (trainer);
      rc = -1;
      goto cleanup;
    }

    if (!pcfg_trainer_export_to_file (hashcat_ctx, trainer, pcfg_ctx->loopback_model_file))
    {
      event_log_error (hashcat_ctx, "PCFG loopback: model export failed");
      pcfg_trainer_destroy (trainer);
      rc = -1;
      goto cleanup;
    }

    pcfg_trainer_destroy (trainer);
  }

  // delete pw file after training

  unlink (pcfg_ctx->loopback_pw_file);

  // load the trained model (filtered)

  pcfg_ctx->model = pcfg_model_load_filtered (hashcat_ctx, pcfg_ctx->loopback_model_file);

  if (!pcfg_ctx->model)
  {
    event_log_error (hashcat_ctx, "PCFG loopback: model loading failed");
    rc = -1;
    goto cleanup;
  }

  // transition -a0 → -a10: tear down -a0 session, reinitialize for PCFG

  backend_session_destroy (hashcat_ctx);
  straight_ctx_destroy (hashcat_ctx);

  if (straight_ctx_init (hashcat_ctx) == -1) { rc = -1; goto cleanup; }

  if (backend_session_begin (hashcat_ctx) == -1) { rc = -1; goto cleanup; }

  // set up pcfg_ctx fields needed by pcfg_gen_init

  pcfg_ctx->pcfg_model_file = NULL;
  pcfg_ctx->pcfg_train_file = NULL;
  pcfg_ctx->pcfg_model_save_file = NULL;
  pcfg_ctx->pcfg_limit      = user_options->limit;
  pcfg_ctx->pcfg_skip       = user_options->skip;
  pcfg_ctx->struct_shuffle   = user_options->pcfg_shuffle;
  pcfg_ctx->ahf_type         = user_options->pcfg_ahf_type;
  pcfg_ctx->num_generators   = backend_ctx->backend_devices_cnt;

  pcfg_ctx->generators = (pcfg_gen_t **) hccalloc (pcfg_ctx->num_generators, sizeof (pcfg_gen_t *));

  // create active devices map

  int active_idx = 0;

  pcfg_ctx->active_map = (int *) hccalloc (backend_ctx->backend_devices_cnt, sizeof (int));

  for (int i = 0; i < backend_ctx->backend_devices_cnt; i++)
  {
    if (!backend_ctx->devices_param[i].skipped && !backend_ctx->devices_param[i].skipped_warning)
    {
      pcfg_ctx->active_map[i] = active_idx++;
    }
    else
    {
      pcfg_ctx->active_map[i] = -1;
    }
  }

  pcfg_ctx->num_active_generators = active_idx;

  pcfg_ctx->enabled = true;

  // performance monitor

  pcfg_ctx->perf_threshold = NULL;

  if (user_options->pcfg_pf_threshold != NULL)
  {
    pcfg_ctx->perf_threshold = (pcfg_perf_threshold_t *) hccalloc (1, sizeof (pcfg_perf_threshold_t));

    if (pcfg_ctx->perf_threshold == NULL) { rc = -1; goto cleanup; }

    pcfg_ctx->perf_threshold->enabled                  = false;

    pcfg_ctx->perf_threshold->skip_struct_enabled      = false;
    pcfg_ctx->perf_threshold->struct_threshold_count   = 0;
    pcfg_ctx->perf_threshold->struct_threshold_seconds = 60;

    pcfg_ctx->perf_threshold->skip_cost_enabled       = false;
    pcfg_ctx->perf_threshold->cost_threshold_count    = 0;
    pcfg_ctx->perf_threshold->cost_threshold_seconds  = 60;

    pcfg_ctx->perf_threshold->skip_loop_enabled        = false;
    pcfg_ctx->perf_threshold->loop_threshold_count     = 0;
    pcfg_ctx->perf_threshold->loop_threshold_seconds   = 60;

    pcfg_ctx->perf_threshold->baseline_recovered       = 0;

    pcfg_ctx->perf_threshold->skips_struct_total       = 0;
    pcfg_ctx->perf_threshold->skips_cost_total        = 0;
    pcfg_ctx->perf_threshold->skips_loop_total         = 0;

    pcfg_ctx->perf_threshold->monitoring_active        = false;
    pcfg_ctx->perf_threshold->thread_running           = false;
    pcfg_ctx->perf_threshold->thread_shutdown          = false;

    memset (pcfg_ctx->perf_threshold->gen_perf, 0, sizeof (pcfg_ctx->perf_threshold->gen_perf));

    if (pcfg_perf_threshold_parse (hashcat_ctx, user_options->pcfg_pf_threshold) == -1)
    {
      rc = -1;
      goto cleanup;
    }
  }

  // LOOP: run PCFG attack iterations

  for (;;)
  {
    pcfg_ctx->loopback_generation++;

    event_log_info (hashcat_ctx, "\nPCFG loopback: starting PCFG attack...");

    // record current crack count

    const u32 digests_before = hashes->digests_done;

    // open pw file for writing (to capture new cracks during -a10)

    if (hc_fopen (&pcfg_ctx->loopback_fp, pcfg_ctx->loopback_pw_file, "wb") == false)
    {
      event_log_error (hashcat_ctx, "PCFG loopback: %s: %s", pcfg_ctx->loopback_pw_file, strerror (errno));
      rc = -1;
      break;
    }

    // reset status flags (inner2_loop does not reset these)

    status_ctx->run_main_level2 = true;
    status_ctx->run_main_level3 = true;

    // run PCFG session through standard pipeline (autotune + pcfg_gen_init + cracker threads)

    int il_rc = inner2_loop (hashcat_ctx);

    // close pw file

    if (pcfg_ctx->loopback_fp.pfp != NULL)
    {
      hc_fclose (&pcfg_ctx->loopback_fp);
    }

    if (il_rc == -1) { rc = -1; break; }

    // stop performance monitor thread before destroying generators

    pcfg_perf_monitor_stop (hashcat_ctx);

    // destroy generators (model stays alive for potential update)

    for (int i = 0; i < pcfg_ctx->num_generators; i++)
    {
      pcfg_gen_destroy (pcfg_ctx->generators[i]);
      pcfg_ctx->generators[i] = NULL;
    }

    // cleanup gpu-specific state created by pcfg_gen_init

    if (pcfg_ctx->gpu_prob_ctx != NULL)
    {
      pcfg_gpu_prob_ctx_destroy (pcfg_ctx->gpu_prob_ctx);
      pcfg_ctx->gpu_prob_ctx = NULL;
    }

    if (pcfg_ctx->gpu_prob_data != NULL)
    {
      pcfg_gpu_prob_data_destroy (pcfg_ctx->gpu_prob_data);
      pcfg_ctx->gpu_prob_data = NULL;
    }

    if (pcfg_ctx->omen_gpu_ctx != NULL)
    {
      pcfg_gpu_omen_ctx_destroy (pcfg_ctx->omen_gpu_ctx);
      pcfg_ctx->omen_gpu_ctx = NULL;
    }

    if (pcfg_ctx->omen_gpu_data != NULL)
    {
      pcfg_gpu_omen_data_destroy (pcfg_ctx->omen_gpu_data);
      pcfg_ctx->omen_gpu_data = NULL;
    }


    // check exit conditions

    if (status_ctx->devices_status == STATUS_CRACKED)
    {
      event_log_info (hashcat_ctx, "PCFG loopback: all hashes cracked.");
      break;
    }

    if (status_ctx->devices_status == STATUS_ABORTED
     || status_ctx->devices_status == STATUS_ABORTED_CHECKPOINT
     || status_ctx->devices_status == STATUS_ABORTED_FINISH
     || status_ctx->devices_status == STATUS_ABORTED_RUNTIME
     || status_ctx->devices_status == STATUS_QUIT
     || status_ctx->devices_status == STATUS_ERROR)
    {
      break;
    }

    // STATUS_EXHAUSTED or STATUS_BYPASS: continue to check new cracks

    // check for new cracks

    const u32 new_cracks = hashes->digests_done - digests_before;

    // destroy current model before potential update

    if (pcfg_ctx->model)
    {
      pcfg_model_destroy (pcfg_ctx->model);
      pcfg_ctx->model = NULL;
    }

    if (new_cracks == 0)
    {
      event_log_info (hashcat_ctx, "PCFG loopback: no new passwords cracked, stopping.");
      unlink (pcfg_ctx->loopback_pw_file);
      break;
    }

    event_log_info (hashcat_ctx, "PCFG loopback: %u new passwords cracked, updating model...", new_cracks);

    // update model with new cracked passwords (same as --pcfg-model-update path)

    pcfg_model_t *current_model = pcfg_model_load_fast (hashcat_ctx, pcfg_ctx->loopback_model_file);

    if (!current_model)
    {
      event_log_error (hashcat_ctx, "PCFG loopback: failed to reload model for update");
      rc = -1;
      break;
    }

    u64 base_elements = pcfg_model_count_elements (current_model);

    pcfg_model_destroy (current_model);

    pcfg_trainer_t *trainer = pcfg_trainer_init (hashcat_ctx, pcfg_ctx->loopback_pw_file, base_elements);

    if (!trainer)
    {
      rc = -1;
      break;
    }

    pcfg_trainer_import_from_file (hashcat_ctx, trainer, pcfg_ctx->loopback_model_file);

    if (pcfg_trainer_from_file (hashcat_ctx, trainer, pcfg_ctx->loopback_pw_file) != 0)
    {
      event_log_error (hashcat_ctx, "PCFG loopback: model update training failed");
      pcfg_trainer_destroy (trainer);
      rc = -1;
      break;
    }

    if (!pcfg_trainer_export_to_file (hashcat_ctx, trainer, pcfg_ctx->loopback_model_file))
    {
      event_log_error (hashcat_ctx, "PCFG loopback: model export failed");
      pcfg_trainer_destroy (trainer);
      rc = -1;
      break;
    }

    pcfg_trainer_destroy (trainer);

    // delete pw file, load updated model

    unlink (pcfg_ctx->loopback_pw_file);

    pcfg_ctx->model = pcfg_model_load_filtered (hashcat_ctx, pcfg_ctx->loopback_model_file);

    if (!pcfg_ctx->model)
    {
      event_log_error (hashcat_ctx, "PCFG loopback: updated model loading failed");
      rc = -1;
      break;
    }

    // loop back
  }

  // cleanup

  if (pcfg_ctx->model)
  {
    pcfg_model_destroy (pcfg_ctx->model);
    pcfg_ctx->model = NULL;
  }

  if (pcfg_ctx->generators)
  {
    hcfree (pcfg_ctx->generators);
    pcfg_ctx->generators = NULL;
  }

  if (pcfg_ctx->active_map)
  {
    hcfree (pcfg_ctx->active_map);
    pcfg_ctx->active_map = NULL;
  }

  pcfg_ctx->enabled = false;

  // stop performance monitor and free threshold

  pcfg_perf_monitor_stop (hashcat_ctx);

  if (pcfg_ctx->perf_threshold != NULL)
  {
    hcfree (pcfg_ctx->perf_threshold);
    pcfg_ctx->perf_threshold = NULL;
  }

cleanup:

  // restore original state

  user_options->attack_mode           = saved_attack_mode;
  user_options->pcfg_train_af_disable = saved_train_af_disable;
  user_options->pcfg_train_df_disable = saved_train_df_disable;

  return rc;
}
