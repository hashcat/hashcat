#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "thread.h"
#include "pcfg.h"
#include "pcfg_perf.h"

// helper functions

void pcfg_gen_perf_reset_struct (pcfg_perf_threshold_t *pt, int dev_idx, u64 new_struct_id)
{
  if (pt == NULL) return;
  if (dev_idx < 0 || dev_idx >= DEVICES_MAX) return;
  if (pt->monitoring_active == false) return;

  pcfg_gen_perf_t *gp = &pt->gen_perf[dev_idx];

  time_t now = time (NULL);

  gp->struct_id = new_struct_id;
  gp->struct_start_time = now;
  gp->struct_recovered = 0;
  gp->snapshot_struct_start = now;
}

void pcfg_gen_perf_reset_cost (pcfg_perf_threshold_t *pt, int dev_idx, u32 new_cost)
{
  if (pt == NULL) return;
  if (dev_idx < 0 || dev_idx >= DEVICES_MAX) return;
  if (pt->monitoring_active == false) return;

  pcfg_gen_perf_t *gp = &pt->gen_perf[dev_idx];

  time_t now = time (NULL);

  gp->cost = new_cost;
  gp->cost_start_time = now;
  gp->cost_recovered = 0;
  gp->snapshot_cost_start = now;
}

void pcfg_gen_perf_reset_loop (pcfg_perf_threshold_t *pt, int dev_idx, u64 new_loop_id)
{
  if (pt == NULL) return;
  if (dev_idx < 0 || dev_idx >= DEVICES_MAX) return;
  if (pt->monitoring_active == false) return;

  pcfg_gen_perf_t *gp = &pt->gen_perf[dev_idx];

  time_t now = time (NULL);

  gp->loop_id = new_loop_id;
  gp->loop_start_time = now;
  gp->loop_recovered = 0;
  gp->snapshot_loop_start = now;
}

void pcfg_gen_perf_add_recovered (pcfg_perf_threshold_t *pt, int dev_idx, u64 count)
{
  if (pt == NULL) return;
  if (dev_idx < 0 || dev_idx >= DEVICES_MAX) return;
  if (pt->monitoring_active == false) return;
  if (count == 0) return;

  pcfg_gen_perf_t *gp = &pt->gen_perf[dev_idx];

  gp->struct_recovered += count;
  gp->cost_recovered += count;
  gp->loop_recovered += count;
}

// initialization

void pcfg_perf_threshold_init_generators (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t     *pcfg_ctx     = hashcat_ctx->pcfg_ctx;

  if (pcfg_ctx == NULL) return;
  if (pcfg_ctx->perf_threshold == NULL) return;

  pcfg_perf_threshold_t *pt = pcfg_ctx->perf_threshold;

  memset (pt->gen_perf, 0, sizeof (pt->gen_perf));

  time_t now = time (NULL);

  for (int i = 0; i < pcfg_ctx->num_generators; i++)
  {
    if (pcfg_ctx->active_map[i] == -1) continue;

    pcfg_gen_t *gen = pcfg_ctx->generators[i];
    pcfg_gen_perf_t *gp = &pt->gen_perf[i];

    // Structure - depends on the mode
    if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB)
    {
      gp->struct_id = gen->gpu_prob_current_struct;
    }
    else
    {
      gp->struct_id = gen->curr_struct_idx;
    }

    gp->struct_start_time = now;
    gp->struct_recovered = 0;
    gp->snapshot_struct_start = now;

    // Cost & Loop, only for OMEN
    if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
    {
      gp->cost = gen->omen_target_cost;
      gp->cost_start_time     = now;
      gp->cost_recovered      = 0;
      gp->snapshot_cost_start = now;

      gp->loop_id = gen->omen_global_loop_idx;
      gp->loop_start_time     = now;
      gp->loop_recovered      = 0;
      gp->snapshot_loop_start = now;
    }
  }
}

// parser

int pcfg_perf_threshold_parse (hashcat_ctx_t *hashcat_ctx, const char *input)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  if (input == NULL || strlen (input) == 0) return 0;

  pcfg_perf_threshold_t *pt = pcfg_ctx->perf_threshold;

  // format: <type>:<count>:<time>[,<type>:<count>:<time>]...
  // example: loop:100:1h,cost:10:5m,struct:5:30s

  char *tmp = hcstrdup (input);
  char *saveptr_outer = NULL;
  char *segment = strtok_r (tmp, ",", &saveptr_outer);

  while (segment != NULL)
  {
    while (*segment == ' ') segment++;

    // parse: <type>:<count>:<time>
    char *first_colon = strchr (segment, ':');

    if (first_colon == NULL)
    {
      event_log_error (hashcat_ctx, "Invalid format: %s (expected type:count:time)", segment);
      event_log_error (hashcat_ctx, "Example: cost:10:30s or loop:100:1h,cost:10:5m");
      hcfree (tmp);
      return -1;
    }

    *first_colon = 0;
    const char *type_str = segment;
    const char *rest = first_colon + 1;

    char *second_colon = strchr (rest, ':');

    if (second_colon == NULL)
    {
      event_log_error (hashcat_ctx, "Invalid format: %s (expected type:count:time)", segment);
      event_log_error (hashcat_ctx, "Example: cost:10:30s or loop:100:1h,cost:10:5m");
      hcfree (tmp);
      return -1;
    }

    *second_colon = 0;
    const char *count_str = rest;
    const char *time_str = second_colon + 1;

    char *endptr;

    u64 count = strtoull (count_str, &endptr, 10);

    if (*endptr != '\0')
    {
      event_log_error (hashcat_ctx, "Invalid count value: %s", count_str);
      hcfree (tmp);
      return -1;
    }

    size_t time_len = strlen (time_str);

    if (time_len < 2)
    {
      event_log_error (hashcat_ctx, "Invalid time value: %s", time_str);
      hcfree (tmp);
      return -1;
    }

    char unit = time_str[time_len - 1];
    char time_num[32] = {0};

    strncpy (time_num, time_str, time_len - 1);

    u32 time_value = (u32) strtoul (time_num, &endptr, 10);

    if (*endptr != '\0' || time_value == 0)
    {
      event_log_error (hashcat_ctx, "Invalid time value: %s", time_str);
      hcfree (tmp);
      return -1;
    }

    u32 seconds = 0;

    switch (unit)
    {
      case 's': seconds = time_value; break;
      case 'm': seconds = time_value * 60; break;
      case 'h': seconds = time_value * 3600; break;
      case 'd': seconds = time_value * 86400; break;
      default:
        event_log_error (hashcat_ctx, "Invalid time unit: %c (valid: s, m, h, d)", unit);
        hcfree (tmp);
        return -1;
    }

    if (strcmp (type_str, "struct") == 0)
    {
      pt->skip_struct_enabled = true;
      pt->struct_threshold_count = count;
      pt->struct_threshold_seconds = seconds;
    }
    else if (strcmp (type_str, "cost") == 0)
    {
      pt->skip_cost_enabled = true;
      pt->cost_threshold_count = count;
      pt->cost_threshold_seconds = seconds;
    }
    else if (strcmp (type_str, "loop") == 0)
    {
      pt->skip_loop_enabled = true;
      pt->loop_threshold_count = count;
      pt->loop_threshold_seconds = seconds;
    }
    else
    {
      event_log_error (hashcat_ctx, "Invalid skip type: %s (valid: struct, cost, loop)", type_str);
      hcfree (tmp);
      return -1;
    }

    segment = strtok_r (NULL, ",", &saveptr_outer);
  }

  hcfree (tmp);

  // validation

  if (!pt->skip_struct_enabled && !pt->skip_cost_enabled && !pt->skip_loop_enabled)
  {
    event_log_error (hashcat_ctx, "No valid skip types specified");
    return -1;
  }

  if (pt->skip_loop_enabled && pt->skip_cost_enabled)
  {
    if (pt->loop_threshold_seconds == pt->cost_threshold_seconds && pt->loop_threshold_count == pt->cost_threshold_count)
    {
      event_log_error (hashcat_ctx, "Skip types 'loop' and 'cost' have identical threshold (%" PRIu64 ":%us)", pt->loop_threshold_count, pt->loop_threshold_seconds);
      event_log_error (hashcat_ctx, "Use different count or time values to avoid simultaneous skips");
      return -1;
    }
  }

  if (pt->skip_loop_enabled && pt->skip_struct_enabled)
  {
    if (pt->loop_threshold_seconds == pt->struct_threshold_seconds && pt->loop_threshold_count == pt->struct_threshold_count)
    {
      event_log_error (hashcat_ctx, "Skip types 'loop' and 'struct' have identical threshold (%" PRIu64 ":%us)", pt->loop_threshold_count, pt->loop_threshold_seconds);
      event_log_error (hashcat_ctx, "Use different count or time values to avoid simultaneous skips");
      return -1;
    }
  }

  if (pt->skip_cost_enabled && pt->skip_struct_enabled)
  {
    if (pt->cost_threshold_seconds == pt->struct_threshold_seconds && pt->cost_threshold_count == pt->struct_threshold_count)
    {
      event_log_error (hashcat_ctx, "Skip types 'cost' and 'struct' have identical threshold (%" PRIu64 ":%us)", pt->cost_threshold_count, pt->cost_threshold_seconds);
      event_log_error (hashcat_ctx, "Use different count or time values to avoid simultaneous skips");
      return -1;
    }
  }

  if (pt->skip_loop_enabled && pt->skip_cost_enabled)
  {
    if (pt->cost_threshold_seconds > pt->loop_threshold_seconds)
    {
      event_log_error (hashcat_ctx, "Cost timer (%us) must be <= loop timer (%us)", pt->cost_threshold_seconds, pt->loop_threshold_seconds);
      event_log_error (hashcat_ctx, "Otherwise cost check will never trigger");
      return -1;
    }
  }

  if (pt->skip_cost_enabled && pt->skip_struct_enabled)
  {
    if (pt->struct_threshold_seconds > pt->cost_threshold_seconds)
    {
      event_log_error (hashcat_ctx, "Struct timer (%us) must be <= cost timer (%us)", pt->struct_threshold_seconds, pt->cost_threshold_seconds);
      event_log_error (hashcat_ctx, "Otherwise struct check will never trigger");
      return -1;
    }
  }

  if (pt->skip_loop_enabled && pt->skip_struct_enabled && !pt->skip_cost_enabled)
  {
    if (pt->struct_threshold_seconds > pt->loop_threshold_seconds)
    {
      event_log_error (hashcat_ctx, "Struct timer (%us) must be <= loop timer (%us)", pt->struct_threshold_seconds, pt->loop_threshold_seconds);
      event_log_error (hashcat_ctx, "Otherwise struct check will never trigger");
      return -1;
    }
  }

  if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB || user_options->pcfg_mode == PCFG_MODE_CPU_PROB)
  {
    if (pt->skip_cost_enabled || pt->skip_loop_enabled)
    {
      event_log_error (hashcat_ctx, "Prob (%s) mode only supports 'struct' skip type",
        (user_options->pcfg_mode == PCFG_MODE_CPU_PROB) ? "CPU" : "GPU");
      return -1;
    }
  }
  else if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT ||
           user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST ||
           user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST ||
           user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    if (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_INTERLEAVED)
    {
      // BY_COST Interleaved support only loop and cost
      if (pt->skip_struct_enabled)
      {
        event_log_error (hashcat_ctx, "OMEN Interleaved mode does not support 'struct' skip type");
        return -1;
      }

      if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT)
      {
        // BY_STRUCT Interleaved support only loop solo
        if (pt->skip_cost_enabled)
        {
          event_log_error (hashcat_ctx, "GPU OMEN BY_STRUCT Interleaved mode does not support 'cost' skip type");
          return -1;
        }
      }
    }
    else // PCFG_OMEN_TYPE_CLASSIC
    {
      // Classic don't support loop
      if (pt->skip_loop_enabled)
      {
        event_log_error (hashcat_ctx, "OMEN Classic mode does not support 'loop' skip type");
        return -1;
      }

      if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
      {
        // BY_COST / BY_STRUCT Classic support only cost
        if (pt->skip_struct_enabled)
        {
          event_log_error (hashcat_ctx, "GPU OMEN BY_COST Classic mode does not support 'struct' skip type");
          return -1;
        }
      }
    }
  }

  pt->enabled = true;

  if (user_options->quiet == false)
  {
    event_log_info (hashcat_ctx, "PCFG: Performance threshold enabled");

    if (pt->skip_struct_enabled)
    {
      event_log_info (hashcat_ctx, "PCFG:   struct: skip if < %" PRIu64 " recovered in %us", pt->struct_threshold_count, pt->struct_threshold_seconds);
    }
    if (pt->skip_cost_enabled)
    {
      event_log_info (hashcat_ctx, "PCFG:   cost: skip if < %" PRIu64 " recovered in %us", pt->cost_threshold_count, pt->cost_threshold_seconds);
    }
    if (pt->skip_loop_enabled)
    {
      event_log_info (hashcat_ctx, "PCFG:   loop: skip if < %" PRIu64 " recovered in %us", pt->loop_threshold_count, pt->loop_threshold_seconds);
    }
  }

  return 0;
}

// performance monitor thread

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD thread_perf_monitor (void *p)
#else
HC_API_CALL void *thread_perf_monitor (void *p)
#endif
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) p;

  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (pcfg_ctx == NULL) return 0;
  if (pcfg_ctx->perf_threshold == NULL) return 0;

  pcfg_perf_threshold_t *pt = pcfg_ctx->perf_threshold;

  pt->thread_running    = true;
  pt->monitoring_active = false;

  while (pt->thread_shutdown == false && status_ctx->devices_status != STATUS_RUNNING)
  {
    sleep (1);
  }

  if (pt->thread_shutdown)
  {
    pt->thread_running = false;
    return 0;
  }

  // save baseline
  const hashes_t *hashes = hashcat_ctx->hashes;
  pt->baseline_recovered = hashes->digests_done;

  // init snapshot per each active generator
  for (int i = 0; i < pcfg_ctx->num_generators; i++)
  {
    if (pcfg_ctx->active_map[i] == -1) continue;

    pcfg_gen_perf_t *gp = &pt->gen_perf[i];

    gp->snapshot_struct_start = gp->struct_start_time;
    gp->snapshot_cost_start  = gp->cost_start_time;
    gp->snapshot_loop_start   = gp->loop_start_time;
  }

  pt->monitoring_active = true;

  int group_indices[DEVICES_MAX];

  // main loop - tick every second
  while (pt->thread_shutdown == false)
  {
    sleep (1);

    if (pt->thread_shutdown) break;

    if (status_ctx->devices_status >= STATUS_EXHAUSTED && status_ctx->devices_status <= STATUS_QUIT) break;

    if (status_ctx->devices_status != STATUS_RUNNING) continue;

    time_t now = time (NULL);

    // check for changes
    for (int i = 0; i < pcfg_ctx->num_generators; i++)
    {
      if (pcfg_ctx->active_map[i] == -1) continue;

      pcfg_gen_perf_t *gp = &pt->gen_perf[i];

      if (pt->skip_struct_enabled && gp->snapshot_struct_start != gp->struct_start_time)
      {
        gp->snapshot_struct_start = gp->struct_start_time;
      }

      if (pt->skip_cost_enabled && gp->snapshot_cost_start != gp->cost_start_time)
      {
        gp->snapshot_cost_start = gp->cost_start_time;
      }

      if (pt->skip_loop_enabled && gp->snapshot_loop_start != gp->loop_start_time)
      {
        gp->snapshot_loop_start = gp->loop_start_time;
      }
    }

    // check loop
    if (pt->skip_loop_enabled)
    {
      for (int i = 0; i < pcfg_ctx->num_generators; i++)
      {
        if (pcfg_ctx->active_map[i] == -1) continue;

        pcfg_gen_t *gen = pcfg_ctx->generators[i];

        // skip if is pending
        if (gen->omen_skip_loop) continue;

        pcfg_gen_perf_t *gp = &pt->gen_perf[i];

        // sync loop_id with the current state of the generator
        u64 current_loop_id = gen->omen_global_loop_idx;

        if (gp->loop_id != current_loop_id)
        {
          gp->loop_id = current_loop_id;
          gp->loop_start_time = now;
          gp->loop_recovered = 0;
          gp->snapshot_loop_start = now;
          continue;
        }

        time_t elapsed = now - gp->loop_start_time;

        if (elapsed < (time_t) pt->loop_threshold_seconds) continue;

        // find the group
        u64 trigger_id = gp->loop_id;
        u64 total_recovered = 0;

        int group_count = 0;

        for (int j = 0; j < pcfg_ctx->num_generators; j++)
        {
          if (pcfg_ctx->active_map[j] == -1) continue;

          pcfg_gen_t *gen_j = pcfg_ctx->generators[j];

          // skip if is pending
          if (gen_j->omen_skip_loop) continue;

          pcfg_gen_perf_t *gp_j = &pt->gen_perf[j];

          if (gp_j->loop_id == trigger_id)
          {
            group_indices[group_count++] = j;

            total_recovered += gp_j->loop_recovered;
          }
        }

        if (group_count == 0) continue;

        bool should_skip = (total_recovered < pt->loop_threshold_count);

        if (should_skip)
        {
          for (int k = 0; k < group_count; k++)
          {
            int gen_idx = group_indices[k];
            pcfg_gen_t *gen_k = pcfg_ctx->generators[gen_idx];
            gen_k->omen_skip_loop = true;

            // reset cost and struct timer to get rid of double skip
            pcfg_gen_perf_t *gp_k = &pt->gen_perf[gen_idx];

            gp_k->cost_start_time = now;
            gp_k->cost_recovered = 0;
            gp_k->snapshot_cost_start = now;

            gp_k->struct_start_time = now;
            gp_k->struct_recovered = 0;
            gp_k->snapshot_struct_start = now;
          }

          pt->skips_loop_total++;

          if (user_options->quiet == false)
          {
            char gen_list[256] = {0};
            int pos = 0;

            for (int k = 0; k < group_count && pos < 250; k++)
            {
              if (k > 0) pos += snprintf (gen_list + pos, sizeof (gen_list) - pos, ",");
              pos += snprintf (gen_list + pos, sizeof (gen_list) - pos, "%d", group_indices[k] + 1);
            }

            if (user_options->quiet == false)
            {
              event_log_warning (hashcat_ctx,
                "\nPCFG: Skipping loop %" PRIu64 " on generator%s [%s] (recovered: %" PRIu64 " < threshold: %" PRIu64 " in %lds) - loop skip #%" PRIu64,
                trigger_id + 1, (group_count > 1) ? "s" : "", gen_list, total_recovered, pt->loop_threshold_count, (long) elapsed, pt->skips_loop_total);
            }
          }
        }
        else
        {
          // reset only loop
          for (int k = 0; k < group_count; k++)
          {
            int gen_idx = group_indices[k];

            pcfg_gen_perf_t *gp_k = &pt->gen_perf[gen_idx];

            gp_k->loop_start_time = now;
            gp_k->loop_recovered = 0;
            gp_k->snapshot_loop_start = now;
          }
        }
      }
    }

    // check cost
    if (pt->skip_cost_enabled)
    {
      for (int i = 0; i < pcfg_ctx->num_generators; i++)
      {
        if (pcfg_ctx->active_map[i] == -1) continue;

        pcfg_gen_t *gen = pcfg_ctx->generators[i];

        // skip if pending (cost or loop)
        if (gen->omen_skip_cost || gen->omen_skip_loop) continue;

        pcfg_gen_perf_t *gp = &pt->gen_perf[i];

        // sync cost with current generator status
        u32 current_cost;

        if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT)
        {
          current_cost = gen->omen_by_cost_current;
        }
        else
        {
          current_cost = gen->omen_target_cost;
        }

        if (gp->cost != current_cost)
        {
          gp->cost = current_cost;
          gp->cost_start_time = now;
          gp->cost_recovered = 0;
          gp->snapshot_cost_start = now;
          continue;
        }

        time_t elapsed = now - gp->cost_start_time;

        if (elapsed < (time_t) pt->cost_threshold_seconds) continue;

        // find group
        u64 trigger_id = (u64) gp->cost;
        u64 total_recovered = 0;

        int group_count = 0;

        for (int j = 0; j < pcfg_ctx->num_generators; j++)
        {
          if (pcfg_ctx->active_map[j] == -1) continue;

          pcfg_gen_t *gen_j = pcfg_ctx->generators[j];

          // skip if pending (cost or loop)
          if (gen_j->omen_skip_cost || gen_j->omen_skip_loop) continue;

          pcfg_gen_perf_t *gp_j = &pt->gen_perf[j];

          if ((u64) gp_j->cost == trigger_id)
          {
            group_indices[group_count++] = j;

            total_recovered += gp_j->cost_recovered;
          }
        }

        if (group_count == 0) continue;

        bool should_skip = (total_recovered < pt->cost_threshold_count);

        if (should_skip)
        {
          for (int k = 0; k < group_count; k++)
          {
            int gen_idx = group_indices[k];

            pcfg_gen_t *gen_k = pcfg_ctx->generators[gen_idx];
            gen_k->omen_skip_cost = true;

            // reset the struct timer to get rid of double skip
            pcfg_gen_perf_t *gp_k = &pt->gen_perf[gen_idx];

            gp_k->struct_start_time = now;
            gp_k->struct_recovered = 0;
            gp_k->snapshot_struct_start = now;
          }

          pt->skips_cost_total++;

          if (user_options->quiet == false)
          {
            int pos = 0;

            char gen_list[256] = {0};

            for (int k = 0; k < group_count && pos < 250; k++)
            {
              if (k > 0) pos += snprintf (gen_list + pos, sizeof (gen_list) - pos, ",");

              pos += snprintf (gen_list + pos, sizeof (gen_list) - pos, "%d", group_indices[k] + 1);
            }

            if (user_options->quiet == false)
            {
              event_log_warning (hashcat_ctx,
                "\nPCFG: Skipping cost %" PRIu64 " on generator%s [%s] (recovered: %" PRIu64 " < threshold: %" PRIu64 " in %lds) - cost skip #%" PRIu64,
                trigger_id, (group_count > 1) ? "s" : "", gen_list, total_recovered, pt->cost_threshold_count, (long) elapsed, pt->skips_cost_total);
            }
          }
        }
        else
        {
          // reset only cost
          for (int k = 0; k < group_count; k++)
          {
            int gen_idx = group_indices[k];

            pcfg_gen_perf_t *gp_k = &pt->gen_perf[gen_idx];

            gp_k->cost_start_time = now;
            gp_k->cost_recovered = 0;
            gp_k->snapshot_cost_start = now;
          }
        }
      }
    }

    // check struct
    if (pt->skip_struct_enabled)
    {
      for (int i = 0; i < pcfg_ctx->num_generators; i++)
      {
        if (pcfg_ctx->active_map[i] == -1) continue;

        pcfg_gen_t *gen = pcfg_ctx->generators[i];

        // skip if pending (struct, cost or loop)
        if (gen->skip_structure || gen->omen_skip_cost || gen->omen_skip_loop) continue;

        pcfg_gen_perf_t *gp = &pt->gen_perf[i];

        // sync struct_id with current generator status
        u64 current_struct_id;

        if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB)
        {
          current_struct_id = gen->gpu_prob_current_struct;
        }
        else if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT)
        {
          current_struct_id = gen->curr_struct_idx;
        }
        else
        {
          current_struct_id = gen->curr_struct_idx;
        }

        if (gp->struct_id != current_struct_id)
        {
          gp->struct_id = current_struct_id;
          gp->struct_start_time = now;
          gp->struct_recovered = 0;
          gp->snapshot_struct_start = now;
          continue;
        }

        time_t elapsed = now - gp->struct_start_time;

        if (elapsed < (time_t) pt->struct_threshold_seconds) continue;

        // find group
        u64 trigger_id = gp->struct_id;
        u64 total_recovered = 0;

        int group_count = 0;

        for (int j = 0; j < pcfg_ctx->num_generators; j++)
        {
          if (pcfg_ctx->active_map[j] == -1) continue;

          pcfg_gen_t *gen_j = pcfg_ctx->generators[j];

          // skip if pending (struct, cost or loop)
          if (gen_j->skip_structure || gen_j->omen_skip_cost || gen_j->omen_skip_loop) continue;

          pcfg_gen_perf_t *gp_j = &pt->gen_perf[j];

          if (gp_j->struct_id == trigger_id)
          {
            group_indices[group_count++] = j;

            total_recovered += gp_j->struct_recovered;
          }
        }

        if (group_count == 0) continue;

        bool should_skip = (total_recovered < pt->struct_threshold_count);

        if (should_skip)
        {
          for (int k = 0; k < group_count; k++)
          {
            int gen_idx = group_indices[k];
            pcfg_gen_t *gen_k = pcfg_ctx->generators[gen_idx];
            gen_k->skip_structure = true;
          }

          pt->skips_struct_total++;

          if (user_options->quiet == false)
          {
            int pos = 0;

            char gen_list[256] = {0};

            for (int k = 0; k < group_count && pos < 250; k++)
            {
              if (k > 0) pos += snprintf (gen_list + pos, sizeof (gen_list) - pos, ",");

              pos += snprintf (gen_list + pos, sizeof (gen_list) - pos, "%d", group_indices[k] + 1);
            }

            if (user_options->quiet == false)
            {
              event_log_warning (hashcat_ctx,
                "\nPCFG: Skipping structure %" PRIu64 " on generator%s [%s] (recovered: %" PRIu64 " < threshold: %" PRIu64 " in %lds) - struct skip #%" PRIu64,
                trigger_id + 1, (group_count > 1) ? "s" : "", gen_list, total_recovered, pt->struct_threshold_count, (long) elapsed, pt->skips_struct_total);
            }
          }
        }
        else
        {
          // reset only struct
          for (int k = 0; k < group_count; k++)
          {
            int gen_idx = group_indices[k];

            pcfg_gen_perf_t *gp_k = &pt->gen_perf[gen_idx];

            gp_k->struct_start_time = now;
            gp_k->struct_recovered = 0;
            gp_k->snapshot_struct_start = now;
          }
        }
      }
    }
  }

  pt->monitoring_active = false;
  pt->thread_running    = false;

  return 0;
}

// thread start/stop

int pcfg_perf_monitor_start (hashcat_ctx_t *hashcat_ctx)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  if (pcfg_ctx == NULL) return 0;
  if (pcfg_ctx->perf_threshold == NULL) return 0;
  if (pcfg_ctx->perf_threshold->enabled == false) return 0;

  pcfg_perf_threshold_t *pt = pcfg_ctx->perf_threshold;

  pt->thread_shutdown = false;
  pt->thread_running  = false;

  hc_thread_create (pt->thread, thread_perf_monitor, hashcat_ctx);

  return 0;
}

void pcfg_perf_monitor_stop (hashcat_ctx_t *hashcat_ctx)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  if (pcfg_ctx == NULL) return;
  if (pcfg_ctx->perf_threshold == NULL) return;
  if (pcfg_ctx->perf_threshold->enabled == false) return;

  pcfg_perf_threshold_t *pt = pcfg_ctx->perf_threshold;

  if (pt->thread_running == false) return;

  pt->thread_shutdown = true;

  hc_thread_join (pt->thread);
}
