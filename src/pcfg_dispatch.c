/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"
#include "backend.h"
#include "dispatch.h"
#include "shared.h"
#include "thread.h"
#include "convert.h"
#include "rp.h"
#include "rp_cpu.h"
#include "wordlist.h"
#include "slow_candidates.h"
#include "status.h"
#include "user_options.h"
#include "pcfg_dispatch.h"
#include "pcfg_backend.h"
#include "pcfg_cpu_random.h"
#include "pcfg_gpu_omen.h"
#include "pcfg_gpu_prob.h"
#include "pcfg.h"

static u64 pcfg_get_words_cur (const hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  const pcfg_ctx_t    *pcfg_ctx    = hashcat_ctx->pcfg_ctx;

  u64 words_sum = 0;

  for (int i = 0; i < backend_ctx->backend_devices_cnt; i++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[i];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    words_sum += device_param->words_done;
  }

  return pcfg_ctx->pcfg_skip + words_sum;
}

// flush (upload & launch)
static int pcfg_gpu_omen_flush_buffer (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pcfg_gen_t *gen)
{
  if (gen->omen_gpu_batch_entry_cnt == 0) return 0;

  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  // abort check before expensive GPU work (consistent with dispatch.c:311)

  if (status_ctx->run_thread_level1 == false)
  {
    gen->omen_gpu_batch_entry_cnt = 0;
    gen->omen_gpu_partition_cnt = 0;

    return 0;
  }

  // calculate cumulative offsets and total keyspace
  u64 current_offset = 0;

  for (u32 i = 0; i < gen->omen_gpu_batch_entry_cnt; i++)
  {
    pcfg_gpu_omen_batch_entry_t *be = &gen->omen_gpu_batch_entries[i];
    u64 ks = be->cumulative_end; // temporarily saved here
    be->cumulative_start = current_offset;
    be->cumulative_end = current_offset + ks;
    current_offset += ks;
  }
  u64 total_keyspace = current_offset;
  if (total_keyspace == 0) return 0;

  // global limit check (Pre-Launch)
  hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

  u64 generated_so_far = pcfg_ctx->words_generated;

  u64 effective_limit = (pcfg_ctx->pcfg_limit > 0) ? pcfg_ctx->pcfg_limit - pcfg_ctx->pcfg_skip : 0;

  u64 actual_pws = total_keyspace;

  if (gen->omen_reserved_budget != UINT64_MAX)
  {
    if (actual_pws > gen->omen_reserved_budget) actual_pws = gen->omen_reserved_budget;

    gen->omen_reserved_budget -= actual_pws;
  }
  else
  {
    u64 limit_left = (effective_limit > 0) ? (effective_limit - generated_so_far) : UINT64_MAX;
    actual_pws = (total_keyspace > limit_left) ? limit_left : total_keyspace;
    if (actual_pws > 0) pcfg_ctx->words_generated += actual_pws;
  }
  hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
  if (actual_pws == 0)
  {
    // limit reached, clear and return
    gen->omen_gpu_batch_entry_cnt = 0;
    gen->omen_gpu_partition_cnt = 0;
    return 0;
  }

  // upload buffer

  u64 size_batch   = gen->omen_gpu_batch_entry_cnt * sizeof (pcfg_gpu_omen_batch_entry_t);
  u64 size_parts   = gen->omen_gpu_partition_cnt * sizeof (pcfg_gpu_omen_partition_t);
  u64 size_structs = gen->omen_gpu_batch_entry_cnt * sizeof (pcfg_gpu_omen_structure_t);
  if (pcfg_gpu_omen_upload_batch (hashcat_ctx, device_param, gen->omen_gpu_batch_entries, size_batch, gen->omen_gpu_partitions, size_parts, gen->omen_gpu_structures, size_structs) == -1) return -1;

  // force 1 because of Work Stealing architecture
  u32 num_devices = 1;

  u64 base_off = 0;
  // run_copy & run_cracker
  device_param->pws_cnt = actual_pws;

  device_param->kernel_params_pcfg_gpu_omen_buf64[0] = base_off;
  device_param->kernel_params_pcfg_gpu_omen_buf32[1] = gen->omen_gpu_batch_entry_cnt;
  device_param->kernel_params_pcfg_gpu_omen_buf64[2] = actual_pws;
  device_param->kernel_params_pcfg_gpu_omen_buf32[3] = num_devices;
  if (run_copy (hashcat_ctx, device_param, actual_pws) == -1) return -1;
  if (run_cracker (hashcat_ctx, device_param, -1, actual_pws) == -1) return -1;
  // update status
  hc_thread_mutex_lock (status_ctx->mux_counter);
  device_param->words_done += actual_pws;
  status_ctx->words_cur = pcfg_get_words_cur (hashcat_ctx);
  hc_thread_mutex_unlock (status_ctx->mux_counter);

  // reset
  gen->omen_gpu_batch_entry_cnt = 0;
  gen->omen_gpu_partition_cnt = 0;

  return 0;
}

// multi-cost wrapper for partition generation
static u64 generate_partitions_multicost (const pcfg_gpu_omen_structure_t *s, const pcfg_omen_extra_t *omen, u8 s_cost, u8 min_term, u32 max_term, u64 range_start, u64 range_len, pcfg_gpu_omen_partition_t *out_partitions, u32 max_partitions, u32 *out_count)
{
  *out_count = 0;
  u64 total_generated = 0;
  u64 cumulative_base = 0;

  u32 min_l = s_cost + min_term;
  u32 max_l = s_cost + max_term;
  if (max_l > 300) max_l = 300;

  u64 req_start = range_start;
  u64 req_end = range_start + range_len;

  // cumulative offset for local_offset of partitions
  u64 local_offset_base = 0;

  for (u32 lvl = min_l; lvl <= max_l; lvl++)
  {
    int rem_cost = (int)lvl - (int)s_cost;
    u64 cost_ks = get_struct_keyspace_at_cost (s, omen, rem_cost);

    if (cost_ks == 0) continue;

    u64 cost_end = cumulative_base + cost_ks;

    if (cost_end > req_start && cumulative_base < req_end)
    {
      u64 local_start = (req_start > cumulative_base) ? (req_start - cumulative_base) : 0;
      u64 local_end_capped = (req_end < cost_end) ? (req_end - cumulative_base) : cost_ks;
      u64 local_len = local_end_capped - local_start;

      if (local_len > 0)
      {
        u32 prev_count = *out_count;
        u32 cnt = 0;
        u64 gen = pcfg_gpu_omen_generate_partitions (s, omen, rem_cost, local_start, local_len, out_partitions + *out_count, max_partitions - *out_count, &cnt);

        // adjust local_offset and local_end of the newly generated partitions
        for (u32 j = 0; j < cnt; j++)
        {
          out_partitions[prev_count + j].local_offset += local_offset_base;
          out_partitions[prev_count + j].local_end    += local_offset_base;
        }

        *out_count += cnt;
        total_generated += gen;
        local_offset_base += gen;

        if (*out_count >= max_partitions) break;
      }
    }

    cumulative_base = cost_end;

    if (cumulative_base >= req_end) break;
  }

  return total_generated;
}

static int calc_pcfg_cpu_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  pcfg_ctx_t           *pcfg_ctx           = hashcat_ctx->pcfg_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;

  int dev_idx = device_param->device_id;

  pcfg_gen_t *gen = pcfg_ctx->generators[dev_idx];

  __attribute__((aligned(32))) char pw_buf[PCFG_PW_STRIDE + 1];

  // PCFG model always produces UTF-8; convert to encoding_to if different

  bool iconv_enabled = strcmp ("utf-8", user_options->encoding_to) != 0;

  iconv_t iconv_ctx = (iconv_t) -1;

  char *iconv_tmp = NULL;

  if (iconv_enabled)
  {
    iconv_ctx = iconv_open (user_options->encoding_to, "utf-8");

    if (iconv_ctx == (iconv_t) -1) return -1;

    iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);
  }

  int rule_jk_len = (int) user_options_extra->rule_len_l;

  const char *rule_jk_buf = user_options->rule_buf_l;

  bool use_rules = run_rule_engine (rule_jk_len, rule_jk_buf);

  while (status_ctx->run_thread_level1 == true)
  {
    u64 words_extra_total = 0;

    //memset (device_param->pws_comp, 0, device_param->size_pws_comp);
    //memset (device_param->pws_idx,  0, device_param->size_pws_idx);
    device_param->pws_idx[0].off = 0;

    device_param->pws_cnt = 0;

    while (device_param->pws_cnt < device_param->kernel_power)
    {
      u32 pw_len = 0;

      int rc = pcfg_gen_next (hashcat_ctx, gen, pw_buf, &pw_len);

      if (rc == -2) break;

      if (rc != 0)
      {
        if (user_options->pcfg_mode != PCFG_MODE_CPU_RANDOM_AHF) break;

        pcfg_cpu_random_ahf_refresh (hashcat_ctx, gen);

        if (pcfg_cpu_random_ahf_reset (gen) == -1) break;

        rc = pcfg_gen_next (hashcat_ctx, gen, pw_buf, &pw_len);

        if (rc != 0) break;
      }

      pw_len = convert_from_hex (hashcat_ctx, pw_buf, pw_len);

      if (iconv_enabled)
      {
        char *iconv_ptr = iconv_tmp;

        size_t iconv_sz = HCBUFSIZ_TINY;

        char *src = pw_buf;

        size_t src_len = pw_len;

        if (iconv (iconv_ctx, &src, &src_len, &iconv_ptr, &iconv_sz) == (size_t) -1) continue;

        pw_len = HCBUFSIZ_TINY - iconv_sz;

        memcpy (pw_buf, iconv_tmp, pw_len);
      }

      if (use_rules)
      {
        if (pw_len >= RP_PASSWORD_SIZE) continue;

        char rule_buf[RP_PASSWORD_SIZE];

        int rule_len = _old_apply_rule (rule_jk_buf, rule_jk_len, pw_buf, (int) pw_len, rule_buf);

        if (rule_len < 0) continue;

        memcpy (pw_buf, rule_buf, rule_len);

        pw_len = (u32) rule_len;
      }

      if (pw_len > PW_MAX) continue;

      if (pw_len < hashconfig->pw_min || pw_len > hashconfig->pw_max)
      {
        words_extra_total++;

        continue;
      }

      pw_add (device_param, (u8 *) pw_buf, pw_len);

      if (status_ctx->run_thread_level1 == false) break;
    }

    if (words_extra_total > 0)
    {
      hc_thread_mutex_lock (status_ctx->mux_counter);

      for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
      {
        status_ctx->words_progress_rejected[salt_pos] += words_extra_total * straight_ctx->kernel_rules_cnt;
      }

      hc_thread_mutex_unlock (status_ctx->mux_counter);
    }

    if (!status_ctx->run_thread_level1) break;

    u64 pws_cnt = device_param->pws_cnt;

    if (pws_cnt == 0) break;

    if (run_copy (hashcat_ctx, device_param, pws_cnt) == -1) goto cleanup_error;

    if (run_cracker (hashcat_ctx, device_param, -1, pws_cnt) == -1) goto cleanup_error;

    device_param->pws_cnt = 0;

    if (!status_ctx->run_thread_level1) break;

    if (device_param->speed_only_finish == true) break;

    hc_thread_mutex_lock (status_ctx->mux_counter);

    device_param->words_done += pws_cnt + words_extra_total;

    status_ctx->words_cur = pcfg_get_words_cur (hashcat_ctx);

    hc_thread_mutex_unlock (status_ctx->mux_counter);
  }

  if (iconv_enabled)
  {
    iconv_close (iconv_ctx);
    hcfree (iconv_tmp);
  }

  return 0;

cleanup_error:

  if (iconv_enabled)
  {
    iconv_close (iconv_ctx);
    hcfree (iconv_tmp);
  }

  return -1;
}

int pcfg_gpu_omen_upload_batch (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const pcfg_gpu_omen_batch_entry_t *batch_entries, u64 size_batch_entries, const pcfg_gpu_omen_partition_t *partitions, u64 size_partitions, const pcfg_gpu_omen_structure_t *structures, u64 size_structures)
{
  if (device_param->is_cuda == true)
  {
    if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_omen_batch_entries, batch_entries, size_batch_entries) == -1) return -1;
    if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_omen_partitions, partitions, size_partitions) == -1) return -1;
    if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_omen_structures, structures, size_structures) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_omen_batch_entries, batch_entries, size_batch_entries) == -1) return -1;
    if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_omen_partitions, partitions, size_partitions) == -1) return -1;
    if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_omen_structures, structures, size_structures) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_omen_batch_entries, 0, batch_entries, size_batch_entries) == -1) return -1;
    if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_omen_partitions, 0, partitions, size_partitions) == -1) return -1;
    if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_omen_structures, 0, structures, size_structures) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_omen_batch_entries, CL_TRUE, 0, size_batch_entries, batch_entries, 0, NULL, NULL) == -1) return -1;
    if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_omen_partitions, CL_TRUE, 0, size_partitions, partitions, 0, NULL, NULL) == -1) return -1;
    if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_omen_structures, CL_TRUE, 0, size_structures, structures, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
}

int backend_session_pcfg_gpu_prob_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  pcfg_ctx_t   *pcfg_ctx   = hashcat_ctx->pcfg_ctx;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  int dev_idx = device_param->device_id;

  pcfg_gen_t *gen = pcfg_ctx->generators[dev_idx];

  pcfg_gpu_prob_ctx_t *gpu_prob_ctx = pcfg_ctx->gpu_prob_ctx;

  if (gpu_prob_ctx == NULL) return -1;

  pcfg_gpu_prob_data_t *lin = gpu_prob_ctx->linear_data;

  if (lin == NULL) return -1;

  u32 struct_cnt = lin->struct_cnt;
  u32 num_devices = gpu_prob_ctx->num_devices;

  while (status_ctx->run_thread_level1 == true)
  {
    if (gen->gpu_prob_current_struct >= struct_cnt) break;

    if (gen->skip_structure)
    {
      gen->skip_structure = false;

      gen->gpu_prob_current_struct++;
      gen->gpu_prob_current_local_idx = 0;

      if (pcfg_ctx->perf_threshold != NULL && pcfg_ctx->perf_threshold->monitoring_active && pcfg_ctx->perf_threshold->skip_struct_enabled)
      {
        pcfg_gen_perf_reset_struct (pcfg_ctx->perf_threshold, dev_idx, gen->gpu_prob_current_struct);
      }

      continue;
    }

    // calculate current absolute global index
    const pcfg_gpu_prob_structure_t *s_curr = &lin->structures[gen->gpu_prob_current_struct];

    u64 global_idx = s_curr->cumulative + gen->gpu_prob_current_local_idx;

    // check end of work
    u64 effective_end = lin->total_keyspace;

    if (gpu_prob_ctx->limit > 0 && gpu_prob_ctx->limit < effective_end)
    {
      effective_end = gpu_prob_ctx->limit;
    }

    if (global_idx >= effective_end) break;

    u64 pws_cnt = device_param->kernel_power;

    // check if we exceed the total keyspace
    u64 covered_range = pws_cnt * num_devices;

    if (global_idx + covered_range > effective_end)
    {
      // recalculate pws_cnt to arrive exactly at the end
      u64 remaining = effective_end - global_idx;

      pws_cnt = (remaining + num_devices - 1) / num_devices;
    }

    if (pws_cnt == 0)
    {
      // go to the next struct
      gen->gpu_prob_current_struct++;
      gen->gpu_prob_current_local_idx = 0;
      continue;
    }

    device_param->pws_cnt = pws_cnt;

    // set gpu kernel params
    device_param->kernel_params_pcfg_gpu_prob_buf64[0] = global_idx;  // base_off (global start for this device)
    device_param->kernel_params_pcfg_gpu_prob_buf32[1] = struct_cnt;  // struct_cnt

    // gen
    if (run_copy (hashcat_ctx, device_param, pws_cnt) == -1) return -1;

    // crack
    if (run_cracker (hashcat_ctx, device_param, -1, pws_cnt) == -1) return -1;

    // update status
    gen->gpu_prob_total_generated += pws_cnt;

    // update generator status for the next batch
    u64 next_global_idx = global_idx + pws_cnt * num_devices;

    // find the new current structure (advance struct_idx until cumulative <= next_global)
    while (gen->gpu_prob_current_struct < struct_cnt - 1)
    {
      const pcfg_gpu_prob_structure_t *s_next = &lin->structures[gen->gpu_prob_current_struct + 1];

      if (s_next->cumulative > next_global_idx) break;

      gen->gpu_prob_current_struct++;
    }

    // if we have gone beyond the last struct
    if (gen->gpu_prob_current_struct >= struct_cnt)
    {
      gen->gpu_prob_current_struct = struct_cnt; // end
      gen->gpu_prob_current_local_idx = 0;
    }
    else
    {
      // calculate the new local_idx
      const pcfg_gpu_prob_structure_t *s_new = &lin->structures[gen->gpu_prob_current_struct];

      u64 new_local_raw = next_global_idx - s_new->cumulative;

      gen->gpu_prob_current_local_idx = new_local_raw;
    }

    // status update
    if (!status_ctx->run_thread_level1) break;
    if (device_param->speed_only_finish == true) break;

    hc_thread_mutex_lock (status_ctx->mux_counter);
    device_param->words_done += pws_cnt;
    status_ctx->words_cur = pcfg_get_words_cur (hashcat_ctx);
    hc_thread_mutex_unlock (status_ctx->mux_counter);
  }

  return 0;
}

int backend_session_pcfg_gpu_omen_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;
  pcfg_gpu_omen_data_t *lin = pcfg_ctx->omen_gpu_data;

  pcfg_gen_t *gen = pcfg_ctx->generators[device_param->device_id];

  if (!gen || !gen->omen_gpu_batch_entries || !gen->omen_gpu_partitions || !gen->omen_gpu_structures) return -1;

  const u32 gpu_max_structs   = pcfg_ctx->global_max_structs;
  const u32 max_batch_entries = MIN (PCFG_OMEN_HOST_MAX_BATCH_ENTRIES, gpu_max_structs);
  const u32 max_partitions    = MIN (PCFG_OMEN_HOST_MAX_PARTITIONS,    gpu_max_structs * PCFG_OMEN_PARTITIONS_MAX);

  u64 burst_size = lin->burst_size;

  if (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_CLASSIC) burst_size = UINT64_MAX;

  u64 total_work_units = (u64) pcfg_ctx->omen_num_chunks * pcfg_ctx->omen_max_loops;
  gen->omen_reserved_budget = UINT64_MAX;

  // main Work Stealing loop
  while (status_ctx->run_thread_level1)
  {
    // collect the Work Unit
    hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

    u64 effective_limit = (pcfg_ctx->pcfg_limit > 0) ? pcfg_ctx->pcfg_limit - pcfg_ctx->pcfg_skip : 0;

    if (effective_limit > 0 && gen->omen_reserved_budget == 0 && pcfg_ctx->words_generated >= effective_limit)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      break;
    }
    if (pcfg_ctx->omen_next_work_unit_idx >= total_work_units)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      break;
    }
    // if there is a skip in progress and we are not the first to take the work unit with the skip
    while (pcfg_ctx->omen_skip_in_progress && pcfg_ctx->omen_skip_remainder == 0)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);

      if (!status_ctx->run_thread_level1) return 0;

      usleep (100);

      hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

      if (pcfg_ctx->omen_next_work_unit_idx >= total_work_units)
      {
        hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
        return 0;
      }
    }

    u64 work_id = pcfg_ctx->omen_next_work_unit_idx++;
    u64 skip_offset = pcfg_ctx->omen_skip_remainder;
    u32 skip_start_cost = pcfg_ctx->omen_skip_start_cost;
    pcfg_ctx->omen_skip_remainder = 0;
    pcfg_ctx->omen_skip_start_cost = 0; // reset after first use

    // Handle skip_structure (BY_STRUCT Classic)
    if (gen->skip_structure && user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT && user_options->pcfg_omen_type == PCFG_OMEN_TYPE_CLASSIC)
    {
      gen->skip_structure = false;
      gen->omen_gpu_skip_current_struct = true;

      if (pcfg_ctx->perf_threshold != NULL &&
          pcfg_ctx->perf_threshold->monitoring_active &&
          pcfg_ctx->perf_threshold->skip_struct_enabled)
      {
        pcfg_gen_perf_reset_struct (pcfg_ctx->perf_threshold, device_param->device_id, gen->curr_struct_idx + 1);
      }
    }

    // reserve budget for this work unit
    u64 my_budget = UINT64_MAX;
    if (effective_limit > 0)
    {
      if (gen->omen_reserved_budget != UINT64_MAX && gen->omen_reserved_budget > 0)
      {
         // use remaining budget from previous work unit
        my_budget = gen->omen_reserved_budget;
      }
      else
      {
        u64 remaining = (pcfg_ctx->words_generated < effective_limit) ? (effective_limit - pcfg_ctx->words_generated) : 0;
        my_budget = remaining;
        pcfg_ctx->words_generated += remaining;
        gen->omen_reserved_budget = my_budget;
      }
    }
    hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
    u32 chunk_idx = work_id % pcfg_ctx->omen_num_chunks;
    u64 loop_idx  = work_id / pcfg_ctx->omen_num_chunks;

    gen->omen_global_loop_idx = loop_idx;
    gen->omen_target_cost = chunk_idx;

    pcfg_chunk_t *chunk = &pcfg_ctx->omen_chunks[chunk_idx];

    gen->omen_gpu_batch_entry_cnt = 0;
    gen->omen_gpu_partition_cnt = 0;

    u64 current_batch_keyspace = 0;

    // PCFG_MODE_GPU_OMEN_BY_COST (iterate by cost, then by structure)

    if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST)
    {
      // find starting cost
      u32 cost_start = chunk->cost_start;

      if (skip_start_cost > 0 && skip_start_cost >= chunk->cost_start && skip_start_cost <= chunk->cost_end)
      {
        cost_start = skip_start_cost;
      }
      for (u32 cost = cost_start; cost <= chunk->cost_end; cost++)
      {
        if (!status_ctx->run_thread_level1) break;
        if (device_param->speed_only_finish) break;

        gen->omen_by_cost_current = cost;

        u32 i = 0;
        u64 struct_consumed_offset = 0;

        while (i < lin->struct_cnt)
        {
          if (!status_ctx->run_thread_level1) break;
          if (device_param->speed_only_finish) break;

          if (gen->omen_skip_cost)
          {
            gen->omen_skip_cost = false;

            if (pcfg_ctx->perf_threshold != NULL &&
                pcfg_ctx->perf_threshold->monitoring_active &&
                pcfg_ctx->perf_threshold->skip_cost_enabled)
            {
              pcfg_gen_perf_reset_cost (pcfg_ctx->perf_threshold, device_param->device_id, cost + 1);
            }

            break;
          }

          if (gen->omen_skip_loop)
          {
            gen->omen_skip_loop = false;

            u64 target_loop = gen->omen_global_loop_idx + 1;
            u64 target_wu = target_loop * pcfg_ctx->omen_num_chunks;
            if (target_wu > total_work_units) target_wu = total_work_units;

            hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
            if (target_wu > pcfg_ctx->omen_next_work_unit_idx)
              pcfg_ctx->omen_next_work_unit_idx = target_wu;
            hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);

            if (pcfg_ctx->perf_threshold != NULL &&
                pcfg_ctx->perf_threshold->monitoring_active &&
                pcfg_ctx->perf_threshold->skip_loop_enabled)
            {
              pcfg_gen_perf_reset_loop (pcfg_ctx->perf_threshold, device_param->device_id, target_loop);
            }

            goto end_work_unit;
          }

          if (gen->skip_structure)
          {
            gen->skip_structure = false;

            if (pcfg_ctx->perf_threshold != NULL &&
                pcfg_ctx->perf_threshold->monitoring_active &&
                pcfg_ctx->perf_threshold->skip_struct_enabled)
            {
              pcfg_gen_perf_reset_struct (pcfg_ctx->perf_threshold, device_param->device_id, i + 1);
            }

            i++;
            struct_consumed_offset = 0;
            continue;
          }

          gen->curr_struct_idx = i;

          const pcfg_gpu_omen_structure_t *s = &lin->structures[i];

          u8 s_cost = lin->struct_costs[i];
          u8 min_term = lin->struct_min_term_cost[i];

          // calculate rem_cost for this cost
          int rem_cost = (int) cost - (int) s_cost;

          // filter structure not active at this cost
          if (rem_cost < 0)
          {
            i++;
            struct_consumed_offset = 0;
            continue;
          }

          if (rem_cost < (int) min_term)
          {
            i++;
            struct_consumed_offset = 0;
            continue;
          }

          // avail_ks: keyspace for this structure at this specific cost (single-cost)
          u64 avail_ks = get_struct_keyspace_at_cost (s, pcfg_ctx->model->omen_data, rem_cost);

          if (avail_ks == 0)
          {
            i++;
            struct_consumed_offset = 0;
            continue;
          }

          // calculate range
          u64 burst_start = loop_idx * burst_size;
          u64 range_start = burst_start + struct_consumed_offset;

          if (range_start >= avail_ks)
          {
            i++;
            struct_consumed_offset = 0;
            continue;
          }

          u64 max_len = burst_size - struct_consumed_offset;
          if (range_start + max_len > avail_ks) max_len = avail_ks - range_start;

          // limitation for kernel_power
          u64 target_pws = device_param->kernel_power;
          u64 space_in_batch = (current_batch_keyspace < target_pws) ? (target_pws - current_batch_keyspace) : 0;

          if (space_in_batch == 0)
          {
            if (pcfg_gpu_omen_flush_buffer (hashcat_ctx, device_param, gen) == -1) return -1;
            hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

            if (effective_limit > 0 && gen->omen_reserved_budget == 0 && pcfg_ctx->words_generated >= effective_limit)
            {
              hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
              goto end_work_unit;
            }

            hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);

            gen->omen_gpu_batch_entry_cnt = 0;
            gen->omen_gpu_partition_cnt = 0;
            current_batch_keyspace = 0;
            space_in_batch = target_pws;
          }

          // apply skip
          if (skip_offset > 0)
          {
            if (skip_offset >= max_len)
            {
              skip_offset -= max_len;

              // if skip is completely consumed, unlock other devices
              if (skip_offset == 0)
              {
                hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
                pcfg_ctx->omen_skip_in_progress = false;
                hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
              }

              struct_consumed_offset += max_len;

              if (struct_consumed_offset >= burst_size || range_start + max_len >= avail_ks)
              {
                i++;
                struct_consumed_offset = 0;
              }

              continue;
            }

            range_start += skip_offset;
            max_len -= skip_offset;

            struct_consumed_offset += skip_offset;

            skip_offset = 0;
            // unlock other devices
            hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
            pcfg_ctx->omen_skip_in_progress = false;
            hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
          }

          u64 range_len = (max_len > space_in_batch) ? space_in_batch : max_len;

          if (my_budget != UINT64_MAX)
          {
            u64 batch_remaining = (my_budget > current_batch_keyspace) ? (my_budget - current_batch_keyspace) : 0;

            if (batch_remaining == 0) goto end_work_unit;

            if (range_len > batch_remaining) range_len = batch_remaining;
          }

          if (range_len == 0)
          {
            if (struct_consumed_offset >= burst_size || range_start >= avail_ks)
            {
              i++;
              struct_consumed_offset = 0;
            }

            continue;
          }

          // check host buffer space
          u32 space_parts = max_partitions - gen->omen_gpu_partition_cnt;
          u32 space_batch = max_batch_entries - gen->omen_gpu_batch_entry_cnt;

          if (space_parts < PCFG_OMEN_PARTITIONS_MAX || space_batch == 0)
          {
            if (pcfg_gpu_omen_flush_buffer (hashcat_ctx, device_param, gen) == -1) return -1;
            gen->omen_gpu_batch_entry_cnt = 0;
            gen->omen_gpu_partition_cnt = 0;
            current_batch_keyspace = 0;
            space_parts = max_partitions;
            space_batch = max_batch_entries;
          }

          pcfg_gpu_omen_partition_t *part_dst = &gen->omen_gpu_partitions[gen->omen_gpu_partition_cnt];

          u32 out_cnt = 0;

          // generate partitions for this single cost
          u64 gen_ks = pcfg_gpu_omen_generate_partitions (s, pcfg_ctx->model->omen_data, rem_cost, range_start, range_len, part_dst, space_parts, &out_cnt);

          if (out_cnt > 0)
          {
            u32 local_struct_idx = gen->omen_gpu_batch_entry_cnt;

            memcpy (&gen->omen_gpu_structures[local_struct_idx], s, sizeof (pcfg_gpu_omen_structure_t));

            pcfg_gpu_omen_batch_entry_t *be = &gen->omen_gpu_batch_entries[local_struct_idx];
            be->struct_idx = local_struct_idx;
            be->partition_offset = gen->omen_gpu_partition_cnt;
            be->partition_count = out_cnt;
            be->cumulative_end = gen_ks;

            gen->burst_cand.struct_idx = gen->curr_struct_idx;

            gen->omen_gpu_batch_entry_cnt++;
            gen->omen_gpu_partition_cnt += out_cnt;

            current_batch_keyspace += gen_ks;

            struct_consumed_offset += gen_ks;
          }
          else
          {
            struct_consumed_offset += range_len;
          }

          if (struct_consumed_offset >= burst_size || range_start + range_len >= avail_ks)
          {
            i++;
            struct_consumed_offset = 0;
          }
        }
      }

    }
    // PCFG_MODE_GPU_OMEN_BY_STRUCT (iterate by structure, then by cost)
    else
    {
      u32 i = 0;
      u64 struct_consumed_offset = 0;

      while (i < lin->struct_cnt)
      {
        if (!status_ctx->run_thread_level1) break;
        if (device_param->speed_only_finish) break;

        if (gen->omen_skip_loop)
        {
          gen->omen_skip_loop = false;

          u64 target_loop = gen->omen_global_loop_idx + 1;
          u64 target_wu = target_loop * pcfg_ctx->omen_num_chunks;
          if (target_wu > total_work_units) target_wu = total_work_units;

          hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
          if (target_wu > pcfg_ctx->omen_next_work_unit_idx)
            pcfg_ctx->omen_next_work_unit_idx = target_wu;
          hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);

          if (pcfg_ctx->perf_threshold != NULL &&
              pcfg_ctx->perf_threshold->monitoring_active &&
              pcfg_ctx->perf_threshold->skip_loop_enabled)
          {
            pcfg_gen_perf_reset_loop (pcfg_ctx->perf_threshold, device_param->device_id, target_loop);
          }

          break;
        }

        if (gen->omen_skip_cost)
        {
          gen->omen_skip_cost = false;

          if (pcfg_ctx->perf_threshold != NULL &&
              pcfg_ctx->perf_threshold->monitoring_active &&
              pcfg_ctx->perf_threshold->skip_struct_enabled)
          {
            pcfg_gen_perf_reset_struct (pcfg_ctx->perf_threshold, device_param->device_id, i + 1);
          }

          i++;
          struct_consumed_offset = 0;
          continue;
        }

        gen->curr_struct_idx = i;

        if (gen->omen_gpu_skip_current_struct)
        {
          gen->omen_gpu_skip_current_struct = false;
          i++;
          struct_consumed_offset = 0;
          continue;
        }

        const pcfg_gpu_omen_structure_t *s = &lin->structures[i];

        u8 s_cost    = lin->struct_costs[i];
        u8 min_term  = lin->struct_min_term_cost[i];
        u32 max_term = pcfg_ctx->analysis_struct_max_term_cost[i];

        u32 min_l = s_cost + min_term;
        u32 max_l = s_cost + max_term;
        if (max_l > 300) max_l = 300;

        // filter chunk
        if (min_l > chunk->cost_end || max_l < chunk->cost_start)
        {
          i++;
          struct_consumed_offset = 0;
          continue;
        }

        // avail_ks: total keyspace for this structure across all active costs in the chunk
        u64 avail_ks = pcfg_ctx->model->structures[i].keyspace;
        u64 burst_start = loop_idx * burst_size;

        u64 range_start = burst_start + struct_consumed_offset;

        if (range_start >= avail_ks)
        {
          i++;
          struct_consumed_offset = 0;
          continue;
        }

        u64 max_len = burst_size - struct_consumed_offset;
        if (range_start + max_len > avail_ks) max_len = avail_ks - range_start;

        // limitation for kernel_power
        u64 target_pws = device_param->kernel_power;
        u64 space_in_batch = (current_batch_keyspace < target_pws) ? (target_pws - current_batch_keyspace) : 0;

        if (space_in_batch == 0)
        {
          if (pcfg_gpu_omen_flush_buffer (hashcat_ctx, device_param, gen) == -1) return -1;
          hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
          if (effective_limit > 0 && gen->omen_reserved_budget == 0 && pcfg_ctx->words_generated >= effective_limit)
          {
            hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
            goto end_work_unit;
          }

          hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);

          gen->omen_gpu_batch_entry_cnt = 0;
          gen->omen_gpu_partition_cnt = 0;
          current_batch_keyspace = 0;
          space_in_batch = target_pws;
        }

        // apply skip
        if (skip_offset > 0)
        {
          if (skip_offset >= max_len)
          {
            skip_offset -= max_len;

            // if skip is completely used up, unlock other devices
            if (skip_offset == 0)
            {
              hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
              pcfg_ctx->omen_skip_in_progress = false;
              hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
            }

            struct_consumed_offset += max_len;

            if (struct_consumed_offset >= burst_size || range_start + max_len >= avail_ks)
            {
              i++;
              struct_consumed_offset = 0;
            }

            continue;
          }

          range_start += skip_offset;
          max_len -= skip_offset;

          struct_consumed_offset += skip_offset;

          skip_offset = 0;
          // unlock other devices
          hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
          pcfg_ctx->omen_skip_in_progress = false;
          hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
        }

        u64 range_len = (max_len > space_in_batch) ? space_in_batch : max_len;

        if (my_budget != UINT64_MAX)
        {
          u64 batch_remaining = (my_budget > current_batch_keyspace) ? (my_budget - current_batch_keyspace) : 0;

          if (batch_remaining == 0) goto end_work_unit;

          if (range_len > batch_remaining) range_len = batch_remaining;
        }

        if (range_len == 0)
        {
          if (struct_consumed_offset >= burst_size || range_start >= avail_ks)
          {
            i++;
            struct_consumed_offset = 0;
          }

          continue;
        }

        // check host buffer space
        u32 space_parts = max_partitions - gen->omen_gpu_partition_cnt;
        u32 space_batch = max_batch_entries - gen->omen_gpu_batch_entry_cnt;

        if (space_parts < PCFG_OMEN_PARTITIONS_MAX || space_batch == 0)
        {
          if (pcfg_gpu_omen_flush_buffer (hashcat_ctx, device_param, gen) == -1) return -1;
          gen->omen_gpu_batch_entry_cnt = 0;
          gen->omen_gpu_partition_cnt = 0;
          current_batch_keyspace = 0;
          space_parts = max_partitions;
          space_batch = max_batch_entries;
        }

        pcfg_gpu_omen_partition_t *part_dst = &gen->omen_gpu_partitions[gen->omen_gpu_partition_cnt];

        u32 out_cnt = 0;

        u64 gen_ks = generate_partitions_multicost (s, pcfg_ctx->model->omen_data, s_cost, min_term, max_term, range_start, range_len, part_dst, space_parts, &out_cnt);

        if (out_cnt > 0)
        {
          u32 local_struct_idx = gen->omen_gpu_batch_entry_cnt;

          memcpy (&gen->omen_gpu_structures[local_struct_idx], s, sizeof (pcfg_gpu_omen_structure_t));

          pcfg_gpu_omen_batch_entry_t *be = &gen->omen_gpu_batch_entries[local_struct_idx];
          be->struct_idx = local_struct_idx;
          be->partition_offset = gen->omen_gpu_partition_cnt;
          be->partition_count = out_cnt;
          be->cumulative_end = gen_ks;

          gen->burst_cand.struct_idx = gen->curr_struct_idx;
          gen->omen_by_cost_current = (min_l >= chunk->cost_start) ? min_l : chunk->cost_start;

          gen->omen_gpu_batch_entry_cnt++;
          gen->omen_gpu_partition_cnt += out_cnt;

          current_batch_keyspace += gen_ks;

          struct_consumed_offset += gen_ks;
        }
        else
        {
          struct_consumed_offset += range_len;
        }

        if (struct_consumed_offset >= burst_size || range_start + range_len >= avail_ks)
        {
          i++;
          struct_consumed_offset = 0;
        }
      }
    }

end_work_unit:

    // chunk's final flush
    if (gen->omen_gpu_batch_entry_cnt > 0)
    {
      if (pcfg_gpu_omen_flush_buffer (hashcat_ctx, device_param, gen) == -1) return -1;
    }
  }

  return 0;
}

int calc_pcfg (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  int rc = 0;

  if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB)
  {
    rc = backend_session_pcfg_gpu_prob_run (hashcat_ctx, device_param);
  }
  else if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST)
  {
    rc = backend_session_pcfg_gpu_omen_run (hashcat_ctx, device_param);
  }
  else
  {
    rc = calc_pcfg_cpu_run (hashcat_ctx, device_param);
  }

  if (rc == -1) return -1;

  device_param->kernel_accel_prev   = device_param->kernel_accel;
  device_param->kernel_loops_prev   = device_param->kernel_loops;
  device_param->kernel_threads_prev = device_param->kernel_threads;
  device_param->kernel_accel   = 0;
  device_param->kernel_loops   = 0;
  device_param->kernel_threads = 0;

  return 0;
}
