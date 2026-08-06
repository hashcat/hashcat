/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "backend.h"
#include "memory.h"
#include "pcfg_common.h"

#define ANALYSIS_MAX_PARTS  32
#define ANALYSIS_MAX_COSTS 128
#define ANALYSIS_MAX_CHUNKS 2048

typedef struct pcfg_analysis_gpu
{
  const char *name;
  u64  memory_free;
  u64  max_alloc;
  u64  device_global_mem;

} pcfg_analysis_gpu_t;

typedef struct pcfg_gpu_stats
{
  u32  max_structs;
  u32  chunks_needing_subbatch;
  u32  total_dispatches;
  u32  max_batches_per_chunk;

} pcfg_gpu_stats_t;

typedef struct pcfg_analysis_result
{
  // Terminali
  u64  total_terminals;
  u64  terminals_per_cost[PCFG_OMEN_MAX_COST];
  u64  terminals_cumulative[PCFG_OMEN_MAX_COST];
  u64  data_buffer_size_per_cost[PCFG_OMEN_MAX_COST];
  u64  data_buffer_total;

  // Strutture
  u32  total_structures;
  u32  structures_per_cost[ANALYSIS_MAX_COSTS];
  u32  structures_cumulative[ANALYSIS_MAX_COSTS];

  // Max term cost per cost
  u8   max_term_cost_per_cost[ANALYSIS_MAX_COSTS];
  u64  data_needed_per_cost[ANALYSIS_MAX_COSTS];

  // data_buffer parts
  u32  num_parts;
  u8   part_cost_start[ANALYSIS_MAX_PARTS];
  u8   part_cost_end[ANALYSIS_MAX_PARTS];
  u64  part_size[ANALYSIS_MAX_PARTS];

  // Chunk
  u32  num_chunks;
  u16  chunk_cost_start[ANALYSIS_MAX_CHUNKS];
  u16  chunk_cost_end[ANALYSIS_MAX_CHUNKS];
  u32  chunk_struct_count[ANALYSIS_MAX_CHUNKS];
  u64  chunk_data_size[ANALYSIS_MAX_CHUNKS];
  u32  chunk_max_structs[ANALYSIS_MAX_CHUNKS];
  bool chunk_needs_subbatch[ANALYSIS_MAX_CHUNKS];

  // Mode and memory
  bool static_data_mode;
  u64  available_for_data;
  u64  min_gpu_memory;
  u64  min_device_global_mem;
  u64  global_min_max_alloc;
  u32  global_max_structs;

} pcfg_analysis_result_t;

typedef struct scenario_result
{
  u32  active_gpus;
  u32  max_structs;
  u32  num_parts;
  u32  chunks_subbatch;
  u32  total_dispatches;

} scenario_result_t;

static inline u32 calc_stride_words (u32 len)
{
  u32 stride_bytes = (len + PCFG_CHAR_STRIDE - 1) & ~(PCFG_CHAR_STRIDE - 1);
  return stride_bytes / sizeof (u32);
}

static void analyze_terminals (const pcfg_model_t *model, pcfg_analysis_result_t *result)
{
  const pcfg_omen_extra_t *omen = model->omen_data;

  memset (result->terminals_per_cost, 0, sizeof (result->terminals_per_cost));
  result->total_terminals = 0;

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      const u32 cnt = model->terminals[ty][ln].cnt;

      if (cnt == 0) continue;

      const pcfg_omen_slot_map_t *map = &omen->term_maps[ty][ln];

      for (int c = 0; c < PCFG_OMEN_MAX_COST; c++)
      {
        result->terminals_per_cost[c] += map->counts[c];
      }

      result->total_terminals += cnt;
    }
  }

  // cumulative
  result->terminals_cumulative[0] = result->terminals_per_cost[0];

  for (int c = 1; c < PCFG_OMEN_MAX_COST; c++)
  {
    result->terminals_cumulative[c] = result->terminals_cumulative[c - 1] + result->terminals_per_cost[c];
  }

  // data_buffer size for each max_cost
  memset (result->data_buffer_size_per_cost, 0, sizeof (result->data_buffer_size_per_cost));

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      const u32 cnt = model->terminals[ty][ln].cnt;

      if (cnt == 0) continue;

      const pcfg_omen_slot_map_t *map = &omen->term_maps[ty][ln];
      const u32 stride_words = calc_stride_words (ln);
      const u64 bytes_per_term = stride_words * sizeof (u32);

      u64 cumulative_terms = 0;

      for (int c = 0; c < PCFG_OMEN_MAX_COST; c++)
      {
        cumulative_terms += map->counts[c];
        result->data_buffer_size_per_cost[c] += cumulative_terms * bytes_per_term;
      }
    }
  }

  result->data_buffer_total = result->data_buffer_size_per_cost[PCFG_OMEN_MAX_COST - 1];
}

static void analyze_structures (const pcfg_model_t *model, pcfg_analysis_result_t *result)
{
  const pcfg_omen_extra_t *omen = model->omen_data;
  const u32 struct_cnt = model->struct_cnt;

  memset (result->structures_per_cost, 0, sizeof (result->structures_per_cost));
  result->total_structures = struct_cnt;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    u32 min_cost = (u32) omen->struct_costs[i] + (u32) omen->struct_min_term_cost[i];

    if (min_cost >= ANALYSIS_MAX_COSTS) min_cost = ANALYSIS_MAX_COSTS - 1;

    result->structures_per_cost[min_cost]++;
  }

  // cumulative
  result->structures_cumulative[0] = result->structures_per_cost[0];

  for (int l = 1; l < ANALYSIS_MAX_COSTS; l++)
  {
    result->structures_cumulative[l] = result->structures_cumulative[l - 1] + result->structures_per_cost[l];
  }
}

static void analyze_max_term_cost_per_cost (const pcfg_model_t *model, const u8 *struct_max_term_cost, pcfg_analysis_result_t *result)
{
  const pcfg_omen_extra_t *omen = model->omen_data;
  const u32 struct_cnt = model->struct_cnt;

  // pre-calculate min cost for each (type, len)
  u8 slot_min_cost[256][PCFG_VALUE_MAX];

  memset (slot_min_cost, 0xFF, sizeof (slot_min_cost));

  for (int ty = 0; ty < 256; ty++)
  {
    for (int ln = 0; ln < PCFG_VALUE_MAX; ln++)
    {
      const pcfg_omen_slot_map_t *map = &omen->term_maps[ty][ln];

      for (int c = 0; c < PCFG_OMEN_MAX_COST; c++)
      {
        if (map->counts[c] > 0)
        {
          slot_min_cost[ty][ln] = (u8) c;
          break;
        }
      }

      if (slot_min_cost[ty][ln] == 0xFF) slot_min_cost[ty][ln] = 0;
    }
  }

  memset (result->max_term_cost_per_cost, 0, sizeof (result->max_term_cost_per_cost));

  // for each struct
  for (u32 i = 0; i < struct_cnt; i++)
  {
    const pcfg_structure_t *s = &model->structures[i];
    const u8 struct_cost = omen->struct_costs[i];
    const u8 min_term_cost = omen->struct_min_term_cost[i];
    const u8 max_term_total = struct_max_term_cost[i];

    const u32 min_cost = (u32) struct_cost + (u32) min_term_cost;
    u32 max_cost = (u32) struct_cost + (u32) max_term_total;

    if (max_cost >= ANALYSIS_MAX_COSTS) max_cost = ANALYSIS_MAX_COSTS - 1;

    // get min cost for each slot
    const u32 n_slots = s->token_cnt;
    u8 s_min[64];

    for (u32 k = 0; k < n_slots && k < 64; k++)
    {
      u8 ty = s->types[k] & 0x7F;
      u8 ln = s->lengths[k];
      s_min[k] = slot_min_cost[ty][ln];
    }

    // for each cost to which it contributes
    for (u32 cost = min_cost; cost <= max_cost; cost++)
    {
      int term_budget = (int) cost - (int) struct_cost;

      if (term_budget < 0) continue;

      // for each slot, calculate the maximum possible
      for (u32 k = 0; k < n_slots && k < 64; k++)
      {
        // max_for_slot_k = term_budget - (minimum sum of other slots)
        //                = term_budget - (min_term_cost - s_min[k])
        //                = term_budget - min_term_cost + s_min[k]

        int max_for_k = term_budget - (int) min_term_cost + (int) s_min[k];

        if (max_for_k < 0) continue;
        if (max_for_k >= PCFG_OMEN_MAX_COST) max_for_k = PCFG_OMEN_MAX_COST - 1;

        if ((u8) max_for_k > result->max_term_cost_per_cost[cost])
        {
          result->max_term_cost_per_cost[cost] = (u8) max_for_k;
        }
      }
    }
  }

  // find the actual maximum cost of the terminals
  u8 global_max_term_cost = 0;

  for (int c = PCFG_OMEN_MAX_COST - 1; c >= 0; c--)
  {
    if (result->terminals_per_cost[c] > 0)
    {
      global_max_term_cost = (u8) c;
      break;
    }
  }

  // apply the cap at all costs
  for (int l = 0; l < ANALYSIS_MAX_COSTS; l++)
  {
    if (result->max_term_cost_per_cost[l] > global_max_term_cost)
    {
      result->max_term_cost_per_cost[l] = global_max_term_cost;
    }
  }

  // calculate buffer date required for cost
  for (int l = 0; l < ANALYSIS_MAX_COSTS; l++)
  {
    u8 max_cost = result->max_term_cost_per_cost[l];

    if (max_cost >= PCFG_OMEN_MAX_COST) max_cost = PCFG_OMEN_MAX_COST - 1;

    result->data_needed_per_cost[l] = result->data_buffer_size_per_cost[max_cost];
  }
}

static void calculate_data_buffer_parts (pcfg_analysis_result_t *result, u64 max_alloc)
{
  result->num_parts = 0;

  u8 current_start = 0;
  u64 current_part_size = 0;
  u64 prev_cumulative = 0;

  for (int c = 0; c < PCFG_OMEN_MAX_COST; c++)
  {
    u64 this_cost_size = result->data_buffer_size_per_cost[c] - prev_cumulative;

    // if this single cost exceeds max_alloc, it must be divided.
    if (this_cost_size > max_alloc)
    {
      // first close the current part if it exists
      if (current_part_size > 0 && result->num_parts < ANALYSIS_MAX_PARTS)
      {
        result->part_cost_start[result->num_parts] = current_start;
        result->part_cost_end[result->num_parts] = c - 1;
        result->part_size[result->num_parts] = current_part_size;
        result->num_parts++;
      }

      // create part for this single cost (it will be marked as too big)
      if (result->num_parts < ANALYSIS_MAX_PARTS)
      {
        result->part_cost_start[result->num_parts] = c;
        result->part_cost_end[result->num_parts] = c;
        result->part_size[result->num_parts] = this_cost_size;
        result->num_parts++;
      }

      // reset for next part
      current_start = c + 1;
      current_part_size = 0;
    }
    // if adding this cost exceeds max_alloc, close current part
    else if (current_part_size + this_cost_size > max_alloc && current_part_size > 0)
    {
      if (result->num_parts < ANALYSIS_MAX_PARTS)
      {
        result->part_cost_start[result->num_parts] = current_start;
        result->part_cost_end[result->num_parts] = c - 1;
        result->part_size[result->num_parts] = current_part_size;
        result->num_parts++;
      }

      // start new part with this cost
      current_start = c;
      current_part_size = this_cost_size;
    }
    else
    {
      // add to current section
      current_part_size += this_cost_size;
    }

    prev_cumulative = result->data_buffer_size_per_cost[c];
  }

  // last part
  if (current_part_size > 0 && result->num_parts < ANALYSIS_MAX_PARTS)
  {
    result->part_cost_start[result->num_parts] = current_start;
    result->part_cost_end[result->num_parts] = PCFG_OMEN_MAX_COST - 1;
    result->part_size[result->num_parts] = current_part_size;
    result->num_parts++;
  }
}

static void simulate_chunking (const pcfg_model_t *model, const u8 *struct_max_term_cost, pcfg_analysis_result_t *result, u32 cost_min, u32 cost_max, u64 static_overhead, u64 per_struct_cost, u32 max_alloc_perc) //, u32 num_gpus)
{
  result->num_chunks = 0;

  const u64 min_gpu_memory = result->min_gpu_memory;
  const u64 global_min_max_alloc = result->global_min_max_alloc;

  // used_static includes data_buffer_total
  const u64 safety_margin = PCFG_OMEN_SAFETY_MARGIN_BYTES (result->min_device_global_mem);
  const u64 used_static = static_overhead + result->data_buffer_total + safety_margin;
  const u64 available_total = (min_gpu_memory > used_static) ? (min_gpu_memory - used_static) : 0;

  // alloc_max_structs based on largest single allocation (partitions)
  const u64 safe_max_alloc = (global_min_max_alloc * max_alloc_perc) / 100;
  u32 alloc_max_structs = (u32) (safe_max_alloc / (PCFG_OMEN_PARTITIONS_MAX * sizeof (pcfg_gpu_omen_partition_t)));

  // mem_max_structs based on total available memory
  const u32 mem_max_structs = (u32) (available_total / per_struct_cost);

  // global_max_structs = MIN(mem, alloc)
  result->global_max_structs = (mem_max_structs < alloc_max_structs) ? mem_max_structs : alloc_max_structs;
  // determine mode
  result->static_data_mode = (result->data_buffer_total <= (min_gpu_memory - static_overhead - safety_margin));
  result->available_for_data = available_total;

  // find actual max cost
  u32 effective_max = cost_min;

  for (u32 i = 0; i < model->struct_cnt; i++)
  {
    u32 ml = (u32) model->omen_data->struct_costs[i] + (u32) struct_max_term_cost[i];

    if (ml > effective_max) effective_max = ml;
  }

  if (effective_max > cost_max) effective_max = cost_max;

  u32 cur = cost_min;

  while (cur <= effective_max && result->num_chunks < ANALYSIS_MAX_CHUNKS)
  {
    // skip costs without structures
    u32 init_count = count_structs_in_range (model, struct_max_term_cost, cur, cur);

    if (init_count == 0)
    {
      cur++;
      continue;
    }

    u32 best_end = cur;
    u32 best_count = 0;
    u64 best_data = 0;
    u32 best_max_structs = 0;
    bool found = false;

    for (u32 try_end = cur; try_end <= effective_max; try_end++)
    {
      u32 count = count_structs_in_range (model, struct_max_term_cost, cur, try_end);

      if (count == 0) continue;

      // Calculate max data buffer in the range
      u64 max_data = 0;

      for (u32 l = cur; l <= try_end && l < ANALYSIS_MAX_COSTS; l++)
      {
        if (result->data_needed_per_cost[l] > max_data)
          max_data = result->data_needed_per_cost[l];
      }

      // In static mode, always use the entire data buffer
      if (result->static_data_mode)
      {
        max_data = result->data_buffer_total;
      }

      // Calculate remaining memory for structures
      u64 remaining_for_structs = 0;

      if (max_data + static_overhead + safety_margin < min_gpu_memory)
      {
        remaining_for_structs = min_gpu_memory - max_data - static_overhead - safety_margin;
      }

      u32 chunk_mem_max_structs = (u32) (remaining_for_structs / per_struct_cost);
      u32 effective_max_structs = (chunk_mem_max_structs < alloc_max_structs) ? chunk_mem_max_structs : alloc_max_structs;

      // Check structure constraint
      if (count > effective_max_structs)
      {
        if (!found)
        {
          // First cost already exceeds limit -> sub-batching needed
          best_end = try_end;
          best_count = count;
          best_data = max_data;
          best_max_structs = effective_max_structs;
          found = true;
        }
        break;
      }

      // Check data constraint (only for dynamic mode)
      if (!result->static_data_mode && max_data > available_total)
      {
        if (!found)
        {
          best_end = try_end;
          best_count = count;
          best_data = max_data;
          best_max_structs = 0;  // Error flag
          found = true;
        }
        break;
      }

      // This range is ok
      best_end = try_end;
      best_count = count;
      best_data = max_data;
      best_max_structs = effective_max_structs;
      found = true;
    }

    if (found && best_count > 0)
    {
      const u32 c = result->num_chunks;

      result->chunk_cost_start[c] = cur;
      result->chunk_cost_end[c] = best_end;
      result->chunk_struct_count[c] = best_count;
      result->chunk_data_size[c] = best_data;
      result->chunk_max_structs[c] = best_max_structs;
      result->chunk_needs_subbatch[c] = (best_max_structs > 0 && best_count > best_max_structs);
      result->num_chunks++;
    }

    cur = best_end + 1;
  }
}
static int print_recommendations (hashcat_ctx_t *hashcat_ctx, const pcfg_analysis_result_t *result, const pcfg_analysis_gpu_t *gpus, u32 num_gpus)
{
  int ret = 0;

  bool has_errors = false;
  bool has_too_big_parts = false;

  u32 error_chunks = 0;

  // count errors
  for (u32 c = 0; c < result->num_chunks; c++)
  {
    if (result->chunk_max_structs[c] == 0)
    {
      has_errors = true;
      error_chunks++;
    }
  }

  for (u32 p = 0; p < result->num_parts; p++)
  {
    if (result->part_size[p] > result->global_min_max_alloc)
    {
      has_too_big_parts = true;
    }
  }

  // find GPU with lower max_alloc
  u32 weakest_gpu = 0;
  u64 min_alloc = UINT64_MAX;

  for (u32 g = 0; g < num_gpus; g++)
  {
    if (gpus[g].max_alloc < min_alloc)
    {
      min_alloc = gpus[g].max_alloc;
      weakest_gpu = g;
    }
  }

  if (has_errors)
  {
    ret = -1;

    event_log_error (hashcat_ctx, "\nCRITICAL: %u chunks cannot be processed (data > GPU memory) ...", error_chunks);

    event_log_warning (hashcat_ctx, "Try using --pcfg-terminal-count-min to reduces data buffer by removing rare terminals");
    event_log_warning (hashcat_ctx, "and/or");
    event_log_warning (hashcat_ctx, "Try using --pcfg-omen-cost-max to skip high costs that require more data");
  }
  else if (has_too_big_parts)
  {
    printf ("  [WARNING] Some data buffer parts exceed max_alloc\n\n");
    printf ("  This may cause allocation failures. Consider:\n");
    printf ("    - Excluding %s (-D option)\n", gpus[weakest_gpu].name);
    printf ("    - Using --pcfg-terminal-count-min to reduce terminal count\n\n");
  }
  else if (!result->static_data_mode)
  {
    printf ("  [INFO] Dynamic mode active (data buffer > GPU memory)\n\n");
    printf ("  Performance may be impacted by per-chunk data loading.\n");
    printf ("  Consider using --pcfg-terminal-count-min to reduce data buffer size.\n\n");
  }
  return ret;
}
int pcfg_omen_analyze_model (hashcat_ctx_t *hashcat_ctx, const pcfg_model_t *model)
{
  if (model == NULL || model->omen_data == NULL)
  {
    event_log_error (hashcat_ctx, "Model or OMEN data not available.");
    return -1;
  }

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (backend_ctx == NULL || backend_ctx->enabled == false)
  {
    event_log_error (hashcat_ctx, "Backend context not available.");
    return -1;
  }

  u32 cost_min = user_options->pcfg_omen_cost_min;
  u32 cost_max = user_options->pcfg_omen_cost_max;

  if (cost_max > PCFG_OMEN_COST_PRACTICAL_MAX) cost_max = PCFG_OMEN_COST_PRACTICAL_MAX;

  u32 num_gpus = 0;

  for (int i = 0; i < backend_ctx->backend_devices_cnt; i++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[i];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    num_gpus++;
  }

  if (num_gpus == 0)
  {
    event_log_error (hashcat_ctx, "No active GPU devices found.");
    return -1;
  }

  pcfg_analysis_gpu_t *gpus = (pcfg_analysis_gpu_t *) hccalloc (num_gpus, sizeof (pcfg_analysis_gpu_t));

  if (gpus == NULL)
  {
    event_log_error (hashcat_ctx, "Failed to allocate GPU info array.");
    return -1;
  }

  u32 gpu_idx = 0;

  for (int i = 0; i < backend_ctx->backend_devices_cnt; i++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[i];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    gpus[gpu_idx].name = device_param->device_name;
    gpus[gpu_idx].memory_free = device_param->device_available_mem;
    gpus[gpu_idx].max_alloc = device_param->device_maxmem_alloc;
    gpus[gpu_idx].device_global_mem = device_param->device_global_mem;

    if (backend_ctx_device_get_memory_free (hashcat_ctx, device_param) == 0)
    {
      gpus[gpu_idx].memory_free = device_param->device_available_mem;
    }

    if (gpus[gpu_idx].max_alloc > gpus[gpu_idx].memory_free) gpus[gpu_idx].max_alloc = gpus[gpu_idx].memory_free;
    gpu_idx++;
  }

  pcfg_analysis_result_t result;
  memset (&result, 0, sizeof (result));

  u8 *struct_max_term_cost = (u8 *) hccalloc (model->struct_cnt, sizeof (u8));

  if (struct_max_term_cost == NULL)
  {
    event_log_error (hashcat_ctx, "%s: failed to allocate struct_max_term_cost", __func__);
    hcfree (gpus);
    return -1;
  }

  // calculate global limits
  result.global_min_max_alloc = UINT64_MAX;
  result.min_gpu_memory = UINT64_MAX;
  result.min_device_global_mem = UINT64_MAX;

  for (u32 g = 0; g < num_gpus; g++)
  {
    if (gpus[g].max_alloc < result.global_min_max_alloc) result.global_min_max_alloc = gpus[g].max_alloc;
    if (gpus[g].memory_free < result.min_gpu_memory) result.min_gpu_memory = gpus[g].memory_free;
    if (gpus[g].device_global_mem < result.min_device_global_mem) result.min_device_global_mem = gpus[g].device_global_mem;
  }

  // perform analisys
  calculate_struct_max_term_cost (model, struct_max_term_cost);
  analyze_terminals (model, &result);
  analyze_structures (model, &result);
  analyze_max_term_cost_per_cost (model, struct_max_term_cost, &result);

  // calculate exact costs for runtime simulation

  const u64 per_struct_cost = sizeof (pcfg_gpu_omen_structure_t) + sizeof (pcfg_gpu_omen_batch_entry_t) + PCFG_OMEN_PARTITIONS_MAX * sizeof (pcfg_gpu_omen_partition_t);
  const u64 size_slot_maps  = 256 * 256 * sizeof (pcfg_gpu_omen_slot_map_t);

  u32 active_blocks = 0;
  static u8 used_slots[256][256];
  memset (used_slots, 0, sizeof (used_slots));

  for (u32 i = 0; i < model->struct_cnt; i++)
  {
    const pcfg_structure_t *s = &model->structures[i];

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      u8 ty = s->types[k] & 0x7F;
      u8 ln = s->lengths[k];

      if (!used_slots[ty][ln])
      {
        used_slots[ty][ln] = 1;
        active_blocks++;
      }
    }
  }

  const u64 size_term_blocks = active_blocks * sizeof (pcfg_term_block_t);
  const u64 static_overhead = size_slot_maps + size_term_blocks;
  calculate_data_buffer_parts (&result, result.global_min_max_alloc);
  simulate_chunking (model, struct_max_term_cost, &result, cost_min, cost_max, static_overhead, per_struct_cost, user_options->pcfg_omen_max_alloc_perc); //, num_gpus);
  int ret = print_recommendations (hashcat_ctx, &result, gpus, num_gpus);
  hcfree (gpus);

  if (ret == 0)
  {
    pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

    pcfg_ctx->analysis_num_chunks = result.num_chunks;
    pcfg_ctx->analysis_max_structs = result.global_max_structs;
    pcfg_ctx->analysis_total_data_size = result.data_buffer_total;

    if (pcfg_ctx->analysis_struct_max_term_cost) hcfree (pcfg_ctx->analysis_struct_max_term_cost);
    pcfg_ctx->analysis_struct_max_term_cost = struct_max_term_cost;

    if (pcfg_ctx->analysis_chunks) hcfree (pcfg_ctx->analysis_chunks);

    // alloc and copy chunks
    pcfg_ctx->analysis_chunks = (pcfg_chunk_t *) hccalloc (result.num_chunks, sizeof (pcfg_chunk_t));

    if (!pcfg_ctx->analysis_chunks)
    {
      event_log_error (hashcat_ctx, "%s: failed to allocate analysis_chunks", __func__);
      hcfree (struct_max_term_cost);
      pcfg_ctx->analysis_struct_max_term_cost = NULL;
      return -1;
    }

    for (u32 i = 0; i < result.num_chunks; i++)
    {
      pcfg_ctx->analysis_chunks[i].cost_start = result.chunk_cost_start[i];
      pcfg_ctx->analysis_chunks[i].cost_end   = result.chunk_cost_end[i];
      pcfg_ctx->analysis_chunks[i].struct_count= result.chunk_struct_count[i];
    }
  }
  else
  {
    hcfree (struct_max_term_cost);
  }

  return ret;
}
