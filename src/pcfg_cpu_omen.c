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

#include "pcfg_common.h"
#include "pcfg_perf.h"
#include "pcfg_cpu_omen.h"

// CPU OMEN direct candidate generation

static inline int pcfg_cpu_omen_generate_direct (const u32 *data_buffer, const pcfg_term_block_t *term_blocks, const pcfg_gpu_omen_structure_t *structure, const pcfg_omen_extra_t *omen, const pcfg_omen_partition_t *partition, u64 partition_local_idx, char *pw_out, u32 *pw_len_out)
{
  const u32 token_cnt = structure->token_cnt;
  const u32 total_len = structure->total_len;
  u64 work_idx = partition_local_idx;
  u32 write_pos = total_len;

  #define PROCESS_TOKEN_LINEAR(K)                                              \
  do {                                                                         \
    const u8 ty   = structure->types[K] & 0x7F;                                \
    const u8 ln   = structure->lengths[K];                                     \
    const u8 cost = partition->costs[K];                                       \
    const pcfg_omen_slot_map_t *sm = &omen->term_maps[ty][ln];                 \
    const u32 count = sm->counts[cost];                                        \
    const u64 recip = sm->recip[cost];                                         \
    const u32 term_idx = fast_mod64 (work_idx, count, recip);                  \
    work_idx = fast_div64 (work_idx, count, recip);                            \
    const u32 real_rank = sm->ranks[cost] + term_idx;                          \
    const u32 blk_idx = structure->block_indices[K];                           \
    const pcfg_term_block_t *blk = &term_blocks[blk_idx];                      \
    write_pos -= ln;                                                           \
    const u64 src_off = blk->data_offset + (u64) real_rank * blk->stride_words;\
    const char *src = (const char *) (data_buffer + src_off);                  \
    switch (ln) {                                                              \
      case 1:  pw_out[write_pos] = src[0]; break;                              \
      case 2:  memcpy (pw_out + write_pos, src, 2); break;                     \
      case 3:  memcpy (pw_out + write_pos, src, 3); break;                     \
      case 4:  memcpy (pw_out + write_pos, src, 4); break;                     \
      case 5:  memcpy (pw_out + write_pos, src, 5); break;                     \
      case 6:  memcpy (pw_out + write_pos, src, 6); break;                     \
      case 7:  memcpy (pw_out + write_pos, src, 7); break;                     \
      case 8:  memcpy (pw_out + write_pos, src, 8); break;                     \
      default: memcpy (pw_out + write_pos, src, ln); break;                    \
    }                                                                          \
  } while(0)

  switch (token_cnt)
  {
    case 1:  PROCESS_TOKEN_LINEAR(0); break;
    case 2:  PROCESS_TOKEN_LINEAR(1); PROCESS_TOKEN_LINEAR(0); break;
    case 3:  PROCESS_TOKEN_LINEAR(2); PROCESS_TOKEN_LINEAR(1); PROCESS_TOKEN_LINEAR(0); break;
    case 4:  PROCESS_TOKEN_LINEAR(3); PROCESS_TOKEN_LINEAR(2); PROCESS_TOKEN_LINEAR(1); PROCESS_TOKEN_LINEAR(0); break;
    default:
      for (int k = (int) token_cnt - 1; k >= 0; k--)
      {
        PROCESS_TOKEN_LINEAR(k);
      }
      break;
  }
  #undef PROCESS_TOKEN_LINEAR

  pw_out[total_len] = '\0';
  *pw_len_out = total_len;
  return 0;
}

// CPU OMEN partition generation (uses linearized structures)

static void pcfg_cpu_omen_generate_partitions (pcfg_gen_t *gen, const pcfg_gpu_omen_structure_t *ls, const pcfg_omen_extra_t *omen, int remaining_cost)
{
  const u32 token_cnt = ls->token_cnt;

  // early exits
  if (token_cnt == 0) return;
  if (remaining_cost < 0) return;
  if (remaining_cost > 31 * (int) token_cnt) return;
  if (gen->omen_partition_cnt >= PCFG_OMEN_PARTITIONS_MAX) return;

  // pre-cache term_maps pointers
  const pcfg_omen_slot_map_t *slot_maps[PCFG_OMEN_MAX_TOKENS];

  for (u32 i = 0; i < token_cnt; i++)
  {
    const u8 ty = ls->types[i] & 0x7F;
    const u8 ln = ls->lengths[i];

    slot_maps[i] = &omen->term_maps[ty][ln];
  }

  // special case: single token
  if (token_cnt == 1)
  {
    if (remaining_cost <= 31)
    {
      u64 cnt = slot_maps[0]->counts[remaining_cost];

      if (cnt > 0)
      {
        pcfg_omen_partition_t *p = &gen->omen_partitions[gen->omen_partition_cnt++];

        memset (p->costs, 0, PCFG_TOKEN_MAX);

        p->costs[0] = (u8) remaining_cost;
        p->combinations = cnt;
        p->cumulative_offset = gen->omen_struct_keyspace;
        p->cumulative_end = p->cumulative_offset + p->combinations;

        gen->omen_struct_keyspace += cnt;
      }
    }

    return;
  }

  const int last_slot = (int) token_cnt - 1;

  // iterative enumeration using stack
  int      stack_next_c[PCFG_OMEN_MAX_TOKENS];
  int      stack_rem[PCFG_OMEN_MAX_TOKENS];
  u64      stack_prod[PCFG_OMEN_MAX_TOKENS];
  u8       current_costs[PCFG_OMEN_MAX_TOKENS];

  memset (current_costs, 0, sizeof (current_costs));

  // initialize slot 0
  stack_next_c[0] = 0;
  stack_prod[0]   = 1;
  stack_rem[0]    = remaining_cost;

  int slot = 0;

  while (slot >= 0)
  {
    if (gen->omen_partition_cnt >= PCFG_OMEN_PARTITIONS_MAX) return;

    // last slot: direct access
    if (slot == last_slot)
    {
      const int final_c = stack_rem[slot];

      if (final_c >= 0 && final_c <= 31)
      {
        u64 cnt = slot_maps[slot]->counts[final_c];

        if (cnt > 0)
        {
          current_costs[slot] = (u8) final_c;

          pcfg_omen_partition_t *p = &gen->omen_partitions[gen->omen_partition_cnt++];

          memcpy (p->costs, current_costs, PCFG_TOKEN_MAX);

          p->combinations      = stack_prod[slot] * cnt;
          p->cumulative_offset = gen->omen_struct_keyspace;
          p->cumulative_end    = p->cumulative_offset + p->combinations;

          gen->omen_struct_keyspace += p->combinations;
        }
      }

      slot--;
      continue;
    }

    // intermediate slots: iterate on possible costs
    const int rem = stack_rem[slot];
    const int slots_after = last_slot - slot;
    const int max_c = (rem > 31) ? 31 : rem;

    bool advanced = false;

    for (int c = stack_next_c[slot]; c <= max_c; c++)
    {
      const int left = rem - c;

      // pruning
      if (left > 31 * slots_after) continue;
      if (left < 0) break;

      u64 cnt = slot_maps[slot]->counts[c];

      if (cnt == 0) continue;

      // found a valid cost
      current_costs[slot] = (u8) c;
      stack_next_c[slot] = c + 1;

      // go to next slot
      slot++;

      stack_rem[slot]    = left;
      stack_next_c[slot] = 0;
      stack_prod[slot]   = stack_prod[slot - 1] * cnt;

      advanced = true;
      break;
    }

    if (!advanced) slot--;
  }
}

// Helper: find next valid cost for BY_STRUCT mode (per-generator)

static bool pcfg_cpu_omen_by_struct_find_cost (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, const pcfg_gpu_omen_data_t *lin, u32 start_cost)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t     *pcfg_ctx     = hashcat_ctx->pcfg_ctx;

  bool is_interleaved = (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_INTERLEAVED);

  u64 burst_start = 0;

  if (is_interleaved)
  {
    burst_start = gen->omen_global_loop_idx * gen->burst_size;
  }

  u32 si     = gen->curr_struct_idx;
  u8  s_cost = gen->omen_by_struct_s_cost;
  u32 max_l  = gen->omen_by_struct_max_l;

  u64 multicost_offset = gen->omen_by_struct_multicost_offset;

  for (u32 lvl = start_cost; lvl <= max_l; lvl++)
  {
    int rem = (int) lvl - (int) s_cost;

    if (rem < 0) continue;

    gen->omen_partition_cnt   = 0;
    gen->omen_struct_keyspace = 0;

    pcfg_cpu_omen_generate_partitions (gen, &lin->structures[si], pcfg_ctx->model->omen_data, rem);

    u64 cost_ks = gen->omen_struct_keyspace;

    if (cost_ks == 0) continue;

    // check if past burst window
    if (is_interleaved && multicost_offset >= gen->omen_current_chunk_max)
    {
      break;
    }

    // check if cost is before burst window
    if (is_interleaved && multicost_offset + cost_ks <= burst_start)
    {
      multicost_offset += cost_ks;
      continue;
    }

    // this cost intersects the burst window
    u64 start_idx = 0;

    if (is_interleaved && burst_start > multicost_offset)
    {
      start_idx = burst_start - multicost_offset;
    }

    gen->omen_struct_keyspace  = cost_ks;
    gen->curr_comb_idx         = start_idx;
    gen->omen_by_struct_multicost_offset = multicost_offset;
    gen->omen_by_struct_cost   = lvl;
    gen->omen_target_cost      = lvl;
    gen->omen_by_cost_current  = lvl;
    gen->omen_lap_found_work   = true;

    gen->omen_display_keyspace = gen->omen_by_struct_total_ks;

    gen->skip_structure        = false;
    gen->burst_cand.struct_idx = gen->curr_struct_idx;

    if (gen->omen_stats)
    {
      pcfg_omen_stats_update (gen->omen_stats, lvl, 0, 1);
      pcfg_omen_stats_loop_update (gen->omen_stats, gen->omen_global_loop_idx, 0, 1);
    }

    return true;
  }

  return false;
}

// CPU OMEN BY_STRUCT advance (mode 6: per-gen work-stealing)

static bool pcfg_cpu_omen_advance_by_struct (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, const pcfg_gpu_omen_ctx_t *ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t     *pcfg_ctx    = hashcat_ctx->pcfg_ctx;

  const pcfg_gpu_omen_data_t *lin = ctx->linear_data;
  pcfg_model_t *m = ctx->model;

  const u8 *struct_min_term_cost    = lin->struct_min_term_cost;
  const u8 *struct_costs            = lin->struct_costs;
  const u8 *struct_max_term_cost    = pcfg_ctx->analysis_struct_max_term_cost;

  u32 chunk_idx = gen->omen_linear_current_work_id % pcfg_ctx->omen_num_chunks;
  pcfg_chunk_t *chunk = &pcfg_ctx->omen_chunks[chunk_idx];
  u32 min_target_cost = chunk->cost_start;
  u32 max_target_cost = chunk->cost_end;

  bool is_interleaved = (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_INTERLEAVED);

  // If we have a current struct, try next cost
  if (gen->curr_struct_idx != UINT32_MAX && gen->curr_struct_idx < chunk->struct_end)
  {
    if (gen->omen_skip_loop)
    {
      return false;  // don't consume flag — let claiming-section handler advance the pool
    }

    // advance multicost_offset past current cost
    gen->omen_by_struct_multicost_offset += gen->omen_struct_keyspace;

    if (pcfg_cpu_omen_by_struct_find_cost (hashcat_ctx, gen, lin, gen->omen_by_struct_cost + 1))
    {
      return true;
    }

    // No more costs, go to next struct
    gen->curr_struct_idx++;
  }
  else if (gen->curr_struct_idx == UINT32_MAX)
  {
    gen->curr_struct_idx = chunk->struct_start;
  }

  // Find next valid struct
  while (gen->curr_struct_idx < chunk->struct_end)
  {
    if (gen->omen_skip_loop)
    {
      return false;  // don't consume flag — let claiming-section handler advance the pool
    }

    u32 si       = gen->curr_struct_idx;
    u8  s_cost   = struct_costs[si];
    u8  min_term = struct_min_term_cost[si];
    u32 max_term = struct_max_term_cost[si];

    u32 min_l = s_cost + min_term;
    u32 max_l = s_cost + max_term;

    if (min_l < min_target_cost) min_l = min_target_cost;
    if (max_l > max_target_cost) max_l = max_target_cost;

    if (min_l > max_l)
    {
      gen->curr_struct_idx++;
      continue;
    }

    u64 total_ks = m->structures[si].keyspace;

    if (total_ks == 0)
    {
      gen->curr_struct_idx++;
      continue;
    }

    // Compute burst window
    u64 chunk_max = total_ks;

    if (is_interleaved)
    {
      u64 burst_start = gen->omen_global_loop_idx * gen->burst_size;

      if (burst_start >= total_ks)
      {
        gen->curr_struct_idx++;
        continue;
      }

      chunk_max = burst_start + gen->burst_size;

      if (chunk_max > total_ks) chunk_max = total_ks;
    }

    // Set struct-cost state
    gen->omen_by_struct_s_cost     = s_cost;
    gen->omen_by_struct_max_l      = max_l;
    gen->omen_by_struct_total_ks      = total_ks;
    gen->omen_current_chunk_max    = chunk_max;
    gen->omen_by_struct_multicost_offset    = 0;

    if (pcfg_cpu_omen_by_struct_find_cost (hashcat_ctx, gen, lin, min_l))
    {
      return true;
    }

    gen->curr_struct_idx++;
  }

  return false;
}

// CPU OMEN advance (mode 4: per-gen work-stealing)

static bool pcfg_cpu_omen_advance_by_cost (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, const pcfg_gpu_omen_ctx_t *ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  const pcfg_gpu_omen_data_t *lin = ctx->linear_data;

  const u8 *struct_min_term_cost = lin->struct_min_term_cost;
  const u8 *struct_costs         = lin->struct_costs;
  const u32 struct_cnt           = lin->struct_cnt;

  u32 chunk_idx = gen->omen_linear_current_work_id % pcfg_ctx->omen_num_chunks;
  u32 cost_end = pcfg_ctx->omen_chunks[chunk_idx].cost_end;

  while (true)
  {
    while (gen->omen_target_cost <= cost_end)
    {
      gen->omen_by_cost_current = gen->omen_target_cost;

      if (gen->omen_skip_cost)
      {
        gen->omen_skip_cost = false;
        if (pcfg_ctx->perf_threshold && pcfg_ctx->perf_threshold->monitoring_active && pcfg_ctx->perf_threshold->skip_cost_enabled)
          pcfg_gen_perf_reset_cost (pcfg_ctx->perf_threshold, gen->dev_id, gen->omen_target_cost + 1);

        if (gen->omen_stats)
        {
          pcfg_omen_stats_cost_end (gen->omen_stats, gen->omen_target_cost);
          pcfg_omen_stats_print_cost (hashcat_ctx, gen->omen_stats, gen->omen_target_cost, gen->id);
        }

        gen->omen_target_cost++;
        gen->curr_struct_idx = UINT32_MAX;

        if (gen->omen_target_cost <= cost_end && gen->omen_stats)
          pcfg_omen_stats_cost_start (gen->omen_stats, gen->omen_target_cost);

        continue;
      }

      if (gen->omen_skip_loop)
      {
        return false;  // don't consume flag — let claiming-section handler advance the pool
      }

      if (gen->curr_struct_idx == UINT32_MAX)
      {
        gen->omen_by_cost_struct_cnt = 0;
        gen->omen_by_cost_struct_idx = 0;

        u32 count = 0;
        const u32 target_cost = gen->omen_target_cost;
        for (u32 i = 0; i < struct_cnt; i++)
        {
          const int rem = (int) target_cost - struct_costs[i];
          count += (rem >= 0) & (rem >= struct_min_term_cost[i]);
        }
        gen->omen_by_cost_struct_cnt = count;
      }

      while (++gen->curr_struct_idx < struct_cnt)
      {
        if (gen->omen_skip_cost || gen->omen_skip_loop)
        {
          gen->curr_struct_idx--;
          break;
        }

        if (gen->omen_target_cost >= struct_costs[gen->curr_struct_idx])
          gen->omen_by_cost_struct_idx++;

        gen->omen_partition_cnt   = 0;
        gen->omen_struct_keyspace = 0;

        int rem = (int) gen->omen_target_cost - struct_costs[gen->curr_struct_idx];
        if (rem < 0 || rem < struct_min_term_cost[gen->curr_struct_idx]) continue;

        pcfg_cpu_omen_generate_partitions (gen, &lin->structures[gen->curr_struct_idx], ctx->model->omen_data, rem);

        if (gen->omen_partition_cnt > 0)
        {
          if (gen->omen_struct_keyspace > user_options->pcfg_omen_keyspace_max)
            gen->omen_struct_keyspace = user_options->pcfg_omen_keyspace_max;

          // Store the INITIAL base offset of the loop
          u64 base_offset = (gen->omen_type == PCFG_OMEN_TYPE_INTERLEAVED) ? (gen->omen_global_loop_idx * gen->burst_size) : 0;

          if (gen->omen_struct_keyspace > base_offset)
          {
            // max_len is calculated from the base offset!
            u64 max_len = gen->omen_struct_keyspace - base_offset;
            if (gen->omen_type == PCFG_OMEN_TYPE_INTERLEAVED && max_len > gen->burst_size)
            {
              max_len = gen->burst_size;
            }

            // Dynamic offset for the cursor
            u64 current_offset = base_offset;

            // mathematical fast-forward of skip (without locks)
            if (gen->omen_skip_remainder > 0)
            {
              if (gen->omen_skip_remainder >= max_len)
              {
                gen->omen_skip_remainder -= max_len;

                if (gen->omen_skip_remainder == 0)
                {
                  pcfg_ctx->omen_skip_in_progress = false; // Safe: we are under the caller's mutex!
                }
                continue;
              }
              else
              {
                current_offset += gen->omen_skip_remainder;
                gen->omen_skip_remainder = 0;

                pcfg_ctx->omen_skip_in_progress = false; // Safe: we are under the caller's mutex!
              }
            }

            gen->curr_comb_idx = current_offset;

            if (gen->omen_type == PCFG_OMEN_TYPE_INTERLEAVED)
            {
              // chunk_max must be calculated from the original base_offset
              gen->omen_current_chunk_max = base_offset + gen->burst_size;
              gen->omen_lap_found_work = true;
              gen->omen_display_keyspace = gen->omen_struct_keyspace;
              gen->omen_by_cost_display_chunk_max = gen->omen_current_chunk_max;
            }
            else
            {
              gen->omen_display_keyspace = gen->omen_struct_keyspace;
            }

            gen->skip_structure = false;
            gen->burst_cand.struct_idx = gen->curr_struct_idx;

            if (gen->omen_stats)
            {
              pcfg_omen_stats_update (gen->omen_stats, gen->omen_target_cost, 0, 1);
              pcfg_omen_stats_loop_update (gen->omen_stats, gen->omen_global_loop_idx, 0, 1);
            }

            return true;
          }
        }
      }

      if (gen->omen_skip_cost || gen->omen_skip_loop) continue;

      if (gen->omen_stats)
      {
        pcfg_omen_stats_cost_end (gen->omen_stats, gen->omen_target_cost);
        pcfg_omen_stats_print_cost (hashcat_ctx, gen->omen_stats, gen->omen_target_cost, gen->id);
      }

      gen->omen_target_cost++;
      gen->curr_struct_idx = UINT32_MAX;

      if (gen->omen_target_cost <= cost_end && gen->omen_stats)
        pcfg_omen_stats_cost_start (gen->omen_stats, gen->omen_target_cost);
    }
    return false;
  }
}

// MODE 4: CPU OMEN BY_COST gen_next handler (returns 0=ok, -1=done)

int pcfg_cpu_omen_by_cost_gen_next (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t     *pcfg_ctx     = hashcat_ctx->pcfg_ctx;
  pcfg_gpu_omen_ctx_t *ctx     = pcfg_ctx->omen_gpu_ctx;
  status_ctx_t *status_ctx     = hashcat_ctx->status_ctx;

restart_cpu_omen_by_cost:

  if (!gen->omen_linear_has_work_unit || gen->omen_linear_work_unit_consumed >= gen->omen_reserved_budget)
  {
    hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

    u64 effective_limit = (pcfg_ctx->pcfg_limit > 0) ? pcfg_ctx->pcfg_limit - pcfg_ctx->pcfg_skip : 0;
    u64 total_work_units = (u64) pcfg_ctx->omen_num_chunks * pcfg_ctx->omen_max_loops;

    if (effective_limit > 0 && pcfg_ctx->words_generated >= effective_limit)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      return -1;
    }

    while (pcfg_ctx->omen_skip_in_progress && pcfg_ctx->omen_skip_remainder == 0)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      if (!status_ctx->run_thread_level1) return -1;
      usleep (100);
      hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

      if (pcfg_ctx->omen_next_work_unit_idx >= total_work_units)
      {
        hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
        return -1;
      }
    }

    u64 skip_offset = pcfg_ctx->omen_skip_remainder;
    u32 skip_start_cost = pcfg_ctx->omen_skip_start_cost;
    pcfg_ctx->omen_skip_remainder = 0;
    pcfg_ctx->omen_skip_start_cost = 0;

    if (gen->omen_skip_loop && user_options->pcfg_omen_type == PCFG_OMEN_TYPE_INTERLEAVED)
    {
      gen->omen_skip_loop = false;
      u64 target_loop = gen->omen_global_loop_idx + 1;
      u64 target_wu = target_loop * pcfg_ctx->omen_num_chunks;
      if (target_wu > total_work_units) target_wu = total_work_units;

      if (target_wu > pcfg_ctx->omen_next_work_unit_idx)
        pcfg_ctx->omen_next_work_unit_idx = target_wu;

      if (pcfg_ctx->perf_threshold && pcfg_ctx->perf_threshold->monitoring_active && pcfg_ctx->perf_threshold->skip_loop_enabled)
        pcfg_gen_perf_reset_loop (pcfg_ctx->perf_threshold, gen->dev_id, target_loop);

      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      goto restart_cpu_omen_by_cost;
    }

    if (gen->omen_skip_cost)
    {
      gen->omen_skip_cost = false;

      if (!pcfg_ctx->omen_cost_skip_done)
      {
        pcfg_ctx->omen_cost_skip_done = true;

        u64 current_work_id = pcfg_ctx->omen_next_work_unit_idx;
        u64 current_loop = current_work_id / pcfg_ctx->omen_num_chunks;
        u32 current_chunk = current_work_id % pcfg_ctx->omen_num_chunks;
        u32 next_chunk = current_chunk + 1;

        u64 next_work_id = (next_chunk < pcfg_ctx->omen_num_chunks)
                           ? (current_loop * pcfg_ctx->omen_num_chunks + next_chunk)
                           : ((current_loop + 1) * pcfg_ctx->omen_num_chunks);

        pcfg_ctx->omen_next_work_unit_idx = (next_work_id < total_work_units) ? next_work_id : total_work_units;
      }

      if (pcfg_ctx->perf_threshold && pcfg_ctx->perf_threshold->monitoring_active && pcfg_ctx->perf_threshold->skip_cost_enabled)
        pcfg_gen_perf_reset_cost (pcfg_ctx->perf_threshold, gen->dev_id, pcfg_ctx->omen_next_work_unit_idx % pcfg_ctx->omen_num_chunks);

      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      goto restart_cpu_omen_by_cost;
    }

    if (pcfg_ctx->omen_next_work_unit_idx >= total_work_units)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      return -1;
    }

    u64 work_id = pcfg_ctx->omen_next_work_unit_idx++;
    gen->omen_linear_current_work_id = work_id;
    gen->omen_linear_has_work_unit = true;
    gen->omen_linear_work_unit_consumed = 0;
    gen->omen_skip_remainder = skip_offset;

    // Exact Budget Calculation
    // Do not limit by burst_size: a work unit covers ALL structs/costs in the chunk,
    // whose total output can exceed burst_size. Only the global limit truncates the budget.
    gen->omen_reserved_budget = UINT64_MAX;

    if (effective_limit > 0)
    {
      u64 remaining_to_limit = effective_limit - pcfg_ctx->words_generated;
      if (remaining_to_limit < gen->omen_reserved_budget) gen->omen_reserved_budget = remaining_to_limit;
    }

    pcfg_ctx->words_generated += gen->omen_reserved_budget;

    u32 chunk_idx = work_id % pcfg_ctx->omen_num_chunks;
    gen->omen_global_loop_idx = work_id / pcfg_ctx->omen_num_chunks;

    u32 cost_start = pcfg_ctx->omen_chunks[chunk_idx].cost_start;
    u32 cost_end = pcfg_ctx->omen_chunks[chunk_idx].cost_end;

    if (skip_start_cost > 0 && skip_start_cost >= cost_start && skip_start_cost <= cost_end)
      gen->omen_target_cost = skip_start_cost;
    else
      gen->omen_target_cost = cost_start;

    gen->curr_struct_idx = UINT32_MAX;

    hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
  }

  bool need_advance = (gen->curr_struct_idx == UINT32_MAX) ||
                      (gen->curr_comb_idx >= gen->omen_struct_keyspace);

  if (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_INTERLEAVED && !need_advance)
  {
    need_advance = (gen->curr_comb_idx >= gen->omen_current_chunk_max);
  }

  if (need_advance)
  {
    if (!pcfg_cpu_omen_advance_by_cost (hashcat_ctx, gen, ctx))
    {
      // Refund the unused budget
      u64 unused = gen->omen_reserved_budget - gen->omen_linear_work_unit_consumed;
      if (unused > 0)
      {
        hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
        pcfg_ctx->words_generated -= unused;
        hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      }

      gen->omen_linear_has_work_unit = false;
      goto restart_cpu_omen_by_cost;
    }
  }

  gen->burst_cand.struct_idx = gen->curr_struct_idx;

  pcfg_omen_partition_t *part = NULL;
  u64 target = gen->curr_comb_idx;
  u32 lo = 0, hi = gen->omen_partition_cnt;

  while (lo < hi)
  {
    const u32 mid = lo + ((hi - lo) >> 1);
    pcfg_omen_partition_t *p = &gen->omen_partitions[mid];

    if (target < p->cumulative_offset) hi = mid;
    else if (target >= p->cumulative_end) lo = mid + 1;
    else
    {
      part = p;
      break;
    }
  }

  if (part == NULL) return -1;
  u64 partition_local_idx = target - part->cumulative_offset;
  const pcfg_gpu_omen_structure_t *s = &ctx->linear_data->structures[gen->curr_struct_idx];

  // Actual generation
  if (pcfg_cpu_omen_generate_direct (ctx->linear_data->data_buffer, ctx->linear_data->term_blocks, s, gen->model->omen_data, part, partition_local_idx, out, len) == 0)
  {
    gen->curr_comb_idx++;
    gen->omen_linear_work_unit_consumed++;
    gen->generated++;

    return 0;
  }

  return -1;
}

// MODE 6: CPU OMEN BY_STRUCT gen_next handler (returns 0=ok, -1=done)

int pcfg_cpu_omen_by_struct_gen_next (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t     *pcfg_ctx    = hashcat_ctx->pcfg_ctx;
  pcfg_gpu_omen_ctx_t *ctx    = pcfg_ctx->omen_gpu_ctx;
  status_ctx_t *status_ctx    = hashcat_ctx->status_ctx;

  bool is_interleaved = (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_INTERLEAVED);

restart_cpu_omen_by_struct:

  if (!gen->omen_linear_has_work_unit || gen->omen_linear_work_unit_consumed >= gen->omen_reserved_budget)
  {
    hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

    u64 effective_limit = (pcfg_ctx->pcfg_limit > 0) ? pcfg_ctx->pcfg_limit - pcfg_ctx->pcfg_skip : 0;
    u64 total_work_units = (u64) pcfg_ctx->omen_num_chunks * pcfg_ctx->omen_max_loops;

    if (effective_limit > 0 && pcfg_ctx->words_generated >= effective_limit)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      return -1;
    }

    while (pcfg_ctx->omen_skip_in_progress && pcfg_ctx->omen_skip_remainder == 0)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      if (!status_ctx->run_thread_level1) return -1;
      usleep (100);
      hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

      if (pcfg_ctx->omen_next_work_unit_idx >= total_work_units)
      {
        hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
        return -1;
      }
    }

    u64 skip_offset = pcfg_ctx->omen_skip_remainder;
    pcfg_ctx->omen_skip_remainder = 0;

    if (gen->omen_skip_loop && is_interleaved)
    {
      gen->omen_skip_loop = false;
      u64 target_loop = gen->omen_global_loop_idx + 1;
      u64 target_wu = target_loop * pcfg_ctx->omen_num_chunks;
      if (target_wu > total_work_units) target_wu = total_work_units;

      if (target_wu > pcfg_ctx->omen_next_work_unit_idx)
        pcfg_ctx->omen_next_work_unit_idx = target_wu;

      if (pcfg_ctx->perf_threshold && pcfg_ctx->perf_threshold->monitoring_active && pcfg_ctx->perf_threshold->skip_loop_enabled)
        pcfg_gen_perf_reset_loop (pcfg_ctx->perf_threshold, gen->dev_id, target_loop);

      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      goto restart_cpu_omen_by_struct;
    }

    if (pcfg_ctx->omen_next_work_unit_idx >= total_work_units)
    {
      hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      return -1;
    }

    u64 work_id = pcfg_ctx->omen_next_work_unit_idx++;
    gen->omen_linear_current_work_id = work_id;
    gen->omen_linear_has_work_unit = true;
    gen->omen_linear_work_unit_consumed = 0;
    gen->omen_skip_remainder = skip_offset;

    gen->omen_reserved_budget = UINT64_MAX;

    if (effective_limit > 0)
    {
      u64 remaining_to_limit = effective_limit - pcfg_ctx->words_generated;
      if (remaining_to_limit < gen->omen_reserved_budget) gen->omen_reserved_budget = remaining_to_limit;
    }

    pcfg_ctx->words_generated += gen->omen_reserved_budget;

    gen->omen_global_loop_idx = work_id / pcfg_ctx->omen_num_chunks;
    gen->curr_struct_idx = UINT32_MAX;

    hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
  }

  // handle skip_cost / skip_structure (struct-first: advance past current struct)
  if (gen->omen_skip_cost || gen->skip_structure)
  {
    gen->omen_skip_cost = false;
    gen->skip_structure = false;
    gen->curr_comb_idx = gen->omen_struct_keyspace;
    gen->omen_by_struct_multicost_offset = gen->omen_by_struct_total_ks;
  }

  bool need_advance = (gen->curr_struct_idx == UINT32_MAX) ||
                      (gen->curr_comb_idx >= gen->omen_struct_keyspace);

  if (is_interleaved && !need_advance)
  {
    need_advance = (gen->omen_by_struct_multicost_offset + gen->curr_comb_idx >= gen->omen_current_chunk_max);
  }

  if (need_advance)
  {
    if (!pcfg_cpu_omen_advance_by_struct (hashcat_ctx, gen, ctx))
    {
      // refund unused budget
      u64 unused = gen->omen_reserved_budget - gen->omen_linear_work_unit_consumed;
      if (unused > 0)
      {
        hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
        pcfg_ctx->words_generated -= unused;
        hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
      }

      gen->omen_linear_has_work_unit = false;
      goto restart_cpu_omen_by_struct;
    }
  }

  // handle skip remainder
  if (gen->omen_skip_remainder > 0)
  {
    u64 avail = gen->omen_struct_keyspace - gen->curr_comb_idx;

    if (is_interleaved)
    {
      u64 burst_avail = gen->omen_current_chunk_max - (gen->omen_by_struct_multicost_offset + gen->curr_comb_idx);

      if (burst_avail < avail) avail = burst_avail;
    }

    if (gen->omen_skip_remainder >= avail)
    {
      gen->omen_skip_remainder -= avail;
      gen->curr_comb_idx += avail;

      need_advance = true;

      if (need_advance)
      {
        if (!pcfg_cpu_omen_advance_by_struct (hashcat_ctx, gen, ctx))
        {
          u64 unused = gen->omen_reserved_budget - gen->omen_linear_work_unit_consumed;
          if (unused > 0)
          {
            hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);
            pcfg_ctx->words_generated -= unused;
            hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
          }

          gen->omen_linear_has_work_unit = false;
          goto restart_cpu_omen_by_struct;
        }
      }

      // recurse to handle remaining skip
      if (gen->omen_skip_remainder > 0)
      {
        goto restart_cpu_omen_by_struct;
      }
    }
    else
    {
      gen->curr_comb_idx += gen->omen_skip_remainder;
      gen->omen_skip_remainder = 0;

      pcfg_ctx->omen_skip_in_progress = false;
    }
  }

  gen->burst_cand.struct_idx = gen->curr_struct_idx;

  pcfg_omen_partition_t *part = NULL;
  u64 target = gen->curr_comb_idx;
  u32 lo = 0, hi = gen->omen_partition_cnt;

  while (lo < hi)
  {
    const u32 mid = lo + ((hi - lo) >> 1);
    pcfg_omen_partition_t *p = &gen->omen_partitions[mid];

    if (target < p->cumulative_offset) hi = mid;
    else if (target >= p->cumulative_end) lo = mid + 1;
    else
    {
      part = p;
      break;
    }
  }

  if (part == NULL) return -1;
  u64 partition_local_idx = target - part->cumulative_offset;
  const pcfg_gpu_omen_structure_t *s = &ctx->linear_data->structures[gen->curr_struct_idx];

  // Actual generation
  if (pcfg_cpu_omen_generate_direct (ctx->linear_data->data_buffer, ctx->linear_data->term_blocks, s, gen->model->omen_data, part, partition_local_idx, out, len) == 0)
  {
    gen->curr_comb_idx++;
    gen->omen_linear_work_unit_consumed++;
    gen->generated++;

    return 0;
  }

  return -1;
}
