/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "timer.h"
#include "filehandling.h"
#include "convert.h"
#include "thread.h"
#include "shared.h"
#include "bitops.h"
#include "status.h"
#include "backend.h"
#include "user_options.h"
#include "xxhash.h"
#include "pcfg_perf.h"
#include "pcfg_cpu_omen.h"
#include "pcfg_cpu_prob.h"
#include "pcfg_cpu_random.h"
#include "pcfg_trainer.h"
#include "pcfg.h"
#include "pcfg_loopback.h"

void pcfg_notify_cracked (hashcat_ctx_t *hashcat_ctx, int device_id, int count)
{
  if (count <= 0) return;

  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  if (!pcfg_ctx || !pcfg_ctx->generators) return;

  if (device_id < 0 || device_id >= pcfg_ctx->num_generators) return;

  pcfg_gen_t *gen = pcfg_ctx->generators[device_id];

  if (gen == NULL) return;

  // update counters for performance monitor
  if (pcfg_ctx->perf_threshold != NULL && pcfg_ctx->perf_threshold->monitoring_active)
  {
    pcfg_gen_perf_add_recovered (pcfg_ctx->perf_threshold, device_id, (u64) count);
  }

  if (gen->omen_stats)
  {
    // assign to the current layer
    u32 current_cost = gen->omen_target_cost;

    if (current_cost <= PCFG_OMEN_COST_PRACTICAL_MAX)
    {
      gen->omen_stats->costs[current_cost].passwords_cracked += count;
    }

    // if Interleaved, also assign to the current loop
    if (gen->omen_type == PCFG_OMEN_TYPE_INTERLEAVED)
    {
      u64 current_loop = gen->omen_global_loop_idx;

      if (current_loop < gen->omen_stats->loops_cap)
      {
        gen->omen_stats->loops[current_loop].passwords_cracked += count;
      }
    }
  }
}

static inline u32 fast_rand_local (u64 *state)
{
  u64 x = *state;

  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;

  *state = x;

  return (u32) x;
}


static int pcfg_gen_init_keyspace (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m)
{
  pcfg_ctx_t   *pcfg_ctx       = hashcat_ctx->pcfg_ctx;
  status_ctx_t *status_ctx     = hashcat_ctx->status_ctx;

  m->total_keyspace = 0;

  // Mutex (if not already created for Mode 9)
  hc_thread_mutex_init (pcfg_ctx->chunk_mutex);

  {
    for (u32 si = 0; si < m->struct_cnt; si++)
    {
      pcfg_structure_t *s = &m->structures[si];

      // check all terminals exist
      bool valid = true;

      unsigned __int128 struct_keyspace = 1;

      for (u32 i = 0; i < s->token_cnt && valid; i++)
      {
        u32 term_cnt = m->terminals[s->types[i]][s->lengths[i]].cnt;

        if (term_cnt == 0)
        {
          valid = false;
        }
        else
        {
          struct_keyspace *= term_cnt;
        }
      }
      if (!valid) continue;

      if (m->total_keyspace + struct_keyspace < m->total_keyspace)
      {
        m->total_keyspace = UINT64_MAX;

        break;
      }
      else
      {
        m->total_keyspace += (u64)struct_keyspace;
      }
    }
  }

  // calculate effective keyspace (take care of skip/limit)
  u64 effective_keyspace = m->total_keyspace;
  u64 skip = pcfg_ctx->pcfg_skip;
  u64 limit = pcfg_ctx->pcfg_limit;

  bool valid_skip = true;
  if (skip >= effective_keyspace)
  {
    effective_keyspace = 0;
    valid_skip = false;
  }
  else if (limit > 0)
  {
    // limit is an absolute position (skip + orig limit)
    u64 end_pos = (limit < effective_keyspace) ? limit : effective_keyspace;
    effective_keyspace = (end_pos > skip) ? (end_pos - skip) : 0;
  }
  else
  {
    effective_keyspace -= skip;
  }
  // update words_cnt/words_base to show Time.Estimated

  const u64 amplifier_cnt = user_options_extra_amplifier (hashcat_ctx);

  if (amplifier_cnt > 1 && effective_keyspace > UINT64_MAX / amplifier_cnt)
  {
    status_ctx->words_cnt = UINT64_MAX;
  }
  else if (amplifier_cnt > 0)
  {
    status_ctx->words_cnt = effective_keyspace * amplifier_cnt;
  }
  else
  {
    status_ctx->words_cnt = effective_keyspace;
  }

  status_ctx->words_base = effective_keyspace;
  // check restore point
  if (status_ctx->words_off > status_ctx->words_base)
  {
    event_log_error (hashcat_ctx, "Restore value is greater than keyspace.");
    return -1;
  }

  if (valid_skip == false)
  {
    event_log_error (hashcat_ctx, "Skip value is greater than keyspace.");
    return -1;
  }

  return 0;
}

int pcfg_gen_init (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  int total = 0;
  int active = 0;

  // For --keyspace, ensure num_active_generators >= 1 (no backend devices available)
  if (user_options->keyspace == true && pcfg_ctx->num_active_generators == 0)
  {
    pcfg_ctx->num_active_generators = 1;
  }

  if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    // Ensure OMEN metadata is built
    if (pcfg_ctx->model->omen_data == NULL)
    {
      pcfg_model_build_omen_metadata (hashcat_ctx, pcfg_ctx->model);
    }

    if (user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_COST && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT && user_options->keyspace == false)
    {
      // Analyze model with real GPU memory (post backend_session_begin)
      if (pcfg_omen_analyze_model (hashcat_ctx, pcfg_ctx->model) != 0)
      {
        event_log_error (hashcat_ctx, "PCFG OMEN: architecture analysis failed (not enough GPU memory?)");
        return -1;
      }
    }

    // Init linear OMEN data
    int rc = pcfg_gpu_omen_data_init (hashcat_ctx, pcfg_ctx->model, &pcfg_ctx->omen_gpu_data);

    if (rc != 0)
    {
      event_log_error (hashcat_ctx, "PCFG OMEN: failed to initialize linear data");
      return -1;
    }

    // Init linear OMEN ctx
    rc = pcfg_gpu_omen_ctx_init (hashcat_ctx, pcfg_ctx->omen_gpu_data, pcfg_ctx->model, pcfg_ctx->num_active_generators, pcfg_ctx->pcfg_skip, pcfg_ctx->pcfg_limit, &pcfg_ctx->omen_gpu_ctx);

    if (rc != 0)
    {
      event_log_error (hashcat_ctx, "PCFG OMEN: failed to initialize context");
      pcfg_gpu_omen_data_destroy (pcfg_ctx->omen_gpu_data);
      pcfg_ctx->omen_gpu_data = NULL;
      return -1;
    }
    if (user_options->keyspace == true) return 0;

    // Free terminal data from model - no longer needed after linearization
    pcfg_model_free_terminal_data (hashcat_ctx, pcfg_ctx->model);

    if (user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_COST && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT)
    {
      if (backend_session_pcfg_gpu_omen_init (hashcat_ctx) != 0)
      {
        event_log_error (hashcat_ctx, "PCFG: backend_session_pcfg_gpu_omen_init failed");
        pcfg_gpu_omen_ctx_destroy (pcfg_ctx->omen_gpu_ctx);
        pcfg_gpu_omen_data_destroy (pcfg_ctx->omen_gpu_data);
        pcfg_ctx->omen_gpu_ctx = NULL;
        pcfg_ctx->omen_gpu_data = NULL;
        return -1;
      }
    }

    // For CPU BY_STRUCT (mode 6): set global_max_structs to struct_cnt
    // so all structures fit in one chunk (no cost-based splitting needed)
    if (user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
    {
      pcfg_ctx->global_max_structs = pcfg_ctx->omen_gpu_data->struct_cnt;
    }

    if (backend_session_pcfg_gpu_omen_runtime_init (hashcat_ctx) != 0)
    {
      event_log_error (hashcat_ctx, "PCFG: backend_session_pcfg_gpu_omen_runtime_init failed");
      pcfg_gpu_omen_ctx_destroy (pcfg_ctx->omen_gpu_ctx);
      pcfg_gpu_omen_data_destroy (pcfg_ctx->omen_gpu_data);
      pcfg_ctx->omen_gpu_ctx = NULL;
      pcfg_ctx->omen_gpu_data = NULL;
      return -1;
    }
  }
  else if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB || user_options->pcfg_mode == PCFG_MODE_CPU_PROB)
  {
    // init linear data
    int rc = pcfg_gpu_prob_data_init (hashcat_ctx, pcfg_ctx->model, &pcfg_ctx->gpu_prob_data);

    if (rc != 0)
    {
      event_log_error (hashcat_ctx, "PCFG PROB: failed to initialize linear data");
      return -1;
    }

    // init linear ctx
    rc = pcfg_gpu_prob_ctx_init (hashcat_ctx, pcfg_ctx->gpu_prob_data, pcfg_ctx->num_active_generators, pcfg_ctx->pcfg_skip, pcfg_ctx->pcfg_limit, &pcfg_ctx->gpu_prob_ctx);

    if (rc != 0)
    {
      event_log_error (hashcat_ctx, "PCFG PROB: failed to initialize context");
      pcfg_gpu_prob_data_destroy (pcfg_ctx->gpu_prob_data);
      pcfg_ctx->gpu_prob_data = NULL;
      return -1;
    }

    if (user_options->keyspace == true) return 0;

    // Free terminal data from model - no longer needed after linearization
    pcfg_model_free_terminal_data (hashcat_ctx, pcfg_ctx->model);

    if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB)
    {
      if (backend_session_pcfg_gpu_prob_init (hashcat_ctx) != 0)
      {
        event_log_error (hashcat_ctx, "PCFG: failed to initialize GPU buffers for Prob (GPU)");
        pcfg_gpu_prob_ctx_destroy (pcfg_ctx->gpu_prob_ctx);
        pcfg_gpu_prob_data_destroy (pcfg_ctx->gpu_prob_data);
        pcfg_ctx->gpu_prob_ctx = NULL;
        pcfg_ctx->gpu_prob_data = NULL;
        return -1;
      }
    }
  }
  else if (user_options->pcfg_mode != PCFG_MODE_CPU_RANDOM_AHF)
  {
    // init keyspace for all other oder_mode
    if (pcfg_gen_init_keyspace (hashcat_ctx, pcfg_ctx->model) != 0)
    {
      event_log_error (hashcat_ctx, "PCFG: Generator keyspace initialization failed");
      return -1;
    }

    if (user_options->keyspace == true) return 0;
  }

  if (user_options->keyspace == true) return 0; // AHF mode: keyspace unknown, return 0

  #if defined (_OPENMP)
  #pragma omp parallel for
  #endif
  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    int dev_idx = backend_devices_idx;

    int shard_id = pcfg_ctx->active_map[dev_idx];

    if (shard_id != -1)
    {
      total++;

      pcfg_ctx->generators[dev_idx] = pcfg_gen_create (hashcat_ctx, dev_idx, shard_id);

      if (pcfg_ctx->generators[dev_idx] != NULL) active++;

      if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST)
      {
        pcfg_gpu_omen_gen_init (pcfg_ctx->generators[dev_idx], shard_id);
      }
      else if (user_options->pcfg_mode == PCFG_MODE_GPU_PROB)
      {
        pcfg_gpu_prob_gen_init (pcfg_ctx->generators[dev_idx], shard_id, pcfg_ctx->gpu_prob_ctx);
      }
    }
  }

  if (total == 0 || active == 0) return -1;

  if (pcfg_ctx->perf_threshold != NULL && pcfg_ctx->perf_threshold->enabled)
  {
    // initialize counter per-generator
    pcfg_perf_threshold_init_generators (hashcat_ctx);
  }

  if (user_options->pcfg_pf_threshold != NULL)
  {
    // start the PCFG performance thread monitor
    pcfg_perf_monitor_start (hashcat_ctx);
  }
  return 0;
}

// pcfg_cpu_random_ahf_refresh moved to pcfg_cpu_random.c

pcfg_gen_t *pcfg_gen_create (hashcat_ctx_t *hashcat_ctx, int dev_id, int thread_id)
{
  user_options_t *user_options = hashcat_ctx->user_options;
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  pcfg_ctx_t     *pcfg_ctx     = hashcat_ctx->pcfg_ctx;

  if (!pcfg_ctx) return NULL;

  pcfg_model_t *model = pcfg_ctx->model;

  if (!model) return NULL;

  int thread_count = backend_ctx->backend_devices_active;

  u64 restore_skip = pcfg_ctx->pcfg_skip;

  pcfg_gen_t *gen = (pcfg_gen_t *) hccalloc (1, sizeof (pcfg_gen_t));

  if (!gen) return NULL;

  gen->id = thread_id;
  gen->dev_id = dev_id;
  gen->model = model;
  gen->ahf_burst_left = 0;
  gen->generated = 0;
  gen->ahf_burst_first = user_options->pcfg_burst_first;
  gen->burst_size = user_options->pcfg_burst_size;
  gen->ahf_terminals_min = user_options->pcfg_ahf_terminals_min;
  gen->limit = 0;
  gen->ahf_struct_cnt = model->struct_cnt;
  gen->ahf_structures = NULL;
  gen->skip_structure = false;
  gen->omen_skip_cost = false;

  // alloc bloom, 16 MB
  gen->ahf_bloom_size = 16 * 1024 * 1024;
  gen->ahf_bloom = (u8 *) hccalloc (gen->ahf_bloom_size, 1);

  // init rng_state
  u64 seed = (u64) time (NULL);

  seed ^= ((u64) thread_id << 32);
  seed ^= (uintptr_t) gen;

  if (seed == 0) seed = 1;

  gen->ahf_rng_state = seed;

  for (int i = 0; i < 10; i++) fast_rand_local (&gen->ahf_rng_state);

  // ahf
  gen->ahf_type = user_options->pcfg_ahf_type;

  // omen
  gen->omen_type = user_options->pcfg_omen_type; // 0 o 1

  gen->omen_partitions = (pcfg_omen_partition_t *) hccalloc (PCFG_OMEN_PARTITIONS_MAX, sizeof (pcfg_omen_partition_t));
  gen->omen_target_cost = user_options->pcfg_omen_cost_min;
  gen->omen_max_target_cost = gen->model->omen_max_cost;

  if (user_options->pcfg_omen_cost_max != PCFG_OMEN_COST_MAX)
  {
    gen->omen_max_target_cost = (user_options->pcfg_omen_cost_max < gen->model->omen_max_cost) ? user_options->pcfg_omen_cost_max : gen->model->omen_max_cost;
  }

  if (gen->omen_target_cost > gen->omen_max_target_cost)
  {
    event_log_error (hashcat_ctx, "Invalid OMEN cost range: min (%u) must be <= max (%u).", gen->omen_target_cost, gen->omen_max_target_cost);
    hcfree (gen->omen_partitions);
    hcfree (gen->ahf_bloom);
    hcfree (gen);
    return NULL;
  }

  gen->omen_global_loop_idx = 0;
  gen->omen_current_chunk_max = 0;
  gen->curr_struct_idx = UINT32_MAX;

  gen->curr_comb_idx = gen->id;

  if ((user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_STRUCT || user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT) && user_options->pcfg_omen_stats == true)
  {
    gen->omen_stats = pcfg_omen_stats_init (gen->omen_target_cost, gen->omen_max_target_cost);
  }
  else
  {
    gen->omen_stats = NULL;
  }

  // end of omen

  // if limit > 0, split by threads
  if (pcfg_ctx->pcfg_limit > 0
      && user_options->pcfg_mode != PCFG_MODE_GPU_PROB
      && user_options->pcfg_mode != PCFG_MODE_CPU_PROB
      && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_COST
      && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    u64 global_target = pcfg_ctx->pcfg_limit;

    u64 local_target = global_target / thread_count;

    if ((u64) thread_id < (global_target % thread_count)) local_target++;

    // if this thread has no work, force immediate stop
    if (local_target == 0)
    {
      gen->limit = 1;
      gen->generated = 1;
    }
    else
    {
      gen->limit = local_target;
    }
  }


  if (user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM_AHF || user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM)
  {
    // estimate heap size
    u64 est_size = (model->struct_cnt / thread_count) + 1000;

    // set cap to 5 MB
    if (est_size > 5000000) est_size = 5000000;

    gen->ahf_heap = pcfg_cpu_random_heap_alloc (est_size);

    if (!gen->ahf_heap)
    {
      hcfree (gen->omen_partitions);
      hcfree (gen->ahf_bloom);
      hcfree (gen);

      return NULL;
    }
  }

  if (user_options->pcfg_mode == PCFG_MODE_CPU_RANDOM)
  {
    u32 loaded = 0;

    // read all structs from model
    for (u32 si = 0; si < model->struct_cnt; si++)
    {
      // check if the struct is for the current generator thread
      if (thread_count > 1 && (si % (u32) thread_count != (u32) thread_id)) continue;

      pcfg_structure_t *s = &model->structures[si];

      // validation

      //if (s->keyspace == 0) continue;

      bool keep = true;

      for (u32 i = 0; i < s->token_cnt && keep; i++)
      {
        u32 term_cnt = model->terminals[s->types[i]][s->lengths[i]].cnt;

        if (term_cnt == 0) keep = false;
      }

      if (!keep) continue;

      if (pcfg_ctx->struct_shuffle) pcfg_cpu_random_structure_shuffle (gen, s);

      // build candidate
      pcfg_candidate_t cand;

      memset (&cand, 0, sizeof (cand));

      cand.struct_idx = si;
      cand.prob = s->prob;

      if (pcfg_cpu_random_build_candidate (model, s, si, &cand, NULL, &gen->ahf_rng_state, gen->ahf_type) == 0)
      {
        pcfg_cpu_random_heap_push (gen->ahf_heap, &cand);

        loaded++;
      }

      if (((si & 0x3FFFF) == (u32) thread_id) && user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Initializing generator %u: %u/%u", (u32) thread_id, loaded, model->struct_cnt);
    }

    if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Generator #%u initialized with %u structure(s)", thread_id, loaded);
  }

  // handle skip (fast-forward)
  if (restore_skip > 0 && user_options->pcfg_mode != PCFG_MODE_GPU_PROB && user_options->pcfg_mode != PCFG_MODE_CPU_PROB && user_options->pcfg_mode != PCFG_MODE_GPU_OMEN_BY_STRUCT && user_options->pcfg_mode != PCFG_MODE_GPU_OMEN_BY_COST && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_COST && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    u64 local_skip = restore_skip / thread_count;

    if ((u64) thread_id < (restore_skip % thread_count)) local_skip++;

    if (local_skip > 0)
    {
      if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Generator #%u - Fast-Skipping %" PRIu64 " candidates...", thread_id, local_skip);

      if (gen->ahf_heap != NULL && gen->ahf_heap->size > 0)
      {
        pcfg_cpu_random_gen_skip (hashcat_ctx, gen, local_skip, restore_skip, thread_count, thread_id);
      }
      else
      {
        // generic fallback
        char dummy[256];
        u32 dummy_len;

        for (u64 i = 0; i < local_skip; i++)
        {
          if (pcfg_gen_next (hashcat_ctx, gen, dummy, &dummy_len) != 0) break;
        }

        gen->generated = 0;
      }

      if (user_options->quiet == false) event_log_info_nn (hashcat_ctx, "PCFG: Generator #%u - Fast-Skipping completed.", thread_id);
    }
  }

  if (pcfg_ctx->struct_shuffle == true)
  {
    // reset bloom filter
    memset (gen->ahf_bloom, 0, gen->ahf_bloom_size);
  }

  return gen;
}

void pcfg_gen_destroy (pcfg_gen_t *gen)
{
  if (gen)
  {
    if (gen->ahf_heap) pcfg_cpu_random_heap_free (gen->ahf_heap);
    if (gen->ahf_structures) hcfree (gen->ahf_structures);
    if (gen->ahf_bloom) hcfree (gen->ahf_bloom);

    if (gen->omen_stats)
    {
      pcfg_omen_stats_destroy (gen->omen_stats);
      gen->omen_stats = NULL;
    }

    if (gen->omen_gpu_batch_entries) hcfree (gen->omen_gpu_batch_entries);
    if (gen->omen_gpu_partitions) hcfree (gen->omen_gpu_partitions);

    hcfree (gen);
  }
}

int pcfg_gen_next(hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len)
{
  if (gen == NULL) return -2;

restart:

  ;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (gen->omen_skip_cost && gen->omen_type == PCFG_OMEN_TYPE_CLASSIC && gen->omen_target_cost >= gen->omen_max_target_cost
      && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    gen->omen_skip_cost = false;
    return -1;
  }

  if (user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_COST
      && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    if (gen->limit > 0 && gen->generated >= gen->limit) return -2;
  }

  // CPU_PROB (mode 2)
  if (user_options->pcfg_mode == PCFG_MODE_CPU_PROB)
  {
    return pcfg_cpu_prob_gen_next (hashcat_ctx, gen, out, len);
  }
  // CPU_OMEN_BY_COST (mode 4)
  else if (user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST)
  {
    return pcfg_cpu_omen_by_cost_gen_next (hashcat_ctx, gen, out, len);
  }
  // CPU_OMEN_BY_STRUCT (mode 6)
  else if (user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    return pcfg_cpu_omen_by_struct_gen_next (hashcat_ctx, gen, out, len);
  }

  // CPU_RANDOM (mode 0) + AHF (mode 1)
  else
  {
    int rc = pcfg_cpu_random_gen_next (hashcat_ctx, gen, out, len);
    if (rc == 2) goto restart;
    return rc;
  }

  return -2;
}

// ctx

int pcfg_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  pcfg_ctx_t     *pcfg_ctx     = hashcat_ctx->pcfg_ctx;
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode != ATTACK_MODE_PCFG
   && user_options->pcfg_loopback == false) return 0;

  if (!pcfg_ctx) return -1;

  // pcfg loopback early init (during -a0 phase, before PCFG attack starts)
  if (user_options->pcfg_loopback == true)
  {
    int rc = pcfg_loopback_ctx_init (hashcat_ctx);

    if (rc == -1) return -1;
    if (rc ==  1) return 0;  // loopback only, not -a10 yet
  }

  hashcat_ctx->pcfg_ctx       = pcfg_ctx;

  pcfg_ctx->pcfg_model_file   = user_options->pcfg_model_file;
  pcfg_ctx->pcfg_train_file   = user_options->pcfg_train_file;
  pcfg_ctx->pcfg_model_save_file    = user_options->pcfg_model_save_file;
  pcfg_ctx->pcfg_limit        = user_options->limit;
  pcfg_ctx->pcfg_skip         = user_options->skip;
  pcfg_ctx->struct_shuffle    = user_options->pcfg_shuffle;
  pcfg_ctx->ahf_type          = user_options->pcfg_ahf_type;
  pcfg_ctx->num_generators    = backend_ctx->backend_devices_cnt;

  pcfg_ctx->generators = (pcfg_gen_t **) hccalloc (pcfg_ctx->num_generators, sizeof (pcfg_gen_t*));

  // create active devices map
  int active_idx = 0;

  pcfg_ctx->active_map = hccalloc (backend_ctx->backend_devices_cnt, sizeof (int));

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

  // performance monitor

  pcfg_ctx->perf_threshold = NULL;

  if (user_options->pcfg_pf_threshold != NULL)
  {
    pcfg_ctx->perf_threshold = (pcfg_perf_threshold_t *) hccalloc (1, sizeof (pcfg_perf_threshold_t));

    if (pcfg_ctx->perf_threshold == NULL) return -1;

    pcfg_ctx->perf_threshold->enabled                  = false;

    pcfg_ctx->perf_threshold->skip_struct_enabled      = false;
    pcfg_ctx->perf_threshold->struct_threshold_count   = 0;
    pcfg_ctx->perf_threshold->struct_threshold_seconds = 60;

    pcfg_ctx->perf_threshold->skip_cost_enabled        = false;
    pcfg_ctx->perf_threshold->cost_threshold_count     = 0;
    pcfg_ctx->perf_threshold->cost_threshold_seconds   = 60;

    pcfg_ctx->perf_threshold->skip_loop_enabled        = false;
    pcfg_ctx->perf_threshold->loop_threshold_count     = 0;
    pcfg_ctx->perf_threshold->loop_threshold_seconds   = 60;

    pcfg_ctx->perf_threshold->baseline_recovered       = 0;

    pcfg_ctx->perf_threshold->skips_struct_total       = 0;
    pcfg_ctx->perf_threshold->skips_cost_total         = 0;
    pcfg_ctx->perf_threshold->skips_loop_total         = 0;

    pcfg_ctx->perf_threshold->monitoring_active        = false;
    pcfg_ctx->perf_threshold->thread_running           = false;
    pcfg_ctx->perf_threshold->thread_shutdown          = false;

    memset (pcfg_ctx->perf_threshold->gen_perf, 0, sizeof (pcfg_ctx->perf_threshold->gen_perf));

    if (pcfg_perf_threshold_parse (hashcat_ctx, user_options->pcfg_pf_threshold) == -1)
    {
      return -1;
    }
  }

  init_char_types_lut();

  // model diff: load both models with load_filtered and exit
  if (user_options->pcfg_model_diff_file)
  {
    pcfg_model_t *model_a = pcfg_model_load_filtered (hashcat_ctx, user_options->pcfg_model_file);

    if (!model_a)
    {
      event_log_error (hashcat_ctx, "PCFG: Failed to load model A: %s", user_options->pcfg_model_file);
      hcfree (pcfg_ctx);
      return -1;
    }

    pcfg_model_t *model_b = pcfg_model_load_filtered (hashcat_ctx, user_options->pcfg_model_diff_file);

    if (!model_b)
    {
      event_log_error (hashcat_ctx, "PCFG: Failed to load model B: %s", user_options->pcfg_model_diff_file);
      pcfg_model_destroy (model_a);
      hcfree (pcfg_ctx);
      return -1;
    }

    pcfg_model_diff (hashcat_ctx, model_a, model_b);

    pcfg_model_destroy (model_b);
    pcfg_model_destroy (model_a);
    hcfree (pcfg_ctx);
    exit (0);
  }

  if (user_options->pcfg_models_cnt > 0 && pcfg_ctx->pcfg_model_save_file)
  {
    // merge models
    if (pcfg_model_merge (hashcat_ctx) != 0) return -1;

    // load and filter merged model
    pcfg_ctx->model = pcfg_model_load_filtered (hashcat_ctx, pcfg_ctx->pcfg_model_save_file);

    if (!pcfg_ctx->model)
    {
      event_log_error (hashcat_ctx, "PCFG: Loading merged model failed");
      return -1;
    }
  }
  // update model with new training
  else if (user_options->pcfg_model_update && pcfg_ctx->pcfg_model_file && pcfg_ctx->pcfg_train_file)
  {
    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Updating model %s with data from %s", pcfg_ctx->pcfg_model_file, pcfg_ctx->pcfg_train_file);
    }

    // load base model (unfiltered)
    pcfg_model_t *base_model = pcfg_model_load_fast (hashcat_ctx, pcfg_ctx->pcfg_model_file);

    if (!base_model) return -1;

    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Count model elements ...");
    }

    u64 base_elements = pcfg_model_count_elements (base_model);

    pcfg_model_destroy (base_model);

    // init trainer with new data
    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Init trainer with new data and %" PRIu64 " base elements", base_elements);
    }

    pcfg_trainer_t *trainer = pcfg_trainer_init (hashcat_ctx, pcfg_ctx->pcfg_train_file, (unsigned long) base_elements);
    if (!trainer) return -1;
    // import base model
    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Import base model ...");
    }

    pcfg_trainer_import_from_file (hashcat_ctx, trainer, pcfg_ctx->pcfg_model_file);

    // train
    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Training on new data %s...", pcfg_ctx->pcfg_train_file);
    }

    if (pcfg_trainer_from_file (hashcat_ctx, trainer, pcfg_ctx->pcfg_train_file) != 0)
    {
      event_log_error (hashcat_ctx, "PCFG: Training failed");
      pcfg_trainer_destroy (trainer);
      return -1;
    }

    // export the updated model to (same or new) file

    char *model_file = (pcfg_ctx->pcfg_model_save_file) ? pcfg_ctx->pcfg_model_save_file : pcfg_ctx->pcfg_model_file;

    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Export updated model to %s ...", model_file);
    }

    if (!pcfg_trainer_export_to_file (hashcat_ctx, trainer, model_file))
    {
      event_log_error (hashcat_ctx, "PCFG: Trainer export to file failed");
      pcfg_trainer_destroy (trainer);
      return -1;
    }

    // cleanup
    pcfg_trainer_destroy (trainer);

    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Loading model from %s", model_file);
    }

    // final load (filtered)
    pcfg_ctx->model = pcfg_model_load_filtered (hashcat_ctx, model_file);

    if (!pcfg_ctx->model)
    {
      event_log_error (hashcat_ctx, "PCFG: Model finalization failed");
      return -1;
    }
  }
  // load model
  else if (pcfg_ctx->pcfg_model_file)
  {
    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Loading model from %s", pcfg_ctx->pcfg_model_file);
    }

    hc_timer_t start;

    hc_timer_set (&start);

    // final load (filtered)
    pcfg_ctx->model = pcfg_model_load_filtered (hashcat_ctx, pcfg_ctx->pcfg_model_file);

    double end_time = hc_timer_get (start);
    double seconds  = end_time / 1000.0;

    if (!pcfg_ctx->model)
    {
      event_log_error (hashcat_ctx, "PCFG: Failed to load model");
      return -1;
    }

    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Model loaded in %.2f seconds", seconds);
    }
  }
  // train
  else if (pcfg_ctx->pcfg_train_file)
  {
    hc_timer_t start;

    hc_timer_set (&start);

    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Training from %s", pcfg_ctx->pcfg_train_file);
    }

    pcfg_trainer_t *trainer = pcfg_trainer_init (hashcat_ctx, pcfg_ctx->pcfg_train_file, 0);

    if (!trainer) return -1;

    if (pcfg_trainer_from_file (hashcat_ctx, trainer, pcfg_ctx->pcfg_train_file) != 0)
    {
      event_log_error (hashcat_ctx, "PCFG: Training failed");
      pcfg_trainer_destroy (trainer);
      return -1;
    }

    char *model_file = (pcfg_ctx->pcfg_model_save_file) ? pcfg_ctx->pcfg_model_save_file : "hashcat.model.pcfg";

    if (!pcfg_trainer_export_to_file (hashcat_ctx, trainer, model_file))
    {
      event_log_error (hashcat_ctx, "PCFG: Trainer export to file failed");
      pcfg_trainer_destroy (trainer);
      return -1;
    }

    // cleanup
    pcfg_trainer_destroy (trainer);

    // final load (filtered)
    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Loading model from %s", model_file);
    }

    pcfg_ctx->model = pcfg_model_load_filtered (hashcat_ctx, model_file);

    if (!pcfg_ctx->model)
    {
      event_log_error (hashcat_ctx, "PCFG: Model finalization failed");
      return -1;
    }

    double end_time = hc_timer_get (start);
    double seconds = end_time / 1000.0;

    if (user_options->quiet == false)
    {
      event_log_info_nn (hashcat_ctx, "PCFG: Training completed in %.2f seconds", seconds);
    }
  }
  else
  {
    event_log_error (hashcat_ctx, "PCFG: Specify --pcfg-model or --pcfg-train");
    return -1;
  }

  // show model info and exit
  if (user_options->pcfg_model_info)
  {
    pcfg_model_info (hashcat_ctx, pcfg_ctx->model);
    pcfg_model_destroy (pcfg_ctx->model);
    hcfree (pcfg_ctx);
    exit (0);
  }



  pcfg_ctx->enabled  = true;

  if (user_options->quiet == false)
  {
    event_log_info_nn (hashcat_ctx, "PCFG: Ready - %u structures, limit %lu", pcfg_ctx->model->struct_cnt, (unsigned long) pcfg_ctx->pcfg_limit);
    event_log_info_nn (hashcat_ctx, NULL);
  }

  return 0;
}

void pcfg_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  if (!pcfg_ctx) return;

  // pcfg loopback cleanup
  if (pcfg_ctx->loopback_enabled == true)
  {
    pcfg_loopback_ctx_destroy (hashcat_ctx);
  }

  if (pcfg_ctx->generators)
  {
    pcfg_print_final_stats (hashcat_ctx);

    for (int i = 0; i < pcfg_ctx->num_generators; i++)
    {
      pcfg_gen_destroy (pcfg_ctx->generators[i]);
    }

    hcfree (pcfg_ctx->generators);
  }

  if (pcfg_ctx->active_map)
  {
    hcfree (pcfg_ctx->active_map);
  }

  // linear

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


  hc_thread_mutex_delete (pcfg_ctx->chunk_mutex);

  // performance monitor

  pcfg_perf_monitor_stop (hashcat_ctx);

  if (pcfg_ctx->perf_threshold != NULL)
  {
    hcfree (pcfg_ctx->perf_threshold);

    pcfg_ctx->perf_threshold = NULL;
  }

  // gpu omen

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

  // analysis + runtime chunks

  if (pcfg_ctx->analysis_struct_max_term_cost != NULL)
  {
    hcfree (pcfg_ctx->analysis_struct_max_term_cost);
    pcfg_ctx->analysis_struct_max_term_cost = NULL;
  }

  if (pcfg_ctx->analysis_chunks != NULL)
  {
    hcfree (pcfg_ctx->analysis_chunks);
    pcfg_ctx->analysis_chunks = NULL;
  }

  if (pcfg_ctx->omen_chunks != NULL)
  {
    hcfree (pcfg_ctx->omen_chunks);
    pcfg_ctx->omen_chunks = NULL;
  }

  if (pcfg_ctx->model)
  {
    pcfg_model_destroy (pcfg_ctx->model);
  }
}