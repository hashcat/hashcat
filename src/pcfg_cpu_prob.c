/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "thread.h"
#include "pcfg_common.h"
#include "pcfg_cpu_prob.h"
#include "pcfg_gpu_prob.h"
#include "pcfg_perf.h"

// MODE 2: CPU PROB

int pcfg_cpu_prob_gen_next (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  pcfg_gpu_prob_data_t *lin = pcfg_ctx->gpu_prob_ctx->linear_data;
  const u32 struct_cnt = lin->struct_cnt;

restart_cpu_prob:
  hc_thread_mutex_lock (pcfg_ctx->chunk_mutex);

  u64 effective_limit = (pcfg_ctx->pcfg_limit > 0) ? pcfg_ctx->pcfg_limit - pcfg_ctx->pcfg_skip : 0;

  if (effective_limit > 0 && pcfg_ctx->words_generated >= effective_limit)
  {
    hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
    return -1;
  }

  if (gen->skip_structure)
  {
    gen->skip_structure = false;
    u32 s_idx = gen->curr_struct_idx;

    if (s_idx < struct_cnt)
    {
      u64 current_global_idx = pcfg_ctx->pcfg_skip + pcfg_ctx->words_generated;
      u64 end_of_struct = lin->structures[s_idx].cumulative + lin->structures[s_idx].keyspace;

      if (current_global_idx < end_of_struct)
      {
        pcfg_ctx->words_generated += (end_of_struct - current_global_idx);

        if (pcfg_ctx->perf_threshold && pcfg_ctx->perf_threshold->monitoring_active && pcfg_ctx->perf_threshold->skip_struct_enabled)
        {
          pcfg_gen_perf_reset_struct (pcfg_ctx->perf_threshold, gen->dev_id, s_idx + 1);
        }
      }
    }
    hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
    goto restart_cpu_prob;
  }

  u64 global_idx = pcfg_ctx->pcfg_skip + pcfg_ctx->words_generated;

  if (global_idx >= lin->total_keyspace)
  {
    hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);
    return -1;
  }

  pcfg_ctx->words_generated++;
  hc_thread_mutex_unlock (pcfg_ctx->chunk_mutex);

  u32 s_idx = gen->curr_struct_idx;
  if (s_idx >= struct_cnt || global_idx < lin->structures[s_idx].cumulative) s_idx = 0;

  while (s_idx < struct_cnt - 1 && global_idx >= lin->structures[s_idx + 1].cumulative)
  {
    s_idx++;
  }

  const pcfg_gpu_prob_structure_t *s = &lin->structures[s_idx];
  u64 local_idx = global_idx - s->cumulative;

  gen->curr_struct_idx = s_idx;
  gen->burst_cand.struct_idx = s_idx;

  if (pcfg_gpu_prob_generate_direct (lin->data_buffer, lin->term_blocks, s, local_idx, out, len) == 0)
  {
    gen->generated++;
    return 0;
  }

  return -1;
}
