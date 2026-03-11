/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "status.h"
#include "user_options.h"
#include "pcfg_omen_stats.h"
#include "pcfg.h"

// truecolor (ANSI 24-bit) color definitions
#define OMEN_COL_NONE      "\x1b[38;2;242;242;242m" // #F2F2F2 - No data
#define OMEN_COL_V_LOW     "\x1b[38;2;214;234;248m" // #D6EAF8 - Very low (<0.01%)
#define OMEN_COL_LOW       "\x1b[38;2;174;214;241m" // #AED6F1 - Low (<0.1%)
#define OMEN_COL_MED_LOW   "\x1b[38;2;133;193;233m" // #85C1E9 - Med-low (<1%)
#define OMEN_COL_MED       "\x1b[38;2;93;173;226m"  // #5DADE2 - Med (<5%)
#define OMEN_COL_MED_HIGH  "\x1b[38;2;247;220;111m" // #F7DC6F - Med-high (<15%)
#define OMEN_COL_HIGH      "\x1b[38;2;245;176;65m"  // #F5B041 - High (<30%)
#define OMEN_COL_HUGE      "\x1b[38;2;192;57;43m"   // #C0392B - Huge (>=30%)
#define OMEN_COL_RESET     "\x1b[0m"

// calculate keyspace for structure at current cost (on-demand)

static void pcfg_omen_calc_struct_keyspace_for_cost (const hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m, u32 cost)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  // if already calculated for this cost, skip
  if (m->omen_data->current_cost_cached == cost) return;

  const u64 keyspace_max = user_options->pcfg_omen_keyspace_max;
  const u64 partition_max = PCFG_OMEN_PARTITIONS_MAX;

  memset (m->omen_data->struct_keyspace_current, 0, m->struct_cnt * sizeof (u64));

  #define DP_MAX_COST_ETA 128

  #ifdef _OPENMP
  #pragma omp parallel
  {
    // each thread has its own DP buffers
    u64 dp_buf_a[DP_MAX_COST_ETA];
    u64 dp_buf_b[DP_MAX_COST_ETA];
    u64 dp_part_a[DP_MAX_COST_ETA];
    u64 dp_part_b[DP_MAX_COST_ETA];

    #pragma omp for
    for (u32 i = 0; i < m->struct_cnt; i++)
    {
      const pcfg_structure_t *s = &m->structures[i];
      const u32 token_cnt = s->token_cnt;

      if (token_cnt == 0) continue;

      u8 s_cost = m->omen_data->struct_costs[i];
      u8 min_terms = m->omen_data->struct_min_term_cost[i];

      int rem = (int) cost - (int) s_cost;

      if (rem < 0 || rem < min_terms) continue;
      if (rem > 31 * (int) token_cnt) continue;

      const pcfg_omen_slot_map_t *slot_maps[PCFG_TOKEN_MAX];

      for (u32 slot = 0; slot < token_cnt; slot++)
      {
        const u8 ty = s->types[slot] & 0x7F;
        const u8 ln = s->lengths[slot];

        slot_maps[slot] = &m->omen_data->term_maps[ty][ln];
      }

      u64 *dp_curr = dp_buf_a;
      u64 *dp_next = dp_buf_b;
      u64 *dp_part_curr = dp_part_a;
      u64 *dp_part_next = dp_part_b;

      memset (dp_curr, 0, (rem + 1) * sizeof (u64));
      memset (dp_part_curr, 0, (rem + 1) * sizeof (u64));

      dp_curr[0] = 1;
      dp_part_curr[0] = 1;

      int curr_max = 0;

      for (u32 slot = 0; slot < token_cnt; slot++)
      {
        const pcfg_omen_slot_map_t *map = slot_maps[slot];

        memset (dp_next, 0, (rem + 1) * sizeof (u64));
        memset (dp_part_next, 0, (rem + 1) * sizeof (u64));

        int next_max = -1;

        for (int prev = 0; prev <= curr_max; prev++)
        {
          const u64 ways = dp_curr[prev];
          const u64 parts = dp_part_curr[prev];

          if (ways == 0) continue;

          const int cmax = (rem - prev < 31) ? (rem - prev) : 31;

          for (int c = 0; c <= cmax; c++)
          {
            const u64 cnt = map->counts[c];

            if (cnt == 0) continue;

            const int nc = prev + c;

            dp_next[nc] += ways * cnt;
            dp_part_next[nc] += parts;

            if (nc > next_max) next_max = nc;
          }
        }

        u64 *tmp = dp_curr;

        dp_curr = dp_next;
        dp_next = tmp;

        tmp = dp_part_curr;
        dp_part_curr = dp_part_next;
        dp_part_next = tmp;

        curr_max = next_max;

        if (curr_max < 0) break;
      }

      if (curr_max >= 0 && rem <= curr_max && dp_curr[rem] > 0)
      {
        u64 struct_keyspace   = dp_curr[rem];
        u64 struct_partitions = dp_part_curr[rem];

        if (struct_partitions > partition_max)
        {
          struct_keyspace = (struct_keyspace * partition_max) / struct_partitions;
        }

        if (struct_keyspace > keyspace_max)
        {
          struct_keyspace = keyspace_max;
        }

        m->omen_data->struct_keyspace_current[i] = struct_keyspace;
      }
    }
  }
  #else
  // no omp

  // DP buffers tmp
  u64 dp_buf_a[DP_MAX_COST_ETA];
  u64 dp_buf_b[DP_MAX_COST_ETA];
  u64 dp_part_a[DP_MAX_COST_ETA];
  u64 dp_part_b[DP_MAX_COST_ETA];

  for (u32 i = 0; i < m->struct_cnt; i++)
  {
    const pcfg_structure_t *s = &m->structures[i];

    const u32 token_cnt = s->token_cnt;

    if (token_cnt == 0) continue;

    u8 s_cost = m->omen_data->struct_costs[i];
    u8 min_terms = m->omen_data->struct_min_term_cost[i];

    int rem = (int) cost - (int) s_cost;

    // skip if not valid for this cost
    if (rem < 0 || rem < min_terms) continue;
    if (rem > 31 * (int) token_cnt) continue;

    // pre-cache term_maps
    const pcfg_omen_slot_map_t *slot_maps[PCFG_TOKEN_MAX];

    for (u32 slot = 0; slot < token_cnt; slot++)
    {
      const u8 ty = s->types[slot] & 0x7F;
      const u8 ln = s->lengths[slot];

      slot_maps[slot] = &m->omen_data->term_maps[ty][ln];
    }

    // DP to calculate keyspace and partitions
    u64 *dp_curr = dp_buf_a;
    u64 *dp_next = dp_buf_b;
    u64 *dp_part_curr = dp_part_a;
    u64 *dp_part_next = dp_part_b;

    memset (dp_curr, 0, (rem + 1) * sizeof (u64));
    memset (dp_part_curr, 0, (rem + 1) * sizeof (u64));

    dp_curr[0] = 1;
    dp_part_curr[0] = 1;

    int curr_max = 0;

    for (u32 slot = 0; slot < token_cnt; slot++)
    {
      const pcfg_omen_slot_map_t *map = slot_maps[slot];

      memset (dp_next, 0, (rem + 1) * sizeof (u64));
      memset (dp_part_next, 0, (rem + 1) * sizeof (u64));

      int next_max = -1;

      for (int prev = 0; prev <= curr_max; prev++)
      {
        const u64 ways = dp_curr[prev];
        const u64 parts = dp_part_curr[prev];

        if (ways == 0) continue;

        const int cmax = (rem - prev < 31) ? (rem - prev) : 31;

        for (int c = 0; c <= cmax; c++)
        {
          const u64 cnt = map->counts[c];

          if (cnt == 0) continue;

          const int nc = prev + c;

          dp_next[nc] += ways * cnt;
          dp_part_next[nc] += parts;

          if (nc > next_max) next_max = nc;
        }
      }

      u64 *tmp = dp_curr;

      dp_curr = dp_next;
      dp_next = tmp;

      tmp = dp_part_curr;

      dp_part_curr = dp_part_next;
      dp_part_next = tmp;

      curr_max = next_max;

      if (curr_max < 0) break;
    }

    // set limits
    if (curr_max >= 0 && rem <= curr_max && dp_curr[rem] > 0)
    {
      u64 struct_keyspace   = dp_curr[rem];
      u64 struct_partitions = dp_part_curr[rem];

      if (struct_partitions > partition_max)
      {
        struct_keyspace = (struct_keyspace * partition_max) / struct_partitions;
      }

      if (struct_keyspace > keyspace_max)
      {
        struct_keyspace = keyspace_max;
      }

      m->omen_data->struct_keyspace_current[i] = struct_keyspace;
    }
  }
  #endif // omp

  m->omen_data->current_cost_cached = cost;
}

// returns the correct ANSI color based on the percentage

static const char *get_omen_heatmap_color (const u64 count, const u64 total)
{
  if (count == 0) return OMEN_COL_NONE;

  const double percentage = (total > 0) ? (double)count * 100.0 / total : 0;

  if (percentage < 0.01) return OMEN_COL_V_LOW;
  if (percentage < 0.1)  return OMEN_COL_LOW;
  if (percentage < 1.0)  return OMEN_COL_MED_LOW;
  if (percentage < 5.0)  return OMEN_COL_MED;
  if (percentage < 15.0) return OMEN_COL_MED_HIGH;
  if (percentage < 30.0) return OMEN_COL_HIGH;

  return OMEN_COL_HUGE;
}

// format large numbers into readable strings (G, M, K)

static void format_pcfg_num (const u64 num, char *buf, size_t len)
{
  if (num >= 1000000000ULL)   snprintf (buf, len, "%6.2fG", (double)num / 1000000000.0);
  else if (num >= 1000000ULL) snprintf (buf, len, "%6.2fM", (double)num / 1000000.0);
  else if (num >= 1000ULL)    snprintf (buf, len, "%6.2fK", (double)num / 1000.0);
  else                        snprintf (buf, len, "%" PRIu64, num);
}

// calculate remaining keyspace in the current cost (Classic)

u64 pcfg_omen_calc_remaining_in_cost_classic (const hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen)
{
  const pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  pcfg_model_t *m = gen->model;

  if (m == NULL || m->omen_data == NULL) return 0;

  u32 current_cost = gen->omen_target_cost;
  u32 num_gens = pcfg_ctx->num_active_generators;
  u64 remaining = 0;

  // calculate keyspace for structure at current cost (if not already done)
  pcfg_omen_calc_struct_keyspace_for_cost (hashcat_ctx, m, current_cost);

  // remaining keyspace in the current structure
  if (gen->curr_struct_idx < m->struct_cnt && gen->curr_comb_idx < gen->omen_struct_keyspace)
  {
    u64 struct_remaining = gen->omen_struct_keyspace - gen->curr_comb_idx;

    remaining += (struct_remaining + num_gens - 1) / num_gens;
  }

  // keyspace of next structures in the current cost
  for (u32 i = gen->curr_struct_idx + 1; i < m->struct_cnt; i++)
  {
    u64 struct_ks = m->omen_data->struct_keyspace_current[i];

    remaining += (struct_ks + num_gens - 1) / num_gens;
  }

  return remaining;
}

u64 pcfg_omen_calc_remaining_in_cost_interleaved (const hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen)
{
  const pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;
  pcfg_model_t *m = gen->model;

  if (m == NULL || m->omen_data == NULL) return 0;

  u32 current_cost = gen->omen_target_cost;
  u32 num_gens = pcfg_ctx->num_active_generators;
  u64 remaining = 0;

  // calculate keyspace for structures at current cost (if not already done)
  pcfg_omen_calc_struct_keyspace_for_cost (hashcat_ctx, m, current_cost);

  u64 offset = gen->omen_global_loop_idx * gen->burst_size;

  // current structure
  if (gen->curr_struct_idx < m->struct_cnt)
  {
    u64 struct_ks = gen->omen_struct_keyspace;
    u64 processed = gen->curr_comb_idx;

    if (processed < struct_ks)
    {
      u64 end_idx = MIN (gen->omen_current_chunk_max, struct_ks);

      if (end_idx > processed)
      {
        u64 struct_remaining = end_idx - processed;

        remaining += (struct_remaining + num_gens - 1) / num_gens;
      }
    }
  }

  // Next structures in the current cost

  u64 future_remaining = 0;

  #ifdef _OPENMP
  #pragma omp parallel for reduction(+:remaining)
  #endif
  for (u32 i = gen->curr_struct_idx + 1; i < m->struct_cnt; i++)
  {
    u64 struct_ks = m->omen_data->struct_keyspace_current[i];

    if (struct_ks == 0) continue;

    // skip if this structure won't be processed in this loop
    if (struct_ks <= (offset + gen->id)) continue;

    // calculate the chunk that will be processed
    u64 start_idx = offset + gen->id;

    u64 end_idx = (offset + gen->burst_size < struct_ks) ? offset + gen->burst_size : struct_ks;

    if (end_idx > start_idx)
    {
      u64 struct_remaining = end_idx - start_idx;

      future_remaining += (struct_remaining + num_gens - 1) / num_gens;
    }
  }

  remaining += future_remaining;

  return remaining;
}

double pcfg_omen_get_total_speed (pcfg_omen_stats_t *stats, u64 loop_id)
{
  struct timeval tv;

  gettimeofday (&tv, NULL);

  double now = (double) tv.tv_sec * 1000.0 + (double) tv.tv_usec / 1000.0;

  pcfg_omen_loop_stats_t *ls = &stats->loops[loop_id];
  ls->duration_ms = now - ls->start_time;
  ls->active = false;

  double duration_sec = ls->duration_ms / 1000.0;
  double speed = (duration_sec > 0) ? (double) ls->passwords_generated / duration_sec : 0;

  return speed;
}

// format ETA into a readable string

void pcfg_omen_format_eta (double eta_seconds, char *buf, size_t buf_size)
{
  if (eta_seconds < 0 || eta_seconds > 365.0 * 24 * 3600 * 100) // > 100 anni
  {
    snprintf (buf, buf_size, "N/A");
    return;
  }

  if (eta_seconds < 60)
  {
    snprintf (buf, buf_size, "%.0fs", eta_seconds);
  }
  else if (eta_seconds < 3600)
  {
    int mins = (int) (eta_seconds / 60);
    int secs = (int) eta_seconds % 60;

    snprintf (buf, buf_size, "%dm%02ds", mins, secs);
  }
  else if (eta_seconds < 86400)
  {
    int hours = (int) (eta_seconds / 3600);
    int mins = ((int) eta_seconds % 3600) / 60;

    snprintf (buf, buf_size, "%dh%02dm", hours, mins);
  }
  else
  {
    int days = (int) (eta_seconds / 86400);
    int hours = ((int) eta_seconds % 86400) / 3600;

    snprintf (buf, buf_size, "%dd%02dh", days, hours);
  }
}

// start Loop

void pcfg_omen_stats_loop_start (pcfg_omen_stats_t *stats, u64 loop_id)
{
  if (!stats) return;

  // realloc if needed
  if (loop_id >= stats->loops_cap)
  {
    u32 new_cap = stats->loops_cap * 2;

    stats->loops = hcrealloc (stats->loops, new_cap * sizeof (pcfg_omen_loop_stats_t), stats->loops_cap * sizeof (pcfg_omen_loop_stats_t));
    stats->loops_cap = new_cap;
  }

  struct timeval tv;

  gettimeofday (&tv, NULL);

  stats->loops[loop_id].start_time = (double) tv.tv_sec * 1000.0 + (double) tv.tv_usec / 1000.0;
  stats->loops[loop_id].active = true;
}

// end loop

void pcfg_omen_stats_loop_end (hashcat_ctx_t *hashcat_ctx, pcfg_omen_stats_t *stats, u64 loop_id, u32 gen_id)
{
  if (!stats || !stats->loops[loop_id].active) return;

  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_CLASSIC) return;

  struct timeval tv;

  gettimeofday (&tv, NULL);

  double now = (double) tv.tv_sec * 1000.0 + (double) tv.tv_usec / 1000.0;

  pcfg_omen_loop_stats_t *ls = &stats->loops[loop_id];

  ls->duration_ms = now - ls->start_time;
  ls->active = false;

  double duration_sec = ls->duration_ms / 1000.0;
  double speed = (duration_sec > 0) ? (double) ls->passwords_generated / duration_sec : 0;

  char speed_buf[32] = { 0 };
  format_speed_display (speed, speed_buf, sizeof (speed_buf));

  event_log_info (hashcat_ctx,
    "\nPCFG: Stats Gen#%u, OMEN Loop %4" PRIu64 ": Duration:%.2fs, Structs:%" PRIu64 ", Passwords:%" PRIu64 ", Cracked:%" PRIu64 ", Speed:%sPw/s",
    gen_id, loop_id + 1, duration_sec, ls->structures_processed, ls->passwords_generated, ls->passwords_cracked, speed_buf);
}

// update Loop Stats

void pcfg_omen_stats_loop_update (pcfg_omen_stats_t *stats, u64 loop_id, u64 pwd_delta, u64 struct_delta)
{
  if (loop_id < stats->loops_cap)
  {
    stats->loops[loop_id].passwords_generated += pwd_delta;
    stats->loops[loop_id].structures_processed += struct_delta;
  }
}

// start tracking a new cost

void pcfg_omen_stats_cost_start (pcfg_omen_stats_t *stats, u32 cost)
{
  if (!stats || !stats->enabled) return;
  if (cost > PCFG_OMEN_COST_PRACTICAL_MAX) return;

  struct timeval tv;

  gettimeofday (&tv, NULL);

  stats->costs[cost].start_time = (double) tv.tv_sec * 1000.0 + (double) tv.tv_usec / 1000.0;
  stats->costs[cost].active = true;
  stats->current_cost = cost;
}

// init OMEN stats

pcfg_omen_stats_t *pcfg_omen_stats_init (u32 cost_min, u32 cost_max)
{
  pcfg_omen_stats_t *stats = (pcfg_omen_stats_t *) hccalloc (1, sizeof (pcfg_omen_stats_t));

  if (!stats) return NULL;

  u32 num_costs = PCFG_OMEN_COST_PRACTICAL_MAX + 1;

  stats->costs = (pcfg_omen_cost_stats_t *) hccalloc (num_costs, sizeof (pcfg_omen_cost_stats_t));

  if (!stats->costs)
  {
    hcfree (stats);
    return NULL;
  }

  for (u32 i = 0; i < num_costs; i++)
  {
    stats->costs[i].cost = i;
  }

  stats->cost_min = cost_min;
  stats->cost_max = cost_max;
  stats->current_cost = cost_min;
  stats->enabled = true;

  // init Loop Stats
  stats->loops_cap = 100; // start capacity
  stats->loops = (pcfg_omen_loop_stats_t *) hccalloc (stats->loops_cap, sizeof (pcfg_omen_loop_stats_t));

  if (!stats->loops)
  {
    hcfree (stats->costs);
    hcfree (stats);
    return NULL;
  }

  // init first loop
  pcfg_omen_stats_loop_start  (stats, 0);
  pcfg_omen_stats_cost_start (stats, cost_min);

  return stats;
}

// destroy OMEN stats

void pcfg_omen_stats_destroy (pcfg_omen_stats_t *stats)
{
  if (!stats) return;

  if (stats->costs) hcfree (stats->costs);
  if (stats->loops)  hcfree (stats->loops);

  hcfree (stats);
}

// end tracking of the current cost

void pcfg_omen_stats_cost_end (pcfg_omen_stats_t *stats, u32 cost)
{
  if (!stats || !stats->enabled) return;
  if (cost > PCFG_OMEN_COST_PRACTICAL_MAX) return;
  if (!stats->costs[cost].active) return;

  struct timeval tv;

  gettimeofday (&tv, NULL);

  double now = (double) tv.tv_sec * 1000.0 + (double) tv.tv_usec / 1000.0;

  stats->costs[cost].duration_ms += (now - stats->costs[cost].start_time);
  stats->costs[cost].active = false;
}

// update stats during generation

void pcfg_omen_stats_update (pcfg_omen_stats_t *stats, u32 cost, u64 passwords_delta, u64 structures_delta)
{
  if (!stats || !stats->enabled) return;
  if (cost > PCFG_OMEN_COST_PRACTICAL_MAX) return;

  stats->costs[cost].passwords_generated  += passwords_delta;
  stats->costs[cost].structures_processed += structures_delta;
}

// print stats for a single cost

void pcfg_omen_stats_print_cost (hashcat_ctx_t *hashcat_ctx, pcfg_omen_stats_t *stats, u32 cost, u32 gen_id)
{
  if (!stats || !stats->enabled) return;
  if (cost > PCFG_OMEN_COST_PRACTICAL_MAX) return;

  pcfg_omen_cost_stats_t *ls = &stats->costs[cost];

  if (ls->passwords_generated == 0 && ls->structures_processed == 0) return;

  double duration_sec = ls->duration_ms / 1000.0;
  double speed = (duration_sec > 0) ? (double) ls->passwords_generated / duration_sec : 0;

  char speed_buf[32] = { 0 };
  format_speed_display (speed, speed_buf, sizeof (speed_buf));

  event_log_info (hashcat_ctx,
    "\nPCFG: Stats Gen#%u, OMEN Cost %3u: Duration:%.2fs, Structs:%" PRIu64 ", Passwords:%" PRIu64 ", Cracked:%" PRIu64 ", Speed:%sPw/s",
    gen_id, cost, duration_sec, ls->structures_processed, ls->passwords_generated, ls->passwords_cracked, speed_buf);
}

void pcfg_print_final_stats (hashcat_ctx_t *hashcat_ctx)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (!pcfg_ctx) return;
  if (user_options->pcfg_omen_stats == false) return;

  const u32 m = user_options->pcfg_mode;

  if (m != PCFG_MODE_CPU_OMEN_BY_COST
   && m != PCFG_MODE_GPU_OMEN_BY_COST
   && m != PCFG_MODE_CPU_OMEN_BY_STRUCT
   && m != PCFG_MODE_GPU_OMEN_BY_STRUCT
  ) return;

  event_log_info (hashcat_ctx, "PCFG OMEN (%s) Statistics Summary (%u Generators)",
                  user_options->pcfg_omen_type == PCFG_OMEN_TYPE_CLASSIC ? "Classic" : "Interleaved",
                  pcfg_ctx->num_active_generators);

  event_log_info (hashcat_ctx, "=====================================================================================================");
  event_log_info (hashcat_ctx, "Gen | Passwords | Cracked | Avg. Speed | Range   | OMEN Cost Distribution (Cost 0-100)");
  event_log_info (hashcat_ctx, "----+-----------+---------+------------+---------+---------------------------------------------------");

  u64 global_total_pws = 0;
  u64 global_total_cracked = 0;

  for (int i = 0; i < pcfg_ctx->num_generators; i++)
  {
    pcfg_gen_t *gen = pcfg_ctx->generators[i];

    if (!gen || !gen->omen_stats) continue;

    // end active cost if still in progress
    if (gen->omen_stats->costs[gen->omen_target_cost].active)
    {
      pcfg_omen_stats_cost_end (gen->omen_stats, gen->omen_target_cost);
    }

    // end active loop
    // in Classic mode it will be loop 0
    // in Interleaved mode, the loop is closed in advance_sweep, but if you interrupt halfway through, you need to do it here
    if (gen->omen_stats->loops && gen->omen_stats->loops[gen->omen_global_loop_idx].active)
    {
      pcfg_omen_stats_loop_end (hashcat_ctx, gen->omen_stats, gen->omen_global_loop_idx, gen->id);
    }

    pcfg_omen_stats_t *stats = gen->omen_stats;

    u64 total_pws = 0;
    u64 total_cracked = 0;

    double total_dur_ms = 0;

    // calculation of totals for the current generator
    for (u32 lvl = stats->cost_min; lvl <= stats->cost_max; lvl++)
    {
      total_pws      += stats->costs[lvl].passwords_generated;
      total_cracked  += stats->costs[lvl].passwords_cracked;
      total_dur_ms   += stats->costs[lvl].duration_ms;
    }

    global_total_pws += total_pws;
    global_total_cracked += total_cracked;

    // format output
    char pw_buf[32], crk_buf[32], speed_buf[32];

    format_pcfg_num (total_pws, pw_buf, sizeof (pw_buf));
    format_pcfg_num (total_cracked, crk_buf, sizeof (crk_buf));

    double total_dur_sec = total_dur_ms / 1000.0;
    double avg_speed = (total_dur_sec > 0) ? (double) total_pws / total_dur_sec : 0;

    format_speed_display (avg_speed, speed_buf, sizeof (speed_buf));

    // fixed width heatmap construction (50 blocks to cover 0-100 costs)
    const int BAR_WIDTH = 50;
    const int MAX_OMEN_RANGE = 100;

    char heatmap[4096] = { 0 };

    for (int b = 0; b < BAR_WIDTH; b++)
    {
      // we determine the range of OMEN costs for this block
      u32 lvl_start = (b * (MAX_OMEN_RANGE + 1)) / BAR_WIDTH;
      u32 lvl_end   = ((b + 1) * (MAX_OMEN_RANGE + 1)) / BAR_WIDTH - 1;

      u64 bin_passwords = 0;
      bool bin_has_activity = false;

      for (u32 l = lvl_start; l <= lvl_end; l++)
      {
        if (l <= PCFG_OMEN_COST_PRACTICAL_MAX)
        {
          bin_passwords += stats->costs[l].passwords_generated;
          if (stats->costs[l].passwords_generated > 0 || stats->costs[l].structures_processed > 0)
          {
            bin_has_activity = true;
          }
        }
      }

      const char *color = bin_has_activity ? get_omen_heatmap_color (bin_passwords, total_pws) : OMEN_COL_NONE;

      strncat (heatmap, color, sizeof (heatmap) - strlen (heatmap) - 1);
      strncat (heatmap, "■", sizeof (heatmap) - strlen (heatmap) - 1);
    }

    strncat (heatmap, OMEN_COL_RESET, sizeof (heatmap) - strlen (heatmap) - 1);

    event_log_info (hashcat_ctx, "%2d  | %9s | %7s | %10s | %3u-%-3u | %s",
      gen->id, pw_buf, crk_buf, speed_buf, stats->cost_min, stats->cost_max, heatmap);
  }

  event_log_info (hashcat_ctx, "----+-----------+---------+------------+---------+---------------------------------------------------");

  // Legend
  event_log_info (hashcat_ctx, "Legend (contribution per OMEN range):");
  event_log_info (hashcat_ctx, "%s■%s None %s■%s <0.01%% %s■%s <0.1%% %s■%s <1%% %s■%s <5%% %s■%s <15%% %s■%s <30%% %s■%s Max",
    OMEN_COL_NONE, OMEN_COL_RESET, OMEN_COL_V_LOW, OMEN_COL_RESET, OMEN_COL_LOW, OMEN_COL_RESET,
    OMEN_COL_MED_LOW, OMEN_COL_RESET, OMEN_COL_MED, OMEN_COL_RESET, OMEN_COL_MED_HIGH, OMEN_COL_RESET,
    OMEN_COL_HIGH, OMEN_COL_RESET, OMEN_COL_HUGE, OMEN_COL_RESET);

  event_log_info (hashcat_ctx, "====================================================================================================");

  char global_pw_buf[32], global_crk_buf[32];

  format_pcfg_num (global_total_pws, global_pw_buf, sizeof (global_pw_buf));
  format_pcfg_num (global_total_cracked, global_crk_buf, sizeof (global_crk_buf));

  event_log_info (hashcat_ctx, "GLOBAL TOTAL: Passwords: %s | Cracked: %s", global_pw_buf, global_crk_buf);
  event_log_info (hashcat_ctx, NULL);
}
