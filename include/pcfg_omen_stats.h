/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_OMEN_STATS_H
#define HC_PCFG_OMEN_STATS_H

#include "pcfg_common.h"

// Statistics for each Loop (Interleaved)
typedef struct pcfg_omen_loop_stats
{
  u64    loop_id;
  double duration_ms;
  u64    structures_processed;
  u64    passwords_generated;
  u64    passwords_cracked;
  double start_time;
  bool   active;

} pcfg_omen_loop_stats_t;

// Statistics for each OMEN cost
typedef struct pcfg_omen_cost_stats
{
  u32    cost;
  double duration_ms;
  u64    structures_processed;
  u64    passwords_generated;
  u64    passwords_cracked;
  double start_time;               // Cost start timestamp
  bool   active;                   // the current cost is active

} pcfg_omen_cost_stats_t;

// OMEN global statistics for generator
typedef struct pcfg_omen_stats
{
  pcfg_omen_cost_stats_t *costs; // Array [0..PCFG_OMEN_COST_PRACTICAL_MAX]
  u32  cost_min;
  u32  cost_max;
  u32  current_cost;
  pcfg_omen_loop_stats_t  *loops;
  u32  loops_cap;
  bool enabled;

} pcfg_omen_stats_t;

// OMEN ETA calculation
u64                pcfg_omen_calc_remaining_in_cost_classic     (const hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *g);
u64                pcfg_omen_calc_remaining_in_cost_interleaved (const hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *g);
void               pcfg_omen_format_eta                         (double eta_seconds, char *buf, size_t buf_size);
double             pcfg_omen_get_total_speed                    (pcfg_omen_stats_t *stats, u64 loop_id);

// OMEN stats lifecycle
pcfg_omen_stats_t *pcfg_omen_stats_init                         (u32 cost_min, u32 cost_max);
void               pcfg_omen_stats_destroy                      (pcfg_omen_stats_t *stats);

// OMEN stats tracking
void               pcfg_omen_stats_loop_start                   (pcfg_omen_stats_t *stats, u64 loop_id);
void               pcfg_omen_stats_loop_end                     (hashcat_ctx_t *hashcat_ctx, pcfg_omen_stats_t *stats, u64 loop_id, u32 gen_id);
void               pcfg_omen_stats_loop_update                  (pcfg_omen_stats_t *stats, u64 loop_id, u64 pwd_delta, u64 struct_delta);
void               pcfg_omen_stats_cost_start                  (pcfg_omen_stats_t *stats, u32 cost);
void               pcfg_omen_stats_cost_end                    (pcfg_omen_stats_t *stats, u32 cost);
void               pcfg_omen_stats_update                       (pcfg_omen_stats_t *stats, u32 cost, u64 passwords_delta, u64 structures_delta);

// OMEN stats display
void               pcfg_omen_stats_print_cost                  (hashcat_ctx_t *hashcat_ctx, pcfg_omen_stats_t *stats, u32 cost, u32 gen_id);
void               pcfg_print_final_stats                       (hashcat_ctx_t *hashcat_ctx);

#endif // HC_PCFG_OMEN_STATS_H
