#ifndef PCFG_PERF_H
#define PCFG_PERF_H

#include "types.h"

#include <inttypes.h>

#define DEVICES_MAX 256

// Counter per-generator

typedef struct pcfg_gen_perf
{
  u64         struct_id;
  time_t      struct_start_time;
  u64         struct_recovered;

  u32         cost;
  time_t      cost_start_time;
  u64         cost_recovered;

  u64         loop_id;
  time_t      loop_start_time;
  u64         loop_recovered;

  time_t      snapshot_struct_start;
  time_t      snapshot_cost_start;
  time_t      snapshot_loop_start;

} pcfg_gen_perf_t;

// performance threshold configuration

typedef struct pcfg_perf_threshold
{
  bool        enabled;

  bool        skip_struct_enabled;
  u64         struct_threshold_count;
  u32         struct_threshold_seconds;

  bool        skip_cost_enabled;
  u64         cost_threshold_count;
  u32         cost_threshold_seconds;

  bool        skip_loop_enabled;
  u64         loop_threshold_count;
  u32         loop_threshold_seconds;

  // Baseline
  u64         baseline_recovered;

  // Counter per-generator
  pcfg_gen_perf_t gen_perf[DEVICES_MAX];

  u64         skips_struct_total;
  u64         skips_cost_total;
  u64         skips_loop_total;
  bool        monitoring_active;

  hc_thread_t thread;
  bool        thread_running;
  bool        thread_shutdown;

} pcfg_perf_threshold_t;

// Function prototypes

int  pcfg_perf_threshold_parse            (hashcat_ctx_t *hashcat_ctx, const char *input);
void pcfg_perf_threshold_init_generators  (hashcat_ctx_t *hashcat_ctx);
void pcfg_gen_perf_reset_struct           (pcfg_perf_threshold_t *pt, int dev_idx, u64 new_struct_id);
void pcfg_gen_perf_reset_cost            (pcfg_perf_threshold_t *pt, int dev_idx, u32 new_cost);
void pcfg_gen_perf_reset_loop             (pcfg_perf_threshold_t *pt, int dev_idx, u64 new_loop_id);
void pcfg_gen_perf_add_recovered          (pcfg_perf_threshold_t *pt, int dev_idx, u64 count);
int  pcfg_perf_monitor_start              (hashcat_ctx_t *hashcat_ctx);
void pcfg_perf_monitor_stop               (hashcat_ctx_t *hashcat_ctx);

#endif // PCFG_PERF_H
