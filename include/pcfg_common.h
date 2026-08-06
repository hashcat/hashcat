/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_COMMON_H
#define HC_PCFG_COMMON_H

#define PCFG_OMEN_MAX_COST    32
#define PCFG_OMEN_MAX_TOKENS  16
#define PCFG_OMEN_ALIGN       64
#define PCFG_OMEN_TYPE_MAX    256
#define PCFG_OMEN_LEN_MAX     256
#define PCFG_OMEN_MAX_DEVICES 64
#define PCFG_MAX_TERMINALS    (1U << 28)
#define PCFG_CHAR_STRIDE      32
#define PCFG_PW_STRIDE        256
#define PCFG_PATTERN_MAX      64

// Constants
#define PCFG_OMEN_HOST_MAX_BATCH_ENTRIES 65536
#define PCFG_OMEN_HOST_MAX_PARTITIONS    (1024 * 1024)

// status information (for each generator)
typedef struct pcfg_gpu_prob_status_info
{
  u32  current_struct;
  u32  struct_cnt;
  u64  current_local_idx;
  u64  struct_keyspace;
  u64  struct_keyspace_device;
  u64  struct_generated;
  u32  struct_total_len;
  char pattern[PCFG_PATTERN_MAX];
  u64  generated;
  u64  global_position;

} pcfg_gpu_prob_status_info_t;

// status information for omen gpu (for each generator)
typedef struct pcfg_gpu_omen_status_info
{
  // current position
  u32  current_struct;
  u32  struct_cnt;
  u32  current_cost;
  u64  current_loop; // for interleaved mode

  // structure info
  u64  struct_keyspace;
  u64  struct_keyspace_device;
  u64  struct_generated;
  u32  struct_total_len;
  char pattern[PCFG_PATTERN_MAX];

  // cost info
  u32  struct_idx_in_cost;
  u32  omen_cost;

  // global
  u64  generated;
  u64  global_position;

  // type
  u8   omen_type;

} pcfg_gpu_omen_status_info_t;

#include "pcfg.h"

// issue with CUDA, we need a minimum safe margin here or fail ... apply to all
#define PCFG_OMEN_SAFETY_MARGIN_PCT 1
#define PCFG_OMEN_SAFETY_MARGIN_BYTES(global_mem) (((u64)(global_mem) * PCFG_OMEN_SAFETY_MARGIN_PCT) / 100)
// user_options
bool is_desktop_environment         (void);

u64  compute_recip64                (const u32 d);
u64  mulhi64                        (const u64 a, const u64 b);
u64  fast_div64                     (const u64 n, const u32 d, const u64 recip);
u32  fast_mod64                     (const u64 n, const u32 d, const u64 recip);

int  user_options_sanity_pcfg       (hashcat_ctx_t *hashcat_ctx);

int  pcfg_omen_analyze_model        (hashcat_ctx_t *hashcat_ctx, const pcfg_model_t *model);
bool pw_complex_check               (const pcfg_structure_t *s);

u64  get_struct_keyspace_at_cost    (const pcfg_gpu_omen_structure_t *s, const pcfg_omen_extra_t *omen, int target_cost);
u32  count_structs_in_range         (const pcfg_model_t *model, const u8 *struct_max_term_cost, u32 cost_start, u32 cost_end);
void calculate_struct_max_term_cost (const pcfg_model_t *model, u8 *struct_max_term_cost);

u32  calc_aligned_stride_bytes      (u32 len_bytes);

u64  get_theoretical_keyspace      (u8 type, u8 len);

u32  pcfg_get_pattern_str          (const pcfg_structure_t *s, char *out, size_t max_len);

#endif // HC_PCFG_COMMON_H