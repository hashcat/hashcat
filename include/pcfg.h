/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_H
#define HC_PCFG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

#include "pcfg_perf.h"



#define PCFG_MAGIC                 0x50434647
#define PCFG_VERSION               1
#define PCFG_ENCODING_MAX          32
#define ALPHA_LEN_MIN              1
#define STATUS_CHECK_MASK          0xFFFF
#define MAX_DECODE_DEPTH           10

#define PCFG_PW_MAX                256
#define PCFG_TOKEN_MAX             16
#define PCFG_VALUE_MAX             256

#define PCFG_BURST_SIZE            50000
#define PCFG_AHF_BURST_SIZE        25000
#define PCFG_AHF_TERMINALS_MIN     1
#define PCFG_STRUCT_PROB_MAX       100.0
#define PCFG_STRUCT_PROB_MIN       0.0
#define PCFG_TERMINAL_COUNT_MIN    1
#define PCFG_TOKEN_TYPES           "LUMCDSPWYEKQRXJAIBHGV"
#define PCFG_TOKEN_COUNT_MAX       PCFG_TOKEN_MAX
#define PCFG_TOKEN_COUNT_MIN       1
#define PCFG_TOKEN_LEN_MAX         0
#define PCFG_TOKEN_LEN_MIN         1
#define PCFG_PW_LEN_MAX            0
#define PCFG_PW_LEN_MIN            1

#define PCFG_TRAIN_AF_THRESHOLD    2
#define PCFG_OMEN_COST_MIN         0
#define PCFG_OMEN_COST_MAX         100
#define PCFG_OMEN_MAX_LOOPS        100000000000ULL
#define PCFG_OMEN_COST_PRACTICAL_MAX 100
//#define PCFG_OMEN_KEYSPACE_MAX     PCFG_OMEN_MAX_LOOPS
#define PCFG_KEYSPACE_MAX          UINT64_MAX
#define PCFG_OMEN_KEYSPACE_MAX     UINT64_MAX
#define PCFG_OMEN_PARTITIONS_MAX   1024
#define PCFG_OMEN_MAX_ALLOC_PERC   100
#define PCFG_DATA_BUFFER_PARTS_MAX 8

// PCFG Character Sets
#define PCFG_CHARS_DIGIT           "0123456789"
#define PCFG_CHARS_LOWER           "abcdefghijklmnopqrstuvwxyz"
#define PCFG_CHARS_UPPER           "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define PCFG_CHARS_SPECIAL         "!@#$%^&*(){}[]<>?~`+=\"'"
#define PCFG_CHARS_PUNCT           ".,:;/\\|"
#define PCFG_CHARS_WHITE           " \t_-"

// Bit 7 on = Generated, off = Dictionary
#define PCFG_SYNTHETIC_FLAG        0x80
#define PCFG_MARKOV_MAX_SUCCESSORS 24

typedef enum pcfg_train_format
{
  PCFG_TRAIN_FORMAT_WORDLIST = 0,
  PCFG_TRAIN_FORMAT_WEIGHED_WORDLIST = 1

} pcfg_train_format_t;

typedef enum pcfg_mode
{
  PCFG_MODE_CPU_RANDOM         = 0,
  PCFG_MODE_CPU_RANDOM_AHF     = 1,
  PCFG_MODE_CPU_PROB           = 2,
  PCFG_MODE_GPU_PROB           = 3,
  PCFG_MODE_CPU_OMEN_BY_COST   = 4,
  PCFG_MODE_GPU_OMEN_BY_COST   = 5,
  PCFG_MODE_CPU_OMEN_BY_STRUCT = 6,
  PCFG_MODE_GPU_OMEN_BY_STRUCT = 7,
} pcfg_mode_t;

typedef enum pcfg_ahf_type
{
  PCFG_AHF_TYPE_MARKOV         = 0,
  PCFG_AHF_TYPE_RANDOM         = 1

} pcfg_ahf_type_t;

typedef enum pcfg_omen_type
{
  PCFG_OMEN_TYPE_INTERLEAVED   = 0,
  PCFG_OMEN_TYPE_CLASSIC       = 1

} pcfg_omen_type_t;

typedef enum pcfg_token_type
{
  PCFG_TK_LOWER       = 'L',
  PCFG_TK_UPPER       = 'U',
  PCFG_TK_MIXED       = 'M',
  PCFG_TK_CAPITALIZED = 'C',
  PCFG_TK_DIGIT       = 'D',
  PCFG_TK_SPECIAL     = 'S',
  PCFG_TK_PUNCT       = 'P',
  PCFG_TK_UNICODE     = 'X',
  PCFG_TK_WHITESPACE  = 'W',
  PCFG_TK_YEAR        = 'Y',
  PCFG_TK_EMAIL       = 'E',
  PCFG_TK_KEYBOARD    = 'K',
  PCFG_TK_REPEAT      = 'R',
  PCFG_TK_SEQUENCE    = 'Q',
  PCFG_TK_EMOJI       = 'J',
  PCFG_TK_LATIN_EXT   = 'A',
  PCFG_TK_CYRILLIC    = 'I',
  PCFG_TK_ARABIC      = 'B',
  PCFG_TK_ASIAN       = 'H',
  PCFG_TK_GREEK       = 'G',
  PCFG_TK_HEBREW      = 'V'

} pcfg_token_type_t;

// forward declarations

struct pcfg_gpu_omen_batch_entry;
typedef struct pcfg_gpu_omen_batch_entry pcfg_gpu_omen_batch_entry_t;
struct pcfg_gpu_omen_partition;
typedef struct pcfg_gpu_omen_partition pcfg_gpu_omen_partition_t;
struct pcfg_gpu_omen_structure;
typedef struct pcfg_gpu_omen_structure pcfg_gpu_omen_structure_t;
struct pcfg_gpu_omen_ctx;
typedef struct pcfg_gpu_omen_ctx pcfg_gpu_omen_ctx_t;
struct pcfg_gpu_omen_data;
typedef struct pcfg_gpu_omen_data pcfg_gpu_omen_data_t;
struct pcfg_gpu_prob_data;
typedef struct pcfg_gpu_prob_data pcfg_gpu_prob_data_t;
struct pcfg_gpu_prob_ctx;
typedef struct pcfg_gpu_prob_ctx pcfg_gpu_prob_ctx_t;
struct pcfg_omen_stats;
typedef struct pcfg_omen_stats pcfg_omen_stats_t;

// omen

// Pre-computed rank boundaries and counts for O(1) terminal selection
typedef struct
{
  u32 ranks[32];  // Starting index (rank) for each cost 0-31
  u32 counts[32]; // Exact number of terminals at this cost
  u64 recip[32];  // Mutual for fast division

} pcfg_omen_slot_map_t;

// Shared OMEN metadata in the model
typedef struct
{
  u8  *struct_costs;             // [struct_cnt]
  pcfg_omen_slot_map_t term_maps[256][256]; // [type][length]
  u32 *max_count_per_slot;       // pre-calculated max counts
  u8  *struct_min_term_cost;     // minimum terminal cost per structure
  u64 *cost_keyspace;

  // ETA - only current cost
  u64 *struct_keyspace_current;  // [struct_cnt] - current struct
  u32  current_cost_cached;      // current cost

} pcfg_omen_extra_t;

// A specific way to distribute total cost among tokens
typedef struct
{
  u8  costs[PCFG_TOKEN_MAX];
  u64 combinations;              // Total passwords in this partition
  u64 cumulative_offset;         // Start index within the structure's cost
  u64 cumulative_end;            // cumulative_offset + combinations

} pcfg_omen_partition_t;

// common

typedef struct pcfg_terminal
{
  char  *value;  // 8 bytes
  float  prob;   // 4 bytes
  u32    count;  // 4 bytes
  u16    len;    // 2 bytes

} __attribute__((packed)) pcfg_terminal_t;

typedef struct pcfg_terminal_list
{
  pcfg_terminal_t *items;
  u32    cnt;
  u32    cap;
  char  *string_pool;
  u64    recip;  // pre-calculated reciprocal

} pcfg_terminal_list_t;

typedef struct pcfg_structure
{
  u8     types[PCFG_TOKEN_MAX];
  u8     lengths[PCFG_TOKEN_MAX];
  u32    token_cnt;
  float  prob;
  u64    count;
  u64    keyspace;
  u32    total_len;

} __attribute__((packed)) pcfg_structure_t;

typedef struct pcfg_candidate
{
  double prob;
  u32    pw_len;
  u32    struct_idx;
  u32    term_idx[PCFG_TOKEN_MAX];

} __attribute__((packed)) pcfg_candidate_t;

typedef struct pcfg_heap
{
  pcfg_candidate_t *data;
  u64    size;
  u64    cap;

} pcfg_heap_t;

typedef struct
{
  u8     bins[256];

} pcfg_markov_row_t;

typedef struct
{
  u8     states[256];

} pcfg_markov_start_row_t;

typedef struct
{
  u16    states[128];

} pcfg_markov_start_row_digit_t;

typedef struct
{
  u16    states[4096];

} pcfg_markov_start_row_alpha_t;

typedef struct pcfg_model
{
  char  *name;
  pcfg_structure_t *structures;
  u32    struct_cnt;
  u32    struct_cnt_file;
  u64    pw_total;
  u64    total_keyspace;

  pcfg_terminal_list_t terminals[256][PCFG_VALUE_MAX];

  char encoding_from[PCFG_ENCODING_MAX];

  // markov pw len
  pcfg_markov_start_row_t pw_len_table;

  // markov structures
  pcfg_markov_start_row_t struct_start_row;
  pcfg_markov_row_t *struct_trans_table;

  // markov terminals
  pcfg_markov_row_t *markov_table_lower;
  pcfg_markov_row_t *markov_table_upper;
  pcfg_markov_row_t *markov_table_digit;
  pcfg_markov_row_t *markov_table_latin;
  pcfg_markov_row_t *markov_table_cyrillic;
  pcfg_markov_row_t *markov_table_arabic;
  pcfg_markov_row_t *markov_table_asian;
  pcfg_markov_row_t *markov_table_greek;
  pcfg_markov_row_t *markov_table_hebrew;
  pcfg_markov_row_t *markov_table_all;

  pcfg_markov_start_row_alpha_t start_row_alpha;
  pcfg_markov_start_row_alpha_t start_row_alpha_unicode;
  pcfg_markov_start_row_digit_t start_row_digit;

  float *char_freq;

  // omen
  u32    omen_max_cost;
  u64    omen_max_loops;
  u64    term_totals[256][PCFG_VALUE_MAX];

  pcfg_omen_extra_t *omen_data;

} pcfg_model_t;

typedef struct pcfg_gen
{
  // shared (all modes)
  u32               id;
  u32               dev_id;
  pcfg_model_t     *model;
  u64               generated;
  u64               curr_comb_idx;
  pcfg_candidate_t  burst_cand;
  u32               burst_size;
  u64               limit;

  // shared: prob + omen (modes 2-10)

  u32               curr_struct_idx;
  bool              skip_structure;

  // ahf (modes 0-1)

  u8                ahf_type;
  pcfg_heap_t      *ahf_heap;
  int               ahf_burst_left;
  bool              ahf_burst_first;
  pcfg_structure_t *ahf_structures;
  u32               ahf_struct_cnt;
  char              ahf_pw_cache[PCFG_PW_MAX];
  u8               *ahf_bloom;
  size_t            ahf_bloom_size;
  u64               ahf_rng_state;
  u64               ahf_terminals_min;
  u8                ahf_valid_types[256];
  u32               ahf_valid_types_cnt;
  bool              ahf_cand_unique;
  u64               ahf_estimated_unique_structs;

  // omen shared (modes 5-10)

  u32               omen_target_cost;
  u32               omen_max_target_cost;
  bool              omen_skip_cost;
  u8                omen_type;
  u64               omen_global_loop_idx;
  bool              omen_skip_loop;
  pcfg_omen_stats_t *omen_stats;
  u64               omen_reserved_budget;

  // omen cpu shared (modes 5,6,8,9)

  u64               omen_struct_keyspace;
  pcfg_omen_partition_t *omen_partitions;
  u32               omen_partition_cnt;
  u64               omen_current_chunk_max;

  // omen cpu non-linear (modes 5,8)

  bool              omen_lap_found_work;
  u64               omen_display_keyspace;
  u64               omen_skip_remainder;

  // omen by_cost (mode 9, also read in 5,7)

  u32               omen_by_cost_struct_idx;
  u32               omen_by_cost_struct_cnt;
  u64               omen_by_cost_display_chunk_max;
  u32               omen_by_cost_current;

  // omen cpu (modes 4,6)

  bool              omen_linear_has_work_unit;
  u64               omen_linear_current_work_id;
  u64               omen_linear_work_unit_consumed;

  // omen by_struct cpu (modes 8,9)

  u32               omen_by_struct_cost;
  u64               omen_by_struct_multicost_offset;
  u64               omen_by_struct_total_ks;
  u32               omen_by_struct_max_l;
  u8                omen_by_struct_s_cost;

  // gpu prob (mode 3)

  u32               gpu_prob_current_struct;
  u64               gpu_prob_current_local_idx;
  u64               gpu_prob_total_generated;

  // omen gpu (modes 7,10)

  pcfg_gpu_omen_batch_entry_t *omen_gpu_batch_entries;
  pcfg_gpu_omen_partition_t   *omen_gpu_partitions;
  pcfg_gpu_omen_structure_t   *omen_gpu_structures;
  u32               omen_gpu_batch_entry_cnt;
  u32               omen_gpu_partition_cnt;
  bool              omen_gpu_skip_current_struct;

} pcfg_gen_t;

typedef struct pcfg_chunk
{
  u32               cost_start;
  u32               cost_end;
  u32               struct_count; // number of active structs
  u32               struct_start; // first struct index (inclusive)
  u32               struct_end;   // last struct index (exclusive)

} pcfg_chunk_t;

typedef struct pcfg_ctx
{
  // shared (all modes)
  pcfg_model_t     *model;
  char             *pcfg_model_file;
  char             *pcfg_train_file;
  char             *pcfg_model_save_file;
  u64               pcfg_limit;
  u64               pcfg_skip;
  bool              enabled;
  bool              struct_shuffle;

  pcfg_gen_t      **generators;
  int               num_generators;
  int               num_active_generators;
  int              *active_map;

  pcfg_perf_threshold_t *perf_threshold;
  u32               global_max_structs;
  u64               words_generated;

  // ahf (modes 0-1)
  pcfg_ahf_type_t   ahf_type;

  // gpu prob (mode 3)
  pcfg_gpu_prob_ctx_t  *gpu_prob_ctx;
  pcfg_gpu_prob_data_t *gpu_prob_data;

  // gpu shared (modes 3,5,7)
  u32               data_buffer_num_parts;

  // omen gpu (modes 7,10)
  pcfg_gpu_omen_ctx_t  *omen_gpu_ctx;
  pcfg_gpu_omen_data_t *omen_gpu_data;

  // omen analysis (modes 5-10)
  u32               analysis_num_chunks;
  u64               analysis_total_data_size;
  u32               analysis_max_structs;
  u8               *analysis_struct_max_term_cost;
  pcfg_chunk_t     *analysis_chunks;

  // omen shared (modes 5-10)
  pcfg_chunk_t     *omen_chunks;
  u32               omen_num_chunks;
  u64               omen_max_loops;

  // omen skip/restore (modes 5-10)
  u64               omen_skip_remainder;
  u32               omen_skip_target_cost;
  u32               omen_skip_start_cost;
  bool              omen_skip_in_progress;
  bool              omen_cost_skip_done;        // guards interleaved BY_COST cost skip (multi-device idempotent)

  // dispatcher sync (prob linear + omen)
  hc_thread_mutex_t chunk_mutex;
  u64               omen_next_work_unit_idx;

  // pcfg loopback
  bool              loopback_enabled;
  HCFILE            loopback_fp;
  char             *loopback_pw_file;
  char             *loopback_model_file;
  u32               loopback_generation;
  hc_thread_mutex_t loopback_mutex;

} pcfg_ctx_t;

// generator

int         pcfg_gen_init                (hashcat_ctx_t *hashcat_ctx);
int         pcfg_gen_next                (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *g, char *out, u32 *len);
pcfg_gen_t *pcfg_gen_create              (hashcat_ctx_t *hashcat_ctx, int dev_id, int thread_id);
void        pcfg_gen_destroy             (pcfg_gen_t *g);

// ctx

int         pcfg_ctx_init                (hashcat_ctx_t *hashcat_ctx);
void        pcfg_ctx_destroy             (hashcat_ctx_t *hashcat_ctx);

void        pcfg_notify_cracked          (hashcat_ctx_t *hashcat_ctx, int device_id, int count);
#include "pcfg_model.h"
#include "pcfg_gpu_prob.h"
#include "pcfg_gpu_omen.h"
#include "pcfg_omen_stats.h"

#endif // HC_PCFG_H
