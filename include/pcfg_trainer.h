/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_TRAINER_H
#define HC_PCFG_TRAINER_H

#include "pcfg_common.h"

#define TRAINER_BLOCK_SIZE 100000 // lines per block
#define TRAINER_NUM_BLOCKS 2      // double buffering

// trainer data structures

typedef struct
{
  int8_t x;
  int8_t y;

} key_coord_t;

typedef struct
{
  const char  *name;
  key_coord_t  map[256];
  bool         initialized;
  const char **rows;

} keyboard_layout_t;

// Structure for keeping track of top password candidates
typedef struct
{
  double prob;
  char   password[256];
  u32    struct_idx;

} pcfg_top_pw_t;

typedef struct
{
  u32    index;
  u64    count;

} pcfg_markov_start_row_entry_t;

typedef struct ht_node
{
  char  *key;
  u64    cnt;
  u64    full_hash;
  struct ht_node *next;

} ht_node_t;

typedef struct term_node
{
  u8     type;
  u16    len;
  char  *val;
  u64    cnt;
  u64    full_hash;
  struct term_node *next;

} term_node_t;

typedef struct mem_pool
{
  char  *ptr;
  size_t offset;
  size_t size;
  struct mem_pool *next;

} mem_pool_t;

typedef struct line_block
{
  char **lines;
  u32   *lens;
  u64   *weighs;
  size_t count;
  size_t capacity;

} line_block_t;

typedef struct block_queue
{
  line_block_t     *blocks[TRAINER_NUM_BLOCKS];
  volatile int      ready[TRAINER_NUM_BLOCKS];   // 1 = ready for processing
  volatile int      current_read;                // index where the reader writes
  volatile int      current_process;             // index where the main reads
  volatile bool     done;                        // reader has finished
  hc_thread_mutex_t mutex;
  hc_thread_cond_t  cond_ready;
  hc_thread_cond_t  cond_free;

} block_queue_t;

typedef struct reader_ctx
{
  block_queue_t    *queue;
  HCFILE           *fp;
  char             *line_buf;
  size_t            line_buf_size;
  int               train_format;

} reader_ctx_t;

typedef struct pcfg_trainer
{
  ht_node_t       **struct_ht;
  term_node_t     **global_term_ht;

  u64               ht_size;
  u64               file_lines;
  size_t            pool_block_size;

  u64               term_totals[256][PCFG_VALUE_MAX];
  u64               struct_total;
  u64               pw_cnt;
  mem_pool_t       *pool_head;

  u64               memory_limit;
  u64               memory_used;

  // counting Bloom Filter
  u8               *admit_counters;    // Each byte contains 2 counters (low nibble + high nibble)
  u64               admit_mask;        // Address mask (size - 1)

  // markov pw len
  u64               pw_len_counts[256];

  // markov structures
  u64              *struct_start_counts;
  u64              *struct_trans_counts;

  // markov terminals
  u64              *markov_start_alpha;
  u64              *markov_start_alpha_unicode;
  u64              *markov_start_digit;
  u64              *markov_table;
  u64              *char_freq;

} pcfg_trainer_t;

pcfg_trainer_t *pcfg_trainer_init             (hashcat_ctx_t *hashcat_ctx, const char *train_file, u64 min_elements);
void            pcfg_trainer_destroy          (pcfg_trainer_t *t);
int             pcfg_trainer_add_pw           (pcfg_trainer_t *t, char *pw, u32 len, u64 count, bool use_filter, u16 filter_threshold, bool use_data_filters);
int             pcfg_trainer_from_file        (hashcat_ctx_t *hashcat_ctx, pcfg_trainer_t *t, const char *path);
bool            pcfg_trainer_export_to_file   (hashcat_ctx_t *hashcat_ctx, pcfg_trainer_t *t, const char *path);
bool            pcfg_trainer_import_from_file (hashcat_ctx_t *hashcat_ctx, pcfg_trainer_t *t, const char *path);

void            init_char_types_lut           (void);
bool            is_unicode_script_type        (u8 type);

#endif // HC_PCFG_TRAINER_H
