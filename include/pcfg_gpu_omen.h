/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_GPU_OMEN_H
#define HC_PCFG_GPU_OMEN_H

#include "common.h"
#include "types.h"
#include "pcfg_common.h"
#include "inc_pcfg_gpu_omen.h"

// forward declarations
struct pcfg_model;
typedef struct pcfg_model pcfg_model_t;

// data structures
typedef struct pcfg_gpu_omen_data
{
  u32              *data_buffer;
  u64               data_buffer_words;

  pcfg_term_block_t *term_blocks;
  u32               term_block_cnt;

  int               type_len_to_block[PCFG_OMEN_TYPE_MAX][PCFG_OMEN_LEN_MAX];

  pcfg_gpu_omen_structure_t *structures;
  u32               struct_cnt;

  u8               *struct_costs;
  u8               *struct_min_term_cost;
  u64              *cost_keyspace;

  u64               total_keyspace;  // estimated total keyspace (sum of cost_keyspace)

  // fast skip data
  u64              *sorted_keyspace;
  u64              *prefix_keyspace;
  u64               burst_size;
  u64               max_loops;

} pcfg_gpu_omen_data_t;

// global ctx
typedef struct pcfg_gpu_omen_ctx
{
  pcfg_gpu_omen_data_t *linear_data;
  pcfg_model_t     *model;
  u32               num_devices;
  u64               skip;
  u64               limit;
  u64               effective_keyspace;
  bool              initialized;

} pcfg_gpu_omen_ctx_t;

// Function Prototypes

int   pcfg_gpu_omen_data_init             (hashcat_ctx_t *hashcat_ctx, const pcfg_model_t *m, pcfg_gpu_omen_data_t **out);
void  pcfg_gpu_omen_data_destroy          (pcfg_gpu_omen_data_t *lin);

int   pcfg_gpu_omen_ctx_init              (hashcat_ctx_t *hashcat_ctx, pcfg_gpu_omen_data_t *lin, pcfg_model_t *model, u32 num_devices, u64 skip, u64 limit, pcfg_gpu_omen_ctx_t **out);
void  pcfg_gpu_omen_ctx_destroy           (pcfg_gpu_omen_ctx_t *ctx);

u64   pcfg_gpu_omen_generate_partitions   (const pcfg_gpu_omen_structure_t *s, const pcfg_omen_extra_t *omen, int remaining_cost, u64 range_start, u64 range_len, pcfg_gpu_omen_partition_t *out_partitions, u32 max_partitions, u32 *out_count);

int   pcfg_gpu_omen_gen_init              (pcfg_gen_t *gen, u32 shard_id);
int   pcfg_gpu_omen_get_status_info       (const hashcat_ctx_t *hashcat_ctx, const pcfg_gen_t *gen, pcfg_gpu_omen_status_info_t *info);

#endif // HC_PCFG_GPU_OMEN_H
