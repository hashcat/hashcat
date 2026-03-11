/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_GPU_PROB_H
#define HC_PCFG_GPU_PROB_H

#include "common.h"
#include "types.h"
#include "pcfg_common.h"
#include "inc_pcfg_gpu_prob.h"

// data structures
typedef struct pcfg_gpu_prob_data
{
  u32              *data_buffer;
  u64               data_buffer_words;

  pcfg_term_block_t *term_blocks;
  u32               term_block_cnt;

  pcfg_gpu_prob_structure_t *structures;
  u32               struct_cnt;

  u64               total_keyspace;

  int               type_len_to_block[PCFG_OMEN_TYPE_MAX][PCFG_OMEN_LEN_MAX];

} pcfg_gpu_prob_data_t;

// global ctx

typedef struct pcfg_gpu_prob_ctx
{
  pcfg_gpu_prob_data_t *linear_data;
  u32               num_devices;
  u64               skip;
  u64               limit;
  u64               effective_keyspace;
  bool              initialized;

} pcfg_gpu_prob_ctx_t;

// prototypes

int   pcfg_gpu_prob_data_init        (hashcat_ctx_t *hashcat_ctx, const pcfg_model_t *m, pcfg_gpu_prob_data_t **out);
void  pcfg_gpu_prob_data_destroy     (pcfg_gpu_prob_data_t *lin);

int   pcfg_gpu_prob_ctx_init         (hashcat_ctx_t *hashcat_ctx, pcfg_gpu_prob_data_t *lin, u32 num_devices, u64 skip, u64 limit, pcfg_gpu_prob_ctx_t **out);
void  pcfg_gpu_prob_ctx_destroy      (pcfg_gpu_prob_ctx_t *ctx);

int   pcfg_gpu_prob_generate_direct  (const u32 *data_buffer, const pcfg_term_block_t *term_blocks, const pcfg_gpu_prob_structure_t *structure, u64 local_idx, char *pw_out, u32 *pw_len_out);

void  build_pattern_string           (const pcfg_gpu_prob_structure_t *s, char *out, size_t out_size);

void  pcfg_gpu_prob_gen_init         (pcfg_gen_t *gen, u32 shard_id, pcfg_gpu_prob_ctx_t *ctx);
int   pcfg_gpu_prob_get_status_info  (const pcfg_gpu_prob_ctx_t *ctx, const pcfg_gen_t *gen, pcfg_gpu_prob_status_info_t *info);

#endif // HC_PCFG_GPU_PROB_H
