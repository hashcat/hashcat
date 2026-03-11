/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PCFG_GPU_PROB_H
#define INC_PCFG_GPU_PROB_H

#define PCFG_OMEN_MAX_TOKENS 16

typedef struct pcfg_gpu_prob_structure
{
  u64 cumulative;
  u64 keyspace;
  u32 token_cnt;
  u32 total_len;
  u32 block_indices[PCFG_OMEN_MAX_TOKENS];
  u32 divisors[PCFG_OMEN_MAX_TOKENS];
  u64 recips64[PCFG_OMEN_MAX_TOKENS];
  u32 offsets[PCFG_OMEN_MAX_TOKENS];
  u8  types[PCFG_OMEN_MAX_TOKENS];
  u8  lengths[PCFG_OMEN_MAX_TOKENS];
  u8  padding[8];

} pcfg_gpu_prob_structure_t;

#ifndef PCFG_TERM_BLOCK_INC
#define PCFG_TERM_BLOCK_INC

typedef struct pcfg_term_block
{
  u64  data_offset;
  u32  count;
  u32  stride_words;
  u32  stride_bytes;
  u32  padding[3];

} pcfg_term_block_t;

#endif // PCFG_TERM_BLOCK_INC

#ifdef IS_METAL

#define KERN_ATTR_PCFG_GPU_PROB                                       \
  GLOBAL_AS         pw_t                      *pws_buf,               \
  GLOBAL_AS   const u32                       *data_buffer,           \
  GLOBAL_AS   const pcfg_term_block_t         *term_blocks,           \
  GLOBAL_AS   const pcfg_gpu_prob_structure_t *structures,            \
  CONSTANT_AS const u64                       *cumulative_offsets,    \
  CONSTANT_AS const u64                       &base_off,              \
  CONSTANT_AS const u32                       &struct_cnt,            \
  CONSTANT_AS const u64                       &gid_max,               \
  CONSTANT_AS const u32                       &num_devices,           \
  CONSTANT_AS const u32                       &pw_max,                \
              uint3 hc_gid [[ thread_position_in_grid ]],             \
              uint3 hc_lid [[ thread_position_in_threadgroup ]],      \
              uint3 hc_lsz [[ threads_per_threadgroup ]],             \
              uint3 hc_bid [[ threadgroup_position_in_grid ]]

#else // CUDA, HIP, OpenCL

#define KERN_ATTR_PCFG_GPU_PROB                                       \
  GLOBAL_AS         pw_t                      *pws_buf,               \
  GLOBAL_AS   const u32                       *data_buffer,           \
  GLOBAL_AS   const pcfg_term_block_t         *term_blocks,           \
  GLOBAL_AS   const pcfg_gpu_prob_structure_t *structures,            \
  GLOBAL_AS   const u64                       *cumulative_offsets,    \
              const u64                        base_off,              \
              const u32                        struct_cnt,            \
              const u64                        gid_max,               \
              const u32                        num_devices,           \
              const u32                        pw_max

#endif // IS_METAL

#endif // INC_PCFG_GPU_PROB_H
