/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PCFG_GPU_OMEN_H
#define INC_PCFG_GPU_OMEN_H

#define PCFG_OMEN_MAX_TOKENS 16
#define PCFG_OMEN_MAX_COST 32

// Slot map for GPU (one for each type/len combination used)
typedef struct pcfg_gpu_omen_slot_map_t
{
  u32 ranks[PCFG_OMEN_MAX_COST];   // Starting rank per cost
  u32 counts[PCFG_OMEN_MAX_COST];  // Count per cost
  u64 recip[PCFG_OMEN_MAX_COST];   // Reciprocal per fast div

} pcfg_gpu_omen_slot_map_t;

// Linearized structure for GPU
typedef struct pcfg_gpu_omen_structure
{
  u32 token_cnt;
  u32 total_len;
  u32 block_indices[PCFG_OMEN_MAX_TOKENS];
  u32 offsets[PCFG_OMEN_MAX_TOKENS];      // Byte offset per token (pre-computed)
  u8  types[PCFG_OMEN_MAX_TOKENS];
  u8  lengths[PCFG_OMEN_MAX_TOKENS];
  u8  padding[8];

} pcfg_gpu_omen_structure_t;

// Entry for active structure in the current batch
typedef struct pcfg_gpu_omen_batch_entry
{
  u32 struct_idx;           // Index in structures[]
  u32 partition_offset;     // Offset in partitions[] buffer
  u32 partition_count;      // Number of partitions for this structure
  u32 padding;
  u64 cumulative_start;     // Global start index in the batch
  u64 cumulative_end;       // cumulative_start + struct_keyspace

} pcfg_gpu_omen_batch_entry_t;

// Flattened partition for GPU
typedef struct pcfg_gpu_omen_partition
{
  u64 local_offset;
  u64 local_end;
  u64 partition_inner_offset;
  u8  costs[PCFG_OMEN_MAX_TOKENS];
  u8  padding[8];

} pcfg_gpu_omen_partition_t;

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

// Kernel attributes
#ifdef IS_METAL

#define KERN_ATTR_PCFG_GPU_OMEN                                       \
  GLOBAL_AS         pw_t                        *pws_buf,             \
  GLOBAL_AS   const u32                         *data_p1,             \
  GLOBAL_AS   const u32                         *data_p2,             \
  GLOBAL_AS   const u32                         *data_p3,             \
  GLOBAL_AS   const u32                         *data_p4,             \
  GLOBAL_AS   const u32                         *data_p5,             \
  GLOBAL_AS   const u32                         *data_p6,             \
  GLOBAL_AS   const u32                         *data_p7,             \
  GLOBAL_AS   const u32                         *data_p8,             \
  GLOBAL_AS   const u64                         *part_offsets,        \
  GLOBAL_AS   const pcfg_term_block_t           *term_blocks,         \
  GLOBAL_AS   const pcfg_gpu_omen_structure_t   *structures,          \
  GLOBAL_AS   const pcfg_gpu_omen_slot_map_t    *slot_maps,           \
  GLOBAL_AS   const pcfg_gpu_omen_batch_entry_t *batch_entries,       \
  GLOBAL_AS   const pcfg_gpu_omen_partition_t   *partitions,          \
  CONSTANT_AS const u32                         &num_data_parts,      \
  CONSTANT_AS const u64                         &base_off,            \
  CONSTANT_AS const u32                         &batch_entry_cnt,     \
  CONSTANT_AS const u64                         &gid_max,             \
  CONSTANT_AS const u32                         &num_devices,         \
  CONSTANT_AS const u32                         &pw_max,              \
              uint3 hc_gid [[ thread_position_in_grid ]],             \
              uint3 hc_lid [[ thread_position_in_threadgroup ]],      \
              uint3 hc_lsz [[ threads_per_threadgroup ]],             \
              uint3 hc_bid [[ threadgroup_position_in_grid ]]

#else // CUDA, HIP, OpenCL

#define KERN_ATTR_PCFG_GPU_OMEN                                       \
  GLOBAL_AS         pw_t                        *pws_buf,             \
  GLOBAL_AS   const u32                         *data_p1,             \
  GLOBAL_AS   const u32                         *data_p2,             \
  GLOBAL_AS   const u32                         *data_p3,             \
  GLOBAL_AS   const u32                         *data_p4,             \
  GLOBAL_AS   const u32                         *data_p5,             \
  GLOBAL_AS   const u32                         *data_p6,             \
  GLOBAL_AS   const u32                         *data_p7,             \
  GLOBAL_AS   const u32                         *data_p8,             \
  GLOBAL_AS   const u64                         *part_offsets,        \
  GLOBAL_AS   const pcfg_term_block_t           *term_blocks,         \
  GLOBAL_AS   const pcfg_gpu_omen_structure_t   *structures,          \
  GLOBAL_AS   const pcfg_gpu_omen_slot_map_t    *slot_maps,           \
  GLOBAL_AS   const pcfg_gpu_omen_batch_entry_t *batch_entries,       \
  GLOBAL_AS   const pcfg_gpu_omen_partition_t   *partitions,          \
              const u32                          num_data_parts,      \
              const u64                          base_off,            \
              const u32                          batch_entry_cnt,     \
              const u64                          gid_max,             \
              const u32                          num_devices,         \
              const u32                          pw_max

#endif // IS_METAL

#endif // INC_PCFG_GPU_OMEN_H
