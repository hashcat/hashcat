/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg_gpu_omen.h)
#endif

// Helper functions
DECLSPEC u64 mulhi64 (const u64 a, const u64 b)
{
  const u32 a_lo = (u32) a;
  const u32 a_hi = (u32) (a >> 32);
  const u32 b_lo = (u32) b;
  const u32 b_hi = (u32) (b >> 32);

  const u64 p0 = (u64) a_lo * b_lo;
  const u64 p1 = (u64) a_lo * b_hi;
  const u64 p2 = (u64) a_hi * b_lo;
  const u64 p3 = (u64) a_hi * b_hi;

  const u32 p0_hi = (u32) (p0 >> 32);
  const u32 p1_lo = (u32) p1;
  const u32 p1_hi = (u32) (p1 >> 32);
  const u32 p2_lo = (u32) p2;
  const u32 p2_hi = (u32) (p2 >> 32);

  const u64 sum1 = (u64) p0_hi + p1_lo + p2_lo;
  const u32 carry = (u32) (sum1 >> 32);

  return p3 + p1_hi + p2_hi + carry;
}

// Find batch entry by global index (binary search)
DECLSPEC HC_INLINE u32 find_batch_entry_idx (GLOBAL_AS const pcfg_gpu_omen_batch_entry_t *batch_entries, const u32 batch_entry_cnt, const u64 global_idx)
{
  if (batch_entry_cnt == 1) return 0;

  if (batch_entry_cnt == 2)
  {
    return (global_idx >= batch_entries[1].cumulative_start) ? 1 : 0;
  }

  u32 l = 0;
  u32 r = batch_entry_cnt;

  #pragma unroll 4
  while (l < r)
  {
    const u32 mid = (l + r) >> 1;

    if (batch_entries[mid].cumulative_end <= global_idx)
    {
      l = mid + 1;
    }
    else if (batch_entries[mid].cumulative_start > global_idx)
    {
      r = mid;
    }
    else
    {
      return mid;
    }
  }

  return (l < batch_entry_cnt) ? l : batch_entry_cnt - 1;
}

// Find partition by local index within structure (binary search)
DECLSPEC HC_INLINE u32 find_partition_idx (GLOBAL_AS const pcfg_gpu_omen_partition_t *partitions, const u32 partition_offset, const u32 partition_count, const u64 local_idx)
{
  if (partition_count == 1) return 0;

  if (partition_count == 2)
  {
    const u32 p1_idx = partition_offset + 1;
    return (local_idx >= partitions[p1_idx].local_offset) ? 1 : 0;
  }

  u32 l = 0;
  u32 r = partition_count;

  #pragma unroll 4
  while (l < r)
  {
    const u32 mid = (l + r) >> 1;
    const u32 p_idx = partition_offset + mid;

    if (partitions[p_idx].local_end <= local_idx)
    {
      l = mid + 1;
    }
    else if (partitions[p_idx].local_offset > local_idx)
    {
      r = mid;
    }
    else
    {
      return mid;
    }
  }

  return (l < partition_count) ? l : partition_count - 1;
}

// Compute slot_map index from type and length
DECLSPEC HC_INLINE u32 slot_map_index (const u8 ty, const u8 len)
{
  return ((u32) ty << 8) | (u32) len;
}

// Helper to access multi-part data buffer
DECLSPEC u32 get_terminal_data (GLOBAL_AS const u32 *p1, GLOBAL_AS const u32 *p2, GLOBAL_AS const u32 *p3, GLOBAL_AS const u32 *p4, GLOBAL_AS const u32 *p5, GLOBAL_AS const u32 *p6, GLOBAL_AS const u32 *p7, GLOBAL_AS const u32 *p8, const u32 num_parts, GLOBAL_AS const u64 *part_offsets, const u64 abs_addr)
{
  // Fast path: single part
  if (num_parts == 1)
  {
    return p1[abs_addr];
  }

  // Multi-part logic: find which part contains the address
  if (abs_addr < part_offsets[1]) return p1[abs_addr]; // offset 0 assumed for part 1

  if (num_parts > 1 && abs_addr < part_offsets[2]) return p2[abs_addr - part_offsets[1]];
  if (num_parts > 2 && abs_addr < part_offsets[3]) return p3[abs_addr - part_offsets[2]];
  if (num_parts > 3 && abs_addr < part_offsets[4]) return p4[abs_addr - part_offsets[3]];
  if (num_parts > 4 && abs_addr < part_offsets[5]) return p5[abs_addr - part_offsets[4]];
  if (num_parts > 5 && abs_addr < part_offsets[6]) return p6[abs_addr - part_offsets[5]];
  if (num_parts > 6 && abs_addr < part_offsets[7]) return p7[abs_addr - part_offsets[6]];

  // Fallback to last part
  return p8[abs_addr - part_offsets[7]];
}

// Password generation - AoS version
DECLSPEC void pcfg_gpu_omen_generate_pw (PRIVATE_AS u32 *pw_buf, GLOBAL_AS const u32 *data_p1, GLOBAL_AS const u32 *data_p2, GLOBAL_AS const u32 *data_p3, GLOBAL_AS const u32 *data_p4, GLOBAL_AS const u32 *data_p5, GLOBAL_AS const u32 *data_p6, GLOBAL_AS const u32 *data_p7, GLOBAL_AS const u32 *data_p8, const u32 num_data_parts, GLOBAL_AS const u64 *part_offsets, GLOBAL_AS const pcfg_term_block_t *term_blocks, GLOBAL_AS const pcfg_gpu_omen_structure_t *structure, GLOBAL_AS const pcfg_gpu_omen_slot_map_t *slot_maps, GLOBAL_AS const pcfg_gpu_omen_partition_t *partition, const u64 partition_local_idx)
{
  const u32 token_cnt = structure->token_cnt;

  u64 work_idx = partition_local_idx;

  u32 term_indices[PCFG_OMEN_MAX_TOKENS];

  // Mixed-radix decomposition using partition costs (reverse order)
  #pragma unroll
  for (int k = PCFG_OMEN_MAX_TOKENS - 1; k >= 0; k--)
  {
    if (k < (int) token_cnt)
    {
      const u8 ty   = structure->types[k];
      const u8 ln   = structure->lengths[k];
      const u8 cost = partition->costs[k];

      const u32 sm_idx = slot_map_index (ty, ln);
      GLOBAL_AS const pcfg_gpu_omen_slot_map_t *sm = &slot_maps[sm_idx];

      const u32 count = sm->counts[cost];

      if (count <= 1)
      {
        term_indices[k] = 0;
      }
      else
      {
        /*
        u64 q = work_idx / count;
        term_indices[k] = (u32)(work_idx - q * count);
        work_idx = q;
        */

        const u64 recip = sm->recip[cost];
        const u64 q64 = mulhi64 (work_idx, recip);
        term_indices[k] = (u32) (work_idx - q64 * count);
        work_idx = q64;
      }
    }
  }

  // Assemble password (forward order)
  #pragma unroll
  for (u32 k = 0; k < PCFG_OMEN_MAX_TOKENS; k++)
  {
    if (k >= token_cnt) break;

    const u8 ty   = structure->types[k];
    const u8 ln   = structure->lengths[k];
    const u8 cost = partition->costs[k];

    const u32 sm_idx = slot_map_index (ty, ln);
    GLOBAL_AS const pcfg_gpu_omen_slot_map_t *sm = &slot_maps[sm_idx];

    // Real terminal index = ranks[cost] + term_idx
    const u32 real_rank    = sm->ranks[cost] + term_indices[k];

    const u32 blk_idx = structure->block_indices[k];
    GLOBAL_AS const pcfg_term_block_t *blk = &term_blocks[blk_idx];

    const u32 len          = ln;
    const u32 pos          = structure->offsets[k];
    const u32 stride_words = blk->stride_words;
    const u64 block_base   = blk->data_offset;

    // AoS: all words in the terminal are contiguous
    const u64 src_base     = block_base + (u64) real_rank * stride_words;
    const u32 base_word    = pos >> 2;
    const u32 bit_off      = (pos & 3) << 3;

    if (bit_off == 0)
    {
      // Aligned path
      for (u32 w = 0; w < 64; w++)
      {
        if (w >= stride_words) break;
        if (w * 4 >= len) break;

        // AoS: contiguous access
        const u64 abs_addr = src_base + w;

        u32 val = get_terminal_data (data_p1, data_p2, data_p3, data_p4, data_p5, data_p6, data_p7, data_p8, num_data_parts, part_offsets, abs_addr);

        const u32 remaining = len - w * 4;

        if (remaining < 4)
        {
          val &= (1u << (remaining * 8)) - 1;
        }

        pw_buf[base_word + w] = val;
      }
    }
    else
    {
      // Unaligned path
      for (u32 w = 0; w < 64; w++)
      {
        if (w >= stride_words) break;
        if (w * 4 >= len) break;

        // AoS: contiguous access
        const u64 abs_addr = src_base + w;

        u32 val = get_terminal_data (data_p1, data_p2, data_p3, data_p4, data_p5, data_p6, data_p7, data_p8, num_data_parts, part_offsets, abs_addr);

        const u32 remaining = len - w * 4;

        if (remaining < 4)
        {
          val &= (1u << (remaining * 8)) - 1;
        }

        const u32 dw = base_word + w;

        pw_buf[dw]     |= val << bit_off;
        pw_buf[dw + 1] |= val >> (32 - bit_off);
      }
    }
  }
}

// Main kernel - short passwords (0-31 bytes)
KERNEL_FQ KERNEL_FA void pcfg_gpu_omen_generate_opti (KERN_ATTR_PCFG_GPU_OMEN)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 global_idx = base_off + gid * num_devices;

  // Find batch entry (structure)
  const u32 be_idx = find_batch_entry_idx (batch_entries, batch_entry_cnt, global_idx);

  GLOBAL_AS const pcfg_gpu_omen_batch_entry_t *be = &batch_entries[be_idx];

  // Bounds check
  if (global_idx < be->cumulative_start || global_idx >= be->cumulative_end) return;

  // Local index within structure
  const u64 struct_local_idx = global_idx - be->cumulative_start;

  // Find partition
  const u32 p_rel_idx = find_partition_idx (partitions, be->partition_offset, be->partition_count, struct_local_idx);
  const u32 p_idx = be->partition_offset + p_rel_idx;

  GLOBAL_AS const pcfg_gpu_omen_partition_t *part = &partitions[p_idx];

  // Bounds check
  if (struct_local_idx < part->local_offset || struct_local_idx >= part->local_end) return;

  // Index within partition (accounting for inner offset)
  const u64 partition_local_idx = (struct_local_idx - part->local_offset) + part->partition_inner_offset;

  // Get structure
  GLOBAL_AS const pcfg_gpu_omen_structure_t *s = &structures[be->struct_idx];

  // Generate password
  const u32 pw_words = (pw_max + 3) >> 2;

  u32 pw_buf[15];

  #pragma unroll
  for (u32 i = 0; i < 15; i++) pw_buf[i] = 0;

  pcfg_gpu_omen_generate_pw (pw_buf, data_p1, data_p2, data_p3, data_p4, data_p5, data_p6, data_p7, data_p8, num_data_parts, part_offsets, term_blocks, s, slot_maps, part, partition_local_idx);

  // Write output
  GLOBAL_AS pw_t *dest = &pws_buf[gid];

  for (u32 i = 0; i < pw_words; i++) dest->i[i] = pw_buf[i];

  dest->pw_len = s->total_len;
}

// Main kernel - all password lengths (0-255 bytes)
KERNEL_FQ KERNEL_FA void pcfg_gpu_omen_generate (KERN_ATTR_PCFG_GPU_OMEN)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 global_idx = base_off + gid * num_devices;

  // Find batch entry (structure)
  const u32 be_idx = find_batch_entry_idx (batch_entries, batch_entry_cnt, global_idx);

  GLOBAL_AS const pcfg_gpu_omen_batch_entry_t *be = &batch_entries[be_idx];

  // Bounds check
  if (global_idx < be->cumulative_start || global_idx >= be->cumulative_end) return;

  // Local index within structure
  const u64 struct_local_idx = global_idx - be->cumulative_start;

  // Find partition
  const u32 p_rel_idx = find_partition_idx (partitions, be->partition_offset, be->partition_count, struct_local_idx);
  const u32 p_idx = be->partition_offset + p_rel_idx;

  GLOBAL_AS const pcfg_gpu_omen_partition_t *part = &partitions[p_idx];

  // Bounds check
  if (struct_local_idx < part->local_offset || struct_local_idx >= part->local_end) return;

  // Index within partition
  const u64 partition_local_idx = (struct_local_idx - part->local_offset) + part->partition_inner_offset;

  // Get structure
  GLOBAL_AS const pcfg_gpu_omen_structure_t *s = &structures[be->struct_idx];

  const u32 total_len = s->total_len;
  const u32 pw_words = (pw_max + 3) >> 2;

  GLOBAL_AS pw_t *dest = &pws_buf[gid];

  if (total_len <= 31)
  {
    // Fast path: 9 words in registers (8 + 1 spill for unaligned write)
    u32 pw_buf[9];

    pw_buf[0] = 0;
    pw_buf[1] = 0;
    pw_buf[2] = 0;
    pw_buf[3] = 0;
    pw_buf[4] = 0;
    pw_buf[5] = 0;
    pw_buf[6] = 0;
    pw_buf[7] = 0;
    pw_buf[8] = 0;

    pcfg_gpu_omen_generate_pw (pw_buf, data_p1, data_p2, data_p3, data_p4, data_p5, data_p6, data_p7, data_p8, num_data_parts, part_offsets, term_blocks, s, slot_maps, part, partition_local_idx);

    dest->i[0] = pw_buf[0];
    dest->i[1] = pw_buf[1];
    dest->i[2] = pw_buf[2];
    dest->i[3] = pw_buf[3];
    dest->i[4] = pw_buf[4];
    dest->i[5] = pw_buf[5];
    dest->i[6] = pw_buf[6];
    dest->i[7] = pw_buf[7];

    for (u32 i = 8; i < pw_words; i++) dest->i[i] = 0;
  }
  else if (total_len <= 63)
  {
    // Medium path: 17 words in registers (16 + 1 spill for unaligned write)
    u32 pw_buf[17];

    #pragma unroll
    for (u32 i = 0; i < 17; i++) pw_buf[i] = 0;

    pcfg_gpu_omen_generate_pw (pw_buf, data_p1, data_p2, data_p3, data_p4, data_p5, data_p6, data_p7, data_p8, num_data_parts, part_offsets, term_blocks, s, slot_maps, part, partition_local_idx);

    #pragma unroll
    for (u32 i = 0; i < 16; i++) dest->i[i] = pw_buf[i];

    for (u32 i = 16; i < pw_words; i++) dest->i[i] = 0;
  }
  else
  {
    // Slow path: full pw_t
    pw_t pw;

    for (u32 i = 0; i < pw_words; i++) pw.i[i] = 0;

    pcfg_gpu_omen_generate_pw (pw.i, data_p1, data_p2, data_p3, data_p4, data_p5, data_p6, data_p7, data_p8, num_data_parts, part_offsets, term_blocks, s, slot_maps, part, partition_local_idx);

    pw.pw_len = total_len;

    pws_buf[gid] = pw;

    return;
  }

  dest->pw_len = total_len;
}
