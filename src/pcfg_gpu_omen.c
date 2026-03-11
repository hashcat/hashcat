#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "user_options.h"
#include "pcfg_common.h"

// Temporary array for sort
typedef struct
{
  u64 keyspace;
  u32 index;

} ks_pair_t;

// Descending sort
static int cmp_desc (const void *a, const void *b)
{
  const ks_pair_t *pa = (const ks_pair_t *) a;
  const ks_pair_t *pb = (const ks_pair_t *) b;

  if (pb->keyspace > pa->keyspace) return 1;
  if (pb->keyspace < pa->keyspace) return -1;
  return 0;
}

static int pcfg_gpu_omen_build_skip_data (hashcat_ctx_t *hashcat_ctx, pcfg_gpu_omen_data_t *lin, const pcfg_model_t *m)
{
  user_options_t *user_options = hashcat_ctx->user_options;

  const u32 struct_cnt = lin->struct_cnt;

  lin->burst_size = user_options->pcfg_burst_size;
  lin->max_loops = m->omen_max_loops > 0 ? m->omen_max_loops : 1;

  ks_pair_t *pairs = (ks_pair_t *) hccalloc (struct_cnt, sizeof (ks_pair_t));

  if (pairs == NULL) return -1;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    pairs[i].keyspace = m->structures[i].keyspace;
    pairs[i].index = i;
  }

  qsort (pairs, struct_cnt, sizeof (ks_pair_t), cmp_desc);

  // Allocate final arrays
  lin->sorted_keyspace = (u64 *) hccalloc (struct_cnt, sizeof (u64));
  lin->prefix_keyspace = (u64 *) hccalloc (struct_cnt + 1, sizeof (u64));

  if (lin->sorted_keyspace == NULL || lin->prefix_keyspace == NULL)
  {
    hcfree (pairs);
    return -1;
  }

  lin->prefix_keyspace[0] = 0;

  for (u32 i = 0; i < struct_cnt; i++)
  {
    lin->sorted_keyspace[i] = pairs[i].keyspace;
    lin->prefix_keyspace[i + 1] = lin->prefix_keyspace[i] + pairs[i].keyspace;
  }
  hcfree (pairs);

  return 0;
}
// Data Initialization

int pcfg_gpu_omen_data_init (hashcat_ctx_t *hashcat_ctx, const pcfg_model_t *m, pcfg_gpu_omen_data_t **out)
{
  if (m == NULL || out == NULL) return -1;
  if (m->omen_data == NULL) return -1;

  pcfg_gpu_omen_data_t *lin = (pcfg_gpu_omen_data_t *) hccalloc (1, sizeof (pcfg_gpu_omen_data_t));

  if (lin == NULL) return -1;

  // Initialize type_len_to_block mapping
  for (int t = 0; t < PCFG_OMEN_TYPE_MAX; t++)
  {
    for (int l = 0; l < PCFG_OMEN_LEN_MAX; l++)
    {
      lin->type_len_to_block[t][l] = -1;
    }
  }

  // Discover unique (type, length) pairs
  u32 block_cnt = 0;

  for (u32 si = 0; si < m->struct_cnt; si++)
  {
    const pcfg_structure_t *s = &m->structures[si];

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      const u32 ty = s->types[k] & 0x7F;
      const u32 ln = s->lengths[k];

      if (lin->type_len_to_block[ty][ln] < 0)
      {
        lin->type_len_to_block[ty][ln] = (int) block_cnt;
        block_cnt++;
      }
    }
  }

  lin->term_block_cnt = block_cnt;

  // Allocate and configure term_blocks
  const size_t blocks_size = block_cnt * sizeof (pcfg_term_block_t);

  lin->term_blocks = (pcfg_term_block_t *) hc_alloc_aligned (32, blocks_size);

  if (lin->term_blocks == NULL)
  {
    event_log_error (hashcat_ctx, "! failed to alloc lin->term_blocks with size %" PRIu64, (u64) 32 * blocks_size);
    hcfree (lin);
    return -1;
  }

  memset (lin->term_blocks, 0, blocks_size);

  u64 data_offset_words = 0;

  for (int t = 0; t < PCFG_OMEN_TYPE_MAX; t++)
  {
    for (int l = 0; l < PCFG_OMEN_LEN_MAX; l++)
    {
      const int block_idx = lin->type_len_to_block[t][l];

      if (block_idx >= 0)
      {
        const pcfg_terminal_list_t *list = &m->terminals[t][l];

        pcfg_term_block_t *blk = &lin->term_blocks[block_idx];

        if (list->cnt > PCFG_MAX_TERMINALS)
        {
          event_log_error (hashcat_ctx, "! list->cnt (%lu) > PCFG_MAX_TERMINALS (%d)", (unsigned long) list->cnt, PCFG_MAX_TERMINALS);
          hc_free_aligned ((void **) &lin->term_blocks);
          hcfree (lin);
          return -1;
        }

        const u32 stride_bytes = calc_aligned_stride_bytes (l);
        const u32 stride_words = stride_bytes / sizeof (u32);

        blk->data_offset  = data_offset_words;
        blk->count        = list->cnt;
        blk->stride_words = stride_words;
        blk->stride_bytes = l;

        data_offset_words += (u64) list->cnt * stride_words;
      }
    }
  }

  lin->data_buffer_words = data_offset_words;

  // Allocate and pack data_buffer
  const size_t data_size = (size_t) data_offset_words * sizeof (u32);
  const size_t aligned_data_size = (data_size + PCFG_OMEN_ALIGN - 1) & ~(PCFG_OMEN_ALIGN - 1);

  lin->data_buffer = (u32 *) hc_alloc_aligned (PCFG_OMEN_ALIGN, aligned_data_size);

  if (lin->data_buffer == NULL)
  {
    event_log_error (hashcat_ctx, "! failed to alloc lin->data_buffer with size %" PRIu64, (u64) PCFG_OMEN_ALIGN * aligned_data_size);
    hc_free_aligned ((void **) &lin->term_blocks);
    hcfree (lin);
    return -1;
  }

  memset (lin->data_buffer, 0, aligned_data_size);

  // Pack terminals into data_buffer
  for (int t = 0; t < PCFG_OMEN_TYPE_MAX; t++)
  {
    for (int l = 0; l < PCFG_OMEN_LEN_MAX; l++)
    {
      const int block_idx = lin->type_len_to_block[t][l];

      if (block_idx >= 0)
      {
        const pcfg_terminal_list_t *list = &m->terminals[t][l];
        const pcfg_term_block_t *blk = &lin->term_blocks[block_idx];

        for (u32 i = 0; i < list->cnt; i++)
        {
          u32 *dst = lin->data_buffer + blk->data_offset + i * blk->stride_words;

          const char *src = list->items[i].value;

          memcpy (dst, src, l);
        }
      }
    }
  }

  // Create linearized structures
  lin->struct_cnt = m->struct_cnt;

  const size_t struct_size = m->struct_cnt * sizeof (pcfg_gpu_omen_structure_t);

  lin->structures = (pcfg_gpu_omen_structure_t *) hc_alloc_aligned (64, struct_size);

  if (lin->structures == NULL)
  {
    event_log_error (hashcat_ctx, "! failed to alloc lin->structures with size %" PRIu64, (u64) 64 * struct_size);
    hc_free_aligned ((void **) &lin->data_buffer);
    hc_free_aligned ((void **) &lin->term_blocks);
    hcfree (lin);
    return -1;
  }

  memset (lin->structures, 0, struct_size);

  for (u32 si = 0; si < m->struct_cnt; si++)
  {
    const pcfg_structure_t *s = &m->structures[si];
    pcfg_gpu_omen_structure_t *ls = &lin->structures[si];

    ls->token_cnt = s->token_cnt;
    ls->total_len = s->total_len;

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      const u32 ty = s->types[k] & 0x7F;
      const u32 ln = s->lengths[k];
      const int block_idx = lin->type_len_to_block[ty][ln];

      ls->block_indices[k] = (u32) block_idx;
      ls->types[k] = s->types[k];
      ls->lengths[k] = s->lengths[k];
    }

    // Zero padding
    for (u32 k = s->token_cnt; k < PCFG_OMEN_MAX_TOKENS; k++)
    {
      ls->block_indices[k] = 0;
      ls->types[k] = 0;
      ls->lengths[k] = 0;
    }
  }

  u64 mismatch_cnt = 0;

  // verify block counts match terminal counts
  for (u32 si = 0; si < m->struct_cnt; si++)
  {
    const pcfg_structure_t *s = &m->structures[si];
    const pcfg_gpu_omen_structure_t *ls = &lin->structures[si];

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      u32 blk_idx = ls->block_indices[k];
      u32 blk_cnt = lin->term_blocks[blk_idx].count;
      u32 term_cnt = m->terminals[s->types[k]][s->lengths[k]].cnt;

      if (blk_cnt != term_cnt)
      {
        event_log_warning (hashcat_ctx, "PCFG OMEN: MISMATCH struct=%u token=%u type=0x%02x len=%u blk_cnt=%u term_cnt=%u", si, k, s->types[k], s->lengths[k], blk_cnt, term_cnt);
        mismatch_cnt++;
      }
    }
  }

  if (mismatch_cnt > 0)
  {
    event_log_error (hashcat_ctx, "%s: found %" PRIu64 " mismatch between term_blocks and terminals ...", __func__, mismatch_cnt);
    return -1;
  }

  // verify terminal data was packed correctly (sample check)
  for (u32 blk_idx = 0; blk_idx < lin->term_block_cnt; blk_idx++)
  {
    const pcfg_term_block_t *blk = &lin->term_blocks[blk_idx];

    if (blk->count == 0) continue;

    // Find which type/len this block belongs to
    int found_t = -1, found_l = -1;

    for (int t = 0; t < PCFG_OMEN_TYPE_MAX && found_t < 0; t++)
    {
      for (int l = 0; l < PCFG_OMEN_LEN_MAX; l++)
      {
        if (lin->type_len_to_block[t][l] == (int) blk_idx)
        {
          found_t = t;
          found_l = l;
          break;
        }
      }
    }

    if (found_t < 0) continue;

    const pcfg_terminal_list_t *list = &m->terminals[found_t][found_l];

    // Check first and last terminal
    for (u32 check_idx = 0; check_idx < 2; check_idx++)
    {
      u32 term_idx = (check_idx == 0) ? 0 : (blk->count - 1);

      if (term_idx >= list->cnt) continue;

      const char *orig = list->items[term_idx].value;
      const u32 *packed = lin->data_buffer + blk->data_offset + term_idx * blk->stride_words;

      if (memcmp (orig, packed, blk->stride_bytes) != 0)
      {
        event_log_warning (hashcat_ctx, "PCFG OMEN: DATA MISMATCH block=%u term=%u type=0x%02x len=%u", blk_idx, term_idx, found_t, found_l);
        mismatch_cnt++;
      }
    }
  }

  if (mismatch_cnt > 0)
  {
    event_log_error (hashcat_ctx, "%s: found %" PRIu64 " mismatch between items and data_buffer ...", __func__, mismatch_cnt);
    return -1;
  }

  // verify structure fields match
  for (u32 si = 0; si < m->struct_cnt; si++)
  {
    const pcfg_structure_t *s = &m->structures[si];
    const pcfg_gpu_omen_structure_t *ls = &lin->structures[si];

    if (s->token_cnt != ls->token_cnt)
    {
      event_log_warning (hashcat_ctx, "PCFG OMEN: TOKEN_CNT MISMATCH struct=%u orig=%u lin=%u", si, s->token_cnt, ls->token_cnt);
      mismatch_cnt++;
    }

    if (s->total_len != ls->total_len)
    {
      event_log_warning (hashcat_ctx, "PCFG OMEN: TOTAL_LEN MISMATCH struct=%u orig=%u lin=%u", si, s->total_len, ls->total_len);
      mismatch_cnt++;
    }

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      if (s->types[k] != ls->types[k])
      {
        event_log_warning (hashcat_ctx, "PCFG OMEN: TYPE MISMATCH struct=%u token=%u orig=0x%02x lin=0x%02x", si, k, s->types[k], ls->types[k]);
        mismatch_cnt++;
      }

      if (s->lengths[k] != ls->lengths[k])
      {
        event_log_warning (hashcat_ctx, "PCFG OMEN: LENGTH MISMATCH struct=%u token=%u orig=%u lin=%u", si, k, s->lengths[k], ls->lengths[k]);
        mismatch_cnt++;
      }
    }
  }

  if (mismatch_cnt > 0)
  {
    event_log_error (hashcat_ctx, "%s: found %" PRIu64 " mismatch between structures data ...", __func__, mismatch_cnt);
    return -1;
  }

  // Store pointers to OMEN metadata 
  lin->struct_costs         = m->omen_data->struct_costs;
  lin->struct_min_term_cost = m->omen_data->struct_min_term_cost;
  lin->cost_keyspace        = m->omen_data->cost_keyspace;

  // Calculate estimated total keyspace
  lin->total_keyspace = 0;

  if (lin->cost_keyspace != NULL)
  {
    for (u32 cost = 0; cost <= PCFG_OMEN_COST_PRACTICAL_MAX; cost++)
    {
      if (lin->total_keyspace + lin->cost_keyspace[cost] < lin->total_keyspace)
      {
        lin->total_keyspace = UINT64_MAX;
        break;
      }

      lin->total_keyspace += lin->cost_keyspace[cost];
    }
  }

  if (pcfg_gpu_omen_build_skip_data(hashcat_ctx, lin, m) == -1) return -1;

  *out = lin;

  return 0;
}

void pcfg_gpu_omen_data_destroy (pcfg_gpu_omen_data_t *lin)
{
  if (lin == NULL) return;

  hc_free_aligned ((void **) &lin->structures);
  hc_free_aligned ((void **) &lin->data_buffer);
  hc_free_aligned ((void **) &lin->term_blocks);

  // Note: struct_costs, struct_min_term_cost, cost_keyspace are NOT freed here
  // They belong to omen_data which is freed separately

  // Fast-skip data
  hcfree (lin->sorted_keyspace);
  hcfree (lin->prefix_keyspace);

  hcfree (lin);
}

// Context Initialization

int pcfg_gpu_omen_ctx_init (hashcat_ctx_t *hashcat_ctx, pcfg_gpu_omen_data_t *lin, pcfg_model_t *model, u32 num_devices, u64 skip, u64 limit, pcfg_gpu_omen_ctx_t **out)
{
  if (lin == NULL || model == NULL || out == NULL) return -1;
  if (num_devices == 0 || num_devices > PCFG_OMEN_MAX_DEVICES) return -1;
  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;

  pcfg_gpu_omen_ctx_t *ctx = (pcfg_gpu_omen_ctx_t *) hccalloc (1, sizeof (pcfg_gpu_omen_ctx_t));

  if (ctx == NULL) return -1;

  ctx->linear_data = lin;
  ctx->model = model;
  ctx->num_devices = num_devices;
  ctx->skip = skip;
  ctx->limit = limit;
  ctx->initialized = true;

  // calculate effective keyspace
  u64 total = lin->total_keyspace;

  bool valid_skip = true;
  if (skip >= total)
  {
    ctx->effective_keyspace = 0;
    valid_skip = false;
  }
  else if (limit > 0)
  {
    u64 end_pos = (limit < total) ? limit : total;
    ctx->effective_keyspace = (end_pos > skip) ? (end_pos - skip) : 0;
  }
  else
  {
    ctx->effective_keyspace = total - skip;
  }

  // update words_cnt/words_base to show Time.Estimated

  const u64 amplifier_cnt = user_options_extra_amplifier (hashcat_ctx);

  if (amplifier_cnt > 1 && ctx->effective_keyspace > UINT64_MAX / amplifier_cnt)
  {
    // Overflow: use the maximum representable value
    status_ctx->words_cnt = UINT64_MAX;
  }
  else if (amplifier_cnt > 0)
  {
    status_ctx->words_cnt = ctx->effective_keyspace * amplifier_cnt;
  }
  else
  {
    status_ctx->words_cnt = ctx->effective_keyspace;
  }

  status_ctx->words_base = ctx->effective_keyspace;
  // check restore point
  if (status_ctx->words_off > status_ctx->words_base)
  {
    event_log_error (hashcat_ctx, "Restore value is greater than keyspace.");
    hcfree (ctx);
    return -1;
  }

  if (valid_skip == false)
  {
    event_log_error (hashcat_ctx, "Skip value is greater than keyspace.");
    hcfree (ctx);
    return -1;
  }

  *out = ctx;

  return 0;
}

void pcfg_gpu_omen_ctx_destroy (pcfg_gpu_omen_ctx_t *ctx)
{
  if (ctx == NULL) return;

  // Note: linear_data and model are NOT freed here
  // They are managed separately

  hcfree (ctx);
}

// Generates partitions for a structure, filtering by the range [range_start, range_start + range_len]
// Returns the number of passwords actually covered by the generated partitions.
u64 pcfg_gpu_omen_generate_partitions (const pcfg_gpu_omen_structure_t *s, const pcfg_omen_extra_t *omen, int remaining_cost, u64 range_start, u64 range_len, pcfg_gpu_omen_partition_t *out_partitions, u32 max_partitions, u32 *out_count)
{
  *out_count = 0;

  if (range_len == 0) return 0;

  const u32 token_cnt = s->token_cnt;
  const u64 range_end = range_start + range_len; // Esclusivo

  // pre-cache slot_maps pointers
  const pcfg_omen_slot_map_t *slot_maps[PCFG_OMEN_MAX_TOKENS];

  for (u32 i = 0; i < token_cnt; i++)
  {
    // access to omen->term_maps [256][256] using the types/len of the linearized structure
    const u8 ty = s->types[i] & 0x7F;
    const u8 ln = s->lengths[i];
    slot_maps[i] = &omen->term_maps[ty][ln];
  }

  u64 current_keyspace = 0;   // global keyspace of the structure traversed so far
  u64 generated_keyspace = 0; // keyspace actually generated in output (sum of partition counts)
  u32 p_cnt = 0;

  // stack variables for iterative backtracking
  int stack_next_c[PCFG_OMEN_MAX_TOKENS];
  int stack_rem[PCFG_OMEN_MAX_TOKENS];
  u64 stack_prod[PCFG_OMEN_MAX_TOKENS];
  u8  current_costs[PCFG_OMEN_MAX_TOKENS];

  memset (current_costs, 0, sizeof (current_costs));

  // init slot 0
  stack_next_c[0] = 0;
  stack_prod[0]   = 1;
  stack_rem[0]    = remaining_cost;

  int slot = 0;
  const int last_slot = (int) token_cnt - 1;

  while (slot >= 0)
  {
    // check output limits
    if (p_cnt >= max_partitions) break;

    // if we have already exceeded the end of the required range, stop here
    if (current_keyspace >= range_end) break;

    // last slot: direct assignment
    if (slot == last_slot)
    {
      const int final_c = stack_rem[slot];

      if (final_c >= 0 && final_c <= 31)
      {
        u32 cnt = slot_maps[slot]->counts[final_c];

        if (cnt > 0)
        {
          u64 combinations = stack_prod[slot] * cnt;
          u64 part_start = current_keyspace;
          u64 part_end   = part_start + combinations;

          current_keyspace += combinations;

          // intersection [part_start, part_end) with [range_start, range_end)
          // if the partition ends before the start of the range, or starts after the end, we skip it
          if (part_end > range_start && part_start < range_end)
          {
            // valid partition
            current_costs[slot] = (u8) final_c;

            pcfg_gpu_omen_partition_t *p = &out_partitions[p_cnt];

            memcpy (p->costs, current_costs, sizeof (p->costs));

            // calculate offset for kernel
            // kernel must generate from max(part_start, range_start) to min(part_end, range_end)
            u64 actual_start = (part_start < range_start) ? range_start : part_start;
            u64 actual_end   = (part_end > range_end)     ? range_end   : part_end;
            u64 count        = actual_end - actual_start;

            p->local_offset = generated_keyspace; // offset in the current batch (0..N)
            p->local_end    = generated_keyspace + count;

            // inner offset: if we start in the middle of the partition (ex: Interleaved resume)
            p->partition_inner_offset = actual_start - part_start;

            generated_keyspace += count;
            p_cnt++;
          }
        }
      }

      slot--;
      continue;
    }

    // intermediate slots
    const int rem         = stack_rem[slot];
    const int slots_after = last_slot - slot;
    const int max_c       = (rem > 31) ? 31 : rem;

    bool advanced = false;

    for (int c = stack_next_c[slot]; c <= max_c; c++)
    {
      const int left = rem - c;

      if (left > 31 * slots_after) continue;
      if (left < 0) break;

      u32 cnt = slot_maps[slot]->counts[c];

      if (cnt == 0) continue;

      current_costs[slot] = (u8) c;
      stack_next_c[slot]  = c + 1;

      slot++;

      stack_rem[slot]    = left;
      stack_next_c[slot] = 0;
      stack_prod[slot]   = stack_prod[slot - 1] * cnt;

      advanced = true;
      break;
    }

    if (!advanced) slot--;
  }

  *out_count = p_cnt;
  return generated_keyspace;
}

int pcfg_gpu_omen_gen_init (pcfg_gen_t *gen, u32 shard_id)
{
  if (gen == NULL) return -1;

  // reset base counters
  gen->generated = 0;
  gen->curr_struct_idx = UINT32_MAX;
  gen->curr_comb_idx = (u64) shard_id;

  // alloc temp host buffers
  gen->omen_gpu_batch_entries = (pcfg_gpu_omen_batch_entry_t *) hccalloc (PCFG_OMEN_HOST_MAX_BATCH_ENTRIES, sizeof (pcfg_gpu_omen_batch_entry_t));
  gen->omen_gpu_partitions    = (pcfg_gpu_omen_partition_t *)   hccalloc (PCFG_OMEN_HOST_MAX_PARTITIONS,    sizeof (pcfg_gpu_omen_partition_t));
  gen->omen_gpu_structures    = (pcfg_gpu_omen_structure_t *)   hccalloc (PCFG_OMEN_HOST_MAX_BATCH_ENTRIES, sizeof (pcfg_gpu_omen_structure_t));

  if (!gen->omen_gpu_batch_entries || !gen->omen_gpu_partitions || !gen->omen_gpu_structures)
  {
    if (gen->omen_gpu_batch_entries) hcfree (gen->omen_gpu_batch_entries);
    if (gen->omen_gpu_partitions)    hcfree (gen->omen_gpu_partitions);
    if (gen->omen_gpu_structures)    hcfree (gen->omen_gpu_structures);

    return -1;
  }

  // init counters
  gen->omen_gpu_batch_entry_cnt = 0;
  gen->omen_gpu_partition_cnt   = 0;

  return 0;
}

// status
int pcfg_gpu_omen_get_status_info (const hashcat_ctx_t *hashcat_ctx, const pcfg_gen_t *gen, pcfg_gpu_omen_status_info_t *info)
{
  if (hashcat_ctx == NULL || gen == NULL || info == NULL) return -1;

  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;
  if (!pcfg_ctx || !pcfg_ctx->omen_gpu_data) return -1;

  const pcfg_gpu_omen_data_t *lin = pcfg_ctx->omen_gpu_data;

  info->struct_cnt       = lin->struct_cnt;
  info->generated        = gen->generated;

  // omen_target_cost now contains chunk_idx
  info->current_cost     = gen->omen_target_cost;

  info->current_loop     = gen->omen_global_loop_idx;
  info->omen_cost        = gen->omen_by_cost_current;

  info->omen_type        = hashcat_ctx->user_options->pcfg_omen_type;

  info->struct_idx_in_cost = gen->curr_struct_idx; // current global struct

  if (gen->curr_struct_idx >= lin->struct_cnt || gen->curr_struct_idx == UINT32_MAX)
  {
    return -1;
  }
  else
  {
    // get struct
    const pcfg_gpu_omen_structure_t *ls = &lin->structures[gen->curr_struct_idx];

    info->current_struct = gen->curr_struct_idx;

    // get keyspace
    if (pcfg_ctx->model && pcfg_ctx->model->structures)
    {
      info->struct_keyspace = pcfg_ctx->model->structures[gen->curr_struct_idx].keyspace;
    }
    else
    {
      info->struct_keyspace = 0;
    }

    // for display stats
    info->struct_keyspace_device = info->struct_keyspace;
    info->struct_generated = 0;

    info->struct_total_len = ls->total_len;
    info->global_position = gen->generated;

    // reconstruct string pattern from linearized structure
    if (pcfg_ctx->model)
    {
      pcfg_structure_t *s = &pcfg_ctx->model->structures[gen->curr_struct_idx];
      pcfg_get_pattern_str(s, info->pattern, sizeof (info->pattern));
    }
    else
    {
      snprintf (info->pattern, sizeof (info->pattern), "N/A");
    }
  }

  return 0;
}
