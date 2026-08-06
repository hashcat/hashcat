/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "user_options.h"
#include "pcfg_common.h"

// find initial position for skip

static void pcfg_gpu_prob_apply_skip (const pcfg_gpu_prob_ctx_t *ctx, pcfg_gen_t *gen, u32 shard_id)
{
  const pcfg_gpu_prob_data_t *lin = ctx->linear_data;
  const u64 skip = ctx->skip;
  const u32 num_devices = ctx->num_devices;

  // no-skip case
  if (skip == 0)
  {
    gen->gpu_prob_current_struct = 0;
    gen->gpu_prob_current_local_idx = shard_id;
    return;
  }

  // find structure containing skip position
  u32 struct_idx = 0;

  while (struct_idx < lin->struct_cnt)
  {
    const pcfg_gpu_prob_structure_t *s = &lin->structures[struct_idx];

    u64 struct_end = s->cumulative + s->keyspace;

    if (skip < struct_end) break;

    struct_idx++;
  }

  if (struct_idx >= lin->struct_cnt)
  {
    // skip over total keyspace
    gen->gpu_prob_current_struct = lin->struct_cnt;
    gen->gpu_prob_current_local_idx = 0;
    return;
  }

  // calculate local offset inside the struct
  const pcfg_gpu_prob_structure_t *s = &lin->structures[struct_idx];

  u64 local_offset = skip - s->cumulative;

  // find first index >= local_offset (consistent with shard_id mod num_devices)
  u64 remainder = local_offset % num_devices;
  u64 first_idx = local_offset - remainder + shard_id;

  if (shard_id < remainder)
  {
    first_idx += num_devices;
  }

  // if first_idx is greater/equal than keyspace, go to the next struct
  while (first_idx >= s->keyspace)
  {
    struct_idx++;

    if (struct_idx >= lin->struct_cnt)
    {
      gen->gpu_prob_current_struct = lin->struct_cnt;
      gen->gpu_prob_current_local_idx = 0;
      return;
    }

    s = &lin->structures[struct_idx];
    first_idx = shard_id;
  }

  gen->gpu_prob_current_struct = struct_idx;
  gen->gpu_prob_current_local_idx = first_idx;
}

static inline u64 calc_device_keyspace (u64 keyspace, u32 shard_id, u32 num_devices)
{
  if (shard_id >= keyspace) return 0;

  return (keyspace - 1 - shard_id) / num_devices + 1;
}

// direct generation of a single password

inline int pcfg_gpu_prob_generate_direct (const u32 *data_buffer, const pcfg_term_block_t *term_blocks, const pcfg_gpu_prob_structure_t *structure, u64 local_idx, char *pw_out, u32 *pw_len_out)
{
  const u64 keyspace = structure->keyspace;

  if (local_idx >= keyspace) return -1;

  const u32 token_cnt = structure->token_cnt;

  u64 work_idx = local_idx;

  u32 term_indices[PCFG_OMEN_MAX_TOKENS];

  for (int k = (int) token_cnt - 1; k >= 0; k--)
  {
    const u32 count = structure->divisors[k];
    const u64 recip = structure->recips64[k];

    if (count == 1)
    {
      term_indices[k] = 0;
    }
    else
    {
      const u64 q64 = mulhi64 (work_idx, recip);
      term_indices[k] = (u32) (work_idx - q64 * count);
      work_idx = q64;
    }
  }

  u32 pos = 0;

  for (u32 k = 0; k < token_cnt; k++)
  {
    const u32 blk_idx = structure->block_indices[k];

    const pcfg_term_block_t *blk = &term_blocks[blk_idx];

    const u32 len          = blk->stride_bytes;
    const u32 stride_words = blk->stride_words;
    const u64 block_base   = blk->data_offset;
    const u32 tid          = term_indices[k];

    const u64 src_offset   = block_base + (u64) tid * stride_words;
    const char *src        = (const char *) (data_buffer + src_offset);

    switch (len)
    {
      case 1:  pw_out[pos] = src[0]; break;
      case 2:  pw_out[pos] = src[0]; pw_out[pos+1] = src[1]; break;
      case 3:  pw_out[pos] = src[0]; pw_out[pos+1] = src[1]; pw_out[pos+2] = src[2]; break;
      case 4:  memcpy (pw_out + pos, src, 4); break;
      case 5:  memcpy (pw_out + pos, src, 5); break;
      case 6:  memcpy (pw_out + pos, src, 6); break;
      case 7:  memcpy (pw_out + pos, src, 7); break;
      case 8:  memcpy (pw_out + pos, src, 8); break;
      default: memcpy (pw_out + pos, src, len); break;
    }

    pos += len;
  }

  pw_out[pos] = '\0';
  *pw_len_out = pos;

  return 0;
}

// linear data init

int pcfg_gpu_prob_data_init (hashcat_ctx_t *hashcat_ctx, const pcfg_model_t *m, pcfg_gpu_prob_data_t **out)
{
  if (m == NULL || out == NULL) return -1;

  pcfg_gpu_prob_data_t *lin = (pcfg_gpu_prob_data_t *) hccalloc (1, sizeof (pcfg_gpu_prob_data_t));

  if (lin == NULL) return -1;

  for (int t = 0; t < PCFG_OMEN_TYPE_MAX; t++)
  {
    for (int l = 0; l < PCFG_OMEN_LEN_MAX; l++)
    {
      lin->type_len_to_block[t][l] = -1;
    }
  }

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

  const size_t blocks_size = block_cnt * sizeof (pcfg_term_block_t);

  lin->term_blocks = (pcfg_term_block_t *) hc_alloc_aligned (32, blocks_size);

  if (lin->term_blocks == NULL)
  {
    event_log_error (hashcat_ctx, "%s: failed to alloc lin->term_blocks with size %" PRIu64, __func__, (u64) 32 * blocks_size);
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
          event_log_error (hashcat_ctx, "%s: list->cnt (%lu) > PCFG_MAX_TERMINALS (%d)", __func__, (unsigned long) list->cnt, PCFG_MAX_TERMINALS);
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

  const size_t data_size = (size_t) data_offset_words * sizeof (u32);

  const size_t aligned_data_size = (data_size + PCFG_OMEN_ALIGN - 1) & ~(PCFG_OMEN_ALIGN - 1);

  lin->data_buffer = (u32 *) hc_alloc_aligned (PCFG_OMEN_ALIGN, aligned_data_size);

  if (lin->data_buffer == NULL)
  {
    event_log_error (hashcat_ctx, "%s: failed to alloc lin->data_buffer with size %" PRIu64, __func__, (u64) PCFG_OMEN_ALIGN * aligned_data_size);
    hc_free_aligned ((void **) &lin->term_blocks);
    hcfree (lin);
    return -1;
  }

  memset (lin->data_buffer, 0, aligned_data_size);

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

  lin->struct_cnt = m->struct_cnt;

  const size_t struct_size = m->struct_cnt * sizeof (pcfg_gpu_prob_structure_t);

  lin->structures = (pcfg_gpu_prob_structure_t *) hc_alloc_aligned (256, struct_size);

  if (lin->structures == NULL)
  {
    event_log_error (hashcat_ctx, "%s: failed to alloc lin->structures with size %" PRIu64, __func__, (u64) 256 * struct_size);
    hc_free_aligned ((void **) &lin->data_buffer);
    hc_free_aligned ((void **) &lin->term_blocks);
    hcfree (lin);
    return -1;
  }

  memset (lin->structures, 0, struct_size);

  u64 cumulative = 0;

  for (u32 si = 0; si < m->struct_cnt; si++)
  {
    const pcfg_structure_t *s = &m->structures[si];

    pcfg_gpu_prob_structure_t *ls = &lin->structures[si];

    ls->cumulative = cumulative;
    ls->keyspace = s->keyspace;
    ls->token_cnt = s->token_cnt;
    ls->total_len = s->total_len;

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      ls->types[k] = s->types[k];
      ls->lengths[k] = s->lengths[k];
    }

    u32 write_offset_bytes = 0;

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      const u32 ty = s->types[k] & 0x7F;
      const u32 ln = s->lengths[k];
      const int block_idx = lin->type_len_to_block[ty][ln];

      ls->block_indices[k] = (u32) block_idx;

      const pcfg_term_block_t *blk = &lin->term_blocks[block_idx];

      ls->divisors[k] = blk->count;
      ls->recips64[k] = compute_recip64 (blk->count);
      ls->offsets[k] = write_offset_bytes;

      write_offset_bytes += blk->stride_bytes;
    }

    for (u32 k = s->token_cnt; k < PCFG_OMEN_MAX_TOKENS; k++)
    {
      ls->block_indices[k] = 0;
      ls->divisors[k] = 1;
      ls->recips64[k] = 0;
      ls->offsets[k] = 0;
      ls->types[k] = 0;
      ls->lengths[k] = 0;
    }

    cumulative += s->keyspace;
  }

  // Calculate total keyspace using linearized data
  lin->total_keyspace = 0;

  for (u32 si = 0; si < lin->struct_cnt; si++)
  {
    const pcfg_gpu_prob_structure_t *ls = &lin->structures[si];

    if (ls->token_cnt == 0) continue;

    unsigned __int128 struct_ks = 1;
    bool valid = true;

    for (u32 k = 0; k < ls->token_cnt && valid; k++)
    {
      u32 blk_idx = ls->block_indices[k];
      u32 cnt = lin->term_blocks[blk_idx].count;

      if (cnt == 0)
      {
        valid = false;
      }
      else
      {
        struct_ks *= cnt;
      }
    }

    if (!valid) continue;

    if (lin->total_keyspace + struct_ks < lin->total_keyspace)
    {
      lin->total_keyspace = UINT64_MAX;
      break;
    }

    lin->total_keyspace += (u64) struct_ks;
  }

  // verify cumulative and keyspace consistency
  for (u32 si = 0; si < lin->struct_cnt; si++)
  {
    const pcfg_gpu_prob_structure_t *ls = &lin->structures[si];

    // Verify keyspace matches product of divisors
    if (ls->token_cnt > 0 && ls->keyspace > 0)
    {
      unsigned __int128 product = 1;

      for (u32 k = 0; k < ls->token_cnt; k++)
      {
        product *= ls->divisors[k];
      }

      u64 expected_ks = (product > UINT64_MAX) ? UINT64_MAX : (u64) product;

      if (ls->keyspace != expected_ks)
      {
        event_log_warning (hashcat_ctx, "PCFG PROB: KEYSPACE MISMATCH struct=%u keyspace=%" PRIu64 " product=%" PRIu64, si, ls->keyspace, expected_ks);
      }
    }

    // Verify cumulative is monotonically increasing
    if (si > 0)
    {
      const pcfg_gpu_prob_structure_t *prev = &lin->structures[si - 1];

      u64 expected_cum = prev->cumulative + prev->keyspace;

      // Only check if no overflow
      if (prev->cumulative <= expected_cum && ls->cumulative != expected_cum)
      {
        event_log_warning (hashcat_ctx, "PCFG PROB: CUMULATIVE MISMATCH struct=%u cumulative=%" PRIu64 " expected=%" PRIu64 " (prev_cum=%" PRIu64 " + prev_ks=%" PRIu64 ")", si, ls->cumulative, expected_cum, prev->cumulative, prev->keyspace);
      }
    }

    // Verify first structure starts at 0
    if (si == 0 && ls->cumulative != 0)
    {
      event_log_warning (hashcat_ctx, "PCFG PROB: CUMULATIVE START MISMATCH struct=0 cumulative=%" PRIu64 " expected=0", ls->cumulative);
    }
  }

  u64 mismatch_cnt = 0;

  // verify block counts match terminal counts
  for (u32 si = 0; si < m->struct_cnt; si++)
  {
    const pcfg_structure_t *s = &m->structures[si];
    const pcfg_gpu_prob_structure_t *ls = &lin->structures[si];

    for (u32 k = 0; k < s->token_cnt; k++)
    {
      u32 blk_idx = ls->block_indices[k];
      u32 blk_cnt = lin->term_blocks[blk_idx].count;
      u32 term_cnt = m->terminals[s->types[k]][s->lengths[k]].cnt;

      if (blk_cnt != term_cnt)
      {
        event_log_warning (hashcat_ctx, "PCFG PROB: MISMATCH struct=%u token=%u type=0x%02x len=%u blk_cnt=%u term_cnt=%u", si, k, s->types[k], s->lengths[k], blk_cnt, term_cnt);
        mismatch_cnt++;
      }
    }
  }

  if (mismatch_cnt > 0)
  {
    event_log_error (hashcat_ctx, "%s: found %" PRIu64 " mismatch between term_blocks and terminals ...", __func__, mismatch_cnt);
    return -1;
  }

  // verify divisors match block counts
  for (u32 si = 0; si < m->struct_cnt; si++)
  {
    const pcfg_gpu_prob_structure_t *ls = &lin->structures[si];

    for (u32 k = 0; k < ls->token_cnt; k++)
    {
      u32 blk_idx = ls->block_indices[k];
      u32 blk_cnt = lin->term_blocks[blk_idx].count;
      u32 divisor = ls->divisors[k];

      if (blk_cnt != divisor)
      {
        event_log_warning (hashcat_ctx, "PCFG PROB: DIVISOR MISMATCH struct=%u token=%u blk_cnt=%u divisor=%u", si, k, blk_cnt, divisor);
        mismatch_cnt++;
      }
    }
  }

  if (mismatch_cnt > 0)
  {
    event_log_error (hashcat_ctx, "%s: found %" PRIu64 " mismatch between term_blocks and divisors ...", __func__, mismatch_cnt);
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
        event_log_warning (hashcat_ctx, "PCFG PROB: DATA MISMATCH block=%u term=%u type=0x%02x len=%u", blk_idx, term_idx, found_t, found_l);
        mismatch_cnt++;
      }
    }
  }

  if (mismatch_cnt > 0)
  {
    event_log_error (hashcat_ctx, "%s: found %" PRIu64 " mismatch between items and data_buffer ...", __func__, mismatch_cnt);
    return -1;
  }

  int ret = 0;

  // find where cumulative overflows
  bool overflow_reported = false;
  u32 overflow_struct = UINT32_MAX;

  for (u32 si = 0; si < lin->struct_cnt; si++)
  {
    const pcfg_gpu_prob_structure_t *ls = &lin->structures[si];

    if (ls->cumulative == UINT64_MAX && !overflow_reported)
    {
      event_log_warning (hashcat_ctx, "PCFG PROB: cumulative overflow at struct %u / %u", si, lin->struct_cnt);
      overflow_struct = (si > 0) ? si - 1 : si;
      overflow_reported = true;
      break;
    }
  }

  if (overflow_reported == true)
  {
    // show first structures with large keyspace
    for (u32 si = 0; si < lin->struct_cnt && si < overflow_struct; si++)
    {
      const pcfg_gpu_prob_structure_t *ls = &lin->structures[si];

      event_log_warning (hashcat_ctx, "PCFG PROB: struct %u cumulative=%" PRIu64 " keyspace=%" PRIu64, si, ls->cumulative, ls->keyspace);
    }

    // check overflow struct
    {
      const pcfg_gpu_prob_structure_t *ls = &lin->structures[overflow_struct];

      event_log_warning (hashcat_ctx, "PCFG PROB: struct %u token_cnt=%u divisors:", overflow_struct, ls->token_cnt);

      unsigned __int128 real_ks = 1;

      for (u32 k = 0; k < ls->token_cnt; k++)
      {
        event_log_warning (hashcat_ctx, " %u", ls->divisors[k]);
        real_ks *= ls->divisors[k];
      }

      u64 real_ks_64 = (real_ks > UINT64_MAX) ? UINT64_MAX : (u64) real_ks;

      event_log_warning (hashcat_ctx, " real_ks=%" PRIu64 " stored_ks=%" PRIu64, real_ks_64, ls->keyspace);

      // Print pattern
      char pattern[PCFG_PATTERN_MAX];
      size_t pos = 0;

      for (u32 k = 0; k < ls->token_cnt && pos < sizeof (pattern) - 4; k++)
      {
        char type_char = ls->types[k] & 0x7F;
        u8 len = ls->lengths[k];

        if (len < 10)
        {
          pattern[pos++] = type_char;
          pattern[pos++] = '0' + len;
        }
        else
        {
          int written = snprintf (pattern + pos, sizeof (pattern) - pos, "%c%u", type_char, len);
          if (written > 0) pos += written;
        }
      }

      pattern[pos] = '\0';

      event_log_warning (hashcat_ctx, "PCFG PROB: overflow caused by struct %u pattern=%s token_cnt=%u total_len=%u\n", overflow_struct, pattern, ls->token_cnt, ls->total_len);

      event_log_warning (hashcat_ctx, "PCFG PROB: divisors:");

      for (u32 k = 0; k < ls->token_cnt; k++)
      {
        event_log_warning (hashcat_ctx, " %u", ls->divisors[k]);
      }

      event_log_warning (hashcat_ctx, "\n");

      // first 10 passwords (read directly from AoS buffer)
      event_log_warning (hashcat_ctx, "PCFG PROB: first 10 passwords:");

      for (u64 idx = 0; idx < 10; idx++)
      {
        u64 work_idx = idx;
        u32 term_indices[16];

        for (int k = (int) ls->token_cnt - 1; k >= 0; k--)
        {
          const u32 count = ls->divisors[k];
          const u64 recip = ls->recips64[k];

          if (count == 1)
          {
            term_indices[k] = 0;
          }
          else
          {
            const u64 q = mulhi64 (work_idx, recip);
            term_indices[k] = (u32) (work_idx - q * count);
            work_idx = q;
          }
        }

        char pw[256];
        u32 pw_pos = 0;

        for (u32 k = 0; k < ls->token_cnt; k++)
        {
          const pcfg_term_block_t *blk = &lin->term_blocks[ls->block_indices[k]];
          const u64 src_offset = blk->data_offset + (u64) term_indices[k] * blk->stride_words;
          const char *src = (const char *) (lin->data_buffer + src_offset);

          memcpy (pw + pw_pos, src, blk->stride_bytes);
          pw_pos += blk->stride_bytes;
        }

        pw[pw_pos] = '\0';

        fprintf (stderr, "  [%" PRIu64 "] ", idx);

        for (u32 c = 0; c < pos; c++)
        {
          u8 ch = (u8) pw[c];

          if (ch >= 0x20 && ch < 0x7F)
          {
            fprintf (stderr, "%c", ch);
          }
          else
          {
            fprintf (stderr, "\\x%02x", ch);
          }
        }

        fprintf (stderr, " (len=%zu)\n", pos);
      }

      // check raw terminal data
      for (u32 k = 0; k < ls->token_cnt; k++)
      {
        u32 blk_idx = ls->block_indices[k];
        const pcfg_term_block_t *blk = &lin->term_blocks[blk_idx];

        event_log_warning (hashcat_ctx, "  token %u: blk=%u offset=%" PRIu64 " stride_w=%u stride_b=%u count=%u", k, blk_idx, blk->data_offset, blk->stride_words, blk->stride_bytes, blk->count);

        // Show first terminal raw bytes
        const u32 *src = lin->data_buffer + blk->data_offset;

        fprintf (stderr, "    term[0] hex:");

        for (u32 b = 0; b < blk->stride_bytes; b++)
        {
          fprintf (stderr, " %02x", ((const u8 *) src)[b]);
        }

        fprintf (stderr, " str=");

        for (u32 b = 0; b < blk->stride_bytes; b++)
        {
          u8 ch = ((const u8 *) src)[b];

          if (ch >= 0x20 && ch < 0x7F)
          {
            fprintf (stderr, "%c", ch);
          }
          else
          {
            fprintf (stderr, "\\x%02x", ch);
          }
        }

        fprintf (stderr, "\n");
      }

      // verify index decomposition
      for (u64 idx = 0; idx < 10; idx++)
      {
        u64 work_idx = idx;
        u32 term_indices[16] = { 0 };

        for (int k = (int) ls->token_cnt - 1; k >= 0; k--)
        {
          const u32 count = ls->divisors[k];
          const u64 recip = ls->recips64[k];

          if (count == 1)
          {
            term_indices[k] = 0;
          }
          else
          {
            const u64 q = mulhi64 (work_idx, recip);
            term_indices[k] = (u32) (work_idx - q * count);
            work_idx = q;
          }
        }

        fprintf (stderr, "  idx=%" PRIu64 " indices=[", idx);

        for (u32 k = 0; k < ls->token_cnt; k++)
        {
          fprintf (stderr, "%u", term_indices[k]);
          if (k < ls->token_cnt - 1) fprintf (stderr, ", ");
        }

        fprintf (stderr, "]\n");
      }
    }

    // show structures around overflow point
    for (u32 si = (overflow_struct + 1); si < lin->struct_cnt && si < (overflow_struct + 10); si++)
    {
      const pcfg_gpu_prob_structure_t *ls = &lin->structures[si];

      fprintf (stderr, "PCFG PROB: struct %u cumulative=%" PRIu64 " keyspace=%" PRIu64 "\n", si, ls->cumulative, ls->keyspace);
    }

    event_log_error (hashcat_ctx, "PCFG PROB: Keyspace overflow at structure %u/%u. Structures beyond this point are unreachable in GPU mode.", overflow_struct, lin->struct_cnt);

    event_log_warning (hashcat_ctx, "PCFG PROB: Consider using model filters (--pcfg-token-types, --pcfg-token-count-max) to reduce model size.");

    event_log_warning (hashcat_ctx, NULL);

    ret = -1;
  }
  *out = lin;

  return ret;
}

void pcfg_gpu_prob_data_destroy (pcfg_gpu_prob_data_t *lin)
{
  if (lin == NULL) return;

  hc_free_aligned ((void **) &lin->structures);
  hc_free_aligned ((void **) &lin->data_buffer);
  hc_free_aligned ((void **) &lin->term_blocks);

  hcfree (lin);
}

// init ctx (shared data only)

int pcfg_gpu_prob_ctx_init (hashcat_ctx_t *hashcat_ctx, pcfg_gpu_prob_data_t *lin, u32 num_devices, u64 skip, u64 limit, pcfg_gpu_prob_ctx_t **out)
{
  if (lin == NULL || out == NULL) return -1;
  if (num_devices == 0 || num_devices > PCFG_OMEN_MAX_DEVICES) return -1;

  status_ctx_t *status_ctx = hashcat_ctx->status_ctx;
  pcfg_gpu_prob_ctx_t *ctx = (pcfg_gpu_prob_ctx_t *) hccalloc (1, sizeof (pcfg_gpu_prob_ctx_t));

  if (ctx == NULL) return -1;

  ctx->linear_data = lin;
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
    // limit is absolute position (skip + original_limit)
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

void pcfg_gpu_prob_ctx_destroy (pcfg_gpu_prob_ctx_t *ctx)
{
  if (ctx == NULL) return;

  hcfree (ctx);
}

// init state

void pcfg_gpu_prob_gen_init (pcfg_gen_t *gen, u32 shard_id, pcfg_gpu_prob_ctx_t *ctx)
{
  if (gen == NULL || ctx == NULL) return;

  gen->gpu_prob_total_generated = 0;

  pcfg_gpu_prob_apply_skip (ctx, gen, shard_id);
}

// status

int pcfg_gpu_prob_get_status_info (const pcfg_gpu_prob_ctx_t *ctx, const pcfg_gen_t *gen, pcfg_gpu_prob_status_info_t *info)
{
  if (ctx == NULL || gen == NULL || info == NULL) return -1;

  const pcfg_gpu_prob_data_t *lin = ctx->linear_data;

  info->struct_cnt = lin->struct_cnt;
  info->generated = gen->gpu_prob_total_generated;

  if (gen->gpu_prob_current_struct >= lin->struct_cnt)
  {
    // handle exausted: use last valid struct
    if (lin->struct_cnt > 0)
    {
      const u32 last_struct = lin->struct_cnt - 1;
      const pcfg_gpu_prob_structure_t *s = &lin->structures[last_struct];

      info->current_struct = last_struct;
      info->current_local_idx = s->keyspace;
      info->struct_keyspace = s->keyspace;
      info->struct_keyspace_device = calc_device_keyspace (s->keyspace, gen->id, ctx->num_devices);
      info->struct_generated = info->struct_keyspace_device;
      info->struct_total_len = s->total_len;
      info->global_position = s->cumulative + s->keyspace;

      build_pattern_string (s, info->pattern, sizeof (info->pattern));
    }
    else
    {
      info->current_struct = 0;
      info->current_local_idx = 0;
      info->struct_keyspace = 0;
      info->struct_keyspace_device = 0;
      info->struct_generated = 0;
      info->struct_total_len = 0;
      info->global_position = 0;
      info->pattern[0] = '\0';

      return -2;
    }
  }
  else
  {
    // show ongoing struct
    const pcfg_gpu_prob_structure_t *s = &lin->structures[gen->gpu_prob_current_struct];

    info->current_struct = gen->gpu_prob_current_struct;
    info->current_local_idx = gen->gpu_prob_current_local_idx;
    info->struct_keyspace = s->keyspace;
    info->struct_keyspace_device = calc_device_keyspace (s->keyspace, gen->id, ctx->num_devices);
    info->struct_total_len = s->total_len;
    info->global_position = s->cumulative + gen->gpu_prob_current_local_idx;

    // calculate struct_generated from position (includes skip)
    u64 local_idx = gen->gpu_prob_current_local_idx;
    u32 shard_id = gen->id;
    u32 num_devices = ctx->num_devices;

    // local_idx is always in the form shard_id + k * num_devices
    // k = number of passwords already processed (skip + generate)
    if (local_idx >= shard_id)
    {
      info->struct_generated = (local_idx - shard_id) / num_devices;
    }
    else
    {
      info->struct_generated = 0;
    }

    build_pattern_string (s, info->pattern, sizeof (info->pattern));
  }

  return 0;
}
