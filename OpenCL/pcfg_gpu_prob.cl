/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg_gpu_prob.h)
#endif

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

DECLSPEC HC_INLINE u32 find_struct_idx (
  #ifdef IS_METAL
  CONSTANT_AS const u64 *cumulative_offsets,
  #else
  GLOBAL_AS const u64 *cumulative_offsets,
  #endif
  const u32 struct_cnt, const u64 val)
{
  if (struct_cnt == 1) return 0;  // FAST PATH

  if (struct_cnt == 2)            // FAST PATH
  {
    return (val >= cumulative_offsets[1]) ? 1 : 0;
  }

  u32 l = 0;
  u32 r = struct_cnt;

  #pragma unroll 4
  while (l < r)
  {
    const u32 mid = (l + r) >> 1;

    if (cumulative_offsets[mid] <= val)
    {
      l = mid + 1;
    }
    else
    {
      r = mid;
    }
  }

  return (l > 0) ? l - 1 : 0;
}

DECLSPEC void pcfg_gpu_prob_generate_pw (PRIVATE_AS u32 *pw_buf, GLOBAL_AS const u32 *data_buffer, GLOBAL_AS const pcfg_term_block_t *term_blocks, GLOBAL_AS const pcfg_gpu_prob_structure_t *structure, const u64 local_idx)
{
  const u32 token_cnt = structure->token_cnt;

  // decompose mixed-radix
  u32 term_indices[16];

  u64 work_idx = local_idx;

  #pragma unroll
  for (int k = 15; k >= 0; k--)
  {
    if (k < (int) token_cnt)
    {
      const u32 count = structure->divisors[k];
      const u64 recip = structure->recips64[k];

      if (count <= 1)
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
  }

  // assemble password: AoS + offset precomputed

  #pragma unroll
  for (u32 k = 0; k < 16; k++)
  {
    if (k >= token_cnt) break;

    const u32 blk_idx = structure->block_indices[k];

    GLOBAL_AS const pcfg_term_block_t *blk = &term_blocks[blk_idx];

    const u32 len          = structure->lengths[k];
    const u32 pos          = structure->offsets[k];
    const u32 stride_words = blk->stride_words;
    const u64 block_base   = blk->data_offset;
    const u32 tid          = term_indices[k];

    // AoS: all words in the terminal are contiguous

    const u64 src_base     = block_base + (u64) tid * stride_words;
    const u32 base_word    = pos >> 2;
    const u32 bit_off      = (pos & 3) << 3;

    if (bit_off == 0)
    {
      // aligned path: direct writing, zero shift

      for (u32 w = 0; w < 64; w++)
      {
        if (w >= stride_words) break;

        if (w * 4 >= len) break;

        u32 val = data_buffer[src_base + w]; // AoS is contiguous

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
      // path not aligned: bit_off constant throughout the token

      for (u32 w = 0; w < 64; w++)
      {
        if (w >= stride_words) break;

        if (w * 4 >= len) break;

        u32 val = data_buffer[src_base + w]; // AoS is contiguous

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

// password len 0-31

KERNEL_FQ KERNEL_FA void pcfg_gpu_prob_generate_opti (KERN_ATTR_PCFG_GPU_PROB)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 global_idx = base_off + gid * num_devices;

  const u32 struct_idx = find_struct_idx (cumulative_offsets, struct_cnt, global_idx);

  GLOBAL_AS const pcfg_gpu_prob_structure_t *s = &structures[struct_idx];

  const u64 local_idx = global_idx - s->cumulative;

  if (local_idx >= s->keyspace) return;

  const u32 pw_words = (pw_max + 3) >> 2;

  u32 pw_buf[15];

  #pragma unroll
  for (u32 i = 0; i < 15; i++) pw_buf[i] = 0;

  pcfg_gpu_prob_generate_pw (pw_buf, data_buffer, term_blocks, s, local_idx);

  GLOBAL_AS pw_t *dest = &pws_buf[gid];

  for (u32 i = 0; i < pw_words; i++) dest->i[i] = pw_buf[i];

  dest->pw_len = s->total_len;
}

// password len max 0-255

KERNEL_FQ KERNEL_FA void pcfg_gpu_prob_generate (KERN_ATTR_PCFG_GPU_PROB)
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 global_idx = base_off + gid * num_devices;

  const u32 struct_idx = find_struct_idx (cumulative_offsets, struct_cnt, global_idx);

  GLOBAL_AS const pcfg_gpu_prob_structure_t *s = &structures[struct_idx];

  const u64 local_idx = global_idx - s->cumulative;

  if (local_idx >= s->keyspace) return;

  const u32 total_len = s->total_len;
  const u32 pw_words = (pw_max + 3) >> 2;

  GLOBAL_AS pw_t *dest = &pws_buf[gid];

  if (total_len <= 31)
  {
    // fast path: short password 8 words in registers (0-31 bytes)

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

    pcfg_gpu_prob_generate_pw (pw_buf, data_buffer, term_blocks, s, local_idx);

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
    // medium path: 17 words in registers (32-63 bytes)

    u32 pw_buf[17];

    #pragma unroll
    for (u32 i = 0; i < 17; i++) pw_buf[i] = 0;

    pcfg_gpu_prob_generate_pw (pw_buf, data_buffer, term_blocks, s, local_idx);

    #pragma unroll
    for (u32 i = 0; i < 16; i++) dest->i[i] = pw_buf[i];

    for (u32 i = 16; i < pw_words; i++) dest->i[i] = 0;
  }
  else
  {
    // slow path: long words, full pw_t in scratch memory (64-255 bytes)

    pw_t pw;

    for (u32 i = 0; i < pw_words; i++) pw.i[i] = 0;

    pcfg_gpu_prob_generate_pw (pw.i, data_buffer, term_blocks, s, local_idx);

    pw.pw_len = total_len;

    pws_buf[gid] = pw;

    return;
  }

  dest->pw_len = total_len;
}
