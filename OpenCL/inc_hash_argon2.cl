/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 *
 * Warp code based on original work by Ondrej Mosnáček
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_hash_blake2b.h"
#include "inc_hash_argon2.h"

DECLSPEC void argon2_initial_block (const u32 *in, const u32 lane, const u32 blocknum, const u32 parallelism, GLOBAL_AS argon2_block_t *blocks)
{
  blake2b_ctx_t ctx;

  blake2b_init (&ctx);

  u64 blake_buf[16] = { 0 };

  blake_buf[0] = sizeof(argon2_block_t);

  blake2b_update (&ctx, (u32 *) blake_buf, 4);
  blake2b_update (&ctx, in, 64);

  blake_buf[0] = hl32_to_64 (lane, blocknum);

  blake2b_update (&ctx, (u32 *) blake_buf, 8);

  blake2b_final (&ctx);

  GLOBAL_AS u64 *out = blocks[(blocknum * parallelism) + lane].values;

  out[0] = ctx.h[0];
  out[1] = ctx.h[1];
  out[2] = ctx.h[2];
  out[3] = ctx.h[3];

  for (u32 off = 4; off < 124; off += 4)
  {
    for (u32 idx = 0; idx < 8; idx++) blake_buf[idx] = ctx.h[idx];

    blake2b_init (&ctx);
    blake2b_transform (ctx.h, blake_buf, 64, BLAKE2B_FINAL);

    out[off + 0] = ctx.h[0];
    out[off + 1] = ctx.h[1];
    out[off + 2] = ctx.h[2];
    out[off + 3] = ctx.h[3];
  }

  out[124] = ctx.h[4];
  out[125] = ctx.h[5];
  out[126] = ctx.h[6];
  out[127] = ctx.h[7];
}

DECLSPEC void argon2_initial_hash (GLOBAL_AS const pw_t *pw, GLOBAL_AS const salt_t *salt, const argon2_options_t *options, u64 *blockhash)
{
  blake2b_ctx_t ctx;
  blake2b_init (&ctx);

  u32 option_input[32] = { 0 };

  option_input[0] = options->parallelism;
  option_input[1] = options->digest_len;
  option_input[2] = options->memory_usage_in_kib;
  option_input[3] = options->iterations;
  option_input[4] = options->version;
  option_input[5] = options->type;

  blake2b_update (&ctx, option_input, 24);

  u32 len_input[32] = { 0 };

  len_input[0] = pw->pw_len;

  blake2b_update (&ctx, len_input, 4);
  blake2b_update_global (&ctx, pw->i, pw->pw_len);

  len_input[0] = salt->salt_len;

  blake2b_update (&ctx, len_input, 4);
  blake2b_update_global (&ctx, salt->salt_buf, salt->salt_len);

  len_input[0] = 0;

  blake2b_update (&ctx, len_input, 4); // secret (K)
  blake2b_update (&ctx, len_input, 4); // associated data (X)

  blake2b_final (&ctx);

  for (u32 idx = 0; idx < 8; idx++) blockhash[idx] = ctx.h[idx];
}

DECLSPEC void argon2_init (GLOBAL_AS const pw_t *pw, GLOBAL_AS const salt_t *salt,
                           const argon2_options_t *options, GLOBAL_AS argon2_block_t *out)
{
  u64 blockhash[16] = { 0 };

  argon2_initial_hash (pw, salt, options, blockhash);

  // Generate the first two blocks of each lane
  for (u32 lane = 0; lane < options->parallelism; lane++)
  {
    argon2_initial_block ((u32 *) blockhash, lane, 0, options->parallelism, out);
    argon2_initial_block ((u32 *) blockhash, lane, 1, options->parallelism, out);
  }
}

// TODO: reconsider 'trunc_mul()'
DECLSPEC u64 trunc_mul (u64 x, u64 y)
{
  const u32 xlo = (u32) x;
  const u32 ylo = (u32) y;
  return hl32_to_64_S (hc_umulhi (xlo, ylo), (u32) (xlo * ylo));
}

DECLSPEC inline u32 argon2_ref_address (const argon2_options_t *options, const argon2_pos_t *pos, u32 index, u64 pseudo_random)
{
  u32 ref_lane;
  u32 ref_area;
  u32 ref_index;

  if ((pos->pass == 0) && (pos->slice == 0))
  {
    ref_lane = pos->lane;
  }
  else
  {
    ref_lane = h32_from_64_S (pseudo_random) % options->parallelism;
  }

  ref_area  = (pos->pass == 0) ? pos->slice : (ARGON2_SYNC_POINTS - 1);
  ref_area *= options->segment_length;

  if ((ref_lane == pos->lane) || (index == 0))
  {
      ref_area += (index - 1);
  }

  const u32 j1 = l32_from_64_S (pseudo_random);
  ref_index = (ref_area - 1 - hc_umulhi (ref_area, hc_umulhi (j1, j1)));

  if (pos->pass > 0)
  {
    ref_index += (pos->slice + 1) * options->segment_length;

    if (ref_index >= options->lane_length)
    {
      ref_index -= options->lane_length;
    }
  }

  return (options->parallelism * ref_index) + ref_lane;
}

DECLSPEC void swap_u64 (u64 *x, u64 *y)
{
  u64 tmp = *x;
  *x = *y;
  *y = tmp;
}

DECLSPEC void transpose_permute_block (u64 R[4], int thread)
{
  if (thread & 0x08)
  {
    swap_u64 (&R[0], &R[2]);
    swap_u64 (&R[1], &R[3]);
  }
  if (thread & 0x04)
  {
    swap_u64 (&R[0], &R[1]);
    swap_u64 (&R[2], &R[3]);
  }
}

DECLSPEC int argon2_shift (int idx, int thread)
{
  const int delta = ((idx & 0x02) << 3) + (idx & 0x01);
  return (thread & 0x0e) | (((thread & 0x11) + delta + 0x0e) & 0x11);
}

DECLSPEC void argon2_hash_block (u64 R[4], int thread, LOCAL_AS u64 *shuffle_buf)
{
  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], thread ^ (idx << 2));

  transpose_permute_block (R, thread);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], thread ^ (idx << 2));

  ARGON2_G(R[0], R[1], R[2], R[3]);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx],  (thread & 0x1c) | ((thread + idx) & 0x03));

  ARGON2_G(R[0], R[1], R[2], R[3]);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], ((thread & 0x1c) | ((thread - idx) & 0x03)) ^ (idx << 2));

  transpose_permute_block (R, thread);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], thread ^ (idx << 2));

  ARGON2_G(R[0], R[1], R[2], R[3]);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], argon2_shift (idx, thread));

  ARGON2_G(R[0], R[1], R[2], R[3]);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], argon2_shift ((4 - idx), thread));
}

DECLSPEC void argon2_next_addresses (const argon2_options_t *options, const argon2_pos_t *pos, u32 *addresses, u32 start_index, u32 thread, LOCAL_AS u64 *shuffle_buf)
{
  u64 Z[4] = { 0 };
  u64 tmp[4];

  switch (thread)
  {
    case 0:  Z[0] = pos->pass;                   break;
    case 1:  Z[0] = pos->lane;                   break;
    case 2:  Z[0] = pos->slice;                  break;
    case 3:  Z[0] = options->memory_block_count; break;
    case 4:  Z[0] = options->iterations;         break;
    case 5:  Z[0] = options->type;               break;
    case 6:  Z[0] = (start_index / 128) + 1;     break;
    default: Z[0] = 0;                           break;
  }

  tmp[0] = Z[0];

  argon2_hash_block (Z, thread, shuffle_buf);

  Z[0]  ^= tmp[0];

  for (u32 idx = 0; idx < 4; idx++) tmp[idx] = Z[idx];

  argon2_hash_block (Z, thread, shuffle_buf);

  for (u32 idx = 0; idx < 4; idx++) Z[idx]  ^= tmp[idx];

  for (u32 i = 0, index = (start_index + thread); i < 4; i++, index += THREADS_PER_LANE)
  {
    addresses[i] = argon2_ref_address (options, pos, index, Z[i]);
  }
}

DECLSPEC u32 index_u32x4 (const u32 array[4], u32 index)
{
  switch (index)
  {
    case 0:
      return array[0];
    case 1:
      return array[1];
    case 2:
      return array[2];
    case 3:
      return array[3];
  }

  return -1;
}

DECLSPEC GLOBAL_AS argon2_block_t *argon2_get_current_block (GLOBAL_AS argon2_block_t *blocks, const argon2_options_t *options, u32 lane, u32 index_in_lane, u64 R[4], u32 thread)
{
  // Apply wrap-around to previous block index if the current block is the first block in the lane
  const u32 prev_in_lane = (index_in_lane == 0) ? (options->lane_length - 1) : (index_in_lane - 1);

  GLOBAL_AS argon2_block_t *prev_block = &blocks[(prev_in_lane * options->parallelism) + lane];

  for (u32 idx = 0; idx < 4; idx++) R[idx] = prev_block->values[(idx * THREADS_PER_LANE) + thread];

  return &blocks[(index_in_lane * options->parallelism) + lane];
}

DECLSPEC void argon2_fill_subsegment (GLOBAL_AS argon2_block_t *blocks, const argon2_options_t *options, const argon2_pos_t *pos, bool indep_addr, const u32 addresses[4],
                                      u32 start_index, u32 end_index, GLOBAL_AS argon2_block_t *cur_block, u64 R[4], u32 thread, LOCAL_AS u64 *shuffle_buf)
{
  for (u32 index = start_index; index < end_index; index++, cur_block += options->parallelism)
  {
    u32 ref_address;

    if (indep_addr)
    {
      ref_address = index_u32x4 (addresses, (index / THREADS_PER_LANE) % ARGON2_SYNC_POINTS);
      ref_address = hc__shfl_sync (shuffle_buf, FULL_MASK, ref_address, index);
    }
    else
    {
      ref_address = argon2_ref_address (options, pos, index, R[0]);
      ref_address = hc__shfl_sync (shuffle_buf, FULL_MASK, ref_address, 0);
    }

    GLOBAL_AS const argon2_block_t *ref_block = &blocks[ref_address];

    u64 tmp[4] = { 0 };

    // First pass is overwrite, next passes are XOR with previous
    if ((pos->pass > 0) && (options->version != ARGON2_VERSION_10))
    {
      for (u32 idx = 0; idx < 4; idx++) tmp[idx]  = cur_block->values[(idx * THREADS_PER_LANE) + thread];
    }

    for (u32 idx = 0; idx < 4; idx++) R[idx]   ^= ref_block->values[(idx * THREADS_PER_LANE) + thread];

    for (u32 idx = 0; idx < 4; idx++) tmp[idx] ^= R[idx];

    argon2_hash_block (R, thread, shuffle_buf);

    for (u32 idx = 0; idx < 4; idx++) R[idx]   ^= tmp[idx];

    for (u32 idx = 0; idx < 4; idx++) cur_block->values[(idx * THREADS_PER_LANE) + thread] = R[idx];
  }
}

DECLSPEC void argon2_fill_segment (GLOBAL_AS argon2_block_t *blocks, const argon2_options_t *options, const argon2_pos_t *pos, LOCAL_AS u64 *shuffle_buf)
{
  const u32  thread       = get_local_id(0);

  // We have already generated the first two blocks of each lane (for the first pass)
  const u32 skip_blocks   = (pos->pass == 0) && (pos->slice == 0) ? 2 : 0;
  const u32 index_in_lane = (pos->slice * options->segment_length) + skip_blocks;

  u64 R[4];

  GLOBAL_AS argon2_block_t *cur_block = argon2_get_current_block (blocks, options, pos->lane, index_in_lane, R, thread);

  if ((options->type == TYPE_I) || ((options->type == TYPE_ID) && (pos->pass == 0) && (pos->slice <= 1)))
  {
    for (u32 block_index = 0; block_index < options->segment_length; block_index += 128)
    {
      const u32 start_index = (block_index == 0) ? skip_blocks : block_index;
      const u32 end_index   = MIN(((start_index | 127) + 1), options->segment_length);

      u32 addresses[4];

      argon2_next_addresses (options, pos, addresses, block_index, thread, shuffle_buf);
      argon2_fill_subsegment (blocks, options, pos, true, addresses, start_index, end_index, cur_block, R, thread, shuffle_buf);

      cur_block += (end_index - start_index) * options->parallelism;
    }
  }
  else
  {
    u32 addresses[4] = { 0 };

    argon2_fill_subsegment (blocks, options, pos, false, addresses, skip_blocks, options->segment_length, cur_block, R, thread, shuffle_buf);
  }
}

DECLSPEC void argon2_final (GLOBAL_AS argon2_block_t *blocks, const argon2_options_t *options, u32 *out)
{
  const u32 lane_length = options->lane_length;
  const u32 lanes = options->parallelism;

  argon2_block_t final_block = { };

  for (u32 l = 0; l < lanes; l++)
  {
    for (u32 idx = 0; idx < 128; idx++) final_block.values[idx] ^= blocks[((lane_length - 1) * lanes) + l].values[idx];
  }

  u32 output_len [32] = {0};
  output_len [0] = options->digest_len;

  blake2b_ctx_t ctx;
  blake2b_init (&ctx);

  // Override default (0x40) value in BLAKE2b
  ctx.h[0] ^= 0x40 ^ options->digest_len; 

  blake2b_update (&ctx, output_len, 4);
  blake2b_update (&ctx, (u32 *) final_block.values, sizeof(final_block));

  blake2b_final (&ctx);

  for (int i = 0, idx = 0; i < (options->digest_len / 4); i += 2, idx += 1)
  {
    out [i + 0] = l32_from_64_S (ctx.h[idx]);
    out [i + 1] = h32_from_64_S (ctx.h[idx]);
  }
}
