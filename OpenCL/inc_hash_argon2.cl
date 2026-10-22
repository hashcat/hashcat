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

#define LBLOCKSIZE      (128 / THREADS_PER_LANE)

DECLSPEC void argon2_initial_block (PRIVATE_AS const u32 *in, const u32 lane, const u32 blocknum, const u32 parallelism, GLOBAL_AS argon2_block_t *blocks)
{
  blake2b_ctx_t ctx;

  blake2b_init (&ctx);

  ctx.m[0] = hl32_to_64_S (in[ 0],   sizeof(argon2_block_t));
  ctx.m[1] = hl32_to_64_S (in[ 2],   in[ 1]);
  ctx.m[2] = hl32_to_64_S (in[ 4],   in[ 3]);
  ctx.m[3] = hl32_to_64_S (in[ 6],   in[ 5]);
  ctx.m[4] = hl32_to_64_S (in[ 8],   in[ 7]);
  ctx.m[5] = hl32_to_64_S (in[10],   in[ 9]);
  ctx.m[6] = hl32_to_64_S (in[12],   in[11]);
  ctx.m[7] = hl32_to_64_S (in[14],   in[13]);
  ctx.m[8] = hl32_to_64_S (blocknum, in[15]);
  ctx.m[9] = hl32_to_64_S (0,        lane);

  blake2b_transform (ctx.h, ctx.m, 76, (u64) BLAKE2B_FINAL);

  GLOBAL_AS u64 *out = blocks[(blocknum * parallelism) + lane].values;

  out[0] = ctx.h[0];
  out[1] = ctx.h[1];
  out[2] = ctx.h[2];
  out[3] = ctx.h[3];

  ctx.m[8] = 0;
  ctx.m[9] = 0;

  for (u32 off = 4; off < 124; off += 4)
  {
    for (u32 idx = 0; idx < 8; idx++) ctx.m[idx] = ctx.h[idx];

    ctx.h[0] = BLAKE2B_IV_00 ^ 0x01010040; // default output length: 0x40 = 64 bytes
    ctx.h[1] = BLAKE2B_IV_01;
    ctx.h[2] = BLAKE2B_IV_02;
    ctx.h[3] = BLAKE2B_IV_03;
    ctx.h[4] = BLAKE2B_IV_04;
    ctx.h[5] = BLAKE2B_IV_05;
    ctx.h[6] = BLAKE2B_IV_06;
    ctx.h[7] = BLAKE2B_IV_07;

    blake2b_transform (ctx.h, ctx.m, 64, (u64) BLAKE2B_FINAL);

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

DECLSPEC void blake2b_update_8 (PRIVATE_AS blake2b_ctx_t *ctx, const u32 w0, const u32 w1, const int len)
{
  const int pos = ctx->len & 127;

  if (pos == 0)
  {
    if (ctx->len > 0) // if new block (pos == 0) AND the (old) len is not zero => transform
    {
      blake2b_transform (ctx->h, ctx->m, ctx->len, BLAKE2B_UPDATE);

      for (u32 i = 0; i < 16; i++) ctx->m[i] = 0;
    }
  }

  const u64 m  = hl32_to_64_S (w1, w0);
  const u32 s  = (pos & 7) * 8;
  const u64 m0 = (m << s);
  const u64 m1 = (m >> 8) >> (56 - s);

  const int idx = pos / 8;

  ctx->m[ 0] |= (idx ==  0) ? m0 :                    0;
  ctx->m[ 1] |= (idx ==  1) ? m0 : (idx ==  0) ? m1 : 0;
  ctx->m[ 2] |= (idx ==  2) ? m0 : (idx ==  1) ? m1 : 0;
  ctx->m[ 3] |= (idx ==  3) ? m0 : (idx ==  2) ? m1 : 0;
  ctx->m[ 4] |= (idx ==  4) ? m0 : (idx ==  3) ? m1 : 0;
  ctx->m[ 5] |= (idx ==  5) ? m0 : (idx ==  4) ? m1 : 0;
  ctx->m[ 6] |= (idx ==  6) ? m0 : (idx ==  5) ? m1 : 0;
  ctx->m[ 7] |= (idx ==  7) ? m0 : (idx ==  6) ? m1 : 0;
  ctx->m[ 8] |= (idx ==  8) ? m0 : (idx ==  7) ? m1 : 0;
  ctx->m[ 9] |= (idx ==  9) ? m0 : (idx ==  8) ? m1 : 0;
  ctx->m[10] |= (idx == 10) ? m0 : (idx ==  9) ? m1 : 0;
  ctx->m[11] |= (idx == 11) ? m0 : (idx == 10) ? m1 : 0;
  ctx->m[12] |= (idx == 12) ? m0 : (idx == 11) ? m1 : 0;
  ctx->m[13] |= (idx == 13) ? m0 : (idx == 12) ? m1 : 0;
  ctx->m[14] |= (idx == 14) ? m0 : (idx == 13) ? m1 : 0;
  ctx->m[15] |= (idx == 15) ? m0 : (idx == 14) ? m1 : 0;

  if ((pos + len) > 128)
  {
    const u32 cur_len = ((ctx->len + len) / 128) * 128;

    blake2b_transform (ctx->h, ctx->m, cur_len, (u64) BLAKE2B_UPDATE);

    for (u32 i = 1; i < 16; i++) ctx->m[i] = 0;

    ctx->m[0] = m1;
  }

  ctx->len += len;
}

DECLSPEC void argon2_initial_hash (PRIVATE_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS const argon2_options_t *options, PRIVATE_AS u64 *blockhash)
{
  blake2b_ctx_t ctx;
  blake2b_init (&ctx);

  ctx.m[0] = hl32_to_64_S (options->digest_len, options->parallelism);
  ctx.m[1] = hl32_to_64_S (options->iterations, options->memory_usage_in_kib);
  ctx.m[2] = hl32_to_64_S (options->type,       options->version);
  ctx.len  = 24;

  blake2b_update_8 (&ctx, pw_len, 0, 4);

  for (u32 i = 0, idx = 0; i < pw_len; i += 8, idx += 2)
  {
    blake2b_update_8 (&ctx, pw_buf[idx + 0], pw_buf[idx + 1], MIN((pw_len - i), 8));
  }

  blake2b_update_8 (&ctx, salt_len, 0, 4);

  for (u32 i = 0, idx = 0; i < salt_len; i += 8, idx += 2)
  {
    blake2b_update_8 (&ctx, salt_buf[idx + 0], salt_buf[idx + 1], MIN((salt_len - i), 8));
  }

  blake2b_update_8 (&ctx, 0, 0, 8); // secret (K) and associated data (X)
  blake2b_final (&ctx);

  for (u32 idx = 0; idx < 8; idx++) blockhash[idx] = ctx.h[idx];
}

DECLSPEC void argon2_init_main (PRIVATE_AS const u32 *pw_buf, const int pw_len, PRIVATE_AS const u32 *salt_buf, const int salt_len, PRIVATE_AS const argon2_options_t *options, GLOBAL_AS argon2_block_t *out)
{
  u64 blockhash[16] = { 0 };

  argon2_initial_hash (pw_buf, pw_len, salt_buf, salt_len, options, blockhash);

  // Generate the first two blocks of each lane
  for (u32 lane = 0; lane < options->parallelism; lane++)
  {
    argon2_initial_block ((PRIVATE_AS u32 *) blockhash, lane, 0, options->parallelism, out);
    argon2_initial_block ((PRIVATE_AS u32 *) blockhash, lane, 1, options->parallelism, out);
  }
}

DECLSPEC u64 trunc_mul (const u64 x, const u64 y)
{
  const u32 xlo = l32_from_64_S (x);
  const u32 ylo = l32_from_64_S (y);

  const u32 xyhi = hc_umulhi (xlo, ylo);
  const u32 xylo = hc_umullo (xlo, ylo);

  return hl32_to_64_S (xyhi, xylo);
}

DECLSPEC inline u32 argon2_ref_address (PRIVATE_AS const argon2_options_t *options, PRIVATE_AS const argon2_pos_t *pos, u32 index, u64 pseudo_random)
{
  u32 ref_lane = 0;
  u32 ref_area = 0;
  u32 ref_index = 0;

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

DECLSPEC void swap_u64 (PRIVATE_AS u64 *x, PRIVATE_AS u64 *y)
{
  u64 tmp = *x;
  *x = *y;
  *y = tmp;
}

DECLSPEC void transpose_permute_block (u64 R[4], int argon2_thread)
{
  if (argon2_thread & 0x08)
  {
    swap_u64 (&R[0], &R[2]);
    swap_u64 (&R[1], &R[3]);
  }
  if (argon2_thread & 0x04)
  {
    swap_u64 (&R[0], &R[1]);
    swap_u64 (&R[2], &R[3]);
  }
}

DECLSPEC int argon2_shift (int idx, int argon2_thread)
{
  const int delta = ((idx & 0x02) << 3) + (idx & 0x01);
  return (argon2_thread & 0x0e) | (((argon2_thread & 0x11) + delta + 0x0e) & 0x11);
}

DECLSPEC void argon2_hash_block (u64 R[LBLOCKSIZE], int argon2_thread, LOCAL_AS u64 *shuffle_buf, int argon2_lsz)
{
#if THREADS_PER_LANE == 1
  u64 v[16];

  for (u32 i = 0, offset = 0; i < 8; i++, offset += 16)
  {
    for (u32 j = 0; j < 16; j++) v[j] = R[offset + j];

    ARGON2_P();

    for (u32 j = 0; j < 16; j++) R[offset + j] = v[j];
  }

  for (u32 i = 0, offset = 0; i < 8; i++, offset += 2)
  {
    for (u32 j = 0, k = offset; j < 16; j += 2, k += 16) {
      v[j + 0] = R[k + 0];
      v[j + 1] = R[k + 1];
    }

    ARGON2_P();

    for (u32 j = 0, k = offset; j < 16; j += 2, k += 16)
    {
      R[k + 0] = v[j + 0];
      R[k + 1] = v[j + 1];
    }
  }
#else
  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], argon2_thread ^ (idx << 2), argon2_thread, argon2_lsz);

  transpose_permute_block (R, argon2_thread);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], argon2_thread ^ (idx << 2), argon2_thread, argon2_lsz);

  ARGON2_G(R[0], R[1], R[2], R[3]);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx],  (argon2_thread & 0x1c) | ((argon2_thread + idx) & 0x03), argon2_thread, argon2_lsz);

  ARGON2_G(R[0], R[1], R[2], R[3]);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], ((argon2_thread & 0x1c) | ((argon2_thread - idx) & 0x03)) ^ (idx << 2), argon2_thread, argon2_lsz);

  transpose_permute_block (R, argon2_thread);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], argon2_thread ^ (idx << 2), argon2_thread, argon2_lsz);

  ARGON2_G(R[0], R[1], R[2], R[3]);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], argon2_shift (idx, argon2_thread), argon2_thread, argon2_lsz);

  ARGON2_G(R[0], R[1], R[2], R[3]);

  for (u32 idx = 1; idx < 4; idx++) R[idx] = hc__shfl_sync (shuffle_buf, FULL_MASK, R[idx], argon2_shift ((4 - idx), argon2_thread), argon2_thread, argon2_lsz);
#endif
}

DECLSPEC void argon2_next_addresses (PRIVATE_AS const argon2_options_t *options, PRIVATE_AS const argon2_pos_t *pos, PRIVATE_AS u32 *addresses, u32 start_index, u32 argon2_thread, LOCAL_AS u64 *shuffle_buf, u32 argon2_lsz)
{
  u64 Z[LBLOCKSIZE] = { 0 };
  u64 tmp[LBLOCKSIZE] = { 0 };

  for (u32 i = 0, index = argon2_thread; i < (LBLOCKSIZE / 4); i++, index += THREADS_PER_LANE)
  {
    switch (index)
    {
      case 0:  Z[i] = pos->pass;                   break;
      case 1:  Z[i] = pos->lane;                   break;
      case 2:  Z[i] = pos->slice;                  break;
      case 3:  Z[i] = options->memory_block_count; break;
      case 4:  Z[i] = options->iterations;         break;
      case 5:  Z[i] = options->type;               break;
      case 6:  Z[i] = (start_index / 128) + 1;     break;
      default: Z[i] = 0;                           break;
    }

    tmp[i] = Z[i];
  }

  argon2_hash_block (Z, argon2_thread, shuffle_buf, argon2_lsz);

  for (u32 idx = 0; idx < (LBLOCKSIZE / 4); idx++) Z[idx]  ^= tmp[idx];

  for (u32 idx = 0; idx < LBLOCKSIZE; idx++) tmp[idx] = Z[idx];

  argon2_hash_block (Z, argon2_thread, shuffle_buf, argon2_lsz);

  for (u32 idx = 0; idx < LBLOCKSIZE; idx++) Z[idx]  ^= tmp[idx];

  for (u32 i = 0, index = (start_index + argon2_thread); i < LBLOCKSIZE; i++, index += THREADS_PER_LANE)
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

  return (u32) -1;
}

DECLSPEC GLOBAL_AS argon2_block_t *argon2_get_current_block (GLOBAL_AS argon2_block_t *blocks, PRIVATE_AS const argon2_options_t *options, u32 lane, u32 index_in_lane, u64 R[LBLOCKSIZE], u32 argon2_thread)
{
  // Apply wrap-around to previous block index if the current block is the first block in the lane
  const u32 prev_in_lane = (index_in_lane == 0) ? (options->lane_length - 1) : (index_in_lane - 1);

  GLOBAL_AS argon2_block_t *prev_block = &blocks[(prev_in_lane * options->parallelism) + lane];

  if (lane < options->parallelism)
  {
    for (u32 idx = 0; idx < LBLOCKSIZE; idx++) R[idx] = prev_block->values[(idx * THREADS_PER_LANE) + argon2_thread];
  }

  return &blocks[(index_in_lane * options->parallelism) + lane];
}

DECLSPEC void argon2_fill_subsegment (GLOBAL_AS argon2_block_t *blocks, PRIVATE_AS const argon2_options_t *options, PRIVATE_AS const argon2_pos_t *pos, bool indep_addr, const u32 addresses[LBLOCKSIZE],
                                      u32 start_index, u32 end_index, GLOBAL_AS argon2_block_t *cur_block, u64 R[LBLOCKSIZE], u32 argon2_thread, LOCAL_AS u64 *shuffle_buf, u32 argon2_lsz)
{
  // a row past the last lane, see argon2_lane_limit (), leaves the blocks alone

  const bool has_lane = (pos->lane < options->parallelism);

  for (u32 index = start_index; index < end_index; index++, cur_block += options->parallelism)
  {
    u32 ref_address = 0;

    if (indep_addr)
    {
#if THREADS_PER_LANE == 1
      ref_address = addresses[(index / THREADS_PER_LANE) % LBLOCKSIZE];
#else
      ref_address = index_u32x4 (addresses, (index / THREADS_PER_LANE) % LBLOCKSIZE);
      ref_address = hc__shfl_sync (shuffle_buf, FULL_MASK, ref_address, index, argon2_thread, argon2_lsz);
#endif
    }
    else
    {
      ref_address = argon2_ref_address (options, pos, index, R[0]);
#if THREADS_PER_LANE != 1
      ref_address = hc__shfl_sync (shuffle_buf, FULL_MASK, ref_address, 0, argon2_thread, argon2_lsz);
#endif
    }

    GLOBAL_AS const argon2_block_t *ref_block = &blocks[ref_address];

    u64 tmp[LBLOCKSIZE] = { 0 };

    // First pass is overwrite, next passes are XOR with previous
    if ((has_lane == true) && (pos->pass > 0) && (options->version != ARGON2_VERSION_10))
    {
      for (u32 idx = 0; idx < LBLOCKSIZE; idx++) tmp[idx]  = cur_block->values[(idx * THREADS_PER_LANE) + argon2_thread];
    }

    if (has_lane == true)
    {
      for (u32 idx = 0; idx < LBLOCKSIZE; idx++) R[idx]   ^= ref_block->values[(idx * THREADS_PER_LANE) + argon2_thread];
    }

    for (u32 idx = 0; idx < LBLOCKSIZE; idx++) tmp[idx] ^= R[idx];

    argon2_hash_block (R, argon2_thread, shuffle_buf, argon2_lsz);

    for (u32 idx = 0; idx < LBLOCKSIZE; idx++) R[idx]   ^= tmp[idx];

    if (has_lane == false) continue;

    for (u32 idx = 0; idx < LBLOCKSIZE; idx++) cur_block->values[(idx * THREADS_PER_LANE) + argon2_thread] = R[idx];
  }
}

// The lane where a row of the _loop kernels stops. Where the shuffle is a barrier across the
// workgroup, a row that ran out of lanes early would reach the barrier behind the lane loop while
// the others are still at the ones inside it. There every row runs as many lanes as the fullest
// one, and a row past the last lane only takes part in the shuffles.

DECLSPEC u32 argon2_lane_limit (const u32 parallelism, const u32 rows)
{
  #if defined HC_SHFL_BARRIER && THREADS_PER_LANE != 1
  const u32 lane_limit = ((parallelism + rows - 1) / rows) * rows;
  #else
  const u32 lane_limit = parallelism;
  #endif

  return lane_limit;
}

DECLSPEC void argon2_fill_segment (GLOBAL_AS argon2_block_t *blocks, PRIVATE_AS const argon2_options_t *options, PRIVATE_AS const argon2_pos_t *pos, LOCAL_AS u64 *shuffle_buf, const u32 argon2_thread, const u32 argon2_lsz)
{
  // We have already generated the first two blocks of each lane (for the first pass)
  const u32 skip_blocks   = (pos->pass == 0) && (pos->slice == 0) ? 2 : 0;
  const u32 index_in_lane = (pos->slice * options->segment_length) + skip_blocks;

  u64 R[LBLOCKSIZE] = { 0 };

  GLOBAL_AS argon2_block_t *cur_block = argon2_get_current_block (blocks, options, pos->lane, index_in_lane, R, argon2_thread);

  if ((options->type == TYPE_I) || ((options->type == TYPE_ID) && (pos->pass == 0) && (pos->slice <= 1)))
  {
    for (u32 block_index = 0; block_index < options->segment_length; block_index += 128)
    {
      const u32 start_index = (block_index == 0) ? skip_blocks : block_index;
      const u32 end_index   = MIN(((start_index | 127) + 1), options->segment_length);

      u32 addresses[LBLOCKSIZE] = { 0 };

      argon2_next_addresses (options, pos, addresses, block_index, argon2_thread, shuffle_buf, argon2_lsz);
      argon2_fill_subsegment (blocks, options, pos, true, addresses, start_index, end_index, cur_block, R, argon2_thread, shuffle_buf, argon2_lsz);

      cur_block += (end_index - start_index) * options->parallelism;
    }
  }
  else
  {
    u32 addresses[LBLOCKSIZE] = { 0 };

    argon2_fill_subsegment (blocks, options, pos, false, addresses, skip_blocks, options->segment_length, cur_block, R, argon2_thread, shuffle_buf, argon2_lsz);
  }
}

DECLSPEC void argon2_final (GLOBAL_AS argon2_block_t *blocks, PRIVATE_AS const argon2_options_t *options, PRIVATE_AS u32 *out)
{
  const u32 lane_length = options->lane_length;
  const u32 lanes = options->parallelism;

  blake2b_ctx_t ctx;
  blake2b_init (&ctx);

  // Override default (0x40) value in BLAKE2b
  ctx.h[0] ^= 0x40 ^ options->digest_len;

  u32 rem = options->digest_len;

  for (u32 offset = 0; offset < 128; offset += 16)
  {
    for (u32 l = 0; l < lanes; l++)
    {
      for (u32 idx = 0; idx < 16; idx++)
      {
        ctx.m[idx] ^= blocks[((lane_length - 1) * lanes) + l].values[idx + offset];
      }
    }

    for (u32 idx = 0; idx < 16; idx++)
    {
      const u64 value = ctx.m[idx];

      ctx.m[idx] = hl32_to_64_S (l32_from_64_S (value), rem);

      rem = h32_from_64_S (value);
    }

    ctx.len += 128;

    blake2b_transform (ctx.h, ctx.m, ctx.len, (u64) BLAKE2B_UPDATE);

    for (u32 idx = 0; idx < 16; idx++) ctx.m[idx] = 0;
  }

  ctx.m[0] = hl32_to_64_S (0, rem);

  blake2b_transform (ctx.h, ctx.m, 1028, (u64) BLAKE2B_FINAL);

  for (uint i = 0, idx = 0; i < (options->digest_len / 4); i += 2, idx += 1)
  {
    out [i + 0] = l32_from_64_S (ctx.h[idx]);
    out [i + 1] = h32_from_64_S (ctx.h[idx]);
  }
}

DECLSPEC GLOBAL_AS argon2_block_t *get_argon2_block (PRIVATE_AS const argon2_options_t *options, GLOBAL_AS void *buf, const int idx)
{
  GLOBAL_AS u32 *buf32 = (GLOBAL_AS u32 *) buf;

  #ifdef ARGON2_TMP_ELEM
  return (GLOBAL_AS argon2_block_t *) buf32 + (ARGON2_TMP_ELEM * idx);
  #else
  return (GLOBAL_AS argon2_block_t *) buf32 + (options->memory_block_count * idx);
  #endif
}

DECLSPEC void argon2_init_pp (PRIVATE_AS const pw_t *pw, PRIVATE_AS const salt_t *salt, PRIVATE_AS const argon2_options_t *options, GLOBAL_AS argon2_block_t *out)
{
  argon2_init_main (pw->i, pw->pw_len, salt->salt_buf, salt->salt_len, options, out);
}

DECLSPEC void argon2_init_pg (PRIVATE_AS const pw_t *pw, GLOBAL_AS  const salt_t *salt, PRIVATE_AS const argon2_options_t *options, GLOBAL_AS argon2_block_t *out)
{
  const u32 salt_len = salt->salt_len;

  u32 salt_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    salt_buf[idx] = salt->salt_buf[idx];
  }

  argon2_init_main (pw->i, pw->pw_len, salt_buf, salt_len, options, out);
}

DECLSPEC void argon2_init_gp (GLOBAL_AS const pw_t *pw, PRIVATE_AS const salt_t *salt, PRIVATE_AS const argon2_options_t *options, GLOBAL_AS argon2_block_t *out)
{
  const u32 pw_len = pw->pw_len;

  u32 pw_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    pw_buf[idx] = pw->i[idx];
  }

  argon2_init_main (pw_buf, pw_len, salt->salt_buf, salt->salt_len, options, out);
}

DECLSPEC void argon2_init_gg (GLOBAL_AS const pw_t *pw, GLOBAL_AS  const salt_t *salt, PRIVATE_AS const argon2_options_t *options, GLOBAL_AS argon2_block_t *out)
{
  const u32 pw_len = pw->pw_len;

  u32 pw_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    pw_buf[idx] = pw->i[idx];
  }

  const u32 salt_len = salt->salt_len;

  u32 salt_buf[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    salt_buf[idx] = salt->salt_buf[idx];
  }

  argon2_init_main (pw_buf, pw_len, salt_buf, salt_len, options, out);
}
