
/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

#ifndef INC_HASH_ARGON2_H
#define INC_HASH_ARGON2_H

#define MIN(a,b) (((a) < (b)) ? (a) : (b))

#define ARGON2_VERSION_10 0x10
#define ARGON2_VERSION_13 0x13

#define THREADS_PER_LANE 32
#define FULL_MASK 0xffffffff

#define BLAKE2B_OUTBYTES 64
#define ARGON2_SYNC_POINTS 4
#define ARGON2_ADDRESSES_IN_BLOCK 128

#define TYPE_D  0
#define TYPE_I  1
#define TYPE_ID 2

#if defined IS_CUDA
#define hc__shfl_sync(shfbuf,mask,var,srcLane,argon2_thread,argon2_lsz) __shfl_sync ((mask),(var),(srcLane))
#elif defined IS_HIP
// attention hard coded 32 warps for hip here
#define hc__shfl_sync(shfbuf,mask,var,srcLane,argon2_thread,argon2_lsz) __shfl ((var),(srcLane),32)
#elif defined IS_OPENCL
#define hc__shfl_sync(shfbuf,mask,var,srcLane,argon2_thread,argon2_lsz) hc__shfl ((shfbuf),(var),(srcLane),(argon2_thread),(argon2_lsz))

#if defined IS_AMD && defined IS_GPU
DECLSPEC u64 hc__shfl (MAYBE_UNUSED LOCAL_AS u64 *shuffle_buf, const u64 var, const int src_lane, const u32 argon2_thread, const u32 argon2_lsz)
{
  const u32 idx = src_lane << 2;

  const u32 l32 = l32_from_64_S (var);
  const u32 h32 = h32_from_64_S (var);

  const u32 l32r = __builtin_amdgcn_ds_bpermute (idx, l32);
  const u32 h32r = __builtin_amdgcn_ds_bpermute (idx, h32);

  const u64 out = hl32_to_64_S (h32r, l32r);

  return out;
}
#elif defined IS_NV && defined IS_GPU
DECLSPEC u64 hc__shfl (MAYBE_UNUSED LOCAL_AS u64 *shuffle_buf, const u64 var, const int src_lane, const u32 argon2_thread, const u32 argon2_lsz)
{
  const u32 l32 = l32_from_64_S (var);
  const u32 h32 = h32_from_64_S (var);

  u32 l32r;
  u32 h32r;

  asm("shfl.sync.idx.b32 %0, %1, %2, 0x1f, 0;"
      : "=r"(l32r)
      : "r"(l32), "r"(src_lane));

  asm("shfl.sync.idx.b32 %0, %1, %2, 0x1f, 0;"
      : "=r"(h32r)
      : "r"(h32), "r"(src_lane));

  const u64 out = hl32_to_64_S (h32r, l32r);

  return out;
}
#else
DECLSPEC u64 hc__shfl (MAYBE_UNUSED LOCAL_AS u64 *shuffle_buf, const u64 var, const int src_lane, const u32 argon2_thread, const u32 argon2_lsz)
{
  shuffle_buf[argon2_thread] = var;

  barrier (CLK_LOCAL_MEM_FENCE);

  const u64 out = shuffle_buf[src_lane & (argon2_lsz - 1)];

  return out;
}
#endif

#elif defined IS_METAL
#define hc__shfl_sync(shfbuf,mask,var,srcLane,argon2_thread,argon2_lsz) hc__shfl ((shfbuf),(var),(srcLane),(argon2_thread),(argon2_lsz))

DECLSPEC u64 hc__shfl (LOCAL_AS u64 *shuffle_buf, const u64 var, const int src_lane, const u32 argon2_thread, const u32 argon2_lsz)
{
  shuffle_buf[argon2_thread] = var;

  SYNC_THREADS();

  const u64 out = shuffle_buf[src_lane & (argon2_lsz - 1)];

  return out;
}
#endif

#define ARGON2_G(a,b,c,d)                \
{                                        \
  a = a + b + 2 * trunc_mul(a, b);       \
  d = blake2b_rot32_S (d ^ a);           \
  c = c + d + 2 * trunc_mul(c, d);       \
  b = blake2b_rot24_S (b ^ c);           \
  a = a + b + 2 * trunc_mul(a, b);       \
  d = blake2b_rot16_S (d ^ a);           \
  c = c + d + 2 * trunc_mul(c, d);       \
  b = hc_rotr64_S (b ^ c, 63);           \
}

#define ARGON2_P()                       \
{                                        \
  ARGON2_G(v[0], v[4], v[8], v[12]);     \
  ARGON2_G(v[1], v[5], v[9], v[13]);     \
  ARGON2_G(v[2], v[6], v[10], v[14]);    \
  ARGON2_G(v[3], v[7], v[11], v[15]);    \
                                         \
  ARGON2_G(v[0], v[5], v[10], v[15]);    \
  ARGON2_G(v[1], v[6], v[11], v[12]);    \
  ARGON2_G(v[2], v[7], v[8], v[13]);     \
  ARGON2_G(v[3], v[4], v[9], v[14]);     \
}

typedef struct argon2_block
{
  u64 values[128];

} argon2_block_t;

typedef struct argon2_options
{
  u32 type;
  u32 version;

  u32 iterations;
  u32 parallelism;
  u32 memory_usage_in_kib;

  u32 segment_length;
  u32 lane_length;
  u32 memory_block_count;
  u32 digest_len;

} argon2_options_t;

typedef struct argon2_pos
{
  u32 pass;
  u32 slice;
  u32 lane;

} argon2_pos_t;

DECLSPEC void argon2_init (GLOBAL_AS const pw_t *pw, GLOBAL_AS const salt_t *salt, PRIVATE_AS const argon2_options_t *options, GLOBAL_AS argon2_block_t *out);
DECLSPEC void argon2_fill_segment (GLOBAL_AS argon2_block_t *blocks, PRIVATE_AS const argon2_options_t *options, PRIVATE_AS const argon2_pos_t *pos, LOCAL_AS u64 *shuffle_buf, const u32 argon2_thread, const u32 argon2_lsz);
DECLSPEC void argon2_final (GLOBAL_AS argon2_block_t *blocks, PRIVATE_AS const argon2_options_t *options, PRIVATE_AS u32 *out);

#endif // INC_HASH_ARGON2_H
