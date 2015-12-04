/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define VECT_SIZE1

#include "include/constants.h"
#include "include/kernel_vendor.h"
#include "types_nv.c"

__device__ static u32x swap_workaround (const u32x v)
{
  #if __CUDA_ARCH__ >= 200
  return __byte_perm (v, 0, 0x0123);
  #else
  return (v << 24) + ((v & 0x0000FF00) << 8) + ((v & 0x00FF0000) >> 8) + (v >> 24);
  #endif
}

#include "include/rp_gpu.h"
#include "rp_nv.c"

__device__ __constant__ gpu_rule_t c_rules[1024];

extern "C" __global__ void __launch_bounds__ (256, 1) amp (pw_t *pws, pw_t *pws_amp, gpu_rule_t *rules_buf, comb_t *combs_buf, bf_t *bfs_buf, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = (blockIdx.x * blockDim.x) + threadIdx.x;

  if (gid >= gid_max) return;

  const u32 pw_len = pws[gid].pw_len;

  u32x w0[4];
  u32x w1[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];
  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];

  const u32 out_len = apply_rules (c_rules[0].cmds, w0, w1, pw_len);

  pws_amp[gid].i[0] = w0[0];
  pws_amp[gid].i[1] = w0[1];
  pws_amp[gid].i[2] = w0[2];
  pws_amp[gid].i[3] = w0[3];
  pws_amp[gid].i[4] = w1[0];
  pws_amp[gid].i[5] = w1[1];
  pws_amp[gid].i[6] = w1[2];
  pws_amp[gid].i[7] = w1[3];

  pws_amp[gid].pw_len = out_len;
}
