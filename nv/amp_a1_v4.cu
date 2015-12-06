/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define VECT_SIZE4

#include "include/constants.h"
#include "types_nv.c"

__device__ static void switch_buffer_by_offset (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], const u32 offset)
{
  #if __CUDA_ARCH__ >= 200

  const int offset_minus_4 = 4 - (offset % 4);

  int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  switch (offset / 4)
  {
    case 0:
      w3[1] = __byte_perm (w3[0], w3[1], selector);
      w3[0] = __byte_perm (w2[3], w3[0], selector);
      w2[3] = __byte_perm (w2[2], w2[3], selector);
      w2[2] = __byte_perm (w2[1], w2[2], selector);
      w2[1] = __byte_perm (w2[0], w2[1], selector);
      w2[0] = __byte_perm (w1[3], w2[0], selector);
      w1[3] = __byte_perm (w1[2], w1[3], selector);
      w1[2] = __byte_perm (w1[1], w1[2], selector);
      w1[1] = __byte_perm (w1[0], w1[1], selector);
      w1[0] = __byte_perm (w0[3], w1[0], selector);
      w0[3] = __byte_perm (w0[2], w0[3], selector);
      w0[2] = __byte_perm (w0[1], w0[2], selector);
      w0[1] = __byte_perm (w0[0], w0[1], selector);
      w0[0] = __byte_perm (    0, w0[0], selector);

      break;

    case 1:
      w3[1] = __byte_perm (w2[3], w3[0], selector);
      w3[0] = __byte_perm (w2[2], w2[3], selector);
      w2[3] = __byte_perm (w2[1], w2[2], selector);
      w2[2] = __byte_perm (w2[0], w2[1], selector);
      w2[1] = __byte_perm (w1[3], w2[0], selector);
      w2[0] = __byte_perm (w1[2], w1[3], selector);
      w1[3] = __byte_perm (w1[1], w1[2], selector);
      w1[2] = __byte_perm (w1[0], w1[1], selector);
      w1[1] = __byte_perm (w0[3], w1[0], selector);
      w1[0] = __byte_perm (w0[2], w0[3], selector);
      w0[3] = __byte_perm (w0[1], w0[2], selector);
      w0[2] = __byte_perm (w0[0], w0[1], selector);
      w0[1] = __byte_perm (    0, w0[0], selector);
      w0[0] = 0;

      break;

    case 2:
      w3[1] = __byte_perm (w2[2], w2[3], selector);
      w3[0] = __byte_perm (w2[1], w2[2], selector);
      w2[3] = __byte_perm (w2[0], w2[1], selector);
      w2[2] = __byte_perm (w1[3], w2[0], selector);
      w2[1] = __byte_perm (w1[2], w1[3], selector);
      w2[0] = __byte_perm (w1[1], w1[2], selector);
      w1[3] = __byte_perm (w1[0], w1[1], selector);
      w1[2] = __byte_perm (w0[3], w1[0], selector);
      w1[1] = __byte_perm (w0[2], w0[3], selector);
      w1[0] = __byte_perm (w0[1], w0[2], selector);
      w0[3] = __byte_perm (w0[0], w0[1], selector);
      w0[2] = __byte_perm (    0, w0[0], selector);
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 3:
      w3[1] = __byte_perm (w2[1], w2[2], selector);
      w3[0] = __byte_perm (w2[0], w2[1], selector);
      w2[3] = __byte_perm (w1[3], w2[0], selector);
      w2[2] = __byte_perm (w1[2], w1[3], selector);
      w2[1] = __byte_perm (w1[1], w1[2], selector);
      w2[0] = __byte_perm (w1[0], w1[1], selector);
      w1[3] = __byte_perm (w0[3], w1[0], selector);
      w1[2] = __byte_perm (w0[2], w0[3], selector);
      w1[1] = __byte_perm (w0[1], w0[2], selector);
      w1[0] = __byte_perm (w0[0], w0[1], selector);
      w0[3] = __byte_perm (    0, w0[0], selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 4:
      w3[1] = __byte_perm (w2[0], w2[1], selector);
      w3[0] = __byte_perm (w1[3], w2[0], selector);
      w2[3] = __byte_perm (w1[2], w1[3], selector);
      w2[2] = __byte_perm (w1[1], w1[2], selector);
      w2[1] = __byte_perm (w1[0], w1[1], selector);
      w2[0] = __byte_perm (w0[3], w1[0], selector);
      w1[3] = __byte_perm (w0[2], w0[3], selector);
      w1[2] = __byte_perm (w0[1], w0[2], selector);
      w1[1] = __byte_perm (w0[0], w0[1], selector);
      w1[0] = __byte_perm (    0, w0[0], selector);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 5:
      w3[1] = __byte_perm (w1[3], w2[0], selector);
      w3[0] = __byte_perm (w1[2], w1[3], selector);
      w2[3] = __byte_perm (w1[1], w1[2], selector);
      w2[2] = __byte_perm (w1[0], w1[1], selector);
      w2[1] = __byte_perm (w0[3], w1[0], selector);
      w2[0] = __byte_perm (w0[2], w0[3], selector);
      w1[3] = __byte_perm (w0[1], w0[2], selector);
      w1[2] = __byte_perm (w0[0], w0[1], selector);
      w1[1] = __byte_perm (    0, w0[0], selector);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 6:
      w3[1] = __byte_perm (w1[2], w1[3], selector);
      w3[0] = __byte_perm (w1[1], w1[2], selector);
      w2[3] = __byte_perm (w1[0], w1[1], selector);
      w2[2] = __byte_perm (w0[3], w1[0], selector);
      w2[1] = __byte_perm (w0[2], w0[3], selector);
      w2[0] = __byte_perm (w0[1], w0[2], selector);
      w1[3] = __byte_perm (w0[0], w0[1], selector);
      w1[2] = __byte_perm (    0, w0[0], selector);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 7:
      w3[1] = __byte_perm (w1[1], w1[2], selector);
      w3[0] = __byte_perm (w1[0], w1[1], selector);
      w2[3] = __byte_perm (w0[3], w1[0], selector);
      w2[2] = __byte_perm (w0[2], w0[3], selector);
      w2[1] = __byte_perm (w0[1], w0[2], selector);
      w2[0] = __byte_perm (w0[0], w0[1], selector);
      w1[3] = __byte_perm (    0, w0[0], selector);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 8:
      w3[1] = __byte_perm (w1[0], w1[1], selector);
      w3[0] = __byte_perm (w0[3], w1[0], selector);
      w2[3] = __byte_perm (w0[2], w0[3], selector);
      w2[2] = __byte_perm (w0[1], w0[2], selector);
      w2[1] = __byte_perm (w0[0], w0[1], selector);
      w2[0] = __byte_perm (    0, w0[0], selector);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 9:
      w3[1] = __byte_perm (w0[3], w1[0], selector);
      w3[0] = __byte_perm (w0[2], w0[3], selector);
      w2[3] = __byte_perm (w0[1], w0[2], selector);
      w2[2] = __byte_perm (w0[0], w0[1], selector);
      w2[1] = __byte_perm (    0, w0[0], selector);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 10:
      w3[1] = __byte_perm (w0[2], w0[3], selector);
      w3[0] = __byte_perm (w0[1], w0[2], selector);
      w2[3] = __byte_perm (w0[0], w0[1], selector);
      w2[2] = __byte_perm (    0, w0[0], selector);
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 11:
      w3[1] = __byte_perm (w0[1], w0[2], selector);
      w3[0] = __byte_perm (w0[0], w0[1], selector);
      w2[3] = __byte_perm (    0, w0[0], selector);
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 12:
      w3[1] = __byte_perm (w0[0], w0[1], selector);
      w3[0] = __byte_perm (    0, w0[0], selector);
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;

    case 13:
      w3[1] = __byte_perm (    0, w0[0], selector);
      w3[0] = 0;
      w2[3] = 0;
      w2[2] = 0;
      w2[1] = 0;
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      break;
  }

  #else

  u32x tmp0[4];
  u32x tmp1[4];
  u32x tmp2[1];

  switch (offset % 4)
  {
    case 0:
      tmp0[0] = w0[0];
      tmp0[1] = w0[1];
      tmp0[2] = w0[2];
      tmp0[3] = w0[3];
      tmp1[0] = w1[0];
      tmp1[1] = w1[1];
      tmp1[2] = w1[2];
      tmp1[3] = w1[3];
      tmp2[0] = 0;
      break;

    case 1:
      tmp0[0] =               w0[0] <<  8;
      tmp0[1] = w0[0] >> 24 | w0[1] <<  8;
      tmp0[2] = w0[1] >> 24 | w0[2] <<  8;
      tmp0[3] = w0[2] >> 24 | w0[3] <<  8;
      tmp1[0] = w0[3] >> 24 | w1[0] <<  8;
      tmp1[1] = w1[0] >> 24 | w1[1] <<  8;
      tmp1[2] = w1[1] >> 24 | w1[2] <<  8;
      tmp1[3] = w1[2] >> 24 | w1[3] <<  8;
      tmp2[0] = w1[3] >> 24;
      break;

    case 2:
      tmp0[0] =               w0[0] << 16;
      tmp0[1] = w0[0] >> 16 | w0[1] << 16;
      tmp0[2] = w0[1] >> 16 | w0[2] << 16;
      tmp0[3] = w0[2] >> 16 | w0[3] << 16;
      tmp1[0] = w0[3] >> 16 | w1[0] << 16;
      tmp1[1] = w1[0] >> 16 | w1[1] << 16;
      tmp1[2] = w1[1] >> 16 | w1[2] << 16;
      tmp1[3] = w1[2] >> 16 | w1[3] << 16;
      tmp2[0] = w1[3] >> 16;
      break;

    case 3:
      tmp0[0] =               w0[0] << 24;
      tmp0[1] = w0[0] >>  8 | w0[1] << 24;
      tmp0[2] = w0[1] >>  8 | w0[2] << 24;
      tmp0[3] = w0[2] >>  8 | w0[3] << 24;
      tmp1[0] = w0[3] >>  8 | w1[0] << 24;
      tmp1[1] = w1[0] >>  8 | w1[1] << 24;
      tmp1[2] = w1[1] >>  8 | w1[2] << 24;
      tmp1[3] = w1[2] >>  8 | w1[3] << 24;
      tmp2[0] = w1[3] >>  8;
      break;
  }

  switch (offset / 4)
  {
    case 0:
      w0[0] = tmp0[0];
      w0[1] = tmp0[1];
      w0[2] = tmp0[2];
      w0[3] = tmp0[3];
      w1[0] = tmp1[0];
      w1[1] = tmp1[1];
      w1[2] = tmp1[2];
      w1[3] = tmp1[3];
      w2[0] = tmp2[0];
      break;

    case 1:
      w0[0] = 0;
      w0[1] = tmp0[0];
      w0[2] = tmp0[1];
      w0[3] = tmp0[2];
      w1[0] = tmp0[3];
      w1[1] = tmp1[0];
      w1[2] = tmp1[1];
      w1[3] = tmp1[2];
      w2[0] = tmp1[3];
      w2[1] = tmp2[0];
      break;

    case 2:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = tmp0[0];
      w0[3] = tmp0[1];
      w1[0] = tmp0[2];
      w1[1] = tmp0[3];
      w1[2] = tmp1[0];
      w1[3] = tmp1[1];
      w2[0] = tmp1[2];
      w2[1] = tmp1[3];
      w2[2] = tmp2[0];
      break;

    case 3:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = tmp0[0];
      w1[0] = tmp0[1];
      w1[1] = tmp0[2];
      w1[2] = tmp0[3];
      w1[3] = tmp1[0];
      w2[0] = tmp1[1];
      w2[1] = tmp1[2];
      w2[2] = tmp1[3];
      w2[3] = tmp2[0];
      break;

    case 4:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = tmp0[0];
      w1[1] = tmp0[1];
      w1[2] = tmp0[2];
      w1[3] = tmp0[3];
      w2[0] = tmp1[0];
      w2[1] = tmp1[1];
      w2[2] = tmp1[2];
      w2[3] = tmp1[3];
      w3[0] = tmp2[0];
      break;

    case 5:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = tmp0[0];
      w1[2] = tmp0[1];
      w1[3] = tmp0[2];
      w2[0] = tmp0[3];
      w2[1] = tmp1[0];
      w2[2] = tmp1[1];
      w2[3] = tmp1[2];
      w3[0] = tmp1[3];
      w3[1] = tmp2[0];
      break;

    case 6:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = 0;
      w1[2] = tmp0[0];
      w1[3] = tmp0[1];
      w2[0] = tmp0[2];
      w2[1] = tmp0[3];
      w2[2] = tmp1[0];
      w2[3] = tmp1[1];
      w3[0] = tmp1[2];
      w3[1] = tmp1[3];
      w3[2] = tmp2[0];
      break;

    case 7:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = tmp0[0];
      w2[0] = tmp0[1];
      w2[1] = tmp0[2];
      w2[2] = tmp0[3];
      w2[3] = tmp1[0];
      w3[0] = tmp1[1];
      w3[1] = tmp1[2];
      w3[2] = tmp1[3];
      w3[3] = tmp2[0];
      break;

    case 8:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = tmp0[0];
      w2[1] = tmp0[1];
      w2[2] = tmp0[2];
      w2[3] = tmp0[3];
      w3[0] = tmp1[0];
      w3[1] = tmp1[1];
      w3[2] = tmp1[2];
      w3[3] = tmp1[3];
      break;

    case 9:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = tmp0[0];
      w2[2] = tmp0[1];
      w2[3] = tmp0[2];
      w3[0] = tmp0[3];
      w3[1] = tmp1[0];
      w3[2] = tmp1[1];
      w3[3] = tmp1[2];
      break;

    case 10:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = tmp0[0];
      w2[3] = tmp0[1];
      w3[0] = tmp0[2];
      w3[1] = tmp0[3];
      w3[2] = tmp1[0];
      w3[3] = tmp1[1];
      break;

    case 11:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = tmp0[0];
      w3[0] = tmp0[1];
      w3[1] = tmp0[2];
      w3[2] = tmp0[3];
      w3[3] = tmp1[0];
      break;

    case 12:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = tmp0[0];
      w3[1] = tmp0[1];
      w3[2] = tmp0[2];
      w3[3] = tmp0[3];
      break;

    case 13:
      w0[0] = 0;
      w0[1] = 0;
      w0[2] = 0;
      w0[3] = 0;
      w1[0] = 0;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = tmp0[0];
      w3[2] = tmp0[1];
      w3[3] = tmp0[2];
      break;

  }

  #endif
}

__device__ __constant__ comb_t c_combs[1024];

extern "C" __global__ void __launch_bounds__ (256, 1) amp (pw_t *pws, pw_t *pws_amp, gpu_rule_t *rules_buf, comb_t *combs_buf, bf_t *bfs_buf, const u32 combs_mode, const u32 gid_max)
{
  const u32 gid = (blockIdx.x * blockDim.x) + threadIdx.x;

  if (gid >= gid_max) return;

  const u32 pw_l_len = pws[gid].pw_len;

  u32x wordl0[4];

  wordl0[0] = pws[gid].i[ 0];
  wordl0[1] = pws[gid].i[ 1];
  wordl0[2] = pws[gid].i[ 2];
  wordl0[3] = pws[gid].i[ 3];

  u32x wordl1[4];

  wordl1[0] = pws[gid].i[ 4];
  wordl1[1] = pws[gid].i[ 5];
  wordl1[2] = pws[gid].i[ 6];
  wordl1[3] = pws[gid].i[ 7];

  u32x wordl2[4];

  wordl2[0] = 0;
  wordl2[1] = 0;
  wordl2[2] = 0;
  wordl2[3] = 0;

  u32x wordl3[4];

  wordl3[0] = 0;
  wordl3[1] = 0;
  wordl3[2] = 0;
  wordl3[3] = 0;

  const u32 pw_r_len = c_combs[0].pw_len;

  u32x wordr0[4];

  wordr0[0] = c_combs[0].i[0];
  wordr0[1] = c_combs[0].i[1];
  wordr0[2] = c_combs[0].i[2];
  wordr0[3] = c_combs[0].i[3];

  u32x wordr1[4];

  wordr1[0] = c_combs[0].i[4];
  wordr1[1] = c_combs[0].i[5];
  wordr1[2] = c_combs[0].i[6];
  wordr1[3] = c_combs[0].i[7];

  u32x wordr2[4];

  wordr2[0] = 0;
  wordr2[1] = 0;
  wordr2[2] = 0;
  wordr2[3] = 0;

  u32x wordr3[4];

  wordr3[0] = 0;
  wordr3[1] = 0;
  wordr3[2] = 0;
  wordr3[3] = 0;

  if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
  {
    switch_buffer_by_offset (wordr0, wordr1, wordr2, wordr3, pw_l_len);
  }

  if (combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    switch_buffer_by_offset (wordl0, wordl1, wordl2, wordl3, pw_r_len);
  }

  u32x w0[4];

  w0[0] = wordl0[0] | wordr0[0];
  w0[1] = wordl0[1] | wordr0[1];
  w0[2] = wordl0[2] | wordr0[2];
  w0[3] = wordl0[3] | wordr0[3];

  u32x w1[4];

  w1[0] = wordl1[0] | wordr1[0];
  w1[1] = wordl1[1] | wordr1[1];
  w1[2] = wordl1[2] | wordr1[2];
  w1[3] = wordl1[3] | wordr1[3];

  u32x w2[4];

  w2[0] = wordl2[0] | wordr2[0];
  w2[1] = wordl2[1] | wordr2[1];
  w2[2] = wordl2[2] | wordr2[2];
  w2[3] = wordl2[3] | wordr2[3];

  u32x w3[4];

  w3[0] = wordl3[0] | wordr3[0];
  w3[1] = wordl3[1] | wordr3[1];
  w3[2] = wordl3[2] | wordr3[2];
  w3[3] = wordl3[3] | wordr3[3];

  const u32 pw_len = pw_l_len + pw_r_len;

  pws_amp[gid].i[ 0] = w0[0];
  pws_amp[gid].i[ 1] = w0[1];
  pws_amp[gid].i[ 2] = w0[2];
  pws_amp[gid].i[ 3] = w0[3];
  pws_amp[gid].i[ 4] = w1[0];
  pws_amp[gid].i[ 5] = w1[1];
  pws_amp[gid].i[ 6] = w1[2];
  pws_amp[gid].i[ 7] = w1[3];
  pws_amp[gid].i[ 8] = w2[0];
  pws_amp[gid].i[ 9] = w2[1];
  pws_amp[gid].i[10] = w2[2];
  pws_amp[gid].i[11] = w2[3];
  pws_amp[gid].i[12] = w3[0];
  pws_amp[gid].i[13] = w3[1];
  pws_amp[gid].i[14] = w3[2];
  pws_amp[gid].i[15] = w3[3];

  pws_amp[gid].pw_len = pw_len;
}
