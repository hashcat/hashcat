/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_rp_common.h"
#include "inc_rp_optimized.h"

#ifndef MAYBE_UNUSED
#define MAYBE_UNUSED
#endif

DECLSPEC void truncate_right_optimized (PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 offset)
{
  const u32 tmp = (1u << ((offset & 3u) * 8u)) - 1u;

  const int offset_switch = offset / 4;

  switch (offset_switch)
  {
    case  0:  buf0[0] &= tmp;
              buf0[1]  = 0;
              buf0[2]  = 0;
              buf0[3]  = 0;
              buf1[0]  = 0;
              buf1[1]  = 0;
              buf1[2]  = 0;
              buf1[3]  = 0;
              break;
    case  1:  buf0[1] &= tmp;
              buf0[2]  = 0;
              buf0[3]  = 0;
              buf1[0]  = 0;
              buf1[1]  = 0;
              buf1[2]  = 0;
              buf1[3]  = 0;
              break;
    case  2:  buf0[2] &= tmp;
              buf0[3]  = 0;
              buf1[0]  = 0;
              buf1[1]  = 0;
              buf1[2]  = 0;
              buf1[3]  = 0;
              break;
    case  3:  buf0[3] &= tmp;
              buf1[0]  = 0;
              buf1[1]  = 0;
              buf1[2]  = 0;
              buf1[3]  = 0;
              break;
    case  4:  buf1[0] &= tmp;
              buf1[1]  = 0;
              buf1[2]  = 0;
              buf1[3]  = 0;
              break;
    case  5:  buf1[1] &= tmp;
              buf1[2]  = 0;
              buf1[3]  = 0;
              break;
    case  6:  buf1[2] &= tmp;
              buf1[3]  = 0;
              break;
    case  7:  buf1[3] &= tmp;
              break;
  }
}

DECLSPEC void truncate_left_optimized (PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 offset)
{
  const u32 tmp = ~((1u << ((offset & 3u) * 8u)) - 1u);

  const int offset_switch = offset / 4;

  switch (offset_switch)
  {
    case  0:  buf0[0] &= tmp;
              break;
    case  1:  buf0[0]  = 0;
              buf0[1] &= tmp;
              break;
    case  2:  buf0[0]  = 0;
              buf0[1]  = 0;
              buf0[2] &= tmp;
              break;
    case  3:  buf0[0]  = 0;
              buf0[1]  = 0;
              buf0[2]  = 0;
              buf0[3] &= tmp;
              break;
    case  4:  buf0[0]  = 0;
              buf0[1]  = 0;
              buf0[2]  = 0;
              buf0[3]  = 0;
              buf1[0] &= tmp;
              break;
    case  5:  buf0[0]  = 0;
              buf0[1]  = 0;
              buf0[2]  = 0;
              buf0[3]  = 0;
              buf1[0]  = 0;
              buf1[1] &= tmp;
              break;
    case  6:  buf0[0]  = 0;
              buf0[1]  = 0;
              buf0[2]  = 0;
              buf0[3]  = 0;
              buf1[0]  = 0;
              buf1[1]  = 0;
              buf1[2] &= tmp;
              break;
    case  7:  buf0[0]  = 0;
              buf0[1]  = 0;
              buf0[2]  = 0;
              buf0[3]  = 0;
              buf1[0]  = 0;
              buf1[1]  = 0;
              buf1[2]  = 0;
              buf1[3] &= tmp;
              break;
  }
}

DECLSPEC void lshift_block_optimized (PRIVATE_AS const u32 *in0, PRIVATE_AS const u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1)
{
  out0[0] = hc_bytealign_S (in0[0], in0[1], 3);
  out0[1] = hc_bytealign_S (in0[1], in0[2], 3);
  out0[2] = hc_bytealign_S (in0[2], in0[3], 3);
  out0[3] = hc_bytealign_S (in0[3], in1[0], 3);
  out1[0] = hc_bytealign_S (in1[0], in1[1], 3);
  out1[1] = hc_bytealign_S (in1[1], in1[2], 3);
  out1[2] = hc_bytealign_S (in1[2], in1[3], 3);
  out1[3] = hc_bytealign_S (in1[3],      0, 3);
}

DECLSPEC void rshift_block_optimized (PRIVATE_AS const u32 *in0, PRIVATE_AS const u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1)
{
  out1[3] = hc_bytealign_S (in1[2], in1[3], 1);
  out1[2] = hc_bytealign_S (in1[1], in1[2], 1);
  out1[1] = hc_bytealign_S (in1[0], in1[1], 1);
  out1[0] = hc_bytealign_S (in0[3], in1[0], 1);
  out0[3] = hc_bytealign_S (in0[2], in0[3], 1);
  out0[2] = hc_bytealign_S (in0[1], in0[2], 1);
  out0[1] = hc_bytealign_S (in0[0], in0[1], 1);
  out0[0] = hc_bytealign_S (     0, in0[0], 1);
}

DECLSPEC void lshift_block_optimized_N (PRIVATE_AS const u32 *in0, PRIVATE_AS const u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1, const u32 num)
{
  switch (num)
  {
    case  0:  out0[0] = in0[0];
              out0[1] = in0[1];
              out0[2] = in0[2];
              out0[3] = in0[3];
              out1[0] = in1[0];
              out1[1] = in1[1];
              out1[2] = in1[2];
              out1[3] = in1[3];
              break;
    case  1:  out0[0] = hc_bytealign_S (in0[0], in0[1], 3);
              out0[1] = hc_bytealign_S (in0[1], in0[2], 3);
              out0[2] = hc_bytealign_S (in0[2], in0[3], 3);
              out0[3] = hc_bytealign_S (in0[3], in1[0], 3);
              out1[0] = hc_bytealign_S (in1[0], in1[1], 3);
              out1[1] = hc_bytealign_S (in1[1], in1[2], 3);
              out1[2] = hc_bytealign_S (in1[2], in1[3], 3);
              out1[3] = hc_bytealign_S (in1[3],      0, 3);
              break;
    case  2:  out0[0] = hc_bytealign_S (in0[0], in0[1], 2);
              out0[1] = hc_bytealign_S (in0[1], in0[2], 2);
              out0[2] = hc_bytealign_S (in0[2], in0[3], 2);
              out0[3] = hc_bytealign_S (in0[3], in1[0], 2);
              out1[0] = hc_bytealign_S (in1[0], in1[1], 2);
              out1[1] = hc_bytealign_S (in1[1], in1[2], 2);
              out1[2] = hc_bytealign_S (in1[2], in1[3], 2);
              out1[3] = hc_bytealign_S (in1[3],      0, 2);
              break;
    case  3:  out0[0] = hc_bytealign_S (in0[0], in0[1], 1);
              out0[1] = hc_bytealign_S (in0[1], in0[2], 1);
              out0[2] = hc_bytealign_S (in0[2], in0[3], 1);
              out0[3] = hc_bytealign_S (in0[3], in1[0], 1);
              out1[0] = hc_bytealign_S (in1[0], in1[1], 1);
              out1[1] = hc_bytealign_S (in1[1], in1[2], 1);
              out1[2] = hc_bytealign_S (in1[2], in1[3], 1);
              out1[3] = hc_bytealign_S (in1[3],      0, 1);
              break;
    case  4:  out0[0] = in0[1];
              out0[1] = in0[2];
              out0[2] = in0[3];
              out0[3] = in1[0];
              out1[0] = in1[1];
              out1[1] = in1[2];
              out1[2] = in1[3];
              out1[3] = 0;
              break;
    case  5:  out0[0] = hc_bytealign_S (in0[1], in0[2], 3);
              out0[1] = hc_bytealign_S (in0[2], in0[3], 3);
              out0[2] = hc_bytealign_S (in0[3], in1[0], 3);
              out0[3] = hc_bytealign_S (in1[0], in1[1], 3);
              out1[0] = hc_bytealign_S (in1[1], in1[2], 3);
              out1[1] = hc_bytealign_S (in1[2], in1[3], 3);
              out1[2] = hc_bytealign_S (in1[3],      0, 3);
              out1[3] = 0;
              break;
    case  6:  out0[0] = hc_bytealign_S (in0[1], in0[2], 2);
              out0[1] = hc_bytealign_S (in0[2], in0[3], 2);
              out0[2] = hc_bytealign_S (in0[3], in1[0], 2);
              out0[3] = hc_bytealign_S (in1[0], in1[1], 2);
              out1[0] = hc_bytealign_S (in1[1], in1[2], 2);
              out1[1] = hc_bytealign_S (in1[2], in1[3], 2);
              out1[2] = hc_bytealign_S (in1[3],      0, 2);
              out1[3] = 0;
              break;
    case  7:  out0[0] = hc_bytealign_S (in0[1], in0[2], 1);
              out0[1] = hc_bytealign_S (in0[2], in0[3], 1);
              out0[2] = hc_bytealign_S (in0[3], in1[0], 1);
              out0[3] = hc_bytealign_S (in1[0], in1[1], 1);
              out1[0] = hc_bytealign_S (in1[1], in1[2], 1);
              out1[1] = hc_bytealign_S (in1[2], in1[3], 1);
              out1[2] = hc_bytealign_S (in1[3],      0, 1);
              out1[3] = 0;
              break;
    case  8:  out0[0] = in0[2];
              out0[1] = in0[3];
              out0[2] = in1[0];
              out0[3] = in1[1];
              out1[0] = in1[2];
              out1[1] = in1[3];
              out1[2] = 0;
              out1[3] = 0;
              break;
    case  9:  out0[0] = hc_bytealign_S (in0[2], in0[3], 3);
              out0[1] = hc_bytealign_S (in0[3], in1[0], 3);
              out0[2] = hc_bytealign_S (in1[0], in1[1], 3);
              out0[3] = hc_bytealign_S (in1[1], in1[2], 3);
              out1[0] = hc_bytealign_S (in1[2], in1[3], 3);
              out1[1] = hc_bytealign_S (in1[3],      0, 3);
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 10:  out0[0] = hc_bytealign_S (in0[2], in0[3], 2);
              out0[1] = hc_bytealign_S (in0[3], in1[0], 2);
              out0[2] = hc_bytealign_S (in1[0], in1[1], 2);
              out0[3] = hc_bytealign_S (in1[1], in1[2], 2);
              out1[0] = hc_bytealign_S (in1[2], in1[3], 2);
              out1[1] = hc_bytealign_S (in1[3],      0, 2);
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 11:  out0[0] = hc_bytealign_S (in0[2], in0[3], 1);
              out0[1] = hc_bytealign_S (in0[3], in1[0], 1);
              out0[2] = hc_bytealign_S (in1[0], in1[1], 1);
              out0[3] = hc_bytealign_S (in1[1], in1[2], 1);
              out1[0] = hc_bytealign_S (in1[2], in1[3], 1);
              out1[1] = hc_bytealign_S (in1[3],      0, 1);
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 12:  out0[0] = in0[3];
              out0[1] = in1[0];
              out0[2] = in1[1];
              out0[3] = in1[2];
              out1[0] = in1[3];
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 13:  out0[0] = hc_bytealign_S (in0[3], in1[0], 3);
              out0[1] = hc_bytealign_S (in1[0], in1[1], 3);
              out0[2] = hc_bytealign_S (in1[1], in1[2], 3);
              out0[3] = hc_bytealign_S (in1[2], in1[3], 3);
              out1[0] = hc_bytealign_S (in1[3],      0, 3);
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 14:  out0[0] = hc_bytealign_S (in0[3], in1[0], 2);
              out0[1] = hc_bytealign_S (in1[0], in1[1], 2);
              out0[2] = hc_bytealign_S (in1[1], in1[2], 2);
              out0[3] = hc_bytealign_S (in1[2], in1[3], 2);
              out1[0] = hc_bytealign_S (in1[3],      0, 2);
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 15:  out0[0] = hc_bytealign_S (in0[3], in1[0], 1);
              out0[1] = hc_bytealign_S (in1[0], in1[1], 1);
              out0[2] = hc_bytealign_S (in1[1], in1[2], 1);
              out0[3] = hc_bytealign_S (in1[2], in1[3], 1);
              out1[0] = hc_bytealign_S (in1[3],      0, 1);
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 16:  out0[0] = in1[0];
              out0[1] = in1[1];
              out0[2] = in1[2];
              out0[3] = in1[3];
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 17:  out0[0] = hc_bytealign_S (in1[0], in1[1], 3);
              out0[1] = hc_bytealign_S (in1[1], in1[2], 3);
              out0[2] = hc_bytealign_S (in1[2], in1[3], 3);
              out0[3] = hc_bytealign_S (in1[3],      0, 3);
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 18:  out0[0] = hc_bytealign_S (in1[0], in1[1], 2);
              out0[1] = hc_bytealign_S (in1[1], in1[2], 2);
              out0[2] = hc_bytealign_S (in1[2], in1[3], 2);
              out0[3] = hc_bytealign_S (in1[3],      0, 2);
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 19:  out0[0] = hc_bytealign_S (in1[0], in1[1], 1);
              out0[1] = hc_bytealign_S (in1[1], in1[2], 1);
              out0[2] = hc_bytealign_S (in1[2], in1[3], 1);
              out0[3] = hc_bytealign_S (in1[3],      0, 1);
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 20:  out0[0] = in1[1];
              out0[1] = in1[2];
              out0[2] = in1[3];
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 21:  out0[0] = hc_bytealign_S (in1[1], in1[2], 3);
              out0[1] = hc_bytealign_S (in1[2], in1[3], 3);
              out0[2] = hc_bytealign_S (in1[3],      0, 3);
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 22:  out0[0] = hc_bytealign_S (in1[1], in1[2], 2);
              out0[1] = hc_bytealign_S (in1[2], in1[3], 2);
              out0[2] = hc_bytealign_S (in1[3],      0, 2);
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 23:  out0[0] = hc_bytealign_S (in1[1], in1[2], 1);
              out0[1] = hc_bytealign_S (in1[2], in1[3], 1);
              out0[2] = hc_bytealign_S (in1[3],      0, 1);
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 24:  out0[0] = in1[2];
              out0[1] = in1[3];
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 25:  out0[0] = hc_bytealign_S (in1[2], in1[3], 3);
              out0[1] = hc_bytealign_S (in1[3],      0, 3);
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 26:  out0[0] = hc_bytealign_S (in1[2], in1[3], 2);
              out0[1] = hc_bytealign_S (in1[3],      0, 2);
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 27:  out0[0] = hc_bytealign_S (in1[2], in1[3], 1);
              out0[1] = hc_bytealign_S (in1[3],      0, 1);
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 28:  out0[0] = in1[3];
              out0[1] = 0;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 29:  out0[0] = hc_bytealign_S (in1[3],      0, 3);
              out0[1] = 0;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 30:  out0[0] = hc_bytealign_S (in1[3],      0, 2);
              out0[1] = 0;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 31:  out0[0] = hc_bytealign_S (in1[3],      0, 1);
              out0[1] = 0;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
  }
}

DECLSPEC void rshift_block_optimized_N (PRIVATE_AS const u32 *in0, PRIVATE_AS const u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1, const u32 num)
{
  switch (num)
  {
    case  0:  out1[3] = in1[3];
              out1[2] = in1[2];
              out1[1] = in1[1];
              out1[0] = in1[0];
              out0[3] = in0[3];
              out0[2] = in0[2];
              out0[1] = in0[1];
              out0[0] = in0[0];
              break;
    case  1:  out1[3] = hc_bytealign_S (in1[2], in1[3], 1);
              out1[2] = hc_bytealign_S (in1[1], in1[2], 1);
              out1[1] = hc_bytealign_S (in1[0], in1[1], 1);
              out1[0] = hc_bytealign_S (in0[3], in1[0], 1);
              out0[3] = hc_bytealign_S (in0[2], in0[3], 1);
              out0[2] = hc_bytealign_S (in0[1], in0[2], 1);
              out0[1] = hc_bytealign_S (in0[0], in0[1], 1);
              out0[0] = hc_bytealign_S (     0, in0[0], 1);
              break;
    case  2:  out1[3] = hc_bytealign_S (in1[2], in1[3], 2);
              out1[2] = hc_bytealign_S (in1[1], in1[2], 2);
              out1[1] = hc_bytealign_S (in1[0], in1[1], 2);
              out1[0] = hc_bytealign_S (in0[3], in1[0], 2);
              out0[3] = hc_bytealign_S (in0[2], in0[3], 2);
              out0[2] = hc_bytealign_S (in0[1], in0[2], 2);
              out0[1] = hc_bytealign_S (in0[0], in0[1], 2);
              out0[0] = hc_bytealign_S (     0, in0[0], 2);
              break;
    case  3:  out1[3] = hc_bytealign_S (in1[2], in1[3], 3);
              out1[2] = hc_bytealign_S (in1[1], in1[2], 3);
              out1[1] = hc_bytealign_S (in1[0], in1[1], 3);
              out1[0] = hc_bytealign_S (in0[3], in1[0], 3);
              out0[3] = hc_bytealign_S (in0[2], in0[3], 3);
              out0[2] = hc_bytealign_S (in0[1], in0[2], 3);
              out0[1] = hc_bytealign_S (in0[0], in0[1], 3);
              out0[0] = hc_bytealign_S (     0, in0[0], 3);
              break;
    case  4:  out1[3] = in1[2];
              out1[2] = in1[1];
              out1[1] = in1[0];
              out1[0] = in0[3];
              out0[3] = in0[2];
              out0[2] = in0[1];
              out0[1] = in0[0];
              out0[0] = 0;
              break;
    case  5:  out1[3] = hc_bytealign_S (in1[1], in1[2], 1);
              out1[2] = hc_bytealign_S (in1[0], in1[1], 1);
              out1[1] = hc_bytealign_S (in0[3], in1[0], 1);
              out1[0] = hc_bytealign_S (in0[2], in0[3], 1);
              out0[3] = hc_bytealign_S (in0[1], in0[2], 1);
              out0[2] = hc_bytealign_S (in0[0], in0[1], 1);
              out0[1] = hc_bytealign_S (     0, in0[0], 1);
              out0[0] = 0;
              break;
    case  6:  out1[3] = hc_bytealign_S (in1[1], in1[2], 2);
              out1[2] = hc_bytealign_S (in1[0], in1[1], 2);
              out1[1] = hc_bytealign_S (in0[3], in1[0], 2);
              out1[0] = hc_bytealign_S (in0[2], in0[3], 2);
              out0[3] = hc_bytealign_S (in0[1], in0[2], 2);
              out0[2] = hc_bytealign_S (in0[0], in0[1], 2);
              out0[1] = hc_bytealign_S (     0, in0[0], 2);
              out0[0] = 0;
              break;
    case  7:  out1[3] = hc_bytealign_S (in1[1], in1[2], 3);
              out1[2] = hc_bytealign_S (in1[0], in1[1], 3);
              out1[1] = hc_bytealign_S (in0[3], in1[0], 3);
              out1[0] = hc_bytealign_S (in0[2], in0[3], 3);
              out0[3] = hc_bytealign_S (in0[1], in0[2], 3);
              out0[2] = hc_bytealign_S (in0[0], in0[1], 3);
              out0[1] = hc_bytealign_S (     0, in0[0], 3);
              out0[0] = 0;
              break;
    case  8:  out1[3] = in1[1];
              out1[2] = in1[0];
              out1[1] = in0[3];
              out1[0] = in0[2];
              out0[3] = in0[1];
              out0[2] = in0[0];
              out0[1] = 0;
              out0[0] = 0;
              break;
    case  9:  out1[3] = hc_bytealign_S (in1[0], in1[1], 1);
              out1[2] = hc_bytealign_S (in0[3], in1[0], 1);
              out1[1] = hc_bytealign_S (in0[2], in0[3], 1);
              out1[0] = hc_bytealign_S (in0[1], in0[2], 1);
              out0[3] = hc_bytealign_S (in0[0], in0[1], 1);
              out0[2] = hc_bytealign_S (     0, in0[0], 1);
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 10:  out1[3] = hc_bytealign_S (in1[0], in1[1], 2);
              out1[2] = hc_bytealign_S (in0[3], in1[0], 2);
              out1[1] = hc_bytealign_S (in0[2], in0[3], 2);
              out1[0] = hc_bytealign_S (in0[1], in0[2], 2);
              out0[3] = hc_bytealign_S (in0[0], in0[1], 2);
              out0[2] = hc_bytealign_S (     0, in0[0], 2);
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 11:  out1[3] = hc_bytealign_S (in1[0], in1[1], 3);
              out1[2] = hc_bytealign_S (in0[3], in1[0], 3);
              out1[1] = hc_bytealign_S (in0[2], in0[3], 3);
              out1[0] = hc_bytealign_S (in0[1], in0[2], 3);
              out0[3] = hc_bytealign_S (in0[0], in0[1], 3);
              out0[2] = hc_bytealign_S (     0, in0[0], 3);
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 12:  out1[3] = in1[0];
              out1[2] = in0[3];
              out1[1] = in0[2];
              out1[0] = in0[1];
              out0[3] = in0[0];
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 13:  out1[3] = hc_bytealign_S (in0[3], in1[0], 1);
              out1[2] = hc_bytealign_S (in0[2], in0[3], 1);
              out1[1] = hc_bytealign_S (in0[1], in0[2], 1);
              out1[0] = hc_bytealign_S (in0[0], in0[1], 1);
              out0[3] = hc_bytealign_S (     0, in0[0], 1);
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 14:  out1[3] = hc_bytealign_S (in0[3], in1[0], 2);
              out1[2] = hc_bytealign_S (in0[2], in0[3], 2);
              out1[1] = hc_bytealign_S (in0[1], in0[2], 2);
              out1[0] = hc_bytealign_S (in0[0], in0[1], 2);
              out0[3] = hc_bytealign_S (     0, in0[0], 2);
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 15:  out1[3] = hc_bytealign_S (in0[3], in1[0], 3);
              out1[2] = hc_bytealign_S (in0[2], in0[3], 3);
              out1[1] = hc_bytealign_S (in0[1], in0[2], 3);
              out1[0] = hc_bytealign_S (in0[0], in0[1], 3);
              out0[3] = hc_bytealign_S (     0, in0[0], 3);
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 16:  out1[3] = in0[3];
              out1[2] = in0[2];
              out1[1] = in0[1];
              out1[0] = in0[0];
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 17:  out1[3] = hc_bytealign_S (in0[2], in0[3], 1);
              out1[2] = hc_bytealign_S (in0[1], in0[2], 1);
              out1[1] = hc_bytealign_S (in0[0], in0[1], 1);
              out1[0] = hc_bytealign_S (     0, in0[0], 1);
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 18:  out1[3] = hc_bytealign_S (in0[2], in0[3], 2);
              out1[2] = hc_bytealign_S (in0[1], in0[2], 2);
              out1[1] = hc_bytealign_S (in0[0], in0[1], 2);
              out1[0] = hc_bytealign_S (     0, in0[0], 2);
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 19:  out1[3] = hc_bytealign_S (in0[2], in0[3], 3);
              out1[2] = hc_bytealign_S (in0[1], in0[2], 3);
              out1[1] = hc_bytealign_S (in0[0], in0[1], 3);
              out1[0] = hc_bytealign_S (     0, in0[0], 3);
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 20:  out1[3] = in0[2];
              out1[2] = in0[1];
              out1[1] = in0[0];
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 21:  out1[3] = hc_bytealign_S (in0[1], in0[2], 1);
              out1[2] = hc_bytealign_S (in0[0], in0[1], 1);
              out1[1] = hc_bytealign_S (     0, in0[0], 1);
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 22:  out1[3] = hc_bytealign_S (in0[1], in0[2], 2);
              out1[2] = hc_bytealign_S (in0[0], in0[1], 2);
              out1[1] = hc_bytealign_S (     0, in0[0], 2);
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 23:  out1[3] = hc_bytealign_S (in0[1], in0[2], 3);
              out1[2] = hc_bytealign_S (in0[0], in0[1], 3);
              out1[1] = hc_bytealign_S (     0, in0[0], 3);
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 24:  out1[3] = in0[1];
              out1[2] = in0[0];
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 25:  out1[3] = hc_bytealign_S (in0[0], in0[1], 1);
              out1[2] = hc_bytealign_S (     0, in0[0], 1);
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 26:  out1[3] = hc_bytealign_S (in0[0], in0[1], 2);
              out1[2] = hc_bytealign_S (     0, in0[0], 2);
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 27:  out1[3] = hc_bytealign_S (in0[0], in0[1], 3);
              out1[2] = hc_bytealign_S (     0, in0[0], 3);
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 28:  out1[3] = in0[0];
              out1[2] = 0;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 29:  out1[3] = hc_bytealign_S (     0, in0[0], 1);
              out1[2] = 0;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 30:  out1[3] = hc_bytealign_S (     0, in0[0], 2);
              out1[2] = 0;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 31:  out1[3] = hc_bytealign_S (     0, in0[0], 3);
              out1[2] = 0;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
  }
}

DECLSPEC void append_block1_optimized (const u32 offset, PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 src_r0)
{
  // this version works with 1 byte append only
  const u32 value = src_r0 & 0xff;

  const u32 tmp = value <<  0
                | value <<  8
                | value << 16
                | value << 24;

  u32 v[4];

  set_mark_1x4_S (v, offset);

  const u32 offset16 = offset / 16;

  append_helper_1x4_S (buf0, ((offset16 == 0) ? tmp : 0), v);
  append_helper_1x4_S (buf1, ((offset16 == 1) ? tmp : 0), v);
}

DECLSPEC void append_block8_optimized (const u32 offset, PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, PRIVATE_AS const u32 *src_l0, PRIVATE_AS const u32 *src_l1, PRIVATE_AS const u32 *src_r0, PRIVATE_AS const u32 *src_r1)
{
  u32 s0 = 0;
  u32 s1 = 0;
  u32 s2 = 0;
  u32 s3 = 0;
  u32 s4 = 0;
  u32 s5 = 0;
  u32 s6 = 0;
  u32 s7 = 0;

  const int offset_switch = offset / 4;

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 0) || defined IS_GENERIC
  const u32 src_r00 = src_r0[0];
  const u32 src_r01 = src_r0[1];
  const u32 src_r02 = src_r0[2];
  const u32 src_r03 = src_r0[3];
  const u32 src_r10 = src_r1[0];
  const u32 src_r11 = src_r1[1];
  const u32 src_r12 = src_r1[2];
  const u32 src_r13 = src_r1[3];

  switch (offset_switch)
  {
    case 0:
      s7 = hc_bytealign_S (src_r12, src_r13, offset);
      s6 = hc_bytealign_S (src_r11, src_r12, offset);
      s5 = hc_bytealign_S (src_r10, src_r11, offset);
      s4 = hc_bytealign_S (src_r03, src_r10, offset);
      s3 = hc_bytealign_S (src_r02, src_r03, offset);
      s2 = hc_bytealign_S (src_r01, src_r02, offset);
      s1 = hc_bytealign_S (src_r00, src_r01, offset);
      s0 = hc_bytealign_S (      0, src_r00, offset);
      break;

    case 1:
      s7 = hc_bytealign_S (src_r11, src_r12, offset);
      s6 = hc_bytealign_S (src_r10, src_r11, offset);
      s5 = hc_bytealign_S (src_r03, src_r10, offset);
      s4 = hc_bytealign_S (src_r02, src_r03, offset);
      s3 = hc_bytealign_S (src_r01, src_r02, offset);
      s2 = hc_bytealign_S (src_r00, src_r01, offset);
      s1 = hc_bytealign_S (      0, src_r00, offset);
      s0 = 0;
      break;

    case 2:
      s7 = hc_bytealign_S (src_r10, src_r11, offset);
      s6 = hc_bytealign_S (src_r03, src_r10, offset);
      s5 = hc_bytealign_S (src_r02, src_r03, offset);
      s4 = hc_bytealign_S (src_r01, src_r02, offset);
      s3 = hc_bytealign_S (src_r00, src_r01, offset);
      s2 = hc_bytealign_S (      0, src_r00, offset);
      s1 = 0;
      s0 = 0;
      break;

    case 3:
      s7 = hc_bytealign_S (src_r03, src_r10, offset);
      s6 = hc_bytealign_S (src_r02, src_r03, offset);
      s5 = hc_bytealign_S (src_r01, src_r02, offset);
      s4 = hc_bytealign_S (src_r00, src_r01, offset);
      s3 = hc_bytealign_S (      0, src_r00, offset);
      s2 = 0;
      s1 = 0;
      s0 = 0;

      break;

    case 4:
      s7 = hc_bytealign_S (src_r02, src_r03, offset);
      s6 = hc_bytealign_S (src_r01, src_r02, offset);
      s5 = hc_bytealign_S (src_r00, src_r01, offset);
      s4 = hc_bytealign_S (      0, src_r00, offset);
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 5:
      s7 = hc_bytealign_S (src_r01, src_r02, offset);
      s6 = hc_bytealign_S (src_r00, src_r01, offset);
      s5 = hc_bytealign_S (      0, src_r00, offset);
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 6:
      s7 = hc_bytealign_S (src_r00, src_r01, offset);
      s6 = hc_bytealign_S (      0, src_r00, offset);
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 7:
      s7 = hc_bytealign_S (      0, src_r00, offset);
      s6 = 0;
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;
  }
  #endif

  #if ((defined IS_AMD || defined IS_HIP) && HAS_VPERM == 1) || defined IS_NV

  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset_mod_4;

  #if defined IS_NV
  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;
  #endif

  #if (defined IS_AMD || defined IS_HIP)
  const int selector = l32_from_64_S (0x0706050403020100UL >> (offset_minus_4 * 8));
  #endif

  const u32 src_r00 = src_r0[0];
  const u32 src_r01 = src_r0[1];
  const u32 src_r02 = src_r0[2];
  const u32 src_r03 = src_r0[3];
  const u32 src_r10 = src_r1[0];
  const u32 src_r11 = src_r1[1];
  const u32 src_r12 = src_r1[2];
  const u32 src_r13 = src_r1[3];

  switch (offset_switch)
  {
    case 0:
      s7 = hc_byte_perm_S (src_r12, src_r13, selector);
      s6 = hc_byte_perm_S (src_r11, src_r12, selector);
      s5 = hc_byte_perm_S (src_r10, src_r11, selector);
      s4 = hc_byte_perm_S (src_r03, src_r10, selector);
      s3 = hc_byte_perm_S (src_r02, src_r03, selector);
      s2 = hc_byte_perm_S (src_r01, src_r02, selector);
      s1 = hc_byte_perm_S (src_r00, src_r01, selector);
      s0 = hc_byte_perm_S (      0, src_r00, selector);
      break;

    case 1:
      s7 = hc_byte_perm_S (src_r11, src_r12, selector);
      s6 = hc_byte_perm_S (src_r10, src_r11, selector);
      s5 = hc_byte_perm_S (src_r03, src_r10, selector);
      s4 = hc_byte_perm_S (src_r02, src_r03, selector);
      s3 = hc_byte_perm_S (src_r01, src_r02, selector);
      s2 = hc_byte_perm_S (src_r00, src_r01, selector);
      s1 = hc_byte_perm_S (      0, src_r00, selector);
      s0 = 0;
      break;

    case 2:
      s7 = hc_byte_perm_S (src_r10, src_r11, selector);
      s6 = hc_byte_perm_S (src_r03, src_r10, selector);
      s5 = hc_byte_perm_S (src_r02, src_r03, selector);
      s4 = hc_byte_perm_S (src_r01, src_r02, selector);
      s3 = hc_byte_perm_S (src_r00, src_r01, selector);
      s2 = hc_byte_perm_S (      0, src_r00, selector);
      s1 = 0;
      s0 = 0;
      break;

    case 3:
      s7 = hc_byte_perm_S (src_r03, src_r10, selector);
      s6 = hc_byte_perm_S (src_r02, src_r03, selector);
      s5 = hc_byte_perm_S (src_r01, src_r02, selector);
      s4 = hc_byte_perm_S (src_r00, src_r01, selector);
      s3 = hc_byte_perm_S (      0, src_r00, selector);
      s2 = 0;
      s1 = 0;
      s0 = 0;

      break;

    case 4:
      s7 = hc_byte_perm_S (src_r02, src_r03, selector);
      s6 = hc_byte_perm_S (src_r01, src_r02, selector);
      s5 = hc_byte_perm_S (src_r00, src_r01, selector);
      s4 = hc_byte_perm_S (      0, src_r00, selector);
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 5:
      s7 = hc_byte_perm_S (src_r01, src_r02, selector);
      s6 = hc_byte_perm_S (src_r00, src_r01, selector);
      s5 = hc_byte_perm_S (      0, src_r00, selector);
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 6:
      s7 = hc_byte_perm_S (src_r00, src_r01, selector);
      s6 = hc_byte_perm_S (      0, src_r00, selector);
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 7:
      s7 = hc_byte_perm_S (      0, src_r00, selector);
      s6 = 0;
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;
  }
  #endif

  buf0[0] = src_l0[0] | s0;
  buf0[1] = src_l0[1] | s1;
  buf0[2] = src_l0[2] | s2;
  buf0[3] = src_l0[3] | s3;
  buf1[0] = src_l1[0] | s4;
  buf1[1] = src_l1[1] | s5;
  buf1[2] = src_l1[2] | s6;
  buf1[3] = src_l1[3] | s7;
}

DECLSPEC void reverse_block_optimized (PRIVATE_AS u32 *in0, PRIVATE_AS u32 *in1, PRIVATE_AS u32 *out0, PRIVATE_AS u32 *out1, const u32 len)
{
  rshift_block_optimized_N (in0, in1, out0, out1, 32 - len);

  u32 tib40[4];
  u32 tib41[4];

  tib40[0] = out1[3];
  tib40[1] = out1[2];
  tib40[2] = out1[1];
  tib40[3] = out1[0];
  tib41[0] = out0[3];
  tib41[1] = out0[2];
  tib41[2] = out0[1];
  tib41[3] = out0[0];

  out0[0] = hc_swap32_S (tib40[0]);
  out0[1] = hc_swap32_S (tib40[1]);
  out0[2] = hc_swap32_S (tib40[2]);
  out0[3] = hc_swap32_S (tib40[3]);
  out1[0] = hc_swap32_S (tib41[0]);
  out1[1] = hc_swap32_S (tib41[1]);
  out1[2] = hc_swap32_S (tib41[2]);
  out1[3] = hc_swap32_S (tib41[3]);
}

DECLSPEC void exchange_byte_optimized (PRIVATE_AS u32 *buf, const int off_src, const int off_dst)
{
  PRIVATE_AS u8 *ptr = (PRIVATE_AS u8 *) buf;

  const u8 tmp = ptr[off_src];

  ptr[off_src] = ptr[off_dst];
  ptr[off_dst] = tmp;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_lrest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 t;

  t = buf0[0]; buf0[0] = t | generate_cmask (t);
  t = buf0[1]; buf0[1] = t | generate_cmask (t);
  t = buf0[2]; buf0[2] = t | generate_cmask (t);
  t = buf0[3]; buf0[3] = t | generate_cmask (t);
  t = buf1[0]; buf1[0] = t | generate_cmask (t);
  t = buf1[1]; buf1[1] = t | generate_cmask (t);
  t = buf1[2]; buf1[2] = t | generate_cmask (t);
  t = buf1[3]; buf1[3] = t | generate_cmask (t);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_urest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 t;

  t = buf0[0]; buf0[0] = t & ~(generate_cmask (t));
  t = buf0[1]; buf0[1] = t & ~(generate_cmask (t));
  t = buf0[2]; buf0[2] = t & ~(generate_cmask (t));
  t = buf0[3]; buf0[3] = t & ~(generate_cmask (t));
  t = buf1[0]; buf1[0] = t & ~(generate_cmask (t));
  t = buf1[1]; buf1[1] = t & ~(generate_cmask (t));
  t = buf1[2]; buf1[2] = t & ~(generate_cmask (t));
  t = buf1[3]; buf1[3] = t & ~(generate_cmask (t));

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_lrest_ufirst (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 t;

  t = buf0[0]; buf0[0] = t | generate_cmask (t);
  t = buf0[1]; buf0[1] = t | generate_cmask (t);
  t = buf0[2]; buf0[2] = t | generate_cmask (t);
  t = buf0[3]; buf0[3] = t | generate_cmask (t);
  t = buf1[0]; buf1[0] = t | generate_cmask (t);
  t = buf1[1]; buf1[1] = t | generate_cmask (t);
  t = buf1[2]; buf1[2] = t | generate_cmask (t);
  t = buf1[3]; buf1[3] = t | generate_cmask (t);

  t = buf0[0]; buf0[0] = t & ~(0x00000020 & generate_cmask (t));

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_urest_lfirst (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 t;

  t = buf0[0]; buf0[0] = t & ~(generate_cmask (t));
  t = buf0[1]; buf0[1] = t & ~(generate_cmask (t));
  t = buf0[2]; buf0[2] = t & ~(generate_cmask (t));
  t = buf0[3]; buf0[3] = t & ~(generate_cmask (t));
  t = buf1[0]; buf1[0] = t & ~(generate_cmask (t));
  t = buf1[1]; buf1[1] = t & ~(generate_cmask (t));
  t = buf1[2]; buf1[2] = t & ~(generate_cmask (t));
  t = buf1[3]; buf1[3] = t & ~(generate_cmask (t));

  t = buf0[0]; buf0[0] = t | (0x00000020 & generate_cmask (t));

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_trest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 t;

  t = buf0[0]; buf0[0] = t ^ generate_cmask (t);
  t = buf0[1]; buf0[1] = t ^ generate_cmask (t);
  t = buf0[2]; buf0[2] = t ^ generate_cmask (t);
  t = buf0[3]; buf0[3] = t ^ generate_cmask (t);
  t = buf1[0]; buf1[0] = t ^ generate_cmask (t);
  t = buf1[1]; buf1[1] = t ^ generate_cmask (t);
  t = buf1[2]; buf1[2] = t ^ generate_cmask (t);
  t = buf1[3]; buf1[3] = t ^ generate_cmask (t);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_toggle_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  const u32 tmp = t[p0 / 4];

  const u32 m = 0x20u << ((p0 & 3) * 8);

  t[p0 / 4] = tmp ^ (m & generate_cmask (tmp));

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_toggle_at_sep (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  u32 r0 = search_on_register (buf0[0], p1);
  u32 r1 = search_on_register (buf0[1], p1);
  u32 r2 = search_on_register (buf0[2], p1);
  u32 r3 = search_on_register (buf0[3], p1);
  u32 r4 = search_on_register (buf1[0], p1);
  u32 r5 = search_on_register (buf1[1], p1);
  u32 r6 = search_on_register (buf1[2], p1);
  u32 r7 = search_on_register (buf1[3], p1);

  const u32 rn = (r0 <<  0)
               | (r1 <<  4)
               | (r2 <<  8)
               | (r3 << 12)
               | (r4 << 16)
               | (r5 << 20)
               | (r6 << 24)
               | (r7 << 28);

  if (rn == 0) return in_len;

  u32 occurence = 0;

  u32 ro = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < 32; i++)
  {
    if ((rn >> i) & 1)
    {
      if (occurence == p0)
      {
        ro = 1 << i;

        break;
      }

      occurence++;
    }
  }

  r0 = (ro >>  0) & 15;
  r1 = (ro >>  4) & 15;
  r2 = (ro >>  8) & 15;
  r3 = (ro >> 12) & 15;
  r4 = (ro >> 16) & 15;
  r5 = (ro >> 20) & 15;
  r6 = (ro >> 24) & 15;
  r7 = (ro >> 28) & 15;

  r0 <<= 1;
  r1 <<= 1; r1 |= r0 >> 4;
  r2 <<= 1; r2 |= r1 >> 4;
  r3 <<= 1; r3 |= r2 >> 4;
  r4 <<= 1; r4 |= r3 >> 4;
  r5 <<= 1; r5 |= r4 >> 4;
  r6 <<= 1; r6 |= r5 >> 4;
  r7 <<= 1; r7 |= r6 >> 4;

  buf0[0] = toggle_on_register (buf0[0], r0);
  buf0[1] = toggle_on_register (buf0[1], r1);
  buf0[2] = toggle_on_register (buf0[2], r2);
  buf0[3] = toggle_on_register (buf0[3], r3);
  buf1[0] = toggle_on_register (buf1[0], r4);
  buf1[1] = toggle_on_register (buf1[1], r5);
  buf1[2] = toggle_on_register (buf1[2], r6);
  buf1[3] = toggle_on_register (buf1[3], r7);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_reverse (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  reverse_block_optimized (buf0, buf1, buf0, buf1, in_len);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupeword (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if ((in_len + in_len) >= 32) return in_len;

  u32 out_len = in_len;

  append_block8_optimized (out_len, buf0, buf1, buf0, buf1, buf0, buf1);

  out_len += in_len;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupeword_times (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (((in_len * p0) + in_len) >= 32) return in_len;

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  tib40[0] = buf0[0];
  tib40[1] = buf0[1];
  tib40[2] = buf0[2];
  tib40[3] = buf0[3];
  tib41[0] = buf1[0];
  tib41[1] = buf1[1];
  tib41[2] = buf1[2];
  tib41[3] = buf1[3];

  for (u32 i = 0; i < p0; i++)
  {
    append_block8_optimized (out_len, buf0, buf1, buf0, buf1, tib40, tib41);

    out_len += in_len;
  }

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_reflect (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if ((in_len + in_len) >= 32) return in_len;

  u32 out_len = in_len;

  u32 tib40[4] = { 0 };
  u32 tib41[4] = { 0 };

  reverse_block_optimized (buf0, buf1, tib40, tib41, out_len);

  append_block8_optimized (out_len, buf0, buf1, buf0, buf1, tib40, tib41);

  out_len += in_len;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_append (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if ((in_len + 1) >= 32) return in_len;

  u32 out_len = in_len;

  append_block1_optimized (out_len, buf0, buf1, p0);

  out_len++;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_prepend (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if ((in_len + 1) >= 32) return in_len;

  u32 out_len = in_len;

  rshift_block_optimized (buf0, buf1, buf0, buf1);

  buf0[0] = buf0[0] | p0;

  out_len++;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_rotate_left (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  const u32 in_len1 = in_len - 1;

  const u32 tmp = buf0[0];

  lshift_block_optimized (buf0, buf1, buf0, buf1);

  append_block1_optimized (in_len1, buf0, buf1, tmp);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_rotate_right (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  const u32 in_len1 = in_len - 1;

  const u32 sh = (in_len1 & 3) * 8;

  u32 tmp = 0;

  u32 v[4];

  set_mark_1x4_S (v, in_len1);

  switch (in_len1 / 16)
  {
    case 0:
      tmp |= buf0[0] & v[0];
      tmp |= buf0[1] & v[1];
      tmp |= buf0[2] & v[2];
      tmp |= buf0[3] & v[3];
      break;

    case 1:
      tmp |= buf1[0] & v[0];
      tmp |= buf1[1] & v[1];
      tmp |= buf1[2] & v[2];
      tmp |= buf1[3] & v[3];
      break;
  }

  tmp = (tmp >> sh) & 0xff;

  rshift_block_optimized (buf0, buf1, buf0, buf1);

  buf0[0] |= tmp;

  truncate_right_optimized (buf0, buf1, in_len);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_delete_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  const u32 in_len1 = in_len - 1;

  lshift_block_optimized (buf0, buf1, buf0, buf1);

  return in_len1;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_delete_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  const u32 in_len1 = in_len - 1;

  const u32 mask = (1 << ((in_len1 & 3) * 8)) - 1;

  buf0[0] &=                     (in_len1 <  4)  ? mask : 0xffffffff;
  buf0[1] &= ((in_len1 >=  4) && (in_len1 <  8)) ? mask : 0xffffffff;
  buf0[2] &= ((in_len1 >=  8) && (in_len1 < 12)) ? mask : 0xffffffff;
  buf0[3] &= ((in_len1 >= 12) && (in_len1 < 16)) ? mask : 0xffffffff;
  buf1[0] &= ((in_len1 >= 16) && (in_len1 < 20)) ? mask : 0xffffffff;
  buf1[1] &= ((in_len1 >= 20) && (in_len1 < 24)) ? mask : 0xffffffff;
  buf1[2] &= ((in_len1 >= 24) && (in_len1 < 28)) ? mask : 0xffffffff;
  buf1[3] &=  (in_len1 >= 28)                    ? mask : 0xffffffff;

  return in_len1;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_delete_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  lshift_block_optimized (buf0, buf1, tib40, tib41);

  const u32 ml = (1 << ((p0 & 3) * 8)) - 1;
  const u32 mr = ~ml;

  const int p0_switch = p0 / 4;

  switch (p0_switch)
  {
    case  0:  buf0[0] =  (buf0[0] & ml)
                      | (tib40[0] & mr);
              buf0[1] =  tib40[1];
              buf0[2] =  tib40[2];
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  1:  buf0[1] =  (buf0[1] & ml)
                      | (tib40[1] & mr);
              buf0[2] =  tib40[2];
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  2:  buf0[2] =  (buf0[2] & ml)
                      | (tib40[2] & mr);
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  3:  buf0[3] =  (buf0[3] & ml)
                      | (tib40[3] & mr);
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  4:  buf1[0] =  (buf1[0] & ml)
                      | (tib41[0] & mr);
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  5:  buf1[1] =  (buf1[1] & ml)
                      | (tib41[1] & mr);
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  6:  buf1[2] =  (buf1[2] & ml)
                      | (tib41[2] & mr);
              buf1[3] =  tib41[3];
              break;
    case  7:  buf1[3] =  (buf1[3] & ml)
                      | (tib41[3] & mr);
              break;
  }

  out_len--;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_extract (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  if ((p0 + p1) > in_len) return in_len;

  u32 out_len = p1;

  lshift_block_optimized_N (buf0, buf1, buf0, buf1, p0);

  truncate_right_optimized (buf0, buf1, out_len);

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_omit (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  if ((p0 + p1) > in_len) return in_len;

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  tib40[0] = 0;
  tib40[1] = 0;
  tib40[2] = 0;
  tib40[3] = 0;
  tib41[0] = 0;
  tib41[1] = 0;
  tib41[2] = 0;
  tib41[3] = 0;

  lshift_block_optimized_N (buf0, buf1, tib40, tib41, p1);

  const u32 ml = (1 << ((p0 & 3) * 8)) - 1;
  const u32 mr = ~ml;

  const int p0_switch = p0 / 4;

  switch (p0_switch)
  {
    case  0:  buf0[0] =  (buf0[0] & ml)
                      | (tib40[0] & mr);
              buf0[1] =  tib40[1];
              buf0[2] =  tib40[2];
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  1:  buf0[1] =  (buf0[1] & ml)
                      | (tib40[1] & mr);
              buf0[2] =  tib40[2];
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  2:  buf0[2] =  (buf0[2] & ml)
                      | (tib40[2] & mr);
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  3:  buf0[3] =  (buf0[3] & ml)
                      | (tib40[3] & mr);
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  4:  buf1[0] =  (buf1[0] & ml)
                      | (tib41[0] & mr);
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  5:  buf1[1] =  (buf1[1] & ml)
                      | (tib41[1] & mr);
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  6:  buf1[2] =  (buf1[2] & ml)
                      | (tib41[2] & mr);
              buf1[3] =  tib41[3];
              break;
    case  7:  buf1[3] =  (buf1[3] & ml)
                      | (tib41[3] & mr);
              break;
  }

  out_len -= p1;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_insert (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 > in_len) return in_len;

  if ((in_len + 1) >= 32) return in_len;

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  rshift_block_optimized (buf0, buf1, tib40, tib41);

  const u32 p1n = p1 << ((p0 & 3) * 8);

  const u32 ml = (1 << ((p0 & 3) * 8)) - 1;

  const u32 mr = 0xffffff00 << ((p0 & 3) * 8);

  const int p0_switch = p0 / 4;

  switch (p0_switch)
  {
    case  0:  buf0[0] =  (buf0[0] & ml) | p1n | (tib40[0] & mr);
              buf0[1] =  tib40[1];
              buf0[2] =  tib40[2];
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  1:  buf0[1] =  (buf0[1] & ml) | p1n | (tib40[1] & mr);
              buf0[2] =  tib40[2];
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  2:  buf0[2] =  (buf0[2] & ml) | p1n | (tib40[2] & mr);
              buf0[3] =  tib40[3];
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  3:  buf0[3] =  (buf0[3] & ml) | p1n | (tib40[3] & mr);
              buf1[0] =  tib41[0];
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  4:  buf1[0] =  (buf1[0] & ml) | p1n | (tib41[0] & mr);
              buf1[1] =  tib41[1];
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  5:  buf1[1] =  (buf1[1] & ml) | p1n | (tib41[1] & mr);
              buf1[2] =  tib41[2];
              buf1[3] =  tib41[3];
              break;
    case  6:  buf1[2] =  (buf1[2] & ml) | p1n | (tib41[2] & mr);
              buf1[3] =  tib41[3];
              break;
    case  7:  buf1[3] =  (buf1[3] & ml) | p1n | (tib41[3] & mr);
              break;
  }

  out_len++;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_overstrike (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  const u32 p1n = p1 << ((p0 & 3) * 8);

  const u32 m = ~(0xffu << ((p0 & 3) * 8));

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  const u32 tmp = t[p0 / 4];

  t[p0 / 4] = (tmp & m) | p1n;

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_truncate_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  truncate_right_optimized (buf0, buf1, p0);

  return p0;
}

DECLSPEC u32 search_on_register (const u32 in, const u32 p0)
{
  u32 r = 0;

  if (hc_bfe_S (in,  0, 8) == p0) r |= 1;
  if (hc_bfe_S (in,  8, 8) == p0) r |= 2;
  if (hc_bfe_S (in, 16, 8) == p0) r |= 4;
  if (hc_bfe_S (in, 24, 8) == p0) r |= 8;

  return r;
}

DECLSPEC u32 replace_on_register (const u32 in, const u32 r, const u32 p1)
{
  u32 out = in;

  if (r & 1) out = (out & 0xffffff00) | (p1 <<  0);
  if (r & 2) out = (out & 0xffff00ff) | (p1 <<  8);
  if (r & 4) out = (out & 0xff00ffff) | (p1 << 16);
  if (r & 8) out = (out & 0x00ffffff) | (p1 << 24);

  return out;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  const u32 r0 = search_on_register (buf0[0], p0);
  const u32 r1 = search_on_register (buf0[1], p0);
  const u32 r2 = search_on_register (buf0[2], p0);
  const u32 r3 = search_on_register (buf0[3], p0);
  const u32 r4 = search_on_register (buf1[0], p0);
  const u32 r5 = search_on_register (buf1[1], p0);
  const u32 r6 = search_on_register (buf1[2], p0);
  const u32 r7 = search_on_register (buf1[3], p0);

  const u32 rn = r0 + r1 + r2 + r3 + r4 + r5 + r6 + r7;

  if (rn == 0) return in_len;

  buf0[0] = replace_on_register (buf0[0], r0, p1);
  buf0[1] = replace_on_register (buf0[1], r1, p1);
  buf0[2] = replace_on_register (buf0[2], r2, p1);
  buf0[3] = replace_on_register (buf0[3], r3, p1);
  buf1[0] = replace_on_register (buf1[0], r4, p1);
  buf1[1] = replace_on_register (buf1[1], r5, p1);
  buf1[2] = replace_on_register (buf1[2], r6, p1);
  buf1[3] = replace_on_register (buf1[3], r7, p1);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_class_l (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  PRIVATE_AS u8 *in = (PRIVATE_AS u8 *) buf_in;

  u32 rn = 0;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (!is_l (in[pos])) continue;

    in[pos] = (u8)p1;

    rn++;
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_class_u (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  PRIVATE_AS u8 *in = (PRIVATE_AS u8 *) buf_in;

  u32 rn = 0;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (!is_u (in[pos])) continue;

    in[pos] = (u8)p1;

    rn++;
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_class_d (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  PRIVATE_AS u8 *in = (PRIVATE_AS u8 *) buf_in;

  u32 rn = 0;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (!is_d (in[pos])) continue;

    in[pos] = (u8)p1;

    rn++;
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_class_lh (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  PRIVATE_AS u8 *in = (PRIVATE_AS u8 *) buf_in;

  u32 rn = 0;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (!is_lh (in[pos])) continue;

    in[pos] = (u8)p1;

    rn++;
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_class_uh (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  PRIVATE_AS u8 *in = (PRIVATE_AS u8 *) buf_in;

  u32 rn = 0;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (!is_uh (in[pos])) continue;

    in[pos] = (u8)p1;

    rn++;
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_class_s (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  PRIVATE_AS u8 *in = (PRIVATE_AS u8 *) buf_in;

  u32 rn = 0;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (!is_s (in[pos])) continue;

    in[pos] = (u8)p1;

    rn++;
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_class (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
       if ((u8)p0 == 'l') return rule_op_mangle_replace_class_l  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'u') return rule_op_mangle_replace_class_u  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'd') return rule_op_mangle_replace_class_d  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'h') return rule_op_mangle_replace_class_lh (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'H') return rule_op_mangle_replace_class_uh (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 's') return rule_op_mangle_replace_class_s  (p0, p1, buf0, buf1, in_len);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  const u32 r0 = search_on_register (buf0[0], p0);
  const u32 r1 = search_on_register (buf0[1], p0);
  const u32 r2 = search_on_register (buf0[2], p0);
  const u32 r3 = search_on_register (buf0[3], p0);
  const u32 r4 = search_on_register (buf1[0], p0);
  const u32 r5 = search_on_register (buf1[1], p0);
  const u32 r6 = search_on_register (buf1[2], p0);
  const u32 r7 = search_on_register (buf1[3], p0);

  const u32 rn = r0 + r1 + r2 + r3 + r4 + r5 + r6 + r7;

  if (rn == 0) return in_len;

  u32 out_len = 0;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 buf_out[8] = { 0 };

  PRIVATE_AS u8 *in  = (PRIVATE_AS u8 *) buf_in;
  PRIVATE_AS u8 *out = (PRIVATE_AS u8 *) buf_out;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (in[pos] == (u8) p0) continue;

    out[out_len] = in[pos];

    out_len++;
  }

  buf0[0] = buf_out[0];
  buf0[1] = buf_out[1];
  buf0[2] = buf_out[2];
  buf0[3] = buf_out[3];
  buf1[0] = buf_out[4];
  buf1[1] = buf_out[5];
  buf1[2] = buf_out[6];
  buf1[3] = buf_out[7];

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar_class_l (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 out_len = 0;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 buf_out[8] = { 0 };

  PRIVATE_AS u8 *in  = (PRIVATE_AS u8 *) buf_in;
  PRIVATE_AS u8 *out = (PRIVATE_AS u8 *) buf_out;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (is_l (in[pos])) continue;

    out[out_len] = in[pos];

    out_len++;
  }

  buf0[0] = buf_out[0];
  buf0[1] = buf_out[1];
  buf0[2] = buf_out[2];
  buf0[3] = buf_out[3];
  buf1[0] = buf_out[4];
  buf1[1] = buf_out[5];
  buf1[2] = buf_out[6];
  buf1[3] = buf_out[7];

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar_class_u (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 out_len = 0;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 buf_out[8] = { 0 };

  PRIVATE_AS u8 *in  = (PRIVATE_AS u8 *) buf_in;
  PRIVATE_AS u8 *out = (PRIVATE_AS u8 *) buf_out;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (is_u (in[pos])) continue;

    out[out_len] = in[pos];

    out_len++;
  }

  buf0[0] = buf_out[0];
  buf0[1] = buf_out[1];
  buf0[2] = buf_out[2];
  buf0[3] = buf_out[3];
  buf1[0] = buf_out[4];
  buf1[1] = buf_out[5];
  buf1[2] = buf_out[6];
  buf1[3] = buf_out[7];

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar_class_d (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 out_len = 0;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 buf_out[8] = { 0 };

  PRIVATE_AS u8 *in  = (PRIVATE_AS u8 *) buf_in;
  PRIVATE_AS u8 *out = (PRIVATE_AS u8 *) buf_out;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (is_d (in[pos])) continue;

    out[out_len] = in[pos];

    out_len++;
  }

  buf0[0] = buf_out[0];
  buf0[1] = buf_out[1];
  buf0[2] = buf_out[2];
  buf0[3] = buf_out[3];
  buf1[0] = buf_out[4];
  buf1[1] = buf_out[5];
  buf1[2] = buf_out[6];
  buf1[3] = buf_out[7];

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar_class_lh (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 out_len = 0;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 buf_out[8] = { 0 };

  PRIVATE_AS u8 *in  = (PRIVATE_AS u8 *) buf_in;
  PRIVATE_AS u8 *out = (PRIVATE_AS u8 *) buf_out;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (is_lh (in[pos])) continue;

    out[out_len] = in[pos];

    out_len++;
  }

  buf0[0] = buf_out[0];
  buf0[1] = buf_out[1];
  buf0[2] = buf_out[2];
  buf0[3] = buf_out[3];
  buf1[0] = buf_out[4];
  buf1[1] = buf_out[5];
  buf1[2] = buf_out[6];
  buf1[3] = buf_out[7];

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar_class_uh (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 out_len = 0;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 buf_out[8] = { 0 };

  PRIVATE_AS u8 *in  = (PRIVATE_AS u8 *) buf_in;
  PRIVATE_AS u8 *out = (PRIVATE_AS u8 *) buf_out;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (is_uh (in[pos])) continue;

    out[out_len] = in[pos];

    out_len++;
  }

  buf0[0] = buf_out[0];
  buf0[1] = buf_out[1];
  buf0[2] = buf_out[2];
  buf0[3] = buf_out[3];
  buf1[0] = buf_out[4];
  buf1[1] = buf_out[5];
  buf1[2] = buf_out[6];
  buf1[3] = buf_out[7];

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar_class_s (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 out_len = 0;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 buf_out[8] = { 0 };

  PRIVATE_AS u8 *in  = (PRIVATE_AS u8 *) buf_in;
  PRIVATE_AS u8 *out = (PRIVATE_AS u8 *) buf_out;

  for (u32 pos = 0; pos < in_len; pos++)
  {
    if (is_s (in[pos])) continue;

    out[out_len] = in[pos];

    out_len++;
  }

  buf0[0] = buf_out[0];
  buf0[1] = buf_out[1];
  buf0[2] = buf_out[2];
  buf0[3] = buf_out[3];
  buf1[0] = buf_out[4];
  buf1[1] = buf_out[5];
  buf1[2] = buf_out[6];
  buf1[3] = buf_out[7];

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_purgechar_class (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
       if ((u8)p0 == 'l') return rule_op_mangle_purgechar_class_l  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'u') return rule_op_mangle_purgechar_class_u  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'd') return rule_op_mangle_purgechar_class_d  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'h') return rule_op_mangle_purgechar_class_lh (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'H') return rule_op_mangle_purgechar_class_uh (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 's') return rule_op_mangle_purgechar_class_s  (p0, p1, buf0, buf1, in_len);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupechar_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if ( in_len       ==  0) return in_len;
  if ((in_len + p0) >= 32) return in_len;

  u32 out_len = in_len;

  const u32 tmp = buf0[0] & 0xFF;

  const u32 tmp32 = tmp <<  0
                  | tmp <<  8
                  | tmp << 16
                  | tmp << 24;

  rshift_block_optimized_N (buf0, buf1, buf0, buf1, p0);

  u32 t0[4] = { tmp32, tmp32, tmp32, tmp32 };
  u32 t1[4] = { tmp32, tmp32, tmp32, tmp32 };

  truncate_right_optimized (t0, t1, p0);

  buf0[0] |= t0[0];
  buf0[1] |= t0[1];
  buf0[2] |= t0[2];
  buf0[3] |= t0[3];
  buf1[0] |= t1[0];
  buf1[1] |= t1[1];
  buf1[2] |= t1[2];
  buf1[3] |= t1[3];

  out_len += p0;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupechar_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if ( in_len       ==  0) return in_len;
  if ((in_len + p0) >= 32) return in_len;

  const u32 in_len1 = in_len - 1;

  const u32 sh = (in_len1 & 3) * 8;

  u32 tmp = 0;

  u32 v[4];

  set_mark_1x4_S (v, in_len1);

  switch (in_len1 / 16)
  {
    case 0:
      tmp |= buf0[0] & v[0];
      tmp |= buf0[1] & v[1];
      tmp |= buf0[2] & v[2];
      tmp |= buf0[3] & v[3];
      break;

    case 1:
      tmp |= buf1[0] & v[0];
      tmp |= buf1[1] & v[1];
      tmp |= buf1[2] & v[2];
      tmp |= buf1[3] & v[3];
      break;
  }

  tmp = (tmp >> sh) & 0xff;

  u32 out_len = in_len;

  for (u32 i = 0; i < p0; i++)
  {
    append_block1_optimized (out_len, buf0, buf1, tmp);

    out_len++;
  }

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupechar_all (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if ( in_len           ==  0) return in_len;
  if ((in_len + in_len) >= 32) return in_len;

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  tib40[0] = ((buf0[0] & 0x000000FF) <<  0) | ((buf0[0] & 0x0000FF00) <<  8);
  tib40[1] = ((buf0[0] & 0x00FF0000) >> 16) | ((buf0[0] & 0xFF000000) >>  8);
  tib40[2] = ((buf0[1] & 0x000000FF) <<  0) | ((buf0[1] & 0x0000FF00) <<  8);
  tib40[3] = ((buf0[1] & 0x00FF0000) >> 16) | ((buf0[1] & 0xFF000000) >>  8);
  tib41[0] = ((buf0[2] & 0x000000FF) <<  0) | ((buf0[2] & 0x0000FF00) <<  8);
  tib41[1] = ((buf0[2] & 0x00FF0000) >> 16) | ((buf0[2] & 0xFF000000) >>  8);
  tib41[2] = ((buf0[3] & 0x000000FF) <<  0) | ((buf0[3] & 0x0000FF00) <<  8);
  tib41[3] = ((buf0[3] & 0x00FF0000) >> 16) | ((buf0[3] & 0xFF000000) >>  8);

  buf0[0] = tib40[0] | (tib40[0] <<  8);
  buf0[1] = tib40[1] | (tib40[1] <<  8);
  buf0[2] = tib40[2] | (tib40[2] <<  8);
  buf0[3] = tib40[3] | (tib40[3] <<  8);
  buf1[0] = tib41[0] | (tib41[0] <<  8);
  buf1[1] = tib41[1] | (tib41[1] <<  8);
  buf1[2] = tib41[2] | (tib41[2] <<  8);
  buf1[3] = tib41[3] | (tib41[3] <<  8);

  out_len = out_len + out_len;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_switch_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len < 2) return in_len;

  buf0[0] = (buf0[0] & 0xFFFF0000) | ((buf0[0] << 8) & 0x0000FF00) | ((buf0[0] >> 8) & 0x000000FF);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_switch_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len < 2) return in_len;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  exchange_byte_optimized (t, in_len - 2, in_len - 1);

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_switch_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;
  if (p1 >= in_len) return in_len;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  exchange_byte_optimized (t, p0, p1);

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_chr_shiftl (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  const u32 tmp = t[p0 / 4];

  t[p0 / 4] = (tmp & ml) | (((tmp & mr) << 1) & mr);

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_chr_shiftr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  const u32 tmp = t[p0 / 4];

  t[p0 / 4] = (tmp & ml) | (((tmp & mr) >> 1) & mr);

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_chr_incr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  const u32 n = 0x01010101 & mr;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  const u32 tmp = t[p0 / 4];

  t[p0 / 4] = (tmp & ml) | (((tmp & mr) + n) & mr);

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_chr_decr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 >= in_len) return in_len;

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  const u32 n = 0x01010101 & mr;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  const u32 tmp = t[p0 / 4];

  t[p0 / 4] = (tmp & ml) | (((tmp & mr) - n) & mr);

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_np1 (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if ((p0 + 1) >= in_len) return in_len;

  u32 tib4x[8];

  lshift_block_optimized (buf0, buf1, tib4x + 0, tib4x + 4);

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  const u32 tmp = t[p0 / 4];

  const u32 tmp2 = tib4x[p0 / 4];

  t[p0 / 4] = (tmp & ml) | (tmp2 & mr);

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_replace_nm1 (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 == 0) return in_len;

  if (p0 >= in_len) return in_len;

  u32 tib4x[8];

  rshift_block_optimized (buf0, buf1, tib4x + 0, tib4x + 4);

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  u32 t[8];

  t[0] = buf0[0];
  t[1] = buf0[1];
  t[2] = buf0[2];
  t[3] = buf0[3];
  t[4] = buf1[0];
  t[5] = buf1[1];
  t[6] = buf1[2];
  t[7] = buf1[3];

  const u32 tmp = t[p0 / 4];

  const u32 tmp2 = tib4x[p0 / 4];

  t[p0 / 4] = (tmp & ml) | (tmp2 & mr);

  buf0[0] = t[0];
  buf0[1] = t[1];
  buf0[2] = t[2];
  buf0[3] = t[3];
  buf1[0] = t[4];
  buf1[1] = t[5];
  buf1[2] = t[6];
  buf1[3] = t[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupeblock_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 > in_len) return in_len;

  if ((in_len + p0) >= 32) return in_len;

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  tib40[0] = buf0[0];
  tib40[1] = buf0[1];
  tib40[2] = buf0[2];
  tib40[3] = buf0[3];
  tib41[0] = buf1[0];
  tib41[1] = buf1[1];
  tib41[2] = buf1[2];
  tib41[3] = buf1[3];

  truncate_right_optimized (tib40, tib41, p0);

  rshift_block_optimized_N (buf0, buf1, buf0, buf1, p0);

  buf0[0] |= tib40[0];
  buf0[1] |= tib40[1];
  buf0[2] |= tib40[2];
  buf0[3] |= tib40[3];
  buf1[0] |= tib41[0];
  buf1[1] |= tib41[1];
  buf1[2] |= tib41[2];
  buf1[3] |= tib41[3];

  out_len += p0;

  return out_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_dupeblock_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (p0 > in_len) return in_len;

  if ((in_len + p0) >= 32) return in_len;

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  rshift_block_optimized_N (buf0, buf1, tib40, tib41, p0);

  truncate_left_optimized (tib40, tib41, out_len);

  buf0[0] |= tib40[0];
  buf0[1] |= tib40[1];
  buf0[2] |= tib40[2];
  buf0[3] |= tib40[3];
  buf1[0] |= tib41[0];
  buf1[1] |= tib41[1];
  buf1[2] |= tib41[2];
  buf1[3] |= tib41[3];

  out_len += p0;

  return out_len;
}

DECLSPEC u32 toggle_on_register (const u32 in, const u32 r)
{
  u32 out = in;

  const u32 cmask = generate_cmask (out);

  if (r & 1) out = out ^ (0x00000020 & cmask);
  if (r & 2) out = out ^ (0x00002000 & cmask);
  if (r & 4) out = out ^ (0x00200000 & cmask);
  if (r & 8) out = out ^ (0x20000000 & cmask);

  return out;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  u32 r0 = search_on_register (buf0[0], p0);
  u32 r1 = search_on_register (buf0[1], p0);
  u32 r2 = search_on_register (buf0[2], p0);
  u32 r3 = search_on_register (buf0[3], p0);
  u32 r4 = search_on_register (buf1[0], p0);
  u32 r5 = search_on_register (buf1[1], p0);
  u32 r6 = search_on_register (buf1[2], p0);
  u32 r7 = search_on_register (buf1[3], p0);

  rule_op_mangle_lrest_ufirst (p0, p1, buf0, buf1, in_len);

  const u32 rn = r0 + r1 + r2 + r3 + r4 + r5 + r6 + r7;

  if (rn == 0) return in_len;

  r0 <<= 1;
  r1 <<= 1; r1 |= r0 >> 4;
  r2 <<= 1; r2 |= r1 >> 4;
  r3 <<= 1; r3 |= r2 >> 4;
  r4 <<= 1; r4 |= r3 >> 4;
  r5 <<= 1; r5 |= r4 >> 4;
  r6 <<= 1; r6 |= r5 >> 4;
  r7 <<= 1; r7 |= r6 >> 4;

  buf0[0] = toggle_on_register (buf0[0], r0);
  buf0[1] = toggle_on_register (buf0[1], r1);
  buf0[2] = toggle_on_register (buf0[2], r2);
  buf0[3] = toggle_on_register (buf0[3], r3);
  buf1[0] = toggle_on_register (buf1[0], r4);
  buf1[1] = toggle_on_register (buf1[1], r5);
  buf1[2] = toggle_on_register (buf1[2], r6);
  buf1[3] = toggle_on_register (buf1[3], r7);

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep_class_l (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 rem = 0xff;

  u32 rn = 0;

  for (u32 i = 0, idx = 0; i < in_len; i += 4, idx += 1)
  {
    const u32 t = buf_in[idx];

    buf_in[idx] = t | generate_cmask (t);

    u32 out = rem;

    rem = 0;

    if (is_l ((t >>  0) & 0xff)) { rn++; out |= 0x0000ff00; }
    if (is_l ((t >>  8) & 0xff)) { rn++; out |= 0x00ff0000; }
    if (is_l ((t >> 16) & 0xff)) { rn++; out |= 0xff000000; }
    if (is_l ((t >> 24) & 0xff)) { rn++; rem |= 0x000000ff; }

    buf_in[idx] &= ~(generate_cmask (buf_in[idx]) & out);
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep_class_u (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 rem = 0xff;

  u32 rn = 0;

  for (u32 i = 0, idx = 0; i < in_len; i += 4, idx += 1)
  {
    const u32 t = buf_in[idx];

    buf_in[idx] = t | generate_cmask (t);

    u32 out = rem;

    rem = 0;

    if (is_u ((t >>  0) & 0xff)) { rn++; out |= 0x0000ff00; }
    if (is_u ((t >>  8) & 0xff)) { rn++; out |= 0x00ff0000; }
    if (is_u ((t >> 16) & 0xff)) { rn++; out |= 0xff000000; }
    if (is_u ((t >> 24) & 0xff)) { rn++; rem |= 0x000000ff; }

    buf_in[idx] &= ~(generate_cmask (buf_in[idx]) & out);
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep_class_d (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 rem = 0xff;

  u32 rn = 0;

  for (u32 i = 0, idx = 0; i < in_len; i += 4, idx += 1)
  {
    const u32 t = buf_in[idx];

    buf_in[idx] = t | generate_cmask (t);

    u32 out = rem;

    rem = 0;

    if (is_d ((t >>  0) & 0xff)) { rn++; out |= 0x0000ff00; }
    if (is_d ((t >>  8) & 0xff)) { rn++; out |= 0x00ff0000; }
    if (is_d ((t >> 16) & 0xff)) { rn++; out |= 0xff000000; }
    if (is_d ((t >> 24) & 0xff)) { rn++; rem |= 0x000000ff; }

    buf_in[idx] &= ~(generate_cmask (buf_in[idx]) & out);
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep_class_lh (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 rem = 0xff;

  u32 rn = 0;

  for (u32 i = 0, idx = 0; i < in_len; i += 4, idx += 1)
  {
    const u32 t = buf_in[idx];

    buf_in[idx] = t | generate_cmask (t);

    u32 out = rem;

    rem = 0;

    if (is_lh ((t >>  0) & 0xff)) { rn++; out |= 0x0000ff00; }
    if (is_lh ((t >>  8) & 0xff)) { rn++; out |= 0x00ff0000; }
    if (is_lh ((t >> 16) & 0xff)) { rn++; out |= 0xff000000; }
    if (is_lh ((t >> 24) & 0xff)) { rn++; rem |= 0x000000ff; }

    buf_in[idx] &= ~(generate_cmask (buf_in[idx]) & out);
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep_class_uh (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 rem = 0xff;

  u32 rn = 0;

  for (u32 i = 0, idx = 0; i < in_len; i += 4, idx += 1)
  {
    const u32 t = buf_in[idx];

    buf_in[idx] = t | generate_cmask (t);

    u32 out = rem;

    rem = 0;

    if (is_uh ((t >>  0) & 0xff)) { rn++; out |= 0x0000ff00; }
    if (is_uh ((t >>  8) & 0xff)) { rn++; out |= 0x00ff0000; }
    if (is_uh ((t >> 16) & 0xff)) { rn++; out |= 0xff000000; }
    if (is_uh ((t >> 24) & 0xff)) { rn++; rem |= 0x000000ff; }

    buf_in[idx] &= ~(generate_cmask (buf_in[idx]) & out);
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep_class_s (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
  if (in_len == 0) return in_len;

  u32 buf_in[8];

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 rem = 0xff;

  u32 rn = 0;

  for (u32 i = 0, idx = 0; i < in_len; i += 4, idx += 1)
  {
    const u32 t = buf_in[idx];

    buf_in[idx] = t | generate_cmask (t);

    u32 out = rem;

    rem = 0;

    if (is_s ((t >>  0) & 0xff)) { rn++; out |= 0x0000ff00; }
    if (is_s ((t >>  8) & 0xff)) { rn++; out |= 0x00ff0000; }
    if (is_s ((t >> 16) & 0xff)) { rn++; out |= 0xff000000; }
    if (is_s ((t >> 24) & 0xff)) { rn++; rem |= 0x000000ff; }

    buf_in[idx] &= ~(generate_cmask (buf_in[idx]) & out);
  }

  if (rn == 0) return in_len;

  buf0[0] = buf_in[0];
  buf0[1] = buf_in[1];
  buf0[2] = buf_in[2];
  buf0[3] = buf_in[3];
  buf1[0] = buf_in[4];
  buf1[1] = buf_in[5];
  buf1[2] = buf_in[6];
  buf1[3] = buf_in[7];

  return in_len;
}

DECLSPEC HC_INLINE_RP u32 rule_op_mangle_title_sep_class (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED PRIVATE_AS u32 *buf0, MAYBE_UNUSED PRIVATE_AS u32 *buf1, const u32 in_len)
{
       if ((u8)p0 == 'l') return rule_op_mangle_title_sep_class_l  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'u') return rule_op_mangle_title_sep_class_u  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'd') return rule_op_mangle_title_sep_class_d  (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'h') return rule_op_mangle_title_sep_class_lh (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 'H') return rule_op_mangle_title_sep_class_uh (p0, p1, buf0, buf1, in_len);
  else if ((u8)p0 == 's') return rule_op_mangle_title_sep_class_s  (p0, p1, buf0, buf1, in_len);

  return in_len;
}

DECLSPEC u32 apply_rule_optimized (const u32 name, const u32 p0, const u32 p1, PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 in_len)
{
  u32 out_len = in_len;

  switch (name)
  {
    case RULE_OP_MANGLE_LREST:            out_len = rule_op_mangle_lrest            (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_UREST:            out_len = rule_op_mangle_urest            (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_LREST_UFIRST:     out_len = rule_op_mangle_lrest_ufirst     (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_UREST_LFIRST:     out_len = rule_op_mangle_urest_lfirst     (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_TREST:            out_len = rule_op_mangle_trest            (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_TOGGLE_AT:        out_len = rule_op_mangle_toggle_at        (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_TOGGLE_AT_SEP:    out_len = rule_op_mangle_toggle_at_sep    (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_REVERSE:          out_len = rule_op_mangle_reverse          (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DUPEWORD:         out_len = rule_op_mangle_dupeword         (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DUPEWORD_TIMES:   out_len = rule_op_mangle_dupeword_times   (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_REFLECT:          out_len = rule_op_mangle_reflect          (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_APPEND:           out_len = rule_op_mangle_append           (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_PREPEND:          out_len = rule_op_mangle_prepend          (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_ROTATE_LEFT:      out_len = rule_op_mangle_rotate_left      (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_ROTATE_RIGHT:     out_len = rule_op_mangle_rotate_right     (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DELETE_FIRST:     out_len = rule_op_mangle_delete_first     (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DELETE_LAST:      out_len = rule_op_mangle_delete_last      (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DELETE_AT:        out_len = rule_op_mangle_delete_at        (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_EXTRACT:          out_len = rule_op_mangle_extract          (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_OMIT:             out_len = rule_op_mangle_omit             (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_INSERT:           out_len = rule_op_mangle_insert           (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_OVERSTRIKE:       out_len = rule_op_mangle_overstrike       (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_TRUNCATE_AT:      out_len = rule_op_mangle_truncate_at      (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_REPLACE:          out_len = rule_op_mangle_replace          (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_REPLACE_CLASS:    out_len = rule_op_mangle_replace_class    (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_PURGECHAR:        out_len = rule_op_mangle_purgechar        (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_PURGECHAR_CLASS:  out_len = rule_op_mangle_purgechar_class  (p0, p1, buf0, buf1, out_len); break;
    //case RULE_OP_MANGLE_TOGGLECASE_REC:   out_len = rule_op_mangle_togglecase_rec   (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_FIRST:   out_len = rule_op_mangle_dupechar_first   (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_LAST:    out_len = rule_op_mangle_dupechar_last    (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DUPECHAR_ALL:     out_len = rule_op_mangle_dupechar_all     (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_SWITCH_FIRST:     out_len = rule_op_mangle_switch_first     (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_SWITCH_LAST:      out_len = rule_op_mangle_switch_last      (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_SWITCH_AT:        out_len = rule_op_mangle_switch_at        (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_CHR_SHIFTL:       out_len = rule_op_mangle_chr_shiftl       (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_CHR_SHIFTR:       out_len = rule_op_mangle_chr_shiftr       (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_CHR_INCR:         out_len = rule_op_mangle_chr_incr         (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_CHR_DECR:         out_len = rule_op_mangle_chr_decr         (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_REPLACE_NP1:      out_len = rule_op_mangle_replace_np1      (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_REPLACE_NM1:      out_len = rule_op_mangle_replace_nm1      (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DUPEBLOCK_FIRST:  out_len = rule_op_mangle_dupeblock_first  (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_DUPEBLOCK_LAST:   out_len = rule_op_mangle_dupeblock_last   (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_TITLE_SEP:        out_len = rule_op_mangle_title_sep        (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_TITLE_SEP_CLASS:  out_len = rule_op_mangle_title_sep_class  (p0, p1, buf0, buf1, out_len); break;
    case RULE_OP_MANGLE_TITLE:            out_len = rule_op_mangle_title_sep        (' ', p1, buf0, buf1, out_len); break;
  }

  return out_len;
}

DECLSPEC u32 apply_rules_optimized (CONSTANT_AS const u32 *cmds, PRIVATE_AS u32 *buf0, PRIVATE_AS u32 *buf1, const u32 len)
{
  u32 out_len = len;

  for (u32 i = 0; cmds[i] != 0; i++)
  {
    const u32 cmd = cmds[i];

    const u32 name = (cmd >>  0) & 0xff;
    const u32 p0   = (cmd >>  8) & 0xff;
    const u32 p1   = (cmd >> 16) & 0xff;

    // we need to guarantee input length < 32 otherwise functions like rule_op_mangle_switch_last() and others will read out of boundary
    out_len = apply_rule_optimized (name, p0, p1, buf0, buf1, out_len);
  }

  return out_len;
}

DECLSPEC u32x apply_rules_vect_optimized (PRIVATE_AS const u32 *pw_buf0, PRIVATE_AS const u32 *pw_buf1, const u32 pw_len, CONSTANT_AS const kernel_rule_t *kernel_rules, const u32 il_pos, PRIVATE_AS u32x *buf0, PRIVATE_AS u32x *buf1)
{
  #if VECT_SIZE == 1

  buf0[0] = pw_buf0[0];
  buf0[1] = pw_buf0[1];
  buf0[2] = pw_buf0[2];
  buf0[3] = pw_buf0[3];
  buf1[0] = pw_buf1[0];
  buf1[1] = pw_buf1[1];
  buf1[2] = pw_buf1[2];
  buf1[3] = pw_buf1[3];

  return apply_rules_optimized (kernel_rules[il_pos].cmds, buf0, buf1, pw_len);

  #else

  u32x out_len = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 0; i < VECT_SIZE; i++)
  {
    u32 tmp0[4];
    u32 tmp1[4];

    tmp0[0] = pw_buf0[0];
    tmp0[1] = pw_buf0[1];
    tmp0[2] = pw_buf0[2];
    tmp0[3] = pw_buf0[3];
    tmp1[0] = pw_buf1[0];
    tmp1[1] = pw_buf1[1];
    tmp1[2] = pw_buf1[2];
    tmp1[3] = pw_buf1[3];

    const u32 tmp_len = apply_rules_optimized (kernel_rules[il_pos + i].cmds, tmp0, tmp1, pw_len);

    switch (i)
    {
      #if VECT_SIZE >= 2
      case 0:
        buf0[0].s0 = tmp0[0];
        buf0[1].s0 = tmp0[1];
        buf0[2].s0 = tmp0[2];
        buf0[3].s0 = tmp0[3];
        buf1[0].s0 = tmp1[0];
        buf1[1].s0 = tmp1[1];
        buf1[2].s0 = tmp1[2];
        buf1[3].s0 = tmp1[3];
        out_len.s0 = tmp_len;
        break;

      case 1:
        buf0[0].s1 = tmp0[0];
        buf0[1].s1 = tmp0[1];
        buf0[2].s1 = tmp0[2];
        buf0[3].s1 = tmp0[3];
        buf1[0].s1 = tmp1[0];
        buf1[1].s1 = tmp1[1];
        buf1[2].s1 = tmp1[2];
        buf1[3].s1 = tmp1[3];
        out_len.s1 = tmp_len;
        break;
      #endif

      #if VECT_SIZE >= 4
      case 2:
        buf0[0].s2 = tmp0[0];
        buf0[1].s2 = tmp0[1];
        buf0[2].s2 = tmp0[2];
        buf0[3].s2 = tmp0[3];
        buf1[0].s2 = tmp1[0];
        buf1[1].s2 = tmp1[1];
        buf1[2].s2 = tmp1[2];
        buf1[3].s2 = tmp1[3];
        out_len.s2 = tmp_len;
        break;

      case 3:
        buf0[0].s3 = tmp0[0];
        buf0[1].s3 = tmp0[1];
        buf0[2].s3 = tmp0[2];
        buf0[3].s3 = tmp0[3];
        buf1[0].s3 = tmp1[0];
        buf1[1].s3 = tmp1[1];
        buf1[2].s3 = tmp1[2];
        buf1[3].s3 = tmp1[3];
        out_len.s3 = tmp_len;
        break;
      #endif

      #if VECT_SIZE >= 8
      case 4:
        buf0[0].s4 = tmp0[0];
        buf0[1].s4 = tmp0[1];
        buf0[2].s4 = tmp0[2];
        buf0[3].s4 = tmp0[3];
        buf1[0].s4 = tmp1[0];
        buf1[1].s4 = tmp1[1];
        buf1[2].s4 = tmp1[2];
        buf1[3].s4 = tmp1[3];
        out_len.s4 = tmp_len;
        break;

      case 5:
        buf0[0].s5 = tmp0[0];
        buf0[1].s5 = tmp0[1];
        buf0[2].s5 = tmp0[2];
        buf0[3].s5 = tmp0[3];
        buf1[0].s5 = tmp1[0];
        buf1[1].s5 = tmp1[1];
        buf1[2].s5 = tmp1[2];
        buf1[3].s5 = tmp1[3];
        out_len.s5 = tmp_len;
        break;

      case 6:
        buf0[0].s6 = tmp0[0];
        buf0[1].s6 = tmp0[1];
        buf0[2].s6 = tmp0[2];
        buf0[3].s6 = tmp0[3];
        buf1[0].s6 = tmp1[0];
        buf1[1].s6 = tmp1[1];
        buf1[2].s6 = tmp1[2];
        buf1[3].s6 = tmp1[3];
        out_len.s6 = tmp_len;
        break;

      case 7:
        buf0[0].s7 = tmp0[0];
        buf0[1].s7 = tmp0[1];
        buf0[2].s7 = tmp0[2];
        buf0[3].s7 = tmp0[3];
        buf1[0].s7 = tmp1[0];
        buf1[1].s7 = tmp1[1];
        buf1[2].s7 = tmp1[2];
        buf1[3].s7 = tmp1[3];
        out_len.s7 = tmp_len;
        break;
      #endif

      #if VECT_SIZE >= 16
      case 8:
        buf0[0].s8 = tmp0[0];
        buf0[1].s8 = tmp0[1];
        buf0[2].s8 = tmp0[2];
        buf0[3].s8 = tmp0[3];
        buf1[0].s8 = tmp1[0];
        buf1[1].s8 = tmp1[1];
        buf1[2].s8 = tmp1[2];
        buf1[3].s8 = tmp1[3];
        out_len.s8 = tmp_len;
        break;

      case 9:
        buf0[0].s9 = tmp0[0];
        buf0[1].s9 = tmp0[1];
        buf0[2].s9 = tmp0[2];
        buf0[3].s9 = tmp0[3];
        buf1[0].s9 = tmp1[0];
        buf1[1].s9 = tmp1[1];
        buf1[2].s9 = tmp1[2];
        buf1[3].s9 = tmp1[3];
        out_len.s9 = tmp_len;
        break;

      case 10:
        buf0[0].sa = tmp0[0];
        buf0[1].sa = tmp0[1];
        buf0[2].sa = tmp0[2];
        buf0[3].sa = tmp0[3];
        buf1[0].sa = tmp1[0];
        buf1[1].sa = tmp1[1];
        buf1[2].sa = tmp1[2];
        buf1[3].sa = tmp1[3];
        out_len.sa = tmp_len;
        break;

      case 11:
        buf0[0].sb = tmp0[0];
        buf0[1].sb = tmp0[1];
        buf0[2].sb = tmp0[2];
        buf0[3].sb = tmp0[3];
        buf1[0].sb = tmp1[0];
        buf1[1].sb = tmp1[1];
        buf1[2].sb = tmp1[2];
        buf1[3].sb = tmp1[3];
        out_len.sb = tmp_len;
        break;

      case 12:
        buf0[0].sc = tmp0[0];
        buf0[1].sc = tmp0[1];
        buf0[2].sc = tmp0[2];
        buf0[3].sc = tmp0[3];
        buf1[0].sc = tmp1[0];
        buf1[1].sc = tmp1[1];
        buf1[2].sc = tmp1[2];
        buf1[3].sc = tmp1[3];
        out_len.sc = tmp_len;
        break;

      case 13:
        buf0[0].sd = tmp0[0];
        buf0[1].sd = tmp0[1];
        buf0[2].sd = tmp0[2];
        buf0[3].sd = tmp0[3];
        buf1[0].sd = tmp1[0];
        buf1[1].sd = tmp1[1];
        buf1[2].sd = tmp1[2];
        buf1[3].sd = tmp1[3];
        out_len.sd = tmp_len;
        break;

      case 14:
        buf0[0].se = tmp0[0];
        buf0[1].se = tmp0[1];
        buf0[2].se = tmp0[2];
        buf0[3].se = tmp0[3];
        buf1[0].se = tmp1[0];
        buf1[1].se = tmp1[1];
        buf1[2].se = tmp1[2];
        buf1[3].se = tmp1[3];
        out_len.se = tmp_len;
        break;

      case 15:
        buf0[0].sf = tmp0[0];
        buf0[1].sf = tmp0[1];
        buf0[2].sf = tmp0[2];
        buf0[3].sf = tmp0[3];
        buf1[0].sf = tmp1[0];
        buf1[1].sf = tmp1[1];
        buf1[2].sf = tmp1[2];
        buf1[3].sf = tmp1[3];
        out_len.sf = tmp_len;
        break;
      #endif
    }
  }

  return out_len;

  #endif
}
