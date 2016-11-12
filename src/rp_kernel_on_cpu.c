/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "bitops.h"
#include "rp.h"
#include "rp_kernel_on_cpu.h"

static u32 amd_bytealign (const u32 a, const u32 b, const u32 c)
{
  const u64 tmp = ((((u64) (a)) << 32) | ((u64) (b))) >> ((c & 3) * 8);

  return (u32) tmp;
}

static u32 swap32_S (const u32 value)
{
  return byte_swap_32 (value);
}

static u32 generate_cmask (const u32 value)
{
  const u32 rmask =  ((value & 0x40404040u) >> 1u)
                  & ~((value & 0x80808080u) >> 2u);

  const u32 hmask = (value & 0x1f1f1f1fu) + 0x05050505u;
  const u32 lmask = (value & 0x1f1f1f1fu) + 0x1f1f1f1fu;

  return rmask & ~hmask & lmask;
}

static void truncate_right (u32 buf0[4], u32 buf1[4], const u32 offset)
{
  const u32 tmp = (1u << ((offset & 3u) * 8u)) - 1u;

  switch (offset / 4)
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

static void truncate_left (u32 buf0[4], u32 buf1[4], const u32 offset)
{
  const u32 tmp = ~((1u << ((offset & 3u) * 8u)) - 1u);

  switch (offset / 4)
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

static void lshift_block (const u32 in0[4], const u32 in1[4], u32 out0[4], u32 out1[4])
{
  out0[0] = in0[0] >>  8 | in0[1] << 24;
  out0[1] = in0[1] >>  8 | in0[2] << 24;
  out0[2] = in0[2] >>  8 | in0[3] << 24;
  out0[3] = in0[3] >>  8 | in1[0] << 24;
  out1[0] = in1[0] >>  8 | in1[1] << 24;
  out1[1] = in1[1] >>  8 | in1[2] << 24;
  out1[2] = in1[2] >>  8 | in1[3] << 24;
  out1[3] = in1[3] >>  8;
}

static void rshift_block (const u32 in0[4], const u32 in1[4], u32 out0[4], u32 out1[4])
{
  out1[3] = in1[3] <<  8 | in1[2] >> 24;
  out1[2] = in1[2] <<  8 | in1[1] >> 24;
  out1[1] = in1[1] <<  8 | in1[0] >> 24;
  out1[0] = in1[0] <<  8 | in0[3] >> 24;
  out0[3] = in0[3] <<  8 | in0[2] >> 24;
  out0[2] = in0[2] <<  8 | in0[1] >> 24;
  out0[1] = in0[1] <<  8 | in0[0] >> 24;
  out0[0] = in0[0] <<  8;
}

static void rshift_block_N (const u32 in0[4], const u32 in1[4], u32 out0[4], u32 out1[4], const u32 num)
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
    case  1:  out1[3] = in1[3] <<  8 | in1[2] >> 24;
              out1[2] = in1[2] <<  8 | in1[1] >> 24;
              out1[1] = in1[1] <<  8 | in1[0] >> 24;
              out1[0] = in1[0] <<  8 | in0[3] >> 24;
              out0[3] = in0[3] <<  8 | in0[2] >> 24;
              out0[2] = in0[2] <<  8 | in0[1] >> 24;
              out0[1] = in0[1] <<  8 | in0[0] >> 24;
              out0[0] = in0[0] <<  8;
              break;
    case  2:  out1[3] = in1[3] << 16 | in1[2] >> 16;
              out1[2] = in1[2] << 16 | in1[1] >> 16;
              out1[1] = in1[1] << 16 | in1[0] >> 16;
              out1[0] = in1[0] << 16 | in0[3] >> 16;
              out0[3] = in0[3] << 16 | in0[2] >> 16;
              out0[2] = in0[2] << 16 | in0[1] >> 16;
              out0[1] = in0[1] << 16 | in0[0] >> 16;
              out0[0] = in0[0] << 16;
              break;
    case  3:  out1[3] = in1[3] << 24 | in1[2] >>  8;
              out1[2] = in1[2] << 24 | in1[1] >>  8;
              out1[1] = in1[1] << 24 | in1[0] >>  8;
              out1[0] = in1[0] << 24 | in0[3] >>  8;
              out0[3] = in0[3] << 24 | in0[2] >>  8;
              out0[2] = in0[2] << 24 | in0[1] >>  8;
              out0[1] = in0[1] << 24 | in0[0] >>  8;
              out0[0] = in0[0] << 24;
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
    case  5:  out1[3] = in1[2] <<  8 | in1[1] >> 24;
              out1[2] = in1[1] <<  8 | in1[0] >> 24;
              out1[1] = in1[0] <<  8 | in0[3] >> 24;
              out1[0] = in0[3] <<  8 | in0[2] >> 24;
              out0[3] = in0[2] <<  8 | in0[1] >> 24;
              out0[2] = in0[1] <<  8 | in0[0] >> 24;
              out0[1] = in0[0] <<  8;
              out0[0] = 0;
              break;
    case  6:  out1[3] = in1[2] << 16 | in1[1] >> 16;
              out1[2] = in1[1] << 16 | in1[0] >> 16;
              out1[1] = in1[0] << 16 | in0[3] >> 16;
              out1[0] = in0[3] << 16 | in0[2] >> 16;
              out0[3] = in0[2] << 16 | in0[1] >> 16;
              out0[2] = in0[1] << 16 | in0[0] >> 16;
              out0[1] = in0[0] << 16;
              out0[0] = 0;
              break;
    case  7:  out1[3] = in1[2] << 24 | in1[1] >>  8;
              out1[2] = in1[1] << 24 | in1[0] >>  8;
              out1[1] = in1[0] << 24 | in0[3] >>  8;
              out1[0] = in0[3] << 24 | in0[2] >>  8;
              out0[3] = in0[2] << 24 | in0[1] >>  8;
              out0[2] = in0[1] << 24 | in0[0] >>  8;
              out0[1] = in0[0] << 24;
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
    case  9:  out1[3] = in1[1] <<  8 | in1[0] >> 24;
              out1[2] = in1[0] <<  8 | in0[3] >> 24;
              out1[1] = in0[3] <<  8 | in0[2] >> 24;
              out1[0] = in0[2] <<  8 | in0[1] >> 24;
              out0[3] = in0[1] <<  8 | in0[0] >> 24;
              out0[2] = in0[0] <<  8;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 10:  out1[3] = in1[1] << 16 | in1[0] >> 16;
              out1[2] = in1[0] << 16 | in0[3] >> 16;
              out1[1] = in0[3] << 16 | in0[2] >> 16;
              out1[0] = in0[2] << 16 | in0[1] >> 16;
              out0[3] = in0[1] << 16 | in0[0] >> 16;
              out0[2] = in0[0] << 16;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 11:  out1[3] = in1[1] << 24 | in1[0] >>  8;
              out1[2] = in1[0] << 24 | in0[3] >>  8;
              out1[1] = in0[3] << 24 | in0[2] >>  8;
              out1[0] = in0[2] << 24 | in0[1] >>  8;
              out0[3] = in0[1] << 24 | in0[0] >>  8;
              out0[2] = in0[0] << 24;
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
    case 13:  out1[3] = in1[0] <<  8 | in0[3] >> 24;
              out1[2] = in0[3] <<  8 | in0[2] >> 24;
              out1[1] = in0[2] <<  8 | in0[1] >> 24;
              out1[0] = in0[1] <<  8 | in0[0] >> 24;
              out0[3] = in0[0] <<  8;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 14:  out1[3] = in1[0] << 16 | in0[3] >> 16;
              out1[2] = in0[3] << 16 | in0[2] >> 16;
              out1[1] = in0[2] << 16 | in0[1] >> 16;
              out1[0] = in0[1] << 16 | in0[0] >> 16;
              out0[3] = in0[0] << 16;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 15:  out1[3] = in1[0] << 24 | in0[3] >>  8;
              out1[2] = in0[3] << 24 | in0[2] >>  8;
              out1[1] = in0[2] << 24 | in0[1] >>  8;
              out1[0] = in0[1] << 24 | in0[0] >>  8;
              out0[3] = in0[0] << 24;
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
    case 17:  out1[3] = in0[3] <<  8 | in0[2] >> 24;
              out1[2] = in0[2] <<  8 | in0[1] >> 24;
              out1[1] = in0[1] <<  8 | in0[0] >> 24;
              out1[0] = in0[0] <<  8;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 18:  out1[3] = in0[3] << 16 | in0[2] >> 16;
              out1[2] = in0[2] << 16 | in0[1] >> 16;
              out1[1] = in0[1] << 16 | in0[0] >> 16;
              out1[0] = in0[0] << 16;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 19:  out1[3] = in0[3] << 24 | in0[2] >>  8;
              out1[2] = in0[2] << 24 | in0[1] >>  8;
              out1[1] = in0[1] << 24 | in0[0] >>  8;
              out1[0] = in0[0] << 24;
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
    case 21:  out1[3] = in0[2] <<  8 | in0[1] >> 24;
              out1[2] = in0[1] <<  8 | in0[0] >> 24;
              out1[1] = in0[0] <<  8;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 22:  out1[3] = in0[2] << 16 | in0[1] >> 16;
              out1[2] = in0[1] << 16 | in0[0] >> 16;
              out1[1] = in0[0] << 16;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 23:  out1[3] = in0[2] << 24 | in0[1] >>  8;
              out1[2] = in0[1] << 24 | in0[0] >>  8;
              out1[1] = in0[0] << 24;
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
    case 25:  out1[3] = in0[1] <<  8 | in0[0] >> 24;
              out1[2] = in0[0] <<  8;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 26:  out1[3] = in0[1] << 16 | in0[0] >> 16;
              out1[2] = in0[0] << 16;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 27:  out1[3] = in0[1] << 24 | in0[0] >>  8;
              out1[2] = in0[0] << 24;
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
    case 29:  out1[3] = in0[0] <<  8;
              out1[2] = 0;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 30:  out1[3] = in0[0] << 16;
              out1[2] = 0;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 31:  out1[3] = in0[0] << 24;
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

static void lshift_block_N (const u32 in0[4], const u32 in1[4], u32 out0[4], u32 out1[4], const u32 num)
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
    case  1:  out0[0] = in0[0] >>  8 | in0[1] << 24;
              out0[1] = in0[1] >>  8 | in0[2] << 24;
              out0[2] = in0[2] >>  8 | in0[3] << 24;
              out0[3] = in0[3] >>  8 | in1[0] << 24;
              out1[0] = in1[0] >>  8 | in1[1] << 24;
              out1[1] = in1[1] >>  8 | in1[2] << 24;
              out1[2] = in1[2] >>  8 | in1[3] << 24;
              out1[3] = in1[3] >>  8;
              break;
    case  2:  out0[0] = in0[0] >> 16 | in0[1] << 16;
              out0[1] = in0[1] >> 16 | in0[2] << 16;
              out0[2] = in0[2] >> 16 | in0[3] << 16;
              out0[3] = in0[3] >> 16 | in1[0] << 16;
              out1[0] = in1[0] >> 16 | in1[1] << 16;
              out1[1] = in1[1] >> 16 | in1[2] << 16;
              out1[2] = in1[2] >> 16 | in1[3] << 16;
              out1[3] = in1[3] >> 16;
              break;
    case  3:  out0[0] = in0[0] >> 24 | in0[1] <<  8;
              out0[1] = in0[1] >> 24 | in0[2] <<  8;
              out0[2] = in0[2] >> 24 | in0[3] <<  8;
              out0[3] = in0[3] >> 24 | in1[0] <<  8;
              out1[0] = in1[0] >> 24 | in1[1] <<  8;
              out1[1] = in1[1] >> 24 | in1[2] <<  8;
              out1[2] = in1[2] >> 24 | in1[3] <<  8;
              out1[3] = in1[3] >> 24;
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
    case  5:  out0[0] = in0[1] >>  8 | in0[2] << 24;
              out0[1] = in0[2] >>  8 | in0[3] << 24;
              out0[2] = in0[3] >>  8 | in1[0] << 24;
              out0[3] = in1[0] >>  8 | in1[1] << 24;
              out1[0] = in1[1] >>  8 | in1[2] << 24;
              out1[1] = in1[2] >>  8 | in1[3] << 24;
              out1[2] = in1[3] >>  8;
              out1[3] = 0;
              break;
    case  6:  out0[0] = in0[1] >> 16 | in0[2] << 16;
              out0[1] = in0[2] >> 16 | in0[3] << 16;
              out0[2] = in0[3] >> 16 | in1[0] << 16;
              out0[3] = in1[0] >> 16 | in1[1] << 16;
              out1[0] = in1[1] >> 16 | in1[2] << 16;
              out1[1] = in1[2] >> 16 | in1[3] << 16;
              out1[2] = in1[3] >> 16;
              out1[3] = 0;
              break;
    case  7:  out0[0] = in0[1] >> 24 | in0[2] <<  8;
              out0[1] = in0[2] >> 24 | in0[3] <<  8;
              out0[2] = in0[3] >> 24 | in1[0] <<  8;
              out0[3] = in1[0] >> 24 | in1[1] <<  8;
              out1[0] = in1[1] >> 24 | in1[2] <<  8;
              out1[1] = in1[2] >> 24 | in1[3] <<  8;
              out1[2] = in1[3] >> 24;
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
    case  9:  out0[0] = in0[2] >>  8 | in0[3] << 24;
              out0[1] = in0[3] >>  8 | in1[0] << 24;
              out0[2] = in1[0] >>  8 | in1[1] << 24;
              out0[3] = in1[1] >>  8 | in1[2] << 24;
              out1[0] = in1[2] >>  8 | in1[3] << 24;
              out1[1] = in1[3] >>  8;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 10:  out0[0] = in0[2] >> 16 | in0[3] << 16;
              out0[1] = in0[3] >> 16 | in1[0] << 16;
              out0[2] = in1[0] >> 16 | in1[1] << 16;
              out0[3] = in1[1] >> 16 | in1[2] << 16;
              out1[0] = in1[2] >> 16 | in1[3] << 16;
              out1[1] = in1[3] >> 16;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 11:  out0[0] = in0[2] >> 24 | in0[3] <<  8;
              out0[1] = in0[3] >> 24 | in1[0] <<  8;
              out0[2] = in1[0] >> 24 | in1[1] <<  8;
              out0[3] = in1[1] >> 24 | in1[2] <<  8;
              out1[0] = in1[2] >> 24 | in1[3] <<  8;
              out1[1] = in1[3] >> 24;
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
    case 13:
              out0[0] = in0[3] >>  8 | in1[0] << 24;
              out0[1] = in1[0] >>  8 | in1[1] << 24;
              out0[2] = in1[1] >>  8 | in1[2] << 24;
              out0[3] = in1[2] >>  8 | in1[3] << 24;
              out1[0] = in1[3] >>  8;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 14:  out0[0] = in0[3] >> 16 | in1[0] << 16;
              out0[1] = in1[0] >> 16 | in1[1] << 16;
              out0[2] = in1[1] >> 16 | in1[2] << 16;
              out0[3] = in1[2] >> 16 | in1[3] << 16;
              out1[0] = in1[3] >> 16;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 15:  out0[0] = in0[3] >> 24 | in1[0] <<  8;
              out0[1] = in1[0] >> 24 | in1[1] <<  8;
              out0[2] = in1[1] >> 24 | in1[2] <<  8;
              out0[3] = in1[2] >> 24 | in1[3] <<  8;
              out1[0] = in1[3] >> 24;
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
    case 17:  out0[0] = in1[0] >>  8 | in1[1] << 24;
              out0[1] = in1[1] >>  8 | in1[2] << 24;
              out0[2] = in1[2] >>  8 | in1[3] << 24;
              out0[3] = in1[3] >>  8;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 18:  out0[0] = in1[0] >> 16 | in1[1] << 16;
              out0[1] = in1[1] >> 16 | in1[2] << 16;
              out0[2] = in1[2] >> 16 | in1[3] << 16;
              out0[3] = in1[3] >> 16;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 19:  out0[0] = in1[0] >> 24 | in1[1] <<  8;
              out0[1] = in1[1] >> 24 | in1[2] <<  8;
              out0[2] = in1[2] >> 24 | in1[3] <<  8;
              out0[3] = in1[3] >> 24;
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
    case 21:  out0[0] = in1[1] >>  8 | in1[2] << 24;
              out0[1] = in1[2] >>  8 | in1[3] << 24;
              out0[2] = in1[3] >>  8;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 22:  out0[0] = in1[1] >> 16 | in1[2] << 16;
              out0[1] = in1[2] >> 16 | in1[3] << 16;
              out0[2] = in1[3] >> 16;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 23:  out0[0] = in1[1] >> 24 | in1[2] <<  8;
              out0[1] = in1[2] >> 24 | in1[3] <<  8;
              out0[2] = in1[3] >> 24;
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
    case 25:  out0[0] = in1[2] >>  8 | in1[3] << 24;
              out0[1] = in1[3] >>  8;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 26:  out0[0] = in1[2] >> 16 | in1[3] << 16;
              out0[1] = in1[3] >> 16;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 27:  out0[0] = in1[2] >> 24 | in1[3] <<  8;
              out0[1] = in1[3] >> 24;
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
    case 29:  out0[0] = in1[3] >>  8;
              out0[1] = 0;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 30:  out0[0] = in1[3] >> 16;
              out0[1] = 0;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 31:  out0[0] = in1[3] >> 24;
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

static void append_block1 (const u32 offset, u32 buf0[4], u32 buf1[4], const u32 src_r0)
{
  // this version works with 1 byte append only

  const u32 value = src_r0 & 0xff;

  const u32 shift = (offset & 3) * 8;

  const u32 tmp = value << shift;

  buf0[0] |=                    (offset <  4)  ? tmp : 0;
  buf0[1] |= ((offset >=  4) && (offset <  8)) ? tmp : 0;
  buf0[2] |= ((offset >=  8) && (offset < 12)) ? tmp : 0;
  buf0[3] |= ((offset >= 12) && (offset < 16)) ? tmp : 0;
  buf1[0] |= ((offset >= 16) && (offset < 20)) ? tmp : 0;
  buf1[1] |= ((offset >= 20) && (offset < 24)) ? tmp : 0;
  buf1[2] |= ((offset >= 24) && (offset < 28)) ? tmp : 0;
  buf1[3] |=  (offset >= 28)                   ? tmp : 0;
}

static void append_block8 (const u32 offset, u32 buf0[4], u32 buf1[4], const u32 src_l0[4], const u32 src_l1[4], const u32 src_r0[4], const u32 src_r1[4])
{
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset;

  u32 s0 = 0;
  u32 s1 = 0;
  u32 s2 = 0;
  u32 s3 = 0;
  u32 s4 = 0;
  u32 s5 = 0;
  u32 s6 = 0;
  u32 s7 = 0;
  u32 s8 = 0;

  switch (offset / 4)
  {
    case 0:
      s8 = amd_bytealign (        0, src_r1[3], offset_minus_4);
      s7 = amd_bytealign (src_r1[3], src_r1[2], offset_minus_4);
      s6 = amd_bytealign (src_r1[2], src_r1[1], offset_minus_4);
      s5 = amd_bytealign (src_r1[1], src_r1[0], offset_minus_4);
      s4 = amd_bytealign (src_r1[0], src_r0[3], offset_minus_4);
      s3 = amd_bytealign (src_r0[3], src_r0[2], offset_minus_4);
      s2 = amd_bytealign (src_r0[2], src_r0[1], offset_minus_4);
      s1 = amd_bytealign (src_r0[1], src_r0[0], offset_minus_4);
      s0 = amd_bytealign (src_r0[0],         0, offset_minus_4);
      break;

    case 1:
      s8 = amd_bytealign (        0, src_r1[2], offset_minus_4);
      s7 = amd_bytealign (src_r1[2], src_r1[1], offset_minus_4);
      s6 = amd_bytealign (src_r1[1], src_r1[0], offset_minus_4);
      s5 = amd_bytealign (src_r1[0], src_r0[3], offset_minus_4);
      s4 = amd_bytealign (src_r0[3], src_r0[2], offset_minus_4);
      s3 = amd_bytealign (src_r0[2], src_r0[1], offset_minus_4);
      s2 = amd_bytealign (src_r0[1], src_r0[0], offset_minus_4);
      s1 = amd_bytealign (src_r0[0],         0, offset_minus_4);
      s0 = 0;
      break;

    case 2:
      s8 = amd_bytealign (        0, src_r1[1], offset_minus_4);
      s7 = amd_bytealign (src_r1[1], src_r1[0], offset_minus_4);
      s6 = amd_bytealign (src_r1[0], src_r0[3], offset_minus_4);
      s5 = amd_bytealign (src_r0[3], src_r0[2], offset_minus_4);
      s4 = amd_bytealign (src_r0[2], src_r0[1], offset_minus_4);
      s3 = amd_bytealign (src_r0[1], src_r0[0], offset_minus_4);
      s2 = amd_bytealign (src_r0[0],         0, offset_minus_4);
      s1 = 0;
      s0 = 0;
      break;

    case 3:
      s8 = amd_bytealign (        0, src_r1[0], offset_minus_4);
      s7 = amd_bytealign (src_r1[0], src_r0[3], offset_minus_4);
      s6 = amd_bytealign (src_r0[3], src_r0[2], offset_minus_4);
      s5 = amd_bytealign (src_r0[2], src_r0[1], offset_minus_4);
      s4 = amd_bytealign (src_r0[1], src_r0[0], offset_minus_4);
      s3 = amd_bytealign (src_r0[0],         0, offset_minus_4);
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 4:
      s8 = amd_bytealign (        0, src_r0[3], offset_minus_4);
      s7 = amd_bytealign (src_r0[3], src_r0[2], offset_minus_4);
      s6 = amd_bytealign (src_r0[2], src_r0[1], offset_minus_4);
      s5 = amd_bytealign (src_r0[1], src_r0[0], offset_minus_4);
      s4 = amd_bytealign (src_r0[0],         0, offset_minus_4);
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 5:
      s8 = amd_bytealign (        0, src_r0[2], offset_minus_4);
      s7 = amd_bytealign (src_r0[2], src_r0[1], offset_minus_4);
      s6 = amd_bytealign (src_r0[1], src_r0[0], offset_minus_4);
      s5 = amd_bytealign (src_r0[0],         0, offset_minus_4);
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 6:
      s8 = amd_bytealign (        0, src_r0[1], offset_minus_4);
      s7 = amd_bytealign (src_r0[1], src_r0[0], offset_minus_4);
      s6 = amd_bytealign (src_r0[0],         0, offset_minus_4);
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 7:
      s8 = amd_bytealign (        0, src_r0[0], offset_minus_4);
      s7 = amd_bytealign (src_r0[0],         0, offset_minus_4);
      s6 = 0;
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;
  }

  if (offset_mod_4 == 0)
  {
    buf0[0] = src_l0[0] | s1;
    buf0[1] = src_l0[1] | s2;
    buf0[2] = src_l0[2] | s3;
    buf0[3] = src_l0[3] | s4;
    buf1[0] = src_l1[0] | s5;
    buf1[1] = src_l1[1] | s6;
    buf1[2] = src_l1[2] | s7;
    buf1[3] = src_l1[3] | s8;
  }
  else
  {
    buf0[0] = src_l0[0] | s0;
    buf0[1] = src_l0[1] | s1;
    buf0[2] = src_l0[2] | s2;
    buf0[3] = src_l0[3] | s3;
    buf1[0] = src_l1[0] | s4;
    buf1[1] = src_l1[1] | s5;
    buf1[2] = src_l1[2] | s6;
    buf1[3] = src_l1[3] | s7;
  }
}

static void reverse_block (u32 in0[4], u32 in1[4], u32 out0[4], u32 out1[4], const u32 len)
{
  rshift_block_N (in0, in1, out0, out1, 32 - len);

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

  out0[0] = swap32_S (tib40[0]);
  out0[1] = swap32_S (tib40[1]);
  out0[2] = swap32_S (tib40[2]);
  out0[3] = swap32_S (tib40[3]);
  out1[0] = swap32_S (tib41[0]);
  out1[1] = swap32_S (tib41[1]);
  out1[2] = swap32_S (tib41[2]);
  out1[3] = swap32_S (tib41[3]);
}

static u32 rule_op_mangle_lrest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  buf0[0] |= (generate_cmask (buf0[0]));
  buf0[1] |= (generate_cmask (buf0[1]));
  buf0[2] |= (generate_cmask (buf0[2]));
  buf0[3] |= (generate_cmask (buf0[3]));
  buf1[0] |= (generate_cmask (buf1[0]));
  buf1[1] |= (generate_cmask (buf1[1]));
  buf1[2] |= (generate_cmask (buf1[2]));
  buf1[3] |= (generate_cmask (buf1[3]));

  return in_len;
}

static u32 rule_op_mangle_urest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  buf0[0] &= ~(generate_cmask (buf0[0]));
  buf0[1] &= ~(generate_cmask (buf0[1]));
  buf0[2] &= ~(generate_cmask (buf0[2]));
  buf0[3] &= ~(generate_cmask (buf0[3]));
  buf1[0] &= ~(generate_cmask (buf1[0]));
  buf1[1] &= ~(generate_cmask (buf1[1]));
  buf1[2] &= ~(generate_cmask (buf1[2]));
  buf1[3] &= ~(generate_cmask (buf1[3]));

  return in_len;
}

static u32 rule_op_mangle_lrest_ufirst (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  rule_op_mangle_lrest (p0, p1, buf0, buf1, in_len);

  buf0[0] &= ~(0x00000020 & generate_cmask (buf0[0]));

  return in_len;
}

static u32 rule_op_mangle_urest_lfirst (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  rule_op_mangle_urest (p0, p1, buf0, buf1, in_len);

  buf0[0] |= (0x00000020 & generate_cmask (buf0[0]));

  return in_len;
}

static u32 rule_op_mangle_trest (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  buf0[0] ^= (generate_cmask (buf0[0]));
  buf0[1] ^= (generate_cmask (buf0[1]));
  buf0[2] ^= (generate_cmask (buf0[2]));
  buf0[3] ^= (generate_cmask (buf0[3]));
  buf1[0] ^= (generate_cmask (buf1[0]));
  buf1[1] ^= (generate_cmask (buf1[1]));
  buf1[2] ^= (generate_cmask (buf1[2]));
  buf1[3] ^= (generate_cmask (buf1[3]));

  return in_len;
}

static u32 rule_op_mangle_toggle_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  const u32 tmp = 0x20u << ((p0 & 3) * 8);

  switch (p0 / 4)
  {
    case  0:  buf0[0] ^= (tmp & generate_cmask (buf0[0])); break;
    case  1:  buf0[1] ^= (tmp & generate_cmask (buf0[1])); break;
    case  2:  buf0[2] ^= (tmp & generate_cmask (buf0[2])); break;
    case  3:  buf0[3] ^= (tmp & generate_cmask (buf0[3])); break;
    case  4:  buf1[0] ^= (tmp & generate_cmask (buf1[0])); break;
    case  5:  buf1[1] ^= (tmp & generate_cmask (buf1[1])); break;
    case  6:  buf1[2] ^= (tmp & generate_cmask (buf1[2])); break;
    case  7:  buf1[3] ^= (tmp & generate_cmask (buf1[3])); break;
  }

  return in_len;
}

static u32 rule_op_mangle_reverse (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  reverse_block (buf0, buf1, buf0, buf1, in_len);

  return in_len;
}

static u32 rule_op_mangle_dupeword (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if ((in_len + in_len) >= 32) return (in_len);

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

  append_block8 (out_len, buf0, buf1, buf0, buf1, tib40, tib41);

  out_len += in_len;

  return out_len;
}

static u32 rule_op_mangle_dupeword_times (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (((in_len * p0) + in_len) >= 32) return (in_len);

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
    append_block8 (out_len, buf0, buf1, buf0, buf1, tib40, tib41);

    out_len += in_len;
  }

  return out_len;
}

static u32 rule_op_mangle_reflect (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if ((in_len + in_len) >= 32) return (in_len);

  u32 out_len = in_len;

  u32 tib40[4] = { 0 };
  u32 tib41[4] = { 0 };

  reverse_block (buf0, buf1, tib40, tib41, out_len);

  append_block8 (out_len, buf0, buf1, buf0, buf1, tib40, tib41);

  out_len += in_len;

  return out_len;
}

static u32 rule_op_mangle_append (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if ((in_len + 1) >= 32) return (in_len);

  u32 out_len = in_len;

  append_block1 (out_len, buf0, buf1, p0);

  out_len++;

  return out_len;
}

static u32 rule_op_mangle_prepend (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if ((in_len + 1) >= 32) return (in_len);

  u32 out_len = in_len;

  rshift_block (buf0, buf1, buf0, buf1);

  buf0[0] = buf0[0] | p0;

  out_len++;

  return out_len;
}

static u32 rule_op_mangle_rotate_left (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (in_len == 0) return (in_len);

  const u32 in_len1 = in_len - 1;

  const u32 sh = (in_len1 & 3) * 8;

  const u32 tmp = (buf0[0] & 0xff) << sh;

  lshift_block (buf0, buf1, buf0, buf1);

  buf0[0] |=                     (in_len1 <  4)  ? tmp : 0;
  buf0[1] |= ((in_len1 >=  4) && (in_len1 <  8)) ? tmp : 0;
  buf0[2] |= ((in_len1 >=  8) && (in_len1 < 12)) ? tmp : 0;
  buf0[3] |= ((in_len1 >= 12) && (in_len1 < 16)) ? tmp : 0;
  buf1[0] |= ((in_len1 >= 16) && (in_len1 < 20)) ? tmp : 0;
  buf1[1] |= ((in_len1 >= 20) && (in_len1 < 24)) ? tmp : 0;
  buf1[2] |= ((in_len1 >= 24) && (in_len1 < 28)) ? tmp : 0;
  buf1[3] |=  (in_len1 >= 28)                    ? tmp : 0;

  return in_len;
}

static u32 rule_op_mangle_rotate_right (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if (in_len == 0) return (in_len);

  const u32 in_len1 = in_len - 1;

  const u32 sh = (in_len1 & 3) * 8;

  u32 tmp = 0;

  tmp |=                     (in_len1 <  4)  ? buf0[0] : 0;
  tmp |= ((in_len1 >=  4) && (in_len1 <  8)) ? buf0[1] : 0;
  tmp |= ((in_len1 >=  8) && (in_len1 < 12)) ? buf0[2] : 0;
  tmp |= ((in_len1 >= 12) && (in_len1 < 16)) ? buf0[3] : 0;
  tmp |= ((in_len1 >= 16) && (in_len1 < 20)) ? buf1[0] : 0;
  tmp |= ((in_len1 >= 20) && (in_len1 < 24)) ? buf1[1] : 0;
  tmp |= ((in_len1 >= 24) && (in_len1 < 28)) ? buf1[2] : 0;
  tmp |=  (in_len1 >= 28)                    ? buf1[3] : 0;

  tmp = (tmp >> sh) & 0xff;

  rshift_block (buf0, buf1, buf0, buf1);

  buf0[0] |= tmp;

  truncate_right (buf0, buf1, in_len);

  return in_len;
}

static u32 rule_op_mangle_delete_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (in_len == 0) return (in_len);

  const u32 in_len1 = in_len - 1;

  lshift_block (buf0, buf1, buf0, buf1);

  return in_len1;
}

static u32 rule_op_mangle_delete_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (in_len == 0) return (in_len);

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

static u32 rule_op_mangle_delete_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  lshift_block (buf0, buf1, tib40, tib41);

  const u32 ml = (1u << ((p0 & 3) * 8)) - 1;
  const u32 mr = ~ml;

  switch (p0 / 4)
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

static u32 rule_op_mangle_extract (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  if ((p0 + p1) > in_len) return (in_len);

  u32 out_len = p1;

  lshift_block_N (buf0, buf1, buf0, buf1, p0);

  truncate_right (buf0, buf1, out_len);

  return out_len;
}

static u32 rule_op_mangle_omit (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  if ((p0 + p1) > in_len) return (in_len);

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

  lshift_block_N (buf0, buf1, tib40, tib41, p1);

  const u32 ml = (1u << ((p0 & 3) * 8)) - 1;
  const u32 mr = ~ml;

  switch (p0 / 4)
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

static u32 rule_op_mangle_insert (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 > in_len) return (in_len);

  if ((in_len + 1) >= 32) return (in_len);

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  rshift_block (buf0, buf1, tib40, tib41);

  const u32 p1n = p1 << ((p0 & 3) * 8);

  const u32 ml = (1u << ((p0 & 3) * 8)) - 1;

  const u32 mr = 0xffffff00 << ((p0 & 3) * 8);

  switch (p0 / 4)
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

static u32 rule_op_mangle_overstrike (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  const u32 p1n = p1 << ((p0 & 3) * 8);

  const u32 m = ~(0xffu << ((p0 & 3) * 8));

  switch (p0 / 4)
  {
    case  0: buf0[0] = (buf0[0] & m) | p1n; break;
    case  1: buf0[1] = (buf0[1] & m) | p1n; break;
    case  2: buf0[2] = (buf0[2] & m) | p1n; break;
    case  3: buf0[3] = (buf0[3] & m) | p1n; break;
    case  4: buf1[0] = (buf1[0] & m) | p1n; break;
    case  5: buf1[1] = (buf1[1] & m) | p1n; break;
    case  6: buf1[2] = (buf1[2] & m) | p1n; break;
    case  7: buf1[3] = (buf1[3] & m) | p1n; break;
  }

  return in_len;
}

static u32 rule_op_mangle_truncate_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  truncate_right (buf0, buf1, p0);

  return p0;
}

static u32 rule_op_mangle_replace (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  for (u32 i = 0; i < in_len; i++)
  {
    switch (i)
    {
      case  0: if (((buf0[0] >>  0) & 0xFF) == p0) buf0[0] = (buf0[0] & 0xFFFFFF00) | p1 <<  0; break;
      case  1: if (((buf0[0] >>  8) & 0xFF) == p0) buf0[0] = (buf0[0] & 0xFFFF00FF) | p1 <<  8; break;
      case  2: if (((buf0[0] >> 16) & 0xFF) == p0) buf0[0] = (buf0[0] & 0xFF00FFFF) | p1 << 16; break;
      case  3: if (((buf0[0] >> 24) & 0xFF) == p0) buf0[0] = (buf0[0] & 0x00FFFFFF) | p1 << 24; break;
      case  4: if (((buf0[1] >>  0) & 0xFF) == p0) buf0[1] = (buf0[1] & 0xFFFFFF00) | p1 <<  0; break;
      case  5: if (((buf0[1] >>  8) & 0xFF) == p0) buf0[1] = (buf0[1] & 0xFFFF00FF) | p1 <<  8; break;
      case  6: if (((buf0[1] >> 16) & 0xFF) == p0) buf0[1] = (buf0[1] & 0xFF00FFFF) | p1 << 16; break;
      case  7: if (((buf0[1] >> 24) & 0xFF) == p0) buf0[1] = (buf0[1] & 0x00FFFFFF) | p1 << 24; break;
      case  8: if (((buf0[2] >>  0) & 0xFF) == p0) buf0[2] = (buf0[2] & 0xFFFFFF00) | p1 <<  0; break;
      case  9: if (((buf0[2] >>  8) & 0xFF) == p0) buf0[2] = (buf0[2] & 0xFFFF00FF) | p1 <<  8; break;
      case 10: if (((buf0[2] >> 16) & 0xFF) == p0) buf0[2] = (buf0[2] & 0xFF00FFFF) | p1 << 16; break;
      case 11: if (((buf0[2] >> 24) & 0xFF) == p0) buf0[2] = (buf0[2] & 0x00FFFFFF) | p1 << 24; break;
      case 12: if (((buf0[3] >>  0) & 0xFF) == p0) buf0[3] = (buf0[3] & 0xFFFFFF00) | p1 <<  0; break;
      case 13: if (((buf0[3] >>  8) & 0xFF) == p0) buf0[3] = (buf0[3] & 0xFFFF00FF) | p1 <<  8; break;
      case 14: if (((buf0[3] >> 16) & 0xFF) == p0) buf0[3] = (buf0[3] & 0xFF00FFFF) | p1 << 16; break;
      case 15: if (((buf0[3] >> 24) & 0xFF) == p0) buf0[3] = (buf0[3] & 0x00FFFFFF) | p1 << 24; break;
      case 16: if (((buf1[0] >>  0) & 0xFF) == p0) buf1[0] = (buf1[0] & 0xFFFFFF00) | p1 <<  0; break;
      case 17: if (((buf1[0] >>  8) & 0xFF) == p0) buf1[0] = (buf1[0] & 0xFFFF00FF) | p1 <<  8; break;
      case 18: if (((buf1[0] >> 16) & 0xFF) == p0) buf1[0] = (buf1[0] & 0xFF00FFFF) | p1 << 16; break;
      case 19: if (((buf1[0] >> 24) & 0xFF) == p0) buf1[0] = (buf1[0] & 0x00FFFFFF) | p1 << 24; break;
      case 20: if (((buf1[1] >>  0) & 0xFF) == p0) buf1[1] = (buf1[1] & 0xFFFFFF00) | p1 <<  0; break;
      case 21: if (((buf1[1] >>  8) & 0xFF) == p0) buf1[1] = (buf1[1] & 0xFFFF00FF) | p1 <<  8; break;
      case 22: if (((buf1[1] >> 16) & 0xFF) == p0) buf1[1] = (buf1[1] & 0xFF00FFFF) | p1 << 16; break;
      case 23: if (((buf1[1] >> 24) & 0xFF) == p0) buf1[1] = (buf1[1] & 0x00FFFFFF) | p1 << 24; break;
      case 24: if (((buf1[2] >>  0) & 0xFF) == p0) buf1[2] = (buf1[2] & 0xFFFFFF00) | p1 <<  0; break;
      case 25: if (((buf1[2] >>  8) & 0xFF) == p0) buf1[2] = (buf1[2] & 0xFFFF00FF) | p1 <<  8; break;
      case 26: if (((buf1[2] >> 16) & 0xFF) == p0) buf1[2] = (buf1[2] & 0xFF00FFFF) | p1 << 16; break;
      case 27: if (((buf1[2] >> 24) & 0xFF) == p0) buf1[2] = (buf1[2] & 0x00FFFFFF) | p1 << 24; break;
      case 28: if (((buf1[3] >>  0) & 0xFF) == p0) buf1[3] = (buf1[3] & 0xFFFFFF00) | p1 <<  0; break;
      case 29: if (((buf1[3] >>  8) & 0xFF) == p0) buf1[3] = (buf1[3] & 0xFFFF00FF) | p1 <<  8; break;
      case 30: if (((buf1[3] >> 16) & 0xFF) == p0) buf1[3] = (buf1[3] & 0xFF00FFFF) | p1 << 16; break;
      case 31: if (((buf1[3] >> 24) & 0xFF) == p0) buf1[3] = (buf1[3] & 0x00FFFFFF) | p1 << 24; break;
    }
  }

  return in_len;
}

static u32 rule_op_mangle_purgechar (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  u32 out_len = 0;

  u32 buf_in[8] = { 0 };

  buf_in[0] = buf0[0];
  buf_in[1] = buf0[1];
  buf_in[2] = buf0[2];
  buf_in[3] = buf0[3];
  buf_in[4] = buf1[0];
  buf_in[5] = buf1[1];
  buf_in[6] = buf1[2];
  buf_in[7] = buf1[3];

  u32 buf_out[8] = { 0 };

  u8 *in  = (u8 *) buf_in;
  u8 *out = (u8 *) buf_out;

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

/*
static u32 rule_op_mangle_togglecase_rec (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  // TODO
  return in_len;
}
*/

static u32 rule_op_mangle_dupechar_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if ( in_len       ==  0) return (in_len);
  if ((in_len + p0) >= 32) return (in_len);

  u32 out_len = in_len;

  const u32 tmp = buf0[0] & 0xFF;

  rshift_block_N (buf0, buf1, buf0, buf1, p0);

  switch (p0)
  {
    case  1:  buf0[0] |= tmp <<  0;
              break;
    case  2:  buf0[0] |= tmp <<  0 | tmp << 8;
              break;
    case  3:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16;
              break;
    case  4:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              break;
    case  5:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0;
              break;
    case  6:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8;
              break;
    case  7:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16;
              break;
    case  8:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              break;
    case  9:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0;
              break;
    case 10:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8;
              break;
    case 11:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16;
              break;
    case 12:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              break;
    case 13:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0;
              break;
    case 14:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8;
              break;
    case 15:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16;
              break;
    case 16:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              break;
    case 17:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0;
              break;
    case 18:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8;
              break;
    case 19:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16;
              break;
    case 20:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              break;
    case 21:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0;
              break;
    case 22:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8;
              break;
    case 23:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16;
              break;
    case 24:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              break;
    case 25:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[2] |= tmp <<  0;
              break;
    case 26:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[2] |= tmp <<  0 | tmp << 8;
              break;
    case 27:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[2] |= tmp <<  0 | tmp << 8 | tmp << 16;
              break;
    case 28:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              break;
    case 29:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[3] |= tmp <<  0;
              break;
    case 30:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[3] |= tmp <<  0 | tmp << 8;
              break;
    case 31:  buf0[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf0[3] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[0] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[1] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[2] |= tmp <<  0 | tmp << 8 | tmp << 16 | tmp << 24;
              buf1[3] |= tmp <<  0 | tmp << 8 | tmp << 16;
              break;
  }

  out_len += p0;

  return out_len;
}

static u32 rule_op_mangle_dupechar_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if ( in_len       ==  0) return (in_len);
  if ((in_len + p0) >= 32) return (in_len);

  const u32 in_len1 = in_len - 1;

  const u32 sh = (in_len1 & 3) * 8;

  u32 tmp = 0;

  tmp |=                     (in_len1 <  4)  ? buf0[0] : 0;
  tmp |= ((in_len1 >=  4) && (in_len1 <  8)) ? buf0[1] : 0;
  tmp |= ((in_len1 >=  8) && (in_len1 < 12)) ? buf0[2] : 0;
  tmp |= ((in_len1 >= 12) && (in_len1 < 16)) ? buf0[3] : 0;
  tmp |= ((in_len1 >= 16) && (in_len1 < 20)) ? buf1[0] : 0;
  tmp |= ((in_len1 >= 20) && (in_len1 < 24)) ? buf1[1] : 0;
  tmp |= ((in_len1 >= 24) && (in_len1 < 28)) ? buf1[2] : 0;
  tmp |=  (in_len1 >= 28)                    ? buf1[3] : 0;

  tmp = (tmp >> sh) & 0xff;

  u32 out_len = in_len;

  for (u32 i = 0; i < p0; i++)
  {
    append_block1 (out_len, buf0, buf1, tmp);

    out_len++;
  }

  return out_len;
}

static u32 rule_op_mangle_dupechar_all (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if ( in_len           ==  0) return (in_len);
  if ((in_len + in_len) >= 32) return (in_len);

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

static u32 rule_op_mangle_switch_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (in_len < 2) return (in_len);

  buf0[0] = (buf0[0] & 0xFFFF0000) | ((buf0[0] << 8) & 0x0000FF00) | ((buf0[0] >> 8) & 0x000000FF);

  return in_len;
}

static u32 rule_op_mangle_switch_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (in_len < 2) return (in_len);

  switch (in_len)
  {
    case  2:  buf0[0] = ((buf0[0] << 8) & 0x0000FF00) | ((buf0[0] >> 8) & 0x000000FF);
              break;
    case  3:  buf0[0] =  (buf0[0] & 0x000000FF) | ((buf0[0] <<  8) & 0x00FF0000) | ((buf0[0] >>  8) & 0x0000FF00);
              break;
    case  4:  buf0[0] =  (buf0[0] & 0x0000FFFF) | ((buf0[0] <<  8) & 0xFF000000) | ((buf0[0] >>  8) & 0x00FF0000);
              break;
    case  5:  buf0[1] =  (buf0[0] & 0xFF000000) |   buf0[1];
              buf0[0] =  (buf0[0] & 0x00FFFFFF) |  (buf0[1] << 24);
              buf0[1] =  (buf0[1] >> 24);
              break;
    case  6:  buf0[1] = ((buf0[1] << 8) & 0x0000FF00) | ((buf0[1] >> 8) & 0x000000FF);
              break;
    case  7:  buf0[1] =  (buf0[1] & 0x000000FF) | ((buf0[1] <<  8) & 0x00FF0000) | ((buf0[1] >>  8) & 0x0000FF00);
              break;
    case  8:  buf0[1] =  (buf0[1] & 0x0000FFFF) | ((buf0[1] <<  8) & 0xFF000000) | ((buf0[1] >>  8) & 0x00FF0000);
              break;
    case  9:  buf0[2] =  (buf0[1] & 0xFF000000) |   buf0[2];
              buf0[1] =  (buf0[1] & 0x00FFFFFF) |  (buf0[2] << 24);
              buf0[2] =  (buf0[2] >> 24);
              break;
    case 10:  buf0[2] = ((buf0[2] << 8) & 0x0000FF00) | ((buf0[2] >> 8) & 0x000000FF);
              break;
    case 11:  buf0[2] =  (buf0[2] & 0x000000FF) | ((buf0[2] <<  8) & 0x00FF0000) | ((buf0[2] >>  8) & 0x0000FF00);
              break;
    case 12:  buf0[2] =  (buf0[2] & 0x0000FFFF) | ((buf0[2] <<  8) & 0xFF000000) | ((buf0[2] >>  8) & 0x00FF0000);
              break;
    case 13:  buf0[3] =  (buf0[2] & 0xFF000000) |   buf0[3];
              buf0[2] =  (buf0[2] & 0x00FFFFFF) |  (buf0[3] << 24);
              buf0[3] =  (buf0[3] >> 24);
              break;
    case 14:  buf0[3] = ((buf0[3] << 8) & 0x0000FF00) | ((buf0[3] >> 8) & 0x000000FF);
              break;
    case 15:  buf0[3] =  (buf0[3] & 0x000000FF) |  ((buf0[3] <<  8) & 0x00FF0000) | ((buf0[3] >>  8) & 0x0000FF00);
              break;
    case 16:  buf0[3] =  (buf0[3] & 0x0000FFFF) | ((buf0[3] <<  8) & 0xFF000000) | ((buf0[3] >>  8) & 0x00FF0000);
              break;
    case 17:  buf1[0] =  (buf0[3] & 0xFF000000) |   buf1[0];
              buf0[3] =  (buf0[3] & 0x00FFFFFF) |  (buf1[0] << 24);
              buf1[0] =  (buf1[0] >> 24);
              break;
    case 18:  buf1[0] = ((buf1[0] << 8) & 0x0000FF00) | ((buf1[0] >> 8) & 0x000000FF);
              break;
    case 19:  buf1[0] =  (buf1[0] & 0x000000FF) | ((buf1[0] <<  8) & 0x00FF0000) | ((buf1[0] >>  8) & 0x0000FF00);
              break;
    case 20:  buf1[0] =  (buf1[0] & 0x0000FFFF) | ((buf1[0] <<  8) & 0xFF000000) | ((buf1[0] >>  8) & 0x00FF0000);
              break;
    case 21:  buf1[1] =  (buf1[0] & 0xFF000000) |   buf1[1];
              buf1[0] =  (buf1[0] & 0x00FFFFFF) |  (buf1[1] << 24);
              buf1[1] =  (buf1[1] >> 24);
              break;
    case 22:  buf1[1] = ((buf1[1] << 8) & 0x0000FF00) | ((buf1[1] >> 8) & 0x000000FF);
              break;
    case 23:  buf1[1] =  (buf1[1] & 0x000000FF) | ((buf1[1] <<  8) & 0x00FF0000) | ((buf1[1] >>  8) & 0x0000FF00);
              break;
    case 24:  buf1[1] =  (buf1[1] & 0x0000FFFF) | ((buf1[1] <<  8) & 0xFF000000) | ((buf1[1] >>  8) & 0x00FF0000);
              break;
    case 25:  buf1[2] =  (buf1[1] & 0xFF000000) |   buf1[2];
              buf1[1] =  (buf1[1] & 0x00FFFFFF) |  (buf1[2] << 24);
              buf1[2] =  (buf1[2] >> 24);
              break;
    case 26:  buf1[2] = ((buf1[2] << 8) & 0x0000FF00) | ((buf1[2] >> 8) & 0x000000FF);
              break;
    case 27:  buf1[2] =  (buf1[2] & 0x000000FF) | ((buf1[2] <<  8) & 0x00FF0000) | ((buf1[2] >>  8) & 0x0000FF00);
              break;
    case 28:  buf1[2] =  (buf1[2] & 0x0000FFFF) | ((buf1[2] <<  8) & 0xFF000000) | ((buf1[2] >>  8) & 0x00FF0000);
              break;
    case 29:  buf1[3] =  (buf1[2] & 0xFF000000) |   buf1[3];
              buf1[2] =  (buf1[2] & 0x00FFFFFF) |  (buf1[3] << 24);
              buf1[3] =  (buf1[3] >> 24);
              break;
    case 30:  buf1[3] = ((buf1[3] << 8) & 0x0000FF00) | ((buf1[3] >> 8) & 0x000000FF);
              break;
    case 31:  buf1[3] =  (buf1[3] & 0x000000FF) |  ((buf1[3] <<  8) & 0x00FF0000) | ((buf1[3] >>  8) & 0x0000FF00);
              break;
  }

  return in_len;
}

static u32 rule_op_mangle_switch_at (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);
  if (p1 >= in_len) return (in_len);

  u32 tmp0 = 0;
  u32 tmp1 = 0;

  switch (p0)
  {
    case  0:  tmp0 = (buf0[0] >>  0) & 0xFF;
              break;
    case  1:  tmp0 = (buf0[0] >>  8) & 0xFF;
              break;
    case  2:  tmp0 = (buf0[0] >> 16) & 0xFF;
              break;
    case  3:  tmp0 = (buf0[0] >> 24) & 0xFF;
              break;
    case  4:  tmp0 = (buf0[1] >>  0) & 0xFF;
              break;
    case  5:  tmp0 = (buf0[1] >>  8) & 0xFF;
              break;
    case  6:  tmp0 = (buf0[1] >> 16) & 0xFF;
              break;
    case  7:  tmp0 = (buf0[1] >> 24) & 0xFF;
              break;
    case  8:  tmp0 = (buf0[2] >>  0) & 0xFF;
              break;
    case  9:  tmp0 = (buf0[2] >>  8) & 0xFF;
              break;
    case 10:  tmp0 = (buf0[2] >> 16) & 0xFF;
              break;
    case 11:  tmp0 = (buf0[2] >> 24) & 0xFF;
              break;
    case 12:  tmp0 = (buf0[3] >>  0) & 0xFF;
              break;
    case 13:  tmp0 = (buf0[3] >>  8) & 0xFF;
              break;
    case 14:  tmp0 = (buf0[3] >> 16) & 0xFF;
              break;
    case 15:  tmp0 = (buf0[3] >> 24) & 0xFF;
              break;
    case 16:  tmp0 = (buf1[0] >>  0) & 0xFF;
              break;
    case 17:  tmp0 = (buf1[0] >>  8) & 0xFF;
              break;
    case 18:  tmp0 = (buf1[0] >> 16) & 0xFF;
              break;
    case 19:  tmp0 = (buf1[0] >> 24) & 0xFF;
              break;
    case 20:  tmp0 = (buf1[1] >>  0) & 0xFF;
              break;
    case 21:  tmp0 = (buf1[1] >>  8) & 0xFF;
              break;
    case 22:  tmp0 = (buf1[1] >> 16) & 0xFF;
              break;
    case 23:  tmp0 = (buf1[1] >> 24) & 0xFF;
              break;
    case 24:  tmp0 = (buf1[2] >>  0) & 0xFF;
              break;
    case 25:  tmp0 = (buf1[2] >>  8) & 0xFF;
              break;
    case 26:  tmp0 = (buf1[2] >> 16) & 0xFF;
              break;
    case 27:  tmp0 = (buf1[2] >> 24) & 0xFF;
              break;
    case 28:  tmp0 = (buf1[3] >>  0) & 0xFF;
              break;
    case 29:  tmp0 = (buf1[3] >>  8) & 0xFF;
              break;
    case 30:  tmp0 = (buf1[3] >> 16) & 0xFF;
              break;
    case 31:  tmp0 = (buf1[3] >> 24) & 0xFF;
              break;
  }

  switch (p1)
  {
    case  0:  tmp1 = (buf0[0] >>  0) & 0xff;
              buf0[0]  = (buf0[0] & 0xffffff00) | tmp0 <<  0;
              break;
    case  1:  tmp1 = (buf0[0] >>  8) & 0xff;
              buf0[0]  = (buf0[0] & 0xffff00ff) | tmp0 <<  8;
              break;
    case  2:  tmp1 = (buf0[0] >> 16) & 0xff;
              buf0[0]  = (buf0[0] & 0xff00ffff) | tmp0 << 16;
              break;
    case  3:  tmp1 = (buf0[0] >> 24) & 0xff;
              buf0[0]  = (buf0[0] & 0x00ffffff) | tmp0 << 24;
              break;
    case  4:  tmp1 = (buf0[1] >>  0) & 0xff;
              buf0[1]  = (buf0[1] & 0xffffff00) | tmp0 <<  0;
              break;
    case  5:  tmp1 = (buf0[1] >>  8) & 0xff;
              buf0[1]  = (buf0[1] & 0xffff00ff) | tmp0 <<  8;
              break;
    case  6:  tmp1 = (buf0[1] >> 16) & 0xff;
              buf0[1]  = (buf0[1] & 0xff00ffff) | tmp0 << 16;
              break;
    case  7:  tmp1 = (buf0[1] >> 24) & 0xff;
              buf0[1]  = (buf0[1] & 0x00ffffff) | tmp0 << 24;
              break;
    case  8:  tmp1 = (buf0[2] >>  0) & 0xff;
              buf0[2]  = (buf0[2] & 0xffffff00) | tmp0 <<  0;
              break;
    case  9:  tmp1 = (buf0[2] >>  8) & 0xff;
              buf0[2]  = (buf0[2] & 0xffff00ff) | tmp0 <<  8;
              break;
    case 10:  tmp1 = (buf0[2] >> 16) & 0xff;
              buf0[2]  = (buf0[2] & 0xff00ffff) | tmp0 << 16;
              break;
    case 11:  tmp1 = (buf0[2] >> 24) & 0xff;
              buf0[2]  = (buf0[2] & 0x00ffffff) | tmp0 << 24;
              break;
    case 12:  tmp1 = (buf0[3] >>  0) & 0xff;
              buf0[3]  = (buf0[3] & 0xffffff00) | tmp0 <<  0;
              break;
    case 13:  tmp1 = (buf0[3] >>  8) & 0xff;
              buf0[3]  = (buf0[3] & 0xffff00ff) | tmp0 <<  8;
              break;
    case 14:  tmp1 = (buf0[3] >> 16) & 0xff;
              buf0[3]  = (buf0[3] & 0xff00ffff) | tmp0 << 16;
              break;
    case 15:  tmp1 = (buf0[3] >> 24) & 0xff;
              buf0[3]  = (buf0[3] & 0x00ffffff) | tmp0 << 24;
              break;
    case 16:  tmp1 = (buf1[0] >>  0) & 0xff;
              buf1[0]  = (buf1[0] & 0xffffff00) | tmp0 <<  0;
              break;
    case 17:  tmp1 = (buf1[0] >>  8) & 0xff;
              buf1[0]  = (buf1[0] & 0xffff00ff) | tmp0 <<  8;
              break;
    case 18:  tmp1 = (buf1[0] >> 16) & 0xff;
              buf1[0]  = (buf1[0] & 0xff00ffff) | tmp0 << 16;
              break;
    case 19:  tmp1 = (buf1[0] >> 24) & 0xff;
              buf1[0]  = (buf1[0] & 0x00ffffff) | tmp0 << 24;
              break;
    case 20:  tmp1 = (buf1[1] >>  0) & 0xff;
              buf1[1]  = (buf1[1] & 0xffffff00) | tmp0 <<  0;
              break;
    case 21:  tmp1 = (buf1[1] >>  8) & 0xff;
              buf1[1]  = (buf1[1] & 0xffff00ff) | tmp0 <<  8;
              break;
    case 22:  tmp1 = (buf1[1] >> 16) & 0xff;
              buf1[1]  = (buf1[1] & 0xff00ffff) | tmp0 << 16;
              break;
    case 23:  tmp1 = (buf1[1] >> 24) & 0xff;
              buf1[1]  = (buf1[1] & 0x00ffffff) | tmp0 << 24;
              break;
    case 24:  tmp1 = (buf1[2] >>  0) & 0xff;
              buf1[2]  = (buf1[2] & 0xffffff00) | tmp0 <<  0;
              break;
    case 25:  tmp1 = (buf1[2] >>  8) & 0xff;
              buf1[2]  = (buf1[2] & 0xffff00ff) | tmp0 <<  8;
              break;
    case 26:  tmp1 = (buf1[2] >> 16) & 0xff;
              buf1[2]  = (buf1[2] & 0xff00ffff) | tmp0 << 16;
              break;
    case 27:  tmp1 = (buf1[2] >> 24) & 0xff;
              buf1[2]  = (buf1[2] & 0x00ffffff) | tmp0 << 24;
              break;
    case 28:  tmp1 = (buf1[3] >>  0) & 0xff;
              buf1[3]  = (buf1[3] & 0xffffff00) | tmp0 <<  0;
              break;
    case 29:  tmp1 = (buf1[3] >>  8) & 0xff;
              buf1[3]  = (buf1[3] & 0xffff00ff) | tmp0 <<  8;
              break;
    case 30:  tmp1 = (buf1[3] >> 16) & 0xff;
              buf1[3]  = (buf1[3] & 0xff00ffff) | tmp0 << 16;
              break;
    case 31:  tmp1 = (buf1[3] >> 24) & 0xff;
              buf1[3]  = (buf1[3] & 0x00ffffff) | tmp0 << 24;
              break;
  }

  switch (p0)
  {
    case  0:  buf0[0]  = (buf0[0] & 0xffffff00) | tmp1 <<  0;
              break;
    case  1:  buf0[0]  = (buf0[0] & 0xffff00ff) | tmp1 <<  8;
              break;
    case  2:  buf0[0]  = (buf0[0] & 0xff00ffff) | tmp1 << 16;
              break;
    case  3:  buf0[0]  = (buf0[0] & 0x00ffffff) | tmp1 << 24;
              break;
    case  4:  buf0[1]  = (buf0[1] & 0xffffff00) | tmp1 <<  0;
              break;
    case  5:  buf0[1]  = (buf0[1] & 0xffff00ff) | tmp1 <<  8;
              break;
    case  6:  buf0[1]  = (buf0[1] & 0xff00ffff) | tmp1 << 16;
              break;
    case  7:  buf0[1]  = (buf0[1] & 0x00ffffff) | tmp1 << 24;
              break;
    case  8:  buf0[2]  = (buf0[2] & 0xffffff00) | tmp1 <<  0;
              break;
    case  9:  buf0[2]  = (buf0[2] & 0xffff00ff) | tmp1 <<  8;
              break;
    case 10:  buf0[2]  = (buf0[2] & 0xff00ffff) | tmp1 << 16;
              break;
    case 11:  buf0[2]  = (buf0[2] & 0x00ffffff) | tmp1 << 24;
              break;
    case 12:  buf0[3]  = (buf0[3] & 0xffffff00) | tmp1 <<  0;
              break;
    case 13:  buf0[3]  = (buf0[3] & 0xffff00ff) | tmp1 <<  8;
              break;
    case 14:  buf0[3]  = (buf0[3] & 0xff00ffff) | tmp1 << 16;
              break;
    case 15:  buf0[3]  = (buf0[3] & 0x00ffffff) | tmp1 << 24;
              break;
    case 16:  buf1[0]  = (buf1[0] & 0xffffff00) | tmp1 <<  0;
              break;
    case 17:  buf1[0]  = (buf1[0] & 0xffff00ff) | tmp1 <<  8;
              break;
    case 18:  buf1[0]  = (buf1[0] & 0xff00ffff) | tmp1 << 16;
              break;
    case 19:  buf1[0]  = (buf1[0] & 0x00ffffff) | tmp1 << 24;
              break;
    case 20:  buf1[1]  = (buf1[1] & 0xffffff00) | tmp1 <<  0;
              break;
    case 21:  buf1[1]  = (buf1[1] & 0xffff00ff) | tmp1 <<  8;
              break;
    case 22:  buf1[1]  = (buf1[1] & 0xff00ffff) | tmp1 << 16;
              break;
    case 23:  buf1[1]  = (buf1[1] & 0x00ffffff) | tmp1 << 24;
              break;
    case 24:  buf1[2]  = (buf1[2] & 0xffffff00) | tmp1 <<  0;
              break;
    case 25:  buf1[2]  = (buf1[2] & 0xffff00ff) | tmp1 <<  8;
              break;
    case 26:  buf1[2]  = (buf1[2] & 0xff00ffff) | tmp1 << 16;
              break;
    case 27:  buf1[2]  = (buf1[2] & 0x00ffffff) | tmp1 << 24;
              break;
    case 28:  buf1[3]  = (buf1[3] & 0xffffff00) | tmp1 <<  0;
              break;
    case 29:  buf1[3]  = (buf1[3] & 0xffff00ff) | tmp1 <<  8;
              break;
    case 30:  buf1[3]  = (buf1[3] & 0xff00ffff) | tmp1 << 16;
              break;
    case 31:  buf1[3]  = (buf1[3] & 0x00ffffff) | tmp1 << 24;
              break;
  }

  return in_len;
}

static u32 rule_op_mangle_chr_shiftl (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  switch (p0 / 4)
  {
    case  0:  buf0[0] = (buf0[0] & ml) | (((buf0[0] & mr) << 1) & mr); break;
    case  1:  buf0[1] = (buf0[1] & ml) | (((buf0[1] & mr) << 1) & mr); break;
    case  2:  buf0[2] = (buf0[2] & ml) | (((buf0[2] & mr) << 1) & mr); break;
    case  3:  buf0[3] = (buf0[3] & ml) | (((buf0[3] & mr) << 1) & mr); break;
    case  4:  buf1[0] = (buf1[0] & ml) | (((buf1[0] & mr) << 1) & mr); break;
    case  5:  buf1[1] = (buf1[1] & ml) | (((buf1[1] & mr) << 1) & mr); break;
    case  6:  buf1[2] = (buf1[2] & ml) | (((buf1[2] & mr) << 1) & mr); break;
    case  7:  buf1[3] = (buf1[3] & ml) | (((buf1[3] & mr) << 1) & mr); break;
  }

  return in_len;
}

static u32 rule_op_mangle_chr_shiftr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  switch (p0 / 4)
  {
    case  0:  buf0[0] = (buf0[0] & ml) | (((buf0[0] & mr) >> 1) & mr); break;
    case  1:  buf0[1] = (buf0[1] & ml) | (((buf0[1] & mr) >> 1) & mr); break;
    case  2:  buf0[2] = (buf0[2] & ml) | (((buf0[2] & mr) >> 1) & mr); break;
    case  3:  buf0[3] = (buf0[3] & ml) | (((buf0[3] & mr) >> 1) & mr); break;
    case  4:  buf1[0] = (buf1[0] & ml) | (((buf1[0] & mr) >> 1) & mr); break;
    case  5:  buf1[1] = (buf1[1] & ml) | (((buf1[1] & mr) >> 1) & mr); break;
    case  6:  buf1[2] = (buf1[2] & ml) | (((buf1[2] & mr) >> 1) & mr); break;
    case  7:  buf1[3] = (buf1[3] & ml) | (((buf1[3] & mr) >> 1) & mr); break;
  }

  return in_len;
}

static u32 rule_op_mangle_chr_incr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  const u32 n = 0x01010101 & mr;

  switch (p0 / 4)
  {
    case  0:  buf0[0] = (buf0[0] & ml) | (((buf0[0] & mr) + n) & mr); break;
    case  1:  buf0[1] = (buf0[1] & ml) | (((buf0[1] & mr) + n) & mr); break;
    case  2:  buf0[2] = (buf0[2] & ml) | (((buf0[2] & mr) + n) & mr); break;
    case  3:  buf0[3] = (buf0[3] & ml) | (((buf0[3] & mr) + n) & mr); break;
    case  4:  buf1[0] = (buf1[0] & ml) | (((buf1[0] & mr) + n) & mr); break;
    case  5:  buf1[1] = (buf1[1] & ml) | (((buf1[1] & mr) + n) & mr); break;
    case  6:  buf1[2] = (buf1[2] & ml) | (((buf1[2] & mr) + n) & mr); break;
    case  7:  buf1[3] = (buf1[3] & ml) | (((buf1[3] & mr) + n) & mr); break;
  }

  return in_len;
}

static u32 rule_op_mangle_chr_decr (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  const u32 n = 0x01010101 & mr;

  switch (p0 / 4)
  {
    case  0:  buf0[0] = (buf0[0] & ml) | (((buf0[0] & mr) - n) & mr); break;
    case  1:  buf0[1] = (buf0[1] & ml) | (((buf0[1] & mr) - n) & mr); break;
    case  2:  buf0[2] = (buf0[2] & ml) | (((buf0[2] & mr) - n) & mr); break;
    case  3:  buf0[3] = (buf0[3] & ml) | (((buf0[3] & mr) - n) & mr); break;
    case  4:  buf1[0] = (buf1[0] & ml) | (((buf1[0] & mr) - n) & mr); break;
    case  5:  buf1[1] = (buf1[1] & ml) | (((buf1[1] & mr) - n) & mr); break;
    case  6:  buf1[2] = (buf1[2] & ml) | (((buf1[2] & mr) - n) & mr); break;
    case  7:  buf1[3] = (buf1[3] & ml) | (((buf1[3] & mr) - n) & mr); break;
  }

  return in_len;
}

static u32 rule_op_mangle_replace_np1 (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if ((p0 + 1) >= in_len) return (in_len);

  u32 tib40[4];
  u32 tib41[4];

  lshift_block (buf0, buf1, tib40, tib41);

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  switch (p0 / 4)
  {
    case  0:  buf0[0] = (buf0[0] & ml) | (tib40[0] & mr); break;
    case  1:  buf0[1] = (buf0[1] & ml) | (tib40[1] & mr); break;
    case  2:  buf0[2] = (buf0[2] & ml) | (tib40[2] & mr); break;
    case  3:  buf0[3] = (buf0[3] & ml) | (tib40[3] & mr); break;
    case  4:  buf1[0] = (buf1[0] & ml) | (tib41[0] & mr); break;
    case  5:  buf1[1] = (buf1[1] & ml) | (tib41[1] & mr); break;
    case  6:  buf1[2] = (buf1[2] & ml) | (tib41[2] & mr); break;
    case  7:  buf1[3] = (buf1[3] & ml) | (tib41[3] & mr); break;
  }

  return in_len;
}

static u32 rule_op_mangle_replace_nm1 (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 == 0) return (in_len);

  if (p0 >= in_len) return (in_len);

  u32 tib40[4];
  u32 tib41[4];

  rshift_block (buf0, buf1, tib40, tib41);

  const u32 mr = 0xffu << ((p0 & 3) * 8);
  const u32 ml = ~mr;

  switch (p0 / 4)
  {
    case  0:  buf0[0] = (buf0[0] & ml) | (tib40[0] & mr); break;
    case  1:  buf0[1] = (buf0[1] & ml) | (tib40[1] & mr); break;
    case  2:  buf0[2] = (buf0[2] & ml) | (tib40[2] & mr); break;
    case  3:  buf0[3] = (buf0[3] & ml) | (tib40[3] & mr); break;
    case  4:  buf1[0] = (buf1[0] & ml) | (tib41[0] & mr); break;
    case  5:  buf1[1] = (buf1[1] & ml) | (tib41[1] & mr); break;
    case  6:  buf1[2] = (buf1[2] & ml) | (tib41[2] & mr); break;
    case  7:  buf1[3] = (buf1[3] & ml) | (tib41[3] & mr); break;
  }

  return in_len;
}

static u32 rule_op_mangle_dupeblock_first (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 > in_len) return (in_len);

  if ((in_len + p0) >= 32) return (in_len);

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

  truncate_right (tib40, tib41, p0);

  rshift_block_N (buf0, buf1, buf0, buf1, p0);

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

static u32 rule_op_mangle_dupeblock_last (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  if (p0 > in_len) return (in_len);

  if ((in_len + p0) >= 32) return (in_len);

  u32 out_len = in_len;

  u32 tib40[4] = { 0 };
  u32 tib41[4] = { 0 };

  rshift_block_N (buf0, buf1, tib40, tib41, p0);

  truncate_left (tib40, tib41, out_len);

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

static u32 rule_op_mangle_title (MAYBE_UNUSED const u32 p0, MAYBE_UNUSED const u32 p1, MAYBE_UNUSED u32 buf0[4], MAYBE_UNUSED u32 buf1[4], const u32 in_len)
{
  buf0[0] |= (generate_cmask (buf0[0]));
  buf0[1] |= (generate_cmask (buf0[1]));
  buf0[2] |= (generate_cmask (buf0[2]));
  buf0[3] |= (generate_cmask (buf0[3]));
  buf1[0] |= (generate_cmask (buf1[0]));
  buf1[1] |= (generate_cmask (buf1[1]));
  buf1[2] |= (generate_cmask (buf1[2]));
  buf1[3] |= (generate_cmask (buf1[3]));

  buf0[0] &= ~(0x00000020 & generate_cmask (buf0[0]));

  for (u32 i = 0; i < in_len; i++)
  {
    u32 tmp0 = 0;
    u32 tmp1 = 0;

    switch (i)
    {
      case  0:  tmp0 = (buf0[0] >>  0) & 0xFF;
                tmp1 = ~(0x00002000 & generate_cmask (buf0[0])); break;
      case  1:  tmp0 = (buf0[0] >>  8) & 0xFF;
                tmp1 = ~(0x00200000 & generate_cmask (buf0[0])); break;
      case  2:  tmp0 = (buf0[0] >> 16) & 0xFF;
                tmp1 = ~(0x20000000 & generate_cmask (buf0[0])); break;
      case  3:  tmp0 = (buf0[0] >> 24) & 0xFF;
                tmp1 = ~(0x00000020 & generate_cmask (buf0[1])); break;
      case  4:  tmp0 = (buf0[1] >>  0) & 0xFF;
                tmp1 = ~(0x00002000 & generate_cmask (buf0[1])); break;
      case  5:  tmp0 = (buf0[1] >>  8) & 0xFF;
                tmp1 = ~(0x00200000 & generate_cmask (buf0[1])); break;
      case  6:  tmp0 = (buf0[1] >> 16) & 0xFF;
                tmp1 = ~(0x20000000 & generate_cmask (buf0[1])); break;
      case  7:  tmp0 = (buf0[1] >> 24) & 0xFF;
                tmp1 = ~(0x00000020 & generate_cmask (buf0[2])); break;
      case  8:  tmp0 = (buf0[2] >>  0) & 0xFF;
                tmp1 = ~(0x00002000 & generate_cmask (buf0[2])); break;
      case  9:  tmp0 = (buf0[2] >>  8) & 0xFF;
                tmp1 = ~(0x00200000 & generate_cmask (buf0[2])); break;
      case 10:  tmp0 = (buf0[2] >> 16) & 0xFF;
                tmp1 = ~(0x20000000 & generate_cmask (buf0[2])); break;
      case 11:  tmp0 = (buf0[2] >> 24) & 0xFF;
                tmp1 = ~(0x00000020 & generate_cmask (buf0[3])); break;
      case 12:  tmp0 = (buf0[3] >>  0) & 0xFF;
                tmp1 = ~(0x00002000 & generate_cmask (buf0[3])); break;
      case 13:  tmp0 = (buf0[3] >>  8) & 0xFF;
                tmp1 = ~(0x00200000 & generate_cmask (buf0[3])); break;
      case 14:  tmp0 = (buf0[3] >> 16) & 0xFF;
                tmp1 = ~(0x20000000 & generate_cmask (buf0[3])); break;
      case 15:  tmp0 = (buf0[3] >> 24) & 0xFF;
                tmp1 = ~(0x00000020 & generate_cmask (buf1[0])); break;
      case 16:  tmp0 = (buf1[0] >>  0) & 0xFF;
                tmp1 = ~(0x00002000 & generate_cmask (buf1[0])); break;
      case 17:  tmp0 = (buf1[0] >>  8) & 0xFF;
                tmp1 = ~(0x00200000 & generate_cmask (buf1[0])); break;
      case 18:  tmp0 = (buf1[0] >> 16) & 0xFF;
                tmp1 = ~(0x20000000 & generate_cmask (buf1[0])); break;
      case 19:  tmp0 = (buf1[0] >> 24) & 0xFF;
                tmp1 = ~(0x00000020 & generate_cmask (buf1[1])); break;
      case 20:  tmp0 = (buf1[1] >>  0) & 0xFF;
                tmp1 = ~(0x00002000 & generate_cmask (buf1[1])); break;
      case 21:  tmp0 = (buf1[1] >>  8) & 0xFF;
                tmp1 = ~(0x00200000 & generate_cmask (buf1[1])); break;
      case 22:  tmp0 = (buf1[1] >> 16) & 0xFF;
                tmp1 = ~(0x20000000 & generate_cmask (buf1[1])); break;
      case 23:  tmp0 = (buf1[1] >> 24) & 0xFF;
                tmp1 = ~(0x00000020 & generate_cmask (buf1[2])); break;
      case 24:  tmp0 = (buf1[2] >>  0) & 0xFF;
                tmp1 = ~(0x00002000 & generate_cmask (buf1[2])); break;
      case 25:  tmp0 = (buf1[2] >>  8) & 0xFF;
                tmp1 = ~(0x00200000 & generate_cmask (buf1[2])); break;
      case 26:  tmp0 = (buf1[2] >> 16) & 0xFF;
                tmp1 = ~(0x20000000 & generate_cmask (buf1[2])); break;
      case 27:  tmp0 = (buf1[2] >> 24) & 0xFF;
                tmp1 = ~(0x00000020 & generate_cmask (buf1[3])); break;
      case 28:  tmp0 = (buf1[3] >>  0) & 0xFF;
                tmp1 = ~(0x00002000 & generate_cmask (buf1[3])); break;
      case 29:  tmp0 = (buf1[3] >>  8) & 0xFF;
                tmp1 = ~(0x00200000 & generate_cmask (buf1[3])); break;
      case 30:  tmp0 = (buf1[3] >> 16) & 0xFF;
                tmp1 = ~(0x20000000 & generate_cmask (buf1[3])); break;
    }

    if (i < 3)
    {
      if (tmp0   == ' ') buf0[0]   &= tmp1  ;
    }
    else if (i < 7)
    {
      if (tmp0   == ' ') buf0[1]   &= tmp1  ;
    }
    else if (i < 11)
    {
      if (tmp0   == ' ') buf0[2]   &= tmp1  ;
    }
    else if (i < 15)
    {
      if (tmp0   == ' ') buf0[3]   &= tmp1  ;
    }
    else if (i < 19)
    {
      if (tmp0   == ' ') buf1[0]   &= tmp1  ;
    }
    else if (i < 23)
    {
      if (tmp0   == ' ') buf1[1]   &= tmp1  ;
    }
    else if (i < 27)
    {
      if (tmp0   == ' ') buf1[2]   &= tmp1  ;
    }
    else if (i < 31)
    {
      if (tmp0   == ' ') buf1[3]   &= tmp1  ;
    }
  }

  return in_len;
}

u32 apply_rule (const u32 name, const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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
    case RULE_OP_MANGLE_PURGECHAR:        out_len = rule_op_mangle_purgechar        (p0, p1, buf0, buf1, out_len); break;
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
    case RULE_OP_MANGLE_TITLE:            out_len = rule_op_mangle_title            (p0, p1, buf0, buf1, out_len); break;
  }

  return out_len;
}

u32 apply_rules (u32 *cmds, u32 buf0[4], u32 buf1[4], const u32 len)
{
  u32 out_len = len;

  for (u32 i = 0; cmds[i] != 0; i++)
  {
    const u32 cmd = cmds[i];

    const u32 name = (cmd >>  0) & 0xff;
    const u32 p0   = (cmd >>  8) & 0xff;
    const u32 p1   = (cmd >> 16) & 0xff;

    out_len = apply_rule (name, p0, p1, buf0, buf1, out_len);
  }

  return out_len;
}
