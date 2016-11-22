/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

inline u32 generate_cmask (const u32 value)
{
  const u32 rmask =  ((value & 0x40404040u) >> 1u)
                  & ~((value & 0x80808080u) >> 2u);

  const u32 hmask = (value & 0x1f1f1f1fu) + 0x05050505u;
  const u32 lmask = (value & 0x1f1f1f1fu) + 0x1f1f1f1fu;

  return rmask & ~hmask & lmask;
}

inline void truncate_right (u32 buf0[4], u32 buf1[4], const u32 offset)
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

inline void truncate_left (u32 buf0[4], u32 buf1[4], const u32 offset)
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

inline void lshift_block (const u32 in0[4], const u32 in1[4], u32 out0[4], u32 out1[4])
{
  out0[0] = amd_bytealign_S (in0[1], in0[0], 1);
  out0[1] = amd_bytealign_S (in0[2], in0[1], 1);
  out0[2] = amd_bytealign_S (in0[3], in0[2], 1);
  out0[3] = amd_bytealign_S (in1[0], in0[3], 1);
  out1[0] = amd_bytealign_S (in1[1], in1[0], 1);
  out1[1] = amd_bytealign_S (in1[2], in1[1], 1);
  out1[2] = amd_bytealign_S (in1[3], in1[2], 1);
  out1[3] = amd_bytealign_S (     0, in1[3], 1);
}

inline void rshift_block (const u32 in0[4], const u32 in1[4], u32 out0[4], u32 out1[4])
{
  out1[3] = amd_bytealign_S (in1[3], in1[2], 3);
  out1[2] = amd_bytealign_S (in1[2], in1[1], 3);
  out1[1] = amd_bytealign_S (in1[1], in1[0], 3);
  out1[0] = amd_bytealign_S (in1[0], in0[3], 3);
  out0[3] = amd_bytealign_S (in0[3], in0[2], 3);
  out0[2] = amd_bytealign_S (in0[2], in0[1], 3);
  out0[1] = amd_bytealign_S (in0[1], in0[0], 3);
  out0[0] = amd_bytealign_S (in0[0],      0, 3);
}

inline void lshift_block_N (const u32 in0[4], const u32 in1[4], u32 out0[4], u32 out1[4], const u32 num)
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
    case  1:  out0[0] = amd_bytealign_S (in0[1], in0[0], 1);
              out0[1] = amd_bytealign_S (in0[2], in0[1], 1);
              out0[2] = amd_bytealign_S (in0[3], in0[2], 1);
              out0[3] = amd_bytealign_S (in1[0], in0[3], 1);
              out1[0] = amd_bytealign_S (in1[1], in1[0], 1);
              out1[1] = amd_bytealign_S (in1[2], in1[1], 1);
              out1[2] = amd_bytealign_S (in1[3], in1[2], 1);
              out1[3] = amd_bytealign_S (     0, in1[3], 1);
              break;
    case  2:  out0[0] = amd_bytealign_S (in0[1], in0[0], 2);
              out0[1] = amd_bytealign_S (in0[2], in0[1], 2);
              out0[2] = amd_bytealign_S (in0[3], in0[2], 2);
              out0[3] = amd_bytealign_S (in1[0], in0[3], 2);
              out1[0] = amd_bytealign_S (in1[1], in1[0], 2);
              out1[1] = amd_bytealign_S (in1[2], in1[1], 2);
              out1[2] = amd_bytealign_S (in1[3], in1[2], 2);
              out1[3] = amd_bytealign_S (     0, in1[3], 2);
              break;
    case  3:  out0[0] = amd_bytealign_S (in0[1], in0[0], 3);
              out0[1] = amd_bytealign_S (in0[2], in0[1], 3);
              out0[2] = amd_bytealign_S (in0[3], in0[2], 3);
              out0[3] = amd_bytealign_S (in1[0], in0[3], 3);
              out1[0] = amd_bytealign_S (in1[1], in1[0], 3);
              out1[1] = amd_bytealign_S (in1[2], in1[1], 3);
              out1[2] = amd_bytealign_S (in1[3], in1[2], 3);
              out1[3] = amd_bytealign_S (     0, in1[3], 3);
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
    case  5:  out0[0] = amd_bytealign_S (in0[2], in0[1], 1);
              out0[1] = amd_bytealign_S (in0[3], in0[2], 1);
              out0[2] = amd_bytealign_S (in1[0], in0[3], 1);
              out0[3] = amd_bytealign_S (in1[1], in1[0], 1);
              out1[0] = amd_bytealign_S (in1[2], in1[1], 1);
              out1[1] = amd_bytealign_S (in1[3], in1[2], 1);
              out1[2] = amd_bytealign_S (     0, in1[3], 1);
              out1[3] = 0;
              break;
    case  6:  out0[0] = amd_bytealign_S (in0[2], in0[1], 2);
              out0[1] = amd_bytealign_S (in0[3], in0[2], 2);
              out0[2] = amd_bytealign_S (in1[0], in0[3], 2);
              out0[3] = amd_bytealign_S (in1[1], in1[0], 2);
              out1[0] = amd_bytealign_S (in1[2], in1[1], 2);
              out1[1] = amd_bytealign_S (in1[3], in1[2], 2);
              out1[2] = amd_bytealign_S (     0, in1[3], 2);
              out1[3] = 0;
              break;
    case  7:  out0[0] = amd_bytealign_S (in0[2], in0[1], 3);
              out0[1] = amd_bytealign_S (in0[3], in0[2], 3);
              out0[2] = amd_bytealign_S (in1[0], in0[3], 3);
              out0[3] = amd_bytealign_S (in1[1], in1[0], 3);
              out1[0] = amd_bytealign_S (in1[2], in1[1], 3);
              out1[1] = amd_bytealign_S (in1[3], in1[2], 3);
              out1[2] = amd_bytealign_S (     0, in1[3], 3);
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
    case  9:  out0[0] = amd_bytealign_S (in0[3], in0[2], 1);
              out0[1] = amd_bytealign_S (in1[0], in0[3], 1);
              out0[2] = amd_bytealign_S (in1[1], in1[0], 1);
              out0[3] = amd_bytealign_S (in1[2], in1[1], 1);
              out1[0] = amd_bytealign_S (in1[3], in1[2], 1);
              out1[1] = amd_bytealign_S (     0, in1[3], 1);
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 10:  out0[0] = amd_bytealign_S (in0[3], in0[2], 2);
              out0[1] = amd_bytealign_S (in1[0], in0[3], 2);
              out0[2] = amd_bytealign_S (in1[1], in1[0], 2);
              out0[3] = amd_bytealign_S (in1[2], in1[1], 2);
              out1[0] = amd_bytealign_S (in1[3], in1[2], 2);
              out1[1] = amd_bytealign_S (     0, in1[3], 2);
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 11:  out0[0] = amd_bytealign_S (in0[3], in0[2], 3);
              out0[1] = amd_bytealign_S (in1[0], in0[3], 3);
              out0[2] = amd_bytealign_S (in1[1], in1[0], 3);
              out0[3] = amd_bytealign_S (in1[2], in1[1], 3);
              out1[0] = amd_bytealign_S (in1[3], in1[2], 3);
              out1[1] = amd_bytealign_S (     0, in1[3], 3);
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
    case 13:  out0[0] = amd_bytealign_S (in1[0], in0[3], 1);
              out0[1] = amd_bytealign_S (in1[1], in1[0], 1);
              out0[2] = amd_bytealign_S (in1[2], in1[1], 1);
              out0[3] = amd_bytealign_S (in1[3], in1[2], 1);
              out1[0] = amd_bytealign_S (     0, in1[3], 1);
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 14:  out0[0] = amd_bytealign_S (in1[0], in0[3], 2);
              out0[1] = amd_bytealign_S (in1[1], in1[0], 2);
              out0[2] = amd_bytealign_S (in1[2], in1[1], 2);
              out0[3] = amd_bytealign_S (in1[3], in1[2], 2);
              out1[0] = amd_bytealign_S (     0, in1[3], 2);
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 15:  out0[0] = amd_bytealign_S (in1[0], in0[3], 3);
              out0[1] = amd_bytealign_S (in1[1], in1[0], 3);
              out0[2] = amd_bytealign_S (in1[2], in1[1], 3);
              out0[3] = amd_bytealign_S (in1[3], in1[2], 3);
              out1[0] = amd_bytealign_S (     0, in1[3], 3);
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
    case 17:  out0[0] = amd_bytealign_S (in1[1], in1[0], 1);
              out0[1] = amd_bytealign_S (in1[2], in1[1], 1);
              out0[2] = amd_bytealign_S (in1[3], in1[2], 1);
              out0[3] = amd_bytealign_S (     0, in1[3], 1);
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 18:  out0[0] = amd_bytealign_S (in1[1], in1[0], 2);
              out0[1] = amd_bytealign_S (in1[2], in1[1], 2);
              out0[2] = amd_bytealign_S (in1[3], in1[2], 2);
              out0[3] = amd_bytealign_S (     0, in1[3], 2);
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 19:  out0[0] = amd_bytealign_S (in1[1], in1[0], 3);
              out0[1] = amd_bytealign_S (in1[2], in1[1], 3);
              out0[2] = amd_bytealign_S (in1[3], in1[2], 3);
              out0[3] = amd_bytealign_S (     0, in1[3], 3);
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
    case 21:  out0[0] = amd_bytealign_S (in1[2], in1[1], 1);
              out0[1] = amd_bytealign_S (in1[3], in1[2], 1);
              out0[2] = amd_bytealign_S (     0, in1[3], 1);
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 22:  out0[0] = amd_bytealign_S (in1[2], in1[1], 2);
              out0[1] = amd_bytealign_S (in1[3], in1[2], 2);
              out0[2] = amd_bytealign_S (     0, in1[3], 2);
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 23:  out0[0] = amd_bytealign_S (in1[2], in1[1], 3);
              out0[1] = amd_bytealign_S (in1[3], in1[2], 3);
              out0[2] = amd_bytealign_S (     0, in1[3], 3);
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
    case 25:  out0[0] = amd_bytealign_S (in1[3], in1[2], 1);
              out0[1] = amd_bytealign_S (     0, in1[3], 1);
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 26:  out0[0] = amd_bytealign_S (in1[3], in1[2], 2);
              out0[1] = amd_bytealign_S (     0, in1[3], 2);
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 27:  out0[0] = amd_bytealign_S (in1[3], in1[2], 3);
              out0[1] = amd_bytealign_S (     0, in1[3], 3);
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
    case 29:  out0[0] = amd_bytealign_S (     0, in1[3], 1);
              out0[1] = 0;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 30:  out0[0] = amd_bytealign_S (     0, in1[3], 2);
              out0[1] = 0;
              out0[2] = 0;
              out0[3] = 0;
              out1[0] = 0;
              out1[1] = 0;
              out1[2] = 0;
              out1[3] = 0;
              break;
    case 31:  out0[0] = amd_bytealign_S (     0, in1[3], 3);
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

inline void rshift_block_N (const u32 in0[4], const u32 in1[4], u32 out0[4], u32 out1[4], const u32 num)
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
    case  1:  out1[3] = amd_bytealign_S (in1[3], in1[2], 3);
              out1[2] = amd_bytealign_S (in1[2], in1[1], 3);
              out1[1] = amd_bytealign_S (in1[1], in1[0], 3);
              out1[0] = amd_bytealign_S (in1[0], in0[3], 3);
              out0[3] = amd_bytealign_S (in0[3], in0[2], 3);
              out0[2] = amd_bytealign_S (in0[2], in0[1], 3);
              out0[1] = amd_bytealign_S (in0[1], in0[0], 3);
              out0[0] = amd_bytealign_S (in0[0],      0, 3);
              break;
    case  2:  out1[3] = amd_bytealign_S (in1[3], in1[2], 2);
              out1[2] = amd_bytealign_S (in1[2], in1[1], 2);
              out1[1] = amd_bytealign_S (in1[1], in1[0], 2);
              out1[0] = amd_bytealign_S (in1[0], in0[3], 2);
              out0[3] = amd_bytealign_S (in0[3], in0[2], 2);
              out0[2] = amd_bytealign_S (in0[2], in0[1], 2);
              out0[1] = amd_bytealign_S (in0[1], in0[0], 2);
              out0[0] = amd_bytealign_S (in0[0],      0, 2);
              break;
    case  3:  out1[3] = amd_bytealign_S (in1[3], in1[2], 1);
              out1[2] = amd_bytealign_S (in1[2], in1[1], 1);
              out1[1] = amd_bytealign_S (in1[1], in1[0], 1);
              out1[0] = amd_bytealign_S (in1[0], in0[3], 1);
              out0[3] = amd_bytealign_S (in0[3], in0[2], 1);
              out0[2] = amd_bytealign_S (in0[2], in0[1], 1);
              out0[1] = amd_bytealign_S (in0[1], in0[0], 1);
              out0[0] = amd_bytealign_S (in0[0],      0, 1);
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
    case  5:  out1[3] = amd_bytealign_S (in1[2], in1[1], 3);
              out1[2] = amd_bytealign_S (in1[1], in1[0], 3);
              out1[1] = amd_bytealign_S (in1[0], in0[3], 3);
              out1[0] = amd_bytealign_S (in0[3], in0[2], 3);
              out0[3] = amd_bytealign_S (in0[2], in0[1], 3);
              out0[2] = amd_bytealign_S (in0[1], in0[0], 3);
              out0[1] = amd_bytealign_S (in0[0],      0, 3);
              out0[0] = 0;
              break;
    case  6:  out1[3] = amd_bytealign_S (in1[2], in1[1], 2);
              out1[2] = amd_bytealign_S (in1[1], in1[0], 2);
              out1[1] = amd_bytealign_S (in1[0], in0[3], 2);
              out1[0] = amd_bytealign_S (in0[3], in0[2], 2);
              out0[3] = amd_bytealign_S (in0[2], in0[1], 2);
              out0[2] = amd_bytealign_S (in0[1], in0[0], 2);
              out0[1] = amd_bytealign_S (in0[0],      0, 2);
              out0[0] = 0;
              break;
    case  7:  out1[3] = amd_bytealign_S (in1[2], in1[1], 1);
              out1[2] = amd_bytealign_S (in1[1], in1[0], 1);
              out1[1] = amd_bytealign_S (in1[0], in0[3], 1);
              out1[0] = amd_bytealign_S (in0[3], in0[2], 1);
              out0[3] = amd_bytealign_S (in0[2], in0[1], 1);
              out0[2] = amd_bytealign_S (in0[1], in0[0], 1);
              out0[1] = amd_bytealign_S (in0[0],      0, 1);
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
    case  9:  out1[3] = amd_bytealign_S (in1[1], in1[0], 3);
              out1[2] = amd_bytealign_S (in1[0], in0[3], 3);
              out1[1] = amd_bytealign_S (in0[3], in0[2], 3);
              out1[0] = amd_bytealign_S (in0[2], in0[1], 3);
              out0[3] = amd_bytealign_S (in0[1], in0[0], 3);
              out0[2] = amd_bytealign_S (in0[0],      0, 3);
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 10:  out1[3] = amd_bytealign_S (in1[1], in1[0], 2);
              out1[2] = amd_bytealign_S (in1[0], in0[3], 2);
              out1[1] = amd_bytealign_S (in0[3], in0[2], 2);
              out1[0] = amd_bytealign_S (in0[2], in0[1], 2);
              out0[3] = amd_bytealign_S (in0[1], in0[0], 2);
              out0[2] = amd_bytealign_S (in0[0],      0, 2);
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 11:  out1[3] = amd_bytealign_S (in1[1], in1[0], 1);
              out1[2] = amd_bytealign_S (in1[0], in0[3], 1);
              out1[1] = amd_bytealign_S (in0[3], in0[2], 1);
              out1[0] = amd_bytealign_S (in0[2], in0[1], 1);
              out0[3] = amd_bytealign_S (in0[1], in0[0], 1);
              out0[2] = amd_bytealign_S (in0[0],      0, 1);
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
    case 13:  out1[3] = amd_bytealign_S (in1[0], in0[3], 3);
              out1[2] = amd_bytealign_S (in0[3], in0[2], 3);
              out1[1] = amd_bytealign_S (in0[2], in0[1], 3);
              out1[0] = amd_bytealign_S (in0[1], in0[0], 3);
              out0[3] = amd_bytealign_S (in0[0],      0, 3);
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 14:  out1[3] = amd_bytealign_S (in1[0], in0[3], 2);
              out1[2] = amd_bytealign_S (in0[3], in0[2], 2);
              out1[1] = amd_bytealign_S (in0[2], in0[1], 2);
              out1[0] = amd_bytealign_S (in0[1], in0[0], 2);
              out0[3] = amd_bytealign_S (in0[0],      0, 2);
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 15:  out1[3] = amd_bytealign_S (in1[0], in0[3], 1);
              out1[2] = amd_bytealign_S (in0[3], in0[2], 1);
              out1[1] = amd_bytealign_S (in0[2], in0[1], 1);
              out1[0] = amd_bytealign_S (in0[1], in0[0], 1);
              out0[3] = amd_bytealign_S (in0[0],      0, 1);
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
    case 17:  out1[3] = amd_bytealign_S (in0[3], in0[2], 3);
              out1[2] = amd_bytealign_S (in0[2], in0[1], 3);
              out1[1] = amd_bytealign_S (in0[1], in0[0], 3);
              out1[0] = amd_bytealign_S (in0[0],      0, 3);
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 18:  out1[3] = amd_bytealign_S (in0[3], in0[2], 2);
              out1[2] = amd_bytealign_S (in0[2], in0[1], 2);
              out1[1] = amd_bytealign_S (in0[1], in0[0], 2);
              out1[0] = amd_bytealign_S (in0[0],      0, 2);
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 19:  out1[3] = amd_bytealign_S (in0[3], in0[2], 1);
              out1[2] = amd_bytealign_S (in0[2], in0[1], 1);
              out1[1] = amd_bytealign_S (in0[1], in0[0], 1);
              out1[0] = amd_bytealign_S (in0[0],      0, 1);
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
    case 21:  out1[3] = amd_bytealign_S (in0[2], in0[1], 3);
              out1[2] = amd_bytealign_S (in0[1], in0[0], 3);
              out1[1] = amd_bytealign_S (in0[0],      0, 3);
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 22:  out1[3] = amd_bytealign_S (in0[2], in0[1], 2);
              out1[2] = amd_bytealign_S (in0[1], in0[0], 2);
              out1[1] = amd_bytealign_S (in0[0],      0, 2);
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 23:  out1[3] = amd_bytealign_S (in0[2], in0[1], 1);
              out1[2] = amd_bytealign_S (in0[1], in0[0], 1);
              out1[1] = amd_bytealign_S (in0[0],      0, 1);
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
    case 25:  out1[3] = amd_bytealign_S (in0[1], in0[0], 3);
              out1[2] = amd_bytealign_S (in0[0],      0, 3);
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 26:  out1[3] = amd_bytealign_S (in0[1], in0[0], 2);
              out1[2] = amd_bytealign_S (in0[0],      0, 2);
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 27:  out1[3] = amd_bytealign_S (in0[1], in0[0], 1);
              out1[2] = amd_bytealign_S (in0[0],      0, 1);
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
    case 29:  out1[3] = amd_bytealign_S (in0[0],      0, 3);
              out1[2] = 0;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 30:  out1[3] = amd_bytealign_S (in0[0],      0, 2);
              out1[2] = 0;
              out1[1] = 0;
              out1[0] = 0;
              out0[3] = 0;
              out0[2] = 0;
              out0[1] = 0;
              out0[0] = 0;
              break;
    case 31:  out1[3] = amd_bytealign_S (in0[0],      0, 1);
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

inline void append_block1 (const u32 offset, u32 buf0[4], u32 buf1[4], const u32 src_r0)
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

inline void append_block8 (const u32 offset, u32 buf0[4], u32 buf1[4], const u32 src_l0[4], const u32 src_l1[4], const u32 src_r0[4], const u32 src_r1[4])
{
  #if defined IS_AMD || defined IS_GENERIC
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
      s8 = amd_bytealign_S (        0, src_r1[3], offset_minus_4);
      s7 = amd_bytealign_S (src_r1[3], src_r1[2], offset_minus_4);
      s6 = amd_bytealign_S (src_r1[2], src_r1[1], offset_minus_4);
      s5 = amd_bytealign_S (src_r1[1], src_r1[0], offset_minus_4);
      s4 = amd_bytealign_S (src_r1[0], src_r0[3], offset_minus_4);
      s3 = amd_bytealign_S (src_r0[3], src_r0[2], offset_minus_4);
      s2 = amd_bytealign_S (src_r0[2], src_r0[1], offset_minus_4);
      s1 = amd_bytealign_S (src_r0[1], src_r0[0], offset_minus_4);
      s0 = amd_bytealign_S (src_r0[0],         0, offset_minus_4);
      break;

    case 1:
      s8 = amd_bytealign_S (        0, src_r1[2], offset_minus_4);
      s7 = amd_bytealign_S (src_r1[2], src_r1[1], offset_minus_4);
      s6 = amd_bytealign_S (src_r1[1], src_r1[0], offset_minus_4);
      s5 = amd_bytealign_S (src_r1[0], src_r0[3], offset_minus_4);
      s4 = amd_bytealign_S (src_r0[3], src_r0[2], offset_minus_4);
      s3 = amd_bytealign_S (src_r0[2], src_r0[1], offset_minus_4);
      s2 = amd_bytealign_S (src_r0[1], src_r0[0], offset_minus_4);
      s1 = amd_bytealign_S (src_r0[0],         0, offset_minus_4);
      s0 = 0;
      break;

    case 2:
      s8 = amd_bytealign_S (        0, src_r1[1], offset_minus_4);
      s7 = amd_bytealign_S (src_r1[1], src_r1[0], offset_minus_4);
      s6 = amd_bytealign_S (src_r1[0], src_r0[3], offset_minus_4);
      s5 = amd_bytealign_S (src_r0[3], src_r0[2], offset_minus_4);
      s4 = amd_bytealign_S (src_r0[2], src_r0[1], offset_minus_4);
      s3 = amd_bytealign_S (src_r0[1], src_r0[0], offset_minus_4);
      s2 = amd_bytealign_S (src_r0[0],         0, offset_minus_4);
      s1 = 0;
      s0 = 0;
      break;

    case 3:
      s8 = amd_bytealign_S (        0, src_r1[0], offset_minus_4);
      s7 = amd_bytealign_S (src_r1[0], src_r0[3], offset_minus_4);
      s6 = amd_bytealign_S (src_r0[3], src_r0[2], offset_minus_4);
      s5 = amd_bytealign_S (src_r0[2], src_r0[1], offset_minus_4);
      s4 = amd_bytealign_S (src_r0[1], src_r0[0], offset_minus_4);
      s3 = amd_bytealign_S (src_r0[0],         0, offset_minus_4);
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 4:
      s8 = amd_bytealign_S (        0, src_r0[3], offset_minus_4);
      s7 = amd_bytealign_S (src_r0[3], src_r0[2], offset_minus_4);
      s6 = amd_bytealign_S (src_r0[2], src_r0[1], offset_minus_4);
      s5 = amd_bytealign_S (src_r0[1], src_r0[0], offset_minus_4);
      s4 = amd_bytealign_S (src_r0[0],         0, offset_minus_4);
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 5:
      s8 = amd_bytealign_S (        0, src_r0[2], offset_minus_4);
      s7 = amd_bytealign_S (src_r0[2], src_r0[1], offset_minus_4);
      s6 = amd_bytealign_S (src_r0[1], src_r0[0], offset_minus_4);
      s5 = amd_bytealign_S (src_r0[0],         0, offset_minus_4);
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 6:
      s8 = amd_bytealign_S (        0, src_r0[1], offset_minus_4);
      s7 = amd_bytealign_S (src_r0[1], src_r0[0], offset_minus_4);
      s6 = amd_bytealign_S (src_r0[0],         0, offset_minus_4);
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 7:
      s8 = amd_bytealign_S (        0, src_r0[0], offset_minus_4);
      s7 = amd_bytealign_S (src_r0[0],         0, offset_minus_4);
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
  #endif

  #ifdef IS_NV
  const int offset_minus_4 = 4 - (offset % 4);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  u32 s0 = 0;
  u32 s1 = 0;
  u32 s2 = 0;
  u32 s3 = 0;
  u32 s4 = 0;
  u32 s5 = 0;
  u32 s6 = 0;
  u32 s7 = 0;

  switch (offset / 4)
  {
    case 0:
      s7 = __byte_perm_S (src_r1[2], src_r1[3], selector);
      s6 = __byte_perm_S (src_r1[1], src_r1[2], selector);
      s5 = __byte_perm_S (src_r1[0], src_r1[1], selector);
      s4 = __byte_perm_S (src_r0[3], src_r1[0], selector);
      s3 = __byte_perm_S (src_r0[2], src_r0[3], selector);
      s2 = __byte_perm_S (src_r0[1], src_r0[2], selector);
      s1 = __byte_perm_S (src_r0[0], src_r0[1], selector);
      s0 = __byte_perm_S (        0, src_r0[0], selector);
      break;

    case 1:
      s7 = __byte_perm_S (src_r1[1], src_r1[2], selector);
      s6 = __byte_perm_S (src_r1[0], src_r1[1], selector);
      s5 = __byte_perm_S (src_r0[3], src_r1[0], selector);
      s4 = __byte_perm_S (src_r0[2], src_r0[3], selector);
      s3 = __byte_perm_S (src_r0[1], src_r0[2], selector);
      s2 = __byte_perm_S (src_r0[0], src_r0[1], selector);
      s1 = __byte_perm_S (        0, src_r0[0], selector);
      s0 = 0;
      break;

    case 2:
      s7 = __byte_perm_S (src_r1[0], src_r1[1], selector);
      s6 = __byte_perm_S (src_r0[3], src_r1[0], selector);
      s5 = __byte_perm_S (src_r0[2], src_r0[3], selector);
      s4 = __byte_perm_S (src_r0[1], src_r0[2], selector);
      s3 = __byte_perm_S (src_r0[0], src_r0[1], selector);
      s2 = __byte_perm_S (        0, src_r0[0], selector);
      s1 = 0;
      s0 = 0;
      break;

    case 3:
      s7 = __byte_perm_S (src_r0[3], src_r1[0], selector);
      s6 = __byte_perm_S (src_r0[2], src_r0[3], selector);
      s5 = __byte_perm_S (src_r0[1], src_r0[2], selector);
      s4 = __byte_perm_S (src_r0[0], src_r0[1], selector);
      s3 = __byte_perm_S (        0, src_r0[0], selector);
      s2 = 0;
      s1 = 0;
      s0 = 0;

      break;

    case 4:
      s7 = __byte_perm_S (src_r0[2], src_r0[3], selector);
      s6 = __byte_perm_S (src_r0[1], src_r0[2], selector);
      s5 = __byte_perm_S (src_r0[0], src_r0[1], selector);
      s4 = __byte_perm_S (        0, src_r0[0], selector);
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 5:
      s7 = __byte_perm_S (src_r0[1], src_r0[2], selector);
      s6 = __byte_perm_S (src_r0[0], src_r0[1], selector);
      s5 = __byte_perm_S (        0, src_r0[0], selector);
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 6:
      s7 = __byte_perm_S (src_r0[0], src_r0[1], selector);
      s6 = __byte_perm_S (        0, src_r0[0], selector);
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;

    case 7:
      s7 = __byte_perm_S (        0, src_r0[0], selector);
      s6 = 0;
      s5 = 0;
      s4 = 0;
      s3 = 0;
      s2 = 0;
      s1 = 0;
      s0 = 0;
      break;
  }

  buf0[0] = src_l0[0] | s0;
  buf0[1] = src_l0[1] | s1;
  buf0[2] = src_l0[2] | s2;
  buf0[3] = src_l0[3] | s3;
  buf1[0] = src_l1[0] | s4;
  buf1[1] = src_l1[1] | s5;
  buf1[2] = src_l1[2] | s6;
  buf1[3] = src_l1[3] | s7;

  #endif
}

inline void reverse_block (u32 in0[4], u32 in1[4], u32 out0[4], u32 out1[4], const u32 len)
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

inline u32 rule_op_mangle_lrest (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_urest (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_lrest_ufirst (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  rule_op_mangle_lrest (p0, p1, buf0, buf1, in_len);

  buf0[0] &= ~(0x00000020 & generate_cmask (buf0[0]));

  return in_len;
}

inline u32 rule_op_mangle_urest_lfirst (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  rule_op_mangle_urest (p0, p1, buf0, buf1, in_len);

  buf0[0] |= (0x00000020 & generate_cmask (buf0[0]));

  return in_len;
}

inline u32 rule_op_mangle_trest (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_toggle_at (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_reverse (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  reverse_block (buf0, buf1, buf0, buf1, in_len);

  return in_len;
}

inline u32 rule_op_mangle_dupeword (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if ((in_len + in_len) >= 32) return (in_len);

  u32 out_len = in_len;

  append_block8 (out_len, buf0, buf1, buf0, buf1, buf0, buf1);

  out_len += in_len;

  return out_len;
}

inline u32 rule_op_mangle_dupeword_times (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_reflect (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_append (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if ((in_len + 1) >= 32) return (in_len);

  u32 out_len = in_len;

  append_block1 (out_len, buf0, buf1, p0);

  out_len++;

  return out_len;
}

inline u32 rule_op_mangle_prepend (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if ((in_len + 1) >= 32) return (in_len);

  u32 out_len = in_len;

  rshift_block (buf0, buf1, buf0, buf1);

  buf0[0] = buf0[0] | p0;

  out_len++;

  return out_len;
}

inline u32 rule_op_mangle_rotate_left (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_rotate_right (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_delete_first (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if (in_len == 0) return (in_len);

  const u32 in_len1 = in_len - 1;

  lshift_block (buf0, buf1, buf0, buf1);

  return in_len1;
}

inline u32 rule_op_mangle_delete_last (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_delete_at (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  lshift_block (buf0, buf1, tib40, tib41);

  const u32 ml = (1 << ((p0 & 3) * 8)) - 1;
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

inline u32 rule_op_mangle_extract (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  if ((p0 + p1) > in_len) return (in_len);

  u32 out_len = p1;

  lshift_block_N (buf0, buf1, buf0, buf1, p0);

  truncate_right (buf0, buf1, out_len);

  return out_len;
}

inline u32 rule_op_mangle_omit (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

  const u32 ml = (1 << ((p0 & 3) * 8)) - 1;
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

inline u32 rule_op_mangle_insert (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if (p0 > in_len) return (in_len);

  if ((in_len + 1) >= 32) return (in_len);

  u32 out_len = in_len;

  u32 tib40[4];
  u32 tib41[4];

  rshift_block (buf0, buf1, tib40, tib41);

  const u32 p1n = p1 << ((p0 & 3) * 8);

  const u32 ml = (1 << ((p0 & 3) * 8)) - 1;

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

inline u32 rule_op_mangle_overstrike (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_truncate_at (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if (p0 >= in_len) return (in_len);

  truncate_right (buf0, buf1, p0);

  return p0;
}

inline u32 rule_op_mangle_replace (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  const uchar4 tmp0 = (uchar4) (p0);
  const uchar4 tmp1 = (uchar4) (p1);

  uchar4 tmp;

  tmp = as_uchar4 (buf0[0]); tmp = select (tmp, tmp1, tmp == tmp0); buf0[0] = as_uint (tmp);
  tmp = as_uchar4 (buf0[1]); tmp = select (tmp, tmp1, tmp == tmp0); buf0[1] = as_uint (tmp);
  tmp = as_uchar4 (buf0[2]); tmp = select (tmp, tmp1, tmp == tmp0); buf0[2] = as_uint (tmp);
  tmp = as_uchar4 (buf0[3]); tmp = select (tmp, tmp1, tmp == tmp0); buf0[3] = as_uint (tmp);
  tmp = as_uchar4 (buf1[0]); tmp = select (tmp, tmp1, tmp == tmp0); buf1[0] = as_uint (tmp);
  tmp = as_uchar4 (buf1[1]); tmp = select (tmp, tmp1, tmp == tmp0); buf1[1] = as_uint (tmp);
  tmp = as_uchar4 (buf1[2]); tmp = select (tmp, tmp1, tmp == tmp0); buf1[2] = as_uint (tmp);
  tmp = as_uchar4 (buf1[3]); tmp = select (tmp, tmp1, tmp == tmp0); buf1[3] = as_uint (tmp);

  return in_len;
}

inline u32 rule_op_mangle_purgechar (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_togglecase_rec (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  // TODO
  return in_len;
}

inline u32 rule_op_mangle_dupechar_first (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_dupechar_last (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_dupechar_all (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_switch_first (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  if (in_len < 2) return (in_len);

  buf0[0] = (buf0[0] & 0xFFFF0000) | ((buf0[0] << 8) & 0x0000FF00) | ((buf0[0] >> 8) & 0x000000FF);

  return in_len;
}

inline u32 rule_op_mangle_switch_last (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_switch_at (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_chr_shiftl (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_chr_shiftr (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_chr_incr (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_chr_decr (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_replace_np1 (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_replace_nm1 (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_dupeblock_first (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_dupeblock_last (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 rule_op_mangle_title (const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
{
  buf0[0] |= (generate_cmask (buf0[0]));
  buf0[1] |= (generate_cmask (buf0[1]));
  buf0[2] |= (generate_cmask (buf0[2]));
  buf0[3] |= (generate_cmask (buf0[3]));
  buf1[0] |= (generate_cmask (buf1[0]));
  buf1[1] |= (generate_cmask (buf1[1]));
  buf1[2] |= (generate_cmask (buf1[2]));
  buf1[3] |= (generate_cmask (buf1[3]));

  u32 tib40[4];
  u32 tib41[4];

  const uchar4 tmp0 = (uchar4) (' ');
  const uchar4 tmp1 = (uchar4) (0x00);
  const uchar4 tmp2 = (uchar4) (0xff);

  uchar4 tmp;

  tmp = as_uchar4 (buf0[0]); tmp = select (tmp1, tmp2, tmp == tmp0); tib40[0] = as_uint (tmp);
  tmp = as_uchar4 (buf0[1]); tmp = select (tmp1, tmp2, tmp == tmp0); tib40[1] = as_uint (tmp);
  tmp = as_uchar4 (buf0[2]); tmp = select (tmp1, tmp2, tmp == tmp0); tib40[2] = as_uint (tmp);
  tmp = as_uchar4 (buf0[3]); tmp = select (tmp1, tmp2, tmp == tmp0); tib40[3] = as_uint (tmp);
  tmp = as_uchar4 (buf1[0]); tmp = select (tmp1, tmp2, tmp == tmp0); tib41[0] = as_uint (tmp);
  tmp = as_uchar4 (buf1[1]); tmp = select (tmp1, tmp2, tmp == tmp0); tib41[1] = as_uint (tmp);
  tmp = as_uchar4 (buf1[2]); tmp = select (tmp1, tmp2, tmp == tmp0); tib41[2] = as_uint (tmp);
  tmp = as_uchar4 (buf1[3]); tmp = select (tmp1, tmp2, tmp == tmp0); tib41[3] = as_uint (tmp);

  rshift_block (tib40, tib41, tib40, tib41); tib40[0] |= 0xff;

  buf0[0] &= ~(generate_cmask (buf0[0]) & tib40[0]);
  buf0[1] &= ~(generate_cmask (buf0[1]) & tib40[1]);
  buf0[2] &= ~(generate_cmask (buf0[2]) & tib40[2]);
  buf0[3] &= ~(generate_cmask (buf0[3]) & tib40[3]);
  buf1[0] &= ~(generate_cmask (buf1[0]) & tib41[0]);
  buf1[1] &= ~(generate_cmask (buf1[1]) & tib41[1]);
  buf1[2] &= ~(generate_cmask (buf1[2]) & tib41[2]);
  buf1[3] &= ~(generate_cmask (buf1[3]) & tib41[3]);

  return in_len;
}

inline u32 apply_rule (const u32 name, const u32 p0, const u32 p1, u32 buf0[4], u32 buf1[4], const u32 in_len)
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

inline u32 apply_rules (__global const u32 *cmds, u32 buf0[4], u32 buf1[4], const u32 len)
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

inline u32x apply_rules_vect (const u32 pw_buf0[4], const u32 pw_buf1[4], const u32 pw_len, __global const kernel_rule_t *rules_buf, const u32 il_pos, u32x buf0[4], u32x buf1[4])
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

  return apply_rules (rules_buf[il_pos].cmds, buf0, buf1, pw_len);

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

    const u32 tmp_len = apply_rules (rules_buf[il_pos + i].cmds, tmp0, tmp1, pw_len);

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
