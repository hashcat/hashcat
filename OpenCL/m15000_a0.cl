/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define _SHA512_

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_simd.cl"

inline void switch_buffer_by_offset_8x4_le_S (u32 w0[4], u32 w1[4], u32 w2[4], u32 w3[4], u32 w4[4], u32 w5[4], u32 w6[4], u32 w7[4], const u32 offset)
{
  #if defined IS_AMD || defined IS_GENERIC
  const int offset_mod_4 = offset & 3;

  const int offset_minus_4 = 4 - offset;

  switch (offset / 4)
  {
    case 0:
      w7[3] = amd_bytealign_S (w7[3], w7[2], offset_minus_4);
      w7[2] = amd_bytealign_S (w7[2], w7[1], offset_minus_4);
      w7[1] = amd_bytealign_S (w7[1], w7[0], offset_minus_4);
      w7[0] = amd_bytealign_S (w7[0], w6[3], offset_minus_4);
      w6[3] = amd_bytealign_S (w6[3], w6[2], offset_minus_4);
      w6[2] = amd_bytealign_S (w6[2], w6[1], offset_minus_4);
      w6[1] = amd_bytealign_S (w6[1], w6[0], offset_minus_4);
      w6[0] = amd_bytealign_S (w6[0], w5[3], offset_minus_4);
      w5[3] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w5[2] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w5[1] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w5[0] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w4[3] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w4[2] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w4[1] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w4[0] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w3[3] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w3[2] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w3[1] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w3[0] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w2[3] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w2[2] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w2[1] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w2[0] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w1[3] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w1[2] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w1[1] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w1[0] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w0[3] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w0[2] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w0[1] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w0[0] = amd_bytealign_S (w0[0],     0, offset_minus_4);

      if (offset_mod_4 == 0)
      {
        w0[0] = w0[1];
        w0[1] = w0[2];
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 1:
      w7[3] = amd_bytealign_S (w7[2], w7[1], offset_minus_4);
      w7[2] = amd_bytealign_S (w7[1], w7[0], offset_minus_4);
      w7[1] = amd_bytealign_S (w7[0], w6[3], offset_minus_4);
      w7[0] = amd_bytealign_S (w6[3], w6[2], offset_minus_4);
      w6[3] = amd_bytealign_S (w6[2], w6[1], offset_minus_4);
      w6[2] = amd_bytealign_S (w6[1], w6[0], offset_minus_4);
      w6[1] = amd_bytealign_S (w6[0], w5[3], offset_minus_4);
      w6[0] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w5[3] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w5[2] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w5[1] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w5[0] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w4[3] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w4[2] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w4[1] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w4[0] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w3[3] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w3[2] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w3[1] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w3[0] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w2[3] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w2[2] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w2[1] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w2[0] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w1[3] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w1[2] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w1[1] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w1[0] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w0[3] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w0[2] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w0[1] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[1] = w0[2];
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 2:
      w7[3] = amd_bytealign_S (w7[1], w7[0], offset_minus_4);
      w7[2] = amd_bytealign_S (w7[0], w6[3], offset_minus_4);
      w7[1] = amd_bytealign_S (w6[3], w6[2], offset_minus_4);
      w7[0] = amd_bytealign_S (w6[2], w6[1], offset_minus_4);
      w6[3] = amd_bytealign_S (w6[1], w6[0], offset_minus_4);
      w6[2] = amd_bytealign_S (w6[0], w5[3], offset_minus_4);
      w6[1] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w6[0] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w5[3] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w5[2] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w5[1] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w5[0] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w4[3] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w4[2] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w4[1] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w4[0] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w3[3] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w3[2] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w3[1] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w3[0] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w2[3] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w2[2] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w2[1] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w2[0] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w1[3] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w1[2] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w1[1] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w1[0] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w0[3] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w0[2] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[2] = w0[3];
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 3:
      w7[3] = amd_bytealign_S (w7[0], w6[3], offset_minus_4);
      w7[2] = amd_bytealign_S (w6[3], w6[2], offset_minus_4);
      w7[1] = amd_bytealign_S (w6[2], w6[1], offset_minus_4);
      w7[0] = amd_bytealign_S (w6[1], w6[0], offset_minus_4);
      w6[3] = amd_bytealign_S (w6[0], w5[3], offset_minus_4);
      w6[2] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w6[1] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w6[0] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w5[3] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w5[2] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w5[1] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w5[0] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w4[3] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w4[2] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w4[1] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w4[0] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w3[3] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w3[2] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w3[1] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w3[0] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w2[3] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w2[2] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w2[1] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w2[0] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w1[3] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w1[2] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w1[1] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w1[0] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w0[3] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w0[3] = w1[0];
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 4:
      w7[3] = amd_bytealign_S (w6[3], w6[2], offset_minus_4);
      w7[2] = amd_bytealign_S (w6[2], w6[1], offset_minus_4);
      w7[1] = amd_bytealign_S (w6[1], w6[0], offset_minus_4);
      w7[0] = amd_bytealign_S (w6[0], w5[3], offset_minus_4);
      w6[3] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w6[2] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w6[1] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w6[0] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w5[3] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w5[2] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w5[1] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w5[0] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w4[3] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w4[2] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w4[1] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w4[0] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w3[3] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w3[2] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w3[1] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w3[0] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w2[3] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w2[2] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w2[1] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w2[0] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w1[3] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w1[2] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w1[1] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w1[0] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[0] = w1[1];
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 5:
      w7[3] = amd_bytealign_S (w6[2], w6[1], offset_minus_4);
      w7[2] = amd_bytealign_S (w6[1], w6[0], offset_minus_4);
      w7[1] = amd_bytealign_S (w6[0], w5[3], offset_minus_4);
      w7[0] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w6[3] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w6[2] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w6[1] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w6[0] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w5[3] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w5[2] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w5[1] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w5[0] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w4[3] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w4[2] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w4[1] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w4[0] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w3[3] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w3[2] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w3[1] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w3[0] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w2[3] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w2[2] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w2[1] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w2[0] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w1[3] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w1[2] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w1[1] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[1] = w1[2];
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 6:
      w7[3] = amd_bytealign_S (w6[1], w6[0], offset_minus_4);
      w7[2] = amd_bytealign_S (w6[0], w5[3], offset_minus_4);
      w7[1] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w7[0] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w6[3] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w6[2] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w6[1] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w6[0] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w5[3] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w5[2] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w5[1] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w5[0] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w4[3] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w4[2] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w4[1] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w4[0] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w3[3] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w3[2] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w3[1] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w3[0] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w2[3] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w2[2] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w2[1] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w2[0] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w1[3] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w1[2] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[2] = w1[3];
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 7:
      w7[3] = amd_bytealign_S (w6[0], w5[3], offset_minus_4);
      w7[2] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w7[1] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w7[0] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w6[3] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w6[2] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w6[1] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w6[0] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w5[3] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w5[2] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w5[1] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w5[0] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w4[3] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w4[2] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w4[1] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w4[0] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w3[3] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w3[2] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w3[1] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w3[0] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w2[3] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w2[2] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w2[1] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w2[0] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w1[3] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w1[3] = w2[0];
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 8:
      w7[3] = amd_bytealign_S (w5[3], w5[2], offset_minus_4);
      w7[2] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w7[1] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w7[0] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w6[3] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w6[2] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w6[1] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w6[0] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w5[3] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w5[2] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w5[1] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w5[0] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w4[3] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w4[2] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w4[1] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w4[0] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w3[3] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w3[2] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w3[1] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w3[0] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w2[3] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w2[2] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w2[1] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w2[0] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[0] = w2[1];
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 9:
      w7[3] = amd_bytealign_S (w5[2], w5[1], offset_minus_4);
      w7[2] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w7[1] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w7[0] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w6[3] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w6[2] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w6[1] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w6[0] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w5[3] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w5[2] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w5[1] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w5[0] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w4[3] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w4[2] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w4[1] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w4[0] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w3[3] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w3[2] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w3[1] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w3[0] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w2[3] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w2[2] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w2[1] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w2[0] = 0;
      w1[3] = 0;
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;

      if (offset_mod_4 == 0)
      {
        w2[1] = w2[2];
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 10:
      w7[3] = amd_bytealign_S (w5[1], w5[0], offset_minus_4);
      w7[2] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w7[1] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w7[0] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w6[3] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w6[2] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w6[1] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w6[0] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w5[3] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w5[2] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w5[1] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w5[0] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w4[3] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w4[2] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w4[1] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w4[0] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w3[3] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w3[2] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w3[1] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w3[0] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w2[3] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w2[2] = amd_bytealign_S (w0[0],     0, offset_minus_4);
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

      if (offset_mod_4 == 0)
      {
        w2[2] = w2[3];
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 11:
      w7[3] = amd_bytealign_S (w5[0], w5[3], offset_minus_4);
      w7[2] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w7[1] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w7[0] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w6[3] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w6[2] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w6[1] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w6[0] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w5[3] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w5[2] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w5[1] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w5[0] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w4[3] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w4[2] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w4[1] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w4[0] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w3[3] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w3[2] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w3[1] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w3[0] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w2[3] = amd_bytealign_S (w0[0],     0, offset_minus_4);
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

      if (offset_mod_4 == 0)
      {
        w2[3] = w3[0];
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 12:
      w7[3] = amd_bytealign_S (w4[3], w4[2], offset_minus_4);
      w7[2] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w7[1] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w7[0] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w6[3] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w6[2] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w6[1] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w6[0] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w5[3] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w5[2] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w5[1] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w5[0] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w4[3] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w4[2] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w4[1] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w4[0] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w3[3] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w3[2] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w3[1] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w3[0] = amd_bytealign_S (w0[0],     0, offset_minus_4);
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

      if (offset_mod_4 == 0)
      {
        w3[0] = w3[1];
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 13:
      w7[3] = amd_bytealign_S (w4[2], w4[1], offset_minus_4);
      w7[2] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w7[1] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w7[0] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w6[3] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w6[2] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w6[1] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w6[0] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w5[3] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w5[2] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w5[1] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w5[0] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w4[3] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w4[2] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w4[1] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w4[0] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w3[3] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w3[2] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w3[1] = amd_bytealign_S (w0[0],     0, offset_minus_4);
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

      if (offset_mod_4 == 0)
      {
        w3[1] = w3[2];
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 14:
      w7[3] = amd_bytealign_S (w4[1], w4[0], offset_minus_4);
      w7[2] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w7[1] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w7[0] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w6[3] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w6[2] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w6[1] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w6[0] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w5[3] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w5[2] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w5[1] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w5[0] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w4[3] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w4[2] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w4[1] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w4[0] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w3[3] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w3[2] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w3[1] = 0;
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

      if (offset_mod_4 == 0)
      {
        w3[2] = w3[3];
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;

    case 15:
      w7[3] = amd_bytealign_S (w4[0], w3[3], offset_minus_4);
      w7[2] = amd_bytealign_S (w3[3], w3[2], offset_minus_4);
      w7[1] = amd_bytealign_S (w3[2], w3[1], offset_minus_4);
      w7[0] = amd_bytealign_S (w3[1], w3[0], offset_minus_4);
      w6[3] = amd_bytealign_S (w3[0], w2[3], offset_minus_4);
      w6[2] = amd_bytealign_S (w2[3], w2[2], offset_minus_4);
      w6[1] = amd_bytealign_S (w2[2], w2[1], offset_minus_4);
      w6[0] = amd_bytealign_S (w2[1], w2[0], offset_minus_4);
      w5[3] = amd_bytealign_S (w2[0], w1[3], offset_minus_4);
      w5[2] = amd_bytealign_S (w1[3], w1[2], offset_minus_4);
      w5[1] = amd_bytealign_S (w1[2], w1[1], offset_minus_4);
      w5[0] = amd_bytealign_S (w1[1], w1[0], offset_minus_4);
      w4[3] = amd_bytealign_S (w1[0], w0[3], offset_minus_4);
      w4[2] = amd_bytealign_S (w0[3], w0[2], offset_minus_4);
      w4[1] = amd_bytealign_S (w0[2], w0[1], offset_minus_4);
      w4[0] = amd_bytealign_S (w0[1], w0[0], offset_minus_4);
      w3[3] = amd_bytealign_S (w0[0],     0, offset_minus_4);
      w3[2] = 0;
      w3[1] = 0;
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

      if (offset_mod_4 == 0)
      {
        w3[3] = w4[0];
        w4[0] = w4[1];
        w4[1] = w4[2];
        w4[2] = w4[3];
        w4[3] = w5[0];
        w5[0] = w5[1];
        w5[1] = w5[2];
        w5[2] = w5[3];
        w5[3] = w6[0];
        w6[0] = w6[1];
        w6[1] = w6[2];
        w6[2] = w6[3];
        w6[3] = w7[0];
        w7[0] = w7[1];
        w7[1] = w7[2];
        w7[2] = w7[3];
        w7[3] = 0;
      }

      break;
  }
  #endif

  #ifdef IS_NV
  const int offset_minus_4 = 4 - (offset % 4);

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  switch (offset / 4)
  {
    case 0:
      w7[3] = __byte_perm_S (w7[2], w7[3], selector);
      w7[2] = __byte_perm_S (w7[1], w7[2], selector);
      w7[1] = __byte_perm_S (w7[0], w7[1], selector);
      w7[0] = __byte_perm_S (w6[3], w7[0], selector);
      w6[3] = __byte_perm_S (w6[2], w6[3], selector);
      w6[2] = __byte_perm_S (w6[1], w6[2], selector);
      w6[1] = __byte_perm_S (w6[0], w6[1], selector);
      w6[0] = __byte_perm_S (w5[3], w6[0], selector);
      w5[3] = __byte_perm_S (w5[2], w5[3], selector);
      w5[2] = __byte_perm_S (w5[1], w5[2], selector);
      w5[1] = __byte_perm_S (w5[0], w5[1], selector);
      w5[0] = __byte_perm_S (w4[3], w5[0], selector);
      w4[3] = __byte_perm_S (w4[2], w4[3], selector);
      w4[2] = __byte_perm_S (w4[1], w4[2], selector);
      w4[1] = __byte_perm_S (w4[0], w4[1], selector);
      w4[0] = __byte_perm_S (w3[3], w4[0], selector);
      w3[3] = __byte_perm_S (w3[2], w3[3], selector);
      w3[2] = __byte_perm_S (w3[1], w3[2], selector);
      w3[1] = __byte_perm_S (w3[0], w3[1], selector);
      w3[0] = __byte_perm_S (w2[3], w3[0], selector);
      w2[3] = __byte_perm_S (w2[2], w2[3], selector);
      w2[2] = __byte_perm_S (w2[1], w2[2], selector);
      w2[1] = __byte_perm_S (w2[0], w2[1], selector);
      w2[0] = __byte_perm_S (w1[3], w2[0], selector);
      w1[3] = __byte_perm_S (w1[2], w1[3], selector);
      w1[2] = __byte_perm_S (w1[1], w1[2], selector);
      w1[1] = __byte_perm_S (w1[0], w1[1], selector);
      w1[0] = __byte_perm_S (w0[3], w1[0], selector);
      w0[3] = __byte_perm_S (w0[2], w0[3], selector);
      w0[2] = __byte_perm_S (w0[1], w0[2], selector);
      w0[1] = __byte_perm_S (w0[0], w0[1], selector);
      w0[0] = __byte_perm_S (    0, w0[0], selector);
      break;

    case 1:
      w7[3] = __byte_perm_S (w7[1], w7[2], selector);
      w7[2] = __byte_perm_S (w7[0], w7[1], selector);
      w7[1] = __byte_perm_S (w6[3], w7[0], selector);
      w7[0] = __byte_perm_S (w6[2], w6[3], selector);
      w6[3] = __byte_perm_S (w6[1], w6[2], selector);
      w6[2] = __byte_perm_S (w6[0], w6[1], selector);
      w6[1] = __byte_perm_S (w5[3], w6[0], selector);
      w6[0] = __byte_perm_S (w5[2], w5[3], selector);
      w5[3] = __byte_perm_S (w5[1], w5[2], selector);
      w5[2] = __byte_perm_S (w5[0], w5[1], selector);
      w5[1] = __byte_perm_S (w4[3], w5[0], selector);
      w5[0] = __byte_perm_S (w4[2], w4[3], selector);
      w4[3] = __byte_perm_S (w4[1], w4[2], selector);
      w4[2] = __byte_perm_S (w4[0], w4[1], selector);
      w4[1] = __byte_perm_S (w3[3], w4[0], selector);
      w4[0] = __byte_perm_S (w3[2], w3[3], selector);
      w3[3] = __byte_perm_S (w3[1], w3[2], selector);
      w3[2] = __byte_perm_S (w3[0], w3[1], selector);
      w3[1] = __byte_perm_S (w2[3], w3[0], selector);
      w3[0] = __byte_perm_S (w2[2], w2[3], selector);
      w2[3] = __byte_perm_S (w2[1], w2[2], selector);
      w2[2] = __byte_perm_S (w2[0], w2[1], selector);
      w2[1] = __byte_perm_S (w1[3], w2[0], selector);
      w2[0] = __byte_perm_S (w1[2], w1[3], selector);
      w1[3] = __byte_perm_S (w1[1], w1[2], selector);
      w1[2] = __byte_perm_S (w1[0], w1[1], selector);
      w1[1] = __byte_perm_S (w0[3], w1[0], selector);
      w1[0] = __byte_perm_S (w0[2], w0[3], selector);
      w0[3] = __byte_perm_S (w0[1], w0[2], selector);
      w0[2] = __byte_perm_S (w0[0], w0[1], selector);
      w0[1] = __byte_perm_S (    0, w0[0], selector);
      w0[0] = 0;
      break;

    case 2:
      w7[3] = __byte_perm_S (w7[0], w7[1], selector);
      w7[2] = __byte_perm_S (w6[3], w7[0], selector);
      w7[1] = __byte_perm_S (w6[2], w6[3], selector);
      w7[0] = __byte_perm_S (w6[1], w6[2], selector);
      w6[3] = __byte_perm_S (w6[0], w6[1], selector);
      w6[2] = __byte_perm_S (w5[3], w6[0], selector);
      w6[1] = __byte_perm_S (w5[2], w5[3], selector);
      w6[0] = __byte_perm_S (w5[1], w5[2], selector);
      w5[3] = __byte_perm_S (w5[0], w5[1], selector);
      w5[2] = __byte_perm_S (w4[3], w5[0], selector);
      w5[1] = __byte_perm_S (w4[2], w4[3], selector);
      w5[0] = __byte_perm_S (w4[1], w4[2], selector);
      w4[3] = __byte_perm_S (w4[0], w4[1], selector);
      w4[2] = __byte_perm_S (w3[3], w4[0], selector);
      w4[1] = __byte_perm_S (w3[2], w3[3], selector);
      w4[0] = __byte_perm_S (w3[1], w3[2], selector);
      w3[3] = __byte_perm_S (w3[0], w3[1], selector);
      w3[2] = __byte_perm_S (w2[3], w3[0], selector);
      w3[1] = __byte_perm_S (w2[2], w2[3], selector);
      w3[0] = __byte_perm_S (w2[1], w2[2], selector);
      w2[3] = __byte_perm_S (w2[0], w2[1], selector);
      w2[2] = __byte_perm_S (w1[3], w2[0], selector);
      w2[1] = __byte_perm_S (w1[2], w1[3], selector);
      w2[0] = __byte_perm_S (w1[1], w1[2], selector);
      w1[3] = __byte_perm_S (w1[0], w1[1], selector);
      w1[2] = __byte_perm_S (w0[3], w1[0], selector);
      w1[1] = __byte_perm_S (w0[2], w0[3], selector);
      w1[0] = __byte_perm_S (w0[1], w0[2], selector);
      w0[3] = __byte_perm_S (w0[0], w0[1], selector);
      w0[2] = __byte_perm_S (    0, w0[0], selector);
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 3:
      w7[3] = __byte_perm_S (w6[3], w7[0], selector);
      w7[2] = __byte_perm_S (w6[2], w6[3], selector);
      w7[1] = __byte_perm_S (w6[1], w6[2], selector);
      w7[0] = __byte_perm_S (w6[0], w6[1], selector);
      w6[3] = __byte_perm_S (w5[3], w6[0], selector);
      w6[2] = __byte_perm_S (w5[2], w5[3], selector);
      w6[1] = __byte_perm_S (w5[1], w5[2], selector);
      w6[0] = __byte_perm_S (w5[0], w5[1], selector);
      w5[3] = __byte_perm_S (w4[3], w5[0], selector);
      w5[2] = __byte_perm_S (w4[2], w4[3], selector);
      w5[1] = __byte_perm_S (w4[1], w4[2], selector);
      w5[0] = __byte_perm_S (w4[0], w4[1], selector);
      w4[3] = __byte_perm_S (w3[3], w4[0], selector);
      w4[2] = __byte_perm_S (w3[2], w3[3], selector);
      w4[1] = __byte_perm_S (w3[1], w3[2], selector);
      w4[0] = __byte_perm_S (w3[0], w3[1], selector);
      w3[3] = __byte_perm_S (w2[3], w3[0], selector);
      w3[2] = __byte_perm_S (w2[2], w2[3], selector);
      w3[1] = __byte_perm_S (w2[1], w2[2], selector);
      w3[0] = __byte_perm_S (w2[0], w2[1], selector);
      w2[3] = __byte_perm_S (w1[3], w2[0], selector);
      w2[2] = __byte_perm_S (w1[2], w1[3], selector);
      w2[1] = __byte_perm_S (w1[1], w1[2], selector);
      w2[0] = __byte_perm_S (w1[0], w1[1], selector);
      w1[3] = __byte_perm_S (w0[3], w1[0], selector);
      w1[2] = __byte_perm_S (w0[2], w0[3], selector);
      w1[1] = __byte_perm_S (w0[1], w0[2], selector);
      w1[0] = __byte_perm_S (w0[0], w0[1], selector);
      w0[3] = __byte_perm_S (    0, w0[0], selector);
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 4:
      w7[3] = __byte_perm_S (w6[2], w6[3], selector);
      w7[2] = __byte_perm_S (w6[1], w6[2], selector);
      w7[1] = __byte_perm_S (w6[0], w6[1], selector);
      w7[0] = __byte_perm_S (w5[3], w6[0], selector);
      w6[3] = __byte_perm_S (w5[2], w5[3], selector);
      w6[2] = __byte_perm_S (w5[1], w5[2], selector);
      w6[1] = __byte_perm_S (w5[0], w5[1], selector);
      w6[0] = __byte_perm_S (w4[3], w5[0], selector);
      w5[3] = __byte_perm_S (w4[2], w4[3], selector);
      w5[2] = __byte_perm_S (w4[1], w4[2], selector);
      w5[1] = __byte_perm_S (w4[0], w4[1], selector);
      w5[0] = __byte_perm_S (w3[3], w4[0], selector);
      w4[3] = __byte_perm_S (w3[2], w3[3], selector);
      w4[2] = __byte_perm_S (w3[1], w3[2], selector);
      w4[1] = __byte_perm_S (w3[0], w3[1], selector);
      w4[0] = __byte_perm_S (w2[3], w3[0], selector);
      w3[3] = __byte_perm_S (w2[2], w2[3], selector);
      w3[2] = __byte_perm_S (w2[1], w2[2], selector);
      w3[1] = __byte_perm_S (w2[0], w2[1], selector);
      w3[0] = __byte_perm_S (w1[3], w2[0], selector);
      w2[3] = __byte_perm_S (w1[2], w1[3], selector);
      w2[2] = __byte_perm_S (w1[1], w1[2], selector);
      w2[1] = __byte_perm_S (w1[0], w1[1], selector);
      w2[0] = __byte_perm_S (w0[3], w1[0], selector);
      w1[3] = __byte_perm_S (w0[2], w0[3], selector);
      w1[2] = __byte_perm_S (w0[1], w0[2], selector);
      w1[1] = __byte_perm_S (w0[0], w0[1], selector);
      w1[0] = __byte_perm_S (    0, w0[0], selector);
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 5:
      w7[3] = __byte_perm_S (w6[1], w6[2], selector);
      w7[2] = __byte_perm_S (w6[0], w6[1], selector);
      w7[1] = __byte_perm_S (w5[3], w6[0], selector);
      w7[0] = __byte_perm_S (w5[2], w5[3], selector);
      w6[3] = __byte_perm_S (w5[1], w5[2], selector);
      w6[2] = __byte_perm_S (w5[0], w5[1], selector);
      w6[1] = __byte_perm_S (w4[3], w5[0], selector);
      w6[0] = __byte_perm_S (w4[2], w4[3], selector);
      w5[3] = __byte_perm_S (w4[1], w4[2], selector);
      w5[2] = __byte_perm_S (w4[0], w4[1], selector);
      w5[1] = __byte_perm_S (w3[3], w4[0], selector);
      w5[0] = __byte_perm_S (w3[2], w3[3], selector);
      w4[3] = __byte_perm_S (w3[1], w3[2], selector);
      w4[2] = __byte_perm_S (w3[0], w3[1], selector);
      w4[1] = __byte_perm_S (w2[3], w3[0], selector);
      w4[0] = __byte_perm_S (w2[2], w2[3], selector);
      w3[3] = __byte_perm_S (w2[1], w2[2], selector);
      w3[2] = __byte_perm_S (w2[0], w2[1], selector);
      w3[1] = __byte_perm_S (w1[3], w2[0], selector);
      w3[0] = __byte_perm_S (w1[2], w1[3], selector);
      w2[3] = __byte_perm_S (w1[1], w1[2], selector);
      w2[2] = __byte_perm_S (w1[0], w1[1], selector);
      w2[1] = __byte_perm_S (w0[3], w1[0], selector);
      w2[0] = __byte_perm_S (w0[2], w0[3], selector);
      w1[3] = __byte_perm_S (w0[1], w0[2], selector);
      w1[2] = __byte_perm_S (w0[0], w0[1], selector);
      w1[1] = __byte_perm_S (    0, w0[0], selector);
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 6:
      w7[3] = __byte_perm_S (w6[0], w6[1], selector);
      w7[2] = __byte_perm_S (w5[3], w6[0], selector);
      w7[1] = __byte_perm_S (w5[2], w5[3], selector);
      w7[0] = __byte_perm_S (w5[1], w5[2], selector);
      w6[3] = __byte_perm_S (w5[0], w5[1], selector);
      w6[2] = __byte_perm_S (w4[3], w5[0], selector);
      w6[1] = __byte_perm_S (w4[2], w4[3], selector);
      w6[0] = __byte_perm_S (w4[1], w4[2], selector);
      w5[3] = __byte_perm_S (w4[0], w4[1], selector);
      w5[2] = __byte_perm_S (w3[3], w4[0], selector);
      w5[1] = __byte_perm_S (w3[2], w3[3], selector);
      w5[0] = __byte_perm_S (w3[1], w3[2], selector);
      w4[3] = __byte_perm_S (w3[0], w3[1], selector);
      w4[2] = __byte_perm_S (w2[3], w3[0], selector);
      w4[1] = __byte_perm_S (w2[2], w2[3], selector);
      w4[0] = __byte_perm_S (w2[1], w2[2], selector);
      w3[3] = __byte_perm_S (w2[0], w2[1], selector);
      w3[2] = __byte_perm_S (w1[3], w2[0], selector);
      w3[1] = __byte_perm_S (w1[2], w1[3], selector);
      w3[0] = __byte_perm_S (w1[1], w1[2], selector);
      w2[3] = __byte_perm_S (w1[0], w1[1], selector);
      w2[2] = __byte_perm_S (w0[3], w1[0], selector);
      w2[1] = __byte_perm_S (w0[2], w0[3], selector);
      w2[0] = __byte_perm_S (w0[1], w0[2], selector);
      w1[3] = __byte_perm_S (w0[0], w0[1], selector);
      w1[2] = __byte_perm_S (    0, w0[0], selector);
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 7:
      w7[3] = __byte_perm_S (w5[3], w6[0], selector);
      w7[2] = __byte_perm_S (w5[2], w5[3], selector);
      w7[1] = __byte_perm_S (w5[1], w5[2], selector);
      w7[0] = __byte_perm_S (w5[0], w5[1], selector);
      w6[3] = __byte_perm_S (w4[3], w5[0], selector);
      w6[2] = __byte_perm_S (w4[2], w4[3], selector);
      w6[1] = __byte_perm_S (w4[1], w4[2], selector);
      w6[0] = __byte_perm_S (w4[0], w4[1], selector);
      w5[3] = __byte_perm_S (w3[3], w4[0], selector);
      w5[2] = __byte_perm_S (w3[2], w3[3], selector);
      w5[1] = __byte_perm_S (w3[1], w3[2], selector);
      w5[0] = __byte_perm_S (w3[0], w3[1], selector);
      w4[3] = __byte_perm_S (w2[3], w3[0], selector);
      w4[2] = __byte_perm_S (w2[2], w2[3], selector);
      w4[1] = __byte_perm_S (w2[1], w2[2], selector);
      w4[0] = __byte_perm_S (w2[0], w2[1], selector);
      w3[3] = __byte_perm_S (w1[3], w2[0], selector);
      w3[2] = __byte_perm_S (w1[2], w1[3], selector);
      w3[1] = __byte_perm_S (w1[1], w1[2], selector);
      w3[0] = __byte_perm_S (w1[0], w1[1], selector);
      w2[3] = __byte_perm_S (w0[3], w1[0], selector);
      w2[2] = __byte_perm_S (w0[2], w0[3], selector);
      w2[1] = __byte_perm_S (w0[1], w0[2], selector);
      w2[0] = __byte_perm_S (w0[0], w0[1], selector);
      w1[3] = __byte_perm_S (    0, w0[0], selector);
      w1[2] = 0;
      w1[1] = 0;
      w1[0] = 0;
      w0[3] = 0;
      w0[2] = 0;
      w0[1] = 0;
      w0[0] = 0;
      break;

    case 8:
      w7[3] = __byte_perm_S (w5[2], w5[3], selector);
      w7[2] = __byte_perm_S (w5[1], w5[2], selector);
      w7[1] = __byte_perm_S (w5[0], w5[1], selector);
      w7[0] = __byte_perm_S (w4[3], w5[0], selector);
      w6[3] = __byte_perm_S (w4[2], w4[3], selector);
      w6[2] = __byte_perm_S (w4[1], w4[2], selector);
      w6[1] = __byte_perm_S (w4[0], w4[1], selector);
      w6[0] = __byte_perm_S (w3[3], w4[0], selector);
      w5[3] = __byte_perm_S (w3[2], w3[3], selector);
      w5[2] = __byte_perm_S (w3[1], w3[2], selector);
      w5[1] = __byte_perm_S (w3[0], w3[1], selector);
      w5[0] = __byte_perm_S (w2[3], w3[0], selector);
      w4[3] = __byte_perm_S (w2[2], w2[3], selector);
      w4[2] = __byte_perm_S (w2[1], w2[2], selector);
      w4[1] = __byte_perm_S (w2[0], w2[1], selector);
      w4[0] = __byte_perm_S (w1[3], w2[0], selector);
      w3[3] = __byte_perm_S (w1[2], w1[3], selector);
      w3[2] = __byte_perm_S (w1[1], w1[2], selector);
      w3[1] = __byte_perm_S (w1[0], w1[1], selector);
      w3[0] = __byte_perm_S (w0[3], w1[0], selector);
      w2[3] = __byte_perm_S (w0[2], w0[3], selector);
      w2[2] = __byte_perm_S (w0[1], w0[2], selector);
      w2[1] = __byte_perm_S (w0[0], w0[1], selector);
      w2[0] = __byte_perm_S (    0, w0[0], selector);
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
      w7[3] = __byte_perm_S (w5[1], w5[2], selector);
      w7[2] = __byte_perm_S (w5[0], w5[1], selector);
      w7[1] = __byte_perm_S (w4[3], w5[0], selector);
      w7[0] = __byte_perm_S (w4[2], w4[3], selector);
      w6[3] = __byte_perm_S (w4[1], w4[2], selector);
      w6[2] = __byte_perm_S (w4[0], w4[1], selector);
      w6[1] = __byte_perm_S (w3[3], w4[0], selector);
      w6[0] = __byte_perm_S (w3[2], w3[3], selector);
      w5[3] = __byte_perm_S (w3[1], w3[2], selector);
      w5[2] = __byte_perm_S (w3[0], w3[1], selector);
      w5[1] = __byte_perm_S (w2[3], w3[0], selector);
      w5[0] = __byte_perm_S (w2[2], w2[3], selector);
      w4[3] = __byte_perm_S (w2[1], w2[2], selector);
      w4[2] = __byte_perm_S (w2[0], w2[1], selector);
      w4[1] = __byte_perm_S (w1[3], w2[0], selector);
      w4[0] = __byte_perm_S (w1[2], w1[3], selector);
      w3[3] = __byte_perm_S (w1[1], w1[2], selector);
      w3[2] = __byte_perm_S (w1[0], w1[1], selector);
      w3[1] = __byte_perm_S (w0[3], w1[0], selector);
      w3[0] = __byte_perm_S (w0[2], w0[3], selector);
      w2[3] = __byte_perm_S (w0[1], w0[2], selector);
      w2[2] = __byte_perm_S (w0[0], w0[1], selector);
      w2[1] = __byte_perm_S (    0, w0[0], selector);
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
      w7[3] = __byte_perm_S (w5[0], w5[1], selector);
      w7[2] = __byte_perm_S (w4[3], w5[0], selector);
      w7[1] = __byte_perm_S (w4[2], w4[3], selector);
      w7[0] = __byte_perm_S (w4[1], w4[2], selector);
      w6[3] = __byte_perm_S (w4[0], w4[1], selector);
      w6[2] = __byte_perm_S (w3[3], w4[0], selector);
      w6[1] = __byte_perm_S (w3[2], w3[3], selector);
      w6[0] = __byte_perm_S (w3[1], w3[2], selector);
      w5[3] = __byte_perm_S (w3[0], w3[1], selector);
      w5[2] = __byte_perm_S (w2[3], w3[0], selector);
      w5[1] = __byte_perm_S (w2[2], w2[3], selector);
      w5[0] = __byte_perm_S (w2[1], w2[2], selector);
      w4[3] = __byte_perm_S (w2[0], w2[1], selector);
      w4[2] = __byte_perm_S (w1[3], w2[0], selector);
      w4[1] = __byte_perm_S (w1[2], w1[3], selector);
      w4[0] = __byte_perm_S (w1[1], w1[2], selector);
      w3[3] = __byte_perm_S (w1[0], w1[1], selector);
      w3[2] = __byte_perm_S (w0[3], w1[0], selector);
      w3[1] = __byte_perm_S (w0[2], w0[3], selector);
      w3[0] = __byte_perm_S (w0[1], w0[2], selector);
      w2[3] = __byte_perm_S (w0[0], w0[1], selector);
      w2[2] = __byte_perm_S (    0, w0[0], selector);
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
      w7[3] = __byte_perm_S (w4[3], w5[0], selector);
      w7[2] = __byte_perm_S (w4[2], w4[3], selector);
      w7[1] = __byte_perm_S (w4[1], w4[2], selector);
      w7[0] = __byte_perm_S (w4[0], w4[1], selector);
      w6[3] = __byte_perm_S (w3[3], w4[0], selector);
      w6[2] = __byte_perm_S (w3[2], w3[3], selector);
      w6[1] = __byte_perm_S (w3[1], w3[2], selector);
      w6[0] = __byte_perm_S (w3[0], w3[1], selector);
      w5[3] = __byte_perm_S (w2[3], w3[0], selector);
      w5[2] = __byte_perm_S (w2[2], w2[3], selector);
      w5[1] = __byte_perm_S (w2[1], w2[2], selector);
      w5[0] = __byte_perm_S (w2[0], w2[1], selector);
      w4[3] = __byte_perm_S (w1[3], w2[0], selector);
      w4[2] = __byte_perm_S (w1[2], w1[3], selector);
      w4[1] = __byte_perm_S (w1[1], w1[2], selector);
      w4[0] = __byte_perm_S (w1[0], w1[1], selector);
      w3[3] = __byte_perm_S (w0[3], w1[0], selector);
      w3[2] = __byte_perm_S (w0[2], w0[3], selector);
      w3[1] = __byte_perm_S (w0[1], w0[2], selector);
      w3[0] = __byte_perm_S (w0[0], w0[1], selector);
      w2[3] = __byte_perm_S (    0, w0[0], selector);
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
      w7[3] = __byte_perm_S (w4[2], w4[3], selector);
      w7[2] = __byte_perm_S (w4[1], w4[2], selector);
      w7[1] = __byte_perm_S (w4[0], w4[1], selector);
      w7[0] = __byte_perm_S (w3[3], w4[0], selector);
      w6[3] = __byte_perm_S (w3[2], w3[3], selector);
      w6[2] = __byte_perm_S (w3[1], w3[2], selector);
      w6[1] = __byte_perm_S (w3[0], w3[1], selector);
      w6[0] = __byte_perm_S (w2[3], w3[0], selector);
      w5[3] = __byte_perm_S (w2[2], w2[3], selector);
      w5[2] = __byte_perm_S (w2[1], w2[2], selector);
      w5[1] = __byte_perm_S (w2[0], w2[1], selector);
      w5[0] = __byte_perm_S (w1[3], w2[0], selector);
      w4[3] = __byte_perm_S (w1[2], w1[3], selector);
      w4[2] = __byte_perm_S (w1[1], w1[2], selector);
      w4[1] = __byte_perm_S (w1[0], w1[1], selector);
      w4[0] = __byte_perm_S (w0[3], w1[0], selector);
      w3[3] = __byte_perm_S (w0[2], w0[3], selector);
      w3[2] = __byte_perm_S (w0[1], w0[2], selector);
      w3[1] = __byte_perm_S (w0[0], w0[1], selector);
      w3[0] = __byte_perm_S (    0, w0[0], selector);
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
      w7[3] = __byte_perm_S (w4[1], w4[2], selector);
      w7[2] = __byte_perm_S (w4[0], w4[1], selector);
      w7[1] = __byte_perm_S (w3[3], w4[0], selector);
      w7[0] = __byte_perm_S (w3[2], w3[3], selector);
      w6[3] = __byte_perm_S (w3[1], w3[2], selector);
      w6[2] = __byte_perm_S (w3[0], w3[1], selector);
      w6[1] = __byte_perm_S (w2[3], w3[0], selector);
      w6[0] = __byte_perm_S (w2[2], w2[3], selector);
      w5[3] = __byte_perm_S (w2[1], w2[2], selector);
      w5[2] = __byte_perm_S (w2[0], w2[1], selector);
      w5[1] = __byte_perm_S (w1[3], w2[0], selector);
      w5[0] = __byte_perm_S (w1[2], w1[3], selector);
      w4[3] = __byte_perm_S (w1[1], w1[2], selector);
      w4[2] = __byte_perm_S (w1[0], w1[1], selector);
      w4[1] = __byte_perm_S (w0[3], w1[0], selector);
      w4[0] = __byte_perm_S (w0[2], w0[3], selector);
      w3[3] = __byte_perm_S (w0[1], w0[2], selector);
      w3[2] = __byte_perm_S (w0[0], w0[1], selector);
      w3[1] = __byte_perm_S (    0, w0[0], selector);
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

    case 14:
      w7[3] = __byte_perm_S (w4[0], w4[1], selector);
      w7[2] = __byte_perm_S (w3[3], w4[0], selector);
      w7[1] = __byte_perm_S (w3[2], w3[3], selector);
      w7[0] = __byte_perm_S (w3[1], w3[2], selector);
      w6[3] = __byte_perm_S (w3[0], w3[1], selector);
      w6[2] = __byte_perm_S (w2[3], w3[0], selector);
      w6[1] = __byte_perm_S (w2[2], w2[3], selector);
      w6[0] = __byte_perm_S (w2[1], w2[2], selector);
      w5[3] = __byte_perm_S (w2[0], w2[1], selector);
      w5[2] = __byte_perm_S (w1[3], w2[0], selector);
      w5[1] = __byte_perm_S (w1[2], w1[3], selector);
      w5[0] = __byte_perm_S (w1[1], w1[2], selector);
      w4[3] = __byte_perm_S (w1[0], w1[1], selector);
      w4[2] = __byte_perm_S (w0[3], w1[0], selector);
      w4[1] = __byte_perm_S (w0[2], w0[3], selector);
      w4[0] = __byte_perm_S (w0[1], w0[2], selector);
      w3[3] = __byte_perm_S (w0[0], w0[1], selector);
      w3[2] = __byte_perm_S (    0, w0[0], selector);
      w3[1] = 0;
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

    case 15:
      w7[3] = __byte_perm_S (w3[3], w4[0], selector);
      w7[2] = __byte_perm_S (w3[2], w3[3], selector);
      w7[1] = __byte_perm_S (w3[1], w3[2], selector);
      w7[0] = __byte_perm_S (w3[0], w3[1], selector);
      w6[3] = __byte_perm_S (w2[3], w3[0], selector);
      w6[2] = __byte_perm_S (w2[2], w2[3], selector);
      w6[1] = __byte_perm_S (w2[1], w2[2], selector);
      w6[0] = __byte_perm_S (w2[0], w2[1], selector);
      w5[3] = __byte_perm_S (w1[3], w2[0], selector);
      w5[2] = __byte_perm_S (w1[2], w1[3], selector);
      w5[1] = __byte_perm_S (w1[1], w1[2], selector);
      w5[0] = __byte_perm_S (w1[0], w1[1], selector);
      w4[3] = __byte_perm_S (w0[3], w1[0], selector);
      w4[2] = __byte_perm_S (w0[2], w0[3], selector);
      w4[1] = __byte_perm_S (w0[1], w0[2], selector);
      w4[0] = __byte_perm_S (w0[0], w0[1], selector);
      w3[3] = __byte_perm_S (    0, w0[0], selector);
      w3[2] = 0;
      w3[1] = 0;
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
  #endif
}

#define PACKVS84(s0,s1,s2,s3,s4,s5,s6,s7,v0,v1,v2,v3,v4,v5,v6,v7,e) \
  PACKVS4 (s0, v0, e);                                              \
  PACKVS4 (s1, v1, e);                                              \
  PACKVS4 (s2, v2, e);                                              \
  PACKVS4 (s3, v3, e);                                              \
  PACKVS4 (s4, v4, e);                                              \
  PACKVS4 (s5, v5, e);                                              \
  PACKVS4 (s6, v6, e);                                              \
  PACKVS4 (s7, v7, e);

#define PACKSV84(s0,s1,s2,s3,s4,s5,s6,s7,v0,v1,v2,v3,v4,v5,v6,v7,e) \
  PACKSV4 (s0, v0, e);                                              \
  PACKSV4 (s1, v1, e);                                              \
  PACKSV4 (s2, v2, e);                                              \
  PACKSV4 (s3, v3, e);                                              \
  PACKSV4 (s4, v4, e);                                              \
  PACKSV4 (s5, v5, e);                                              \
  PACKSV4 (s6, v6, e);                                              \
  PACKSV4 (s7, v7, e);

inline void switch_buffer_by_offset_8x4_le_VV (u32x w0[4], u32x w1[4], u32x w2[4], u32x w3[4], u32x w4[4], u32x w5[4], u32x w6[4], u32x w7[4], const u32x offset)
{
  #if VECT_SIZE == 1

  switch_buffer_by_offset_8x4_le_S (w0, w1, w2, w3, w4, w5, w6, w7, offset);

  #else

  u32 t0[4];
  u32 t1[4];
  u32 t2[4];
  u32 t3[4];
  u32 t4[4];
  u32 t5[4];
  u32 t6[4];
  u32 t7[4];

  #endif

  #if   VECT_SIZE == 2

  // 1
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 0);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s0);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 0);

  // 2
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 1);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s1);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 1);

  #elif VECT_SIZE == 4

  // 1
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 0);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s0);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 0);

  // 2
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 1);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s1);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 1);

  // 3
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 2);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s2);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 2);

  // 4
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 3);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s3);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 3);

  #elif VECT_SIZE == 8

  // 1
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 0);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s0);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 0);

  // 2
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 1);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s1);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 1);

  // 3
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 2);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s2);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 2);

  // 4
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 3);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s3);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 3);

  // 5
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 4);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s4);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 4);

  // 6
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 5);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s5);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 5);

  // 7
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 6);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s6);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 6);

  // 8
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 7);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s7);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 7);

  #elif VECT_SIZE == 16

  // 1
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 0);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s0);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 0);

  // 2
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 1);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s1);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 1);

  // 3
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 2);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s2);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 2);

  // 4
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 3);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s3);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 3);

  // 5
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 4);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s4);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 4);

  // 6
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 5);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s5);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 5);

  // 7
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 6);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s6);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 6);

  // 8
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 7);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s7);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 7);

  // 9
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 8);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s8);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 8);

  // 10
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 9);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.s9);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, 9);

  // 11
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, a);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.sa);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, a);

  // 12
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, b);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.sb);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, b);

  // 13
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, c);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.sc);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, c);

  // 14
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, d);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.sd);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, d);

  // 15
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, e);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.se);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, e);

  // 16
  PACKVS84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, f);
  switch_buffer_by_offset_8x4_le_S (t0, t1, t2, t3, t4, t5, t6, t7, offset.sf);
  PACKSV84 (t0, t1, t2, t3, t4, t5, t6, t7, w0, w1, w2, w3, w4, w5, w6, w7, f);

  #endif
}

__constant u64 k_sha512[80] =
{
  SHA512C00, SHA512C01, SHA512C02, SHA512C03,
  SHA512C04, SHA512C05, SHA512C06, SHA512C07,
  SHA512C08, SHA512C09, SHA512C0a, SHA512C0b,
  SHA512C0c, SHA512C0d, SHA512C0e, SHA512C0f,
  SHA512C10, SHA512C11, SHA512C12, SHA512C13,
  SHA512C14, SHA512C15, SHA512C16, SHA512C17,
  SHA512C18, SHA512C19, SHA512C1a, SHA512C1b,
  SHA512C1c, SHA512C1d, SHA512C1e, SHA512C1f,
  SHA512C20, SHA512C21, SHA512C22, SHA512C23,
  SHA512C24, SHA512C25, SHA512C26, SHA512C27,
  SHA512C28, SHA512C29, SHA512C2a, SHA512C2b,
  SHA512C2c, SHA512C2d, SHA512C2e, SHA512C2f,
  SHA512C30, SHA512C31, SHA512C32, SHA512C33,
  SHA512C34, SHA512C35, SHA512C36, SHA512C37,
  SHA512C38, SHA512C39, SHA512C3a, SHA512C3b,
  SHA512C3c, SHA512C3d, SHA512C3e, SHA512C3f,
  SHA512C40, SHA512C41, SHA512C42, SHA512C43,
  SHA512C44, SHA512C45, SHA512C46, SHA512C47,
  SHA512C48, SHA512C49, SHA512C4a, SHA512C4b,
  SHA512C4c, SHA512C4d, SHA512C4e, SHA512C4f,
};

static void sha512_transform (const u32x w0[4], const u32x w1[4], const u32x w2[4], const u32x w3[4], const u32x w4[4], const u32x w5[4], const u32x w6[4], const u32x w7[4], u64x digest[8])
{
  u64x w0_t = hl32_to_64 (w0[0], w0[1]);
  u64x w1_t = hl32_to_64 (w0[2], w0[3]);
  u64x w2_t = hl32_to_64 (w1[0], w1[1]);
  u64x w3_t = hl32_to_64 (w1[2], w1[3]);
  u64x w4_t = hl32_to_64 (w2[0], w2[1]);
  u64x w5_t = hl32_to_64 (w2[2], w2[3]);
  u64x w6_t = hl32_to_64 (w3[0], w3[1]);
  u64x w7_t = hl32_to_64 (w3[2], w3[3]);
  u64x w8_t = hl32_to_64 (w4[0], w4[1]);
  u64x w9_t = hl32_to_64 (w4[2], w4[3]);
  u64x wa_t = hl32_to_64 (w5[0], w5[1]);
  u64x wb_t = hl32_to_64 (w5[2], w5[3]);
  u64x wc_t = hl32_to_64 (w6[0], w6[1]);
  u64x wd_t = hl32_to_64 (w6[2], w6[3]);
  u64x we_t = hl32_to_64 (w7[0], w7[1]);
  u64x wf_t = hl32_to_64 (w7[2], w7[3]);

  u64x a = digest[0];
  u64x b = digest[1];
  u64x c = digest[2];
  u64x d = digest[3];
  u64x e = digest[4];
  u64x f = digest[5];
  u64x g = digest[6];
  u64x h = digest[7];

  #define ROUND_EXPAND()                            \
  {                                                 \
    w0_t = SHA512_EXPAND (we_t, w9_t, w1_t, w0_t);  \
    w1_t = SHA512_EXPAND (wf_t, wa_t, w2_t, w1_t);  \
    w2_t = SHA512_EXPAND (w0_t, wb_t, w3_t, w2_t);  \
    w3_t = SHA512_EXPAND (w1_t, wc_t, w4_t, w3_t);  \
    w4_t = SHA512_EXPAND (w2_t, wd_t, w5_t, w4_t);  \
    w5_t = SHA512_EXPAND (w3_t, we_t, w6_t, w5_t);  \
    w6_t = SHA512_EXPAND (w4_t, wf_t, w7_t, w6_t);  \
    w7_t = SHA512_EXPAND (w5_t, w0_t, w8_t, w7_t);  \
    w8_t = SHA512_EXPAND (w6_t, w1_t, w9_t, w8_t);  \
    w9_t = SHA512_EXPAND (w7_t, w2_t, wa_t, w9_t);  \
    wa_t = SHA512_EXPAND (w8_t, w3_t, wb_t, wa_t);  \
    wb_t = SHA512_EXPAND (w9_t, w4_t, wc_t, wb_t);  \
    wc_t = SHA512_EXPAND (wa_t, w5_t, wd_t, wc_t);  \
    wd_t = SHA512_EXPAND (wb_t, w6_t, we_t, wd_t);  \
    we_t = SHA512_EXPAND (wc_t, w7_t, wf_t, we_t);  \
    wf_t = SHA512_EXPAND (wd_t, w8_t, w0_t, wf_t);  \
  }

  #define ROUND_STEP(i)                                                                   \
  {                                                                                       \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, k_sha512[i +  0]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, k_sha512[i +  1]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, k_sha512[i +  2]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, k_sha512[i +  3]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, k_sha512[i +  4]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, k_sha512[i +  5]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, k_sha512[i +  6]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, k_sha512[i +  7]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, k_sha512[i +  8]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, k_sha512[i +  9]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, k_sha512[i + 10]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, k_sha512[i + 11]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, k_sha512[i + 12]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, k_sha512[i + 13]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, k_sha512[i + 14]); \
    SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, k_sha512[i + 15]); \
  }

  ROUND_STEP (0);

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int i = 16; i < 80; i += 16)
  {
    ROUND_EXPAND (); ROUND_STEP (i);
  }

  /* rev
  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
  */

  digest[0] = a;
  digest[1] = b;
  digest[2] = c;
  digest[3] = d;
  digest[4] = e;
  digest[5] = f;
  digest[6] = g;
  digest[7] = h;
}

__kernel void m15000_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[salt_pos].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[salt_pos].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[salt_pos].salt_buf[10];
  salt_buf2[3] = salt_bufs[salt_pos].salt_buf[11];
  salt_buf3[0] = salt_bufs[salt_pos].salt_buf[12];
  salt_buf3[1] = salt_bufs[salt_pos].salt_buf[13];
  salt_buf3[2] = salt_bufs[salt_pos].salt_buf[14];
  salt_buf3[3] = salt_bufs[salt_pos].salt_buf[15];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * append salt
     */

    const u32x pw_salt_len = out_len + salt_len;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];
    u32x w4_t[4];
    u32x w5_t[4];
    u32x w6_t[4];
    u32x w7_t[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];
    w2_t[0] = salt_buf2[0];
    w2_t[1] = salt_buf2[1];
    w2_t[2] = salt_buf2[2];
    w2_t[3] = salt_buf2[3];
    w3_t[0] = salt_buf3[0];
    w3_t[1] = salt_buf3[1];
    w3_t[2] = salt_buf3[2];
    w3_t[3] = salt_buf3[3];
    w4_t[0] = 0x80;
    w4_t[1] = 0;
    w4_t[2] = 0;
    w4_t[3] = 0;
    w5_t[0] = 0;
    w5_t[1] = 0;
    w5_t[2] = 0;
    w5_t[3] = 0;
    w6_t[0] = 0;
    w6_t[1] = 0;
    w6_t[2] = 0;
    w6_t[3] = 0;
    w7_t[0] = 0;
    w7_t[1] = 0;
    w7_t[2] = 0;
    w7_t[3] = 0;

    switch_buffer_by_offset_8x4_le_VV (w0_t, w1_t, w2_t, w3_t, w4_t, w5_t, w6_t, w7_t, out_len);

    w0_t[0] |= w0[0];
    w0_t[1] |= w0[1];
    w0_t[2] |= w0[2];
    w0_t[3] |= w0[3];
    w1_t[0] |= w1[0];
    w1_t[1] |= w1[1];
    w1_t[2] |= w1[2];
    w1_t[3] |= w1[3];
    w2_t[0] |= w2[0];
    w2_t[1] |= w2[1];
    w2_t[2] |= w2[2];
    w2_t[3] |= w2[3];
    w3_t[0] |= w3[0];
    w3_t[1] |= w3[1];
    w3_t[2] |= w3[2];
    w3_t[3] |= w3[3];

    w0_t[0] = swap32 (w0_t[0]);
    w0_t[1] = swap32 (w0_t[1]);
    w0_t[2] = swap32 (w0_t[2]);
    w0_t[3] = swap32 (w0_t[3]);
    w1_t[0] = swap32 (w1_t[0]);
    w1_t[1] = swap32 (w1_t[1]);
    w1_t[2] = swap32 (w1_t[2]);
    w1_t[3] = swap32 (w1_t[3]);
    w2_t[0] = swap32 (w2_t[0]);
    w2_t[1] = swap32 (w2_t[1]);
    w2_t[2] = swap32 (w2_t[2]);
    w2_t[3] = swap32 (w2_t[3]);
    w3_t[0] = swap32 (w3_t[0]);
    w3_t[1] = swap32 (w3_t[1]);
    w3_t[2] = swap32 (w3_t[2]);
    w3_t[3] = swap32 (w3_t[3]);
    w4_t[0] = swap32 (w4_t[0]);
    w4_t[1] = swap32 (w4_t[1]);
    w4_t[2] = swap32 (w4_t[2]);
    w4_t[3] = swap32 (w4_t[3]);
    w5_t[0] = swap32 (w5_t[0]);
    w5_t[1] = swap32 (w5_t[1]);
    w5_t[2] = swap32 (w5_t[2]);
    w5_t[3] = swap32 (w5_t[3]);
    w6_t[0] = swap32 (w6_t[0]);
    w6_t[1] = swap32 (w6_t[1]);
    w6_t[2] = swap32 (w6_t[2]);
    w6_t[3] = swap32 (w6_t[3]);
    w7_t[0] = swap32 (w7_t[0]);
    w7_t[1] = swap32 (w7_t[1]);
    w7_t[2] = 0;
    w7_t[3] = pw_salt_len * 8;

    /**
     * sha512
     */

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform (w0_t, w1_t, w2_t, w3_t, w4_t, w5_t, w6_t, w7_t, digest);

    const u32x r0 = l32_from_64 (digest[7]);
    const u32x r1 = h32_from_64 (digest[7]);
    const u32x r2 = l32_from_64 (digest[3]);
    const u32x r3 = h32_from_64 (digest[3]);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

__kernel void m15000_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m15000_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m15000_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 lid = get_local_id (0);

  /**
   * base
   */

  const u32 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * salt
   */

  u32 salt_buf0[4];
  u32 salt_buf1[4];
  u32 salt_buf2[4];
  u32 salt_buf3[4];

  salt_buf0[0] = salt_bufs[salt_pos].salt_buf[ 0];
  salt_buf0[1] = salt_bufs[salt_pos].salt_buf[ 1];
  salt_buf0[2] = salt_bufs[salt_pos].salt_buf[ 2];
  salt_buf0[3] = salt_bufs[salt_pos].salt_buf[ 3];
  salt_buf1[0] = salt_bufs[salt_pos].salt_buf[ 4];
  salt_buf1[1] = salt_bufs[salt_pos].salt_buf[ 5];
  salt_buf1[2] = salt_bufs[salt_pos].salt_buf[ 6];
  salt_buf1[3] = salt_bufs[salt_pos].salt_buf[ 7];
  salt_buf2[0] = salt_bufs[salt_pos].salt_buf[ 8];
  salt_buf2[1] = salt_bufs[salt_pos].salt_buf[ 9];
  salt_buf2[2] = salt_bufs[salt_pos].salt_buf[10];
  salt_buf2[3] = salt_bufs[salt_pos].salt_buf[11];
  salt_buf3[0] = salt_bufs[salt_pos].salt_buf[12];
  salt_buf3[1] = salt_bufs[salt_pos].salt_buf[13];
  salt_buf3[2] = salt_bufs[salt_pos].salt_buf[14];
  salt_buf3[3] = salt_bufs[salt_pos].salt_buf[15];

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * append salt
     */

    const u32x pw_salt_len = out_len + salt_len;

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];
    u32x w4_t[4];
    u32x w5_t[4];
    u32x w6_t[4];
    u32x w7_t[4];

    w0_t[0] = salt_buf0[0];
    w0_t[1] = salt_buf0[1];
    w0_t[2] = salt_buf0[2];
    w0_t[3] = salt_buf0[3];
    w1_t[0] = salt_buf1[0];
    w1_t[1] = salt_buf1[1];
    w1_t[2] = salt_buf1[2];
    w1_t[3] = salt_buf1[3];
    w2_t[0] = salt_buf2[0];
    w2_t[1] = salt_buf2[1];
    w2_t[2] = salt_buf2[2];
    w2_t[3] = salt_buf2[3];
    w3_t[0] = salt_buf3[0];
    w3_t[1] = salt_buf3[1];
    w3_t[2] = salt_buf3[2];
    w3_t[3] = salt_buf3[3];
    w4_t[0] = 0x80;
    w4_t[1] = 0;
    w4_t[2] = 0;
    w4_t[3] = 0;
    w5_t[0] = 0;
    w5_t[1] = 0;
    w5_t[2] = 0;
    w5_t[3] = 0;
    w6_t[0] = 0;
    w6_t[1] = 0;
    w6_t[2] = 0;
    w6_t[3] = 0;
    w7_t[0] = 0;
    w7_t[1] = 0;
    w7_t[2] = 0;
    w7_t[3] = 0;

    switch_buffer_by_offset_8x4_le_VV (w0_t, w1_t, w2_t, w3_t, w4_t, w5_t, w6_t, w7_t, out_len);

    w0_t[0] |= w0[0];
    w0_t[1] |= w0[1];
    w0_t[2] |= w0[2];
    w0_t[3] |= w0[3];
    w1_t[0] |= w1[0];
    w1_t[1] |= w1[1];
    w1_t[2] |= w1[2];
    w1_t[3] |= w1[3];
    w2_t[0] |= w2[0];
    w2_t[1] |= w2[1];
    w2_t[2] |= w2[2];
    w2_t[3] |= w2[3];
    w3_t[0] |= w3[0];
    w3_t[1] |= w3[1];
    w3_t[2] |= w3[2];
    w3_t[3] |= w3[3];

    w0_t[0] = swap32 (w0_t[0]);
    w0_t[1] = swap32 (w0_t[1]);
    w0_t[2] = swap32 (w0_t[2]);
    w0_t[3] = swap32 (w0_t[3]);
    w1_t[0] = swap32 (w1_t[0]);
    w1_t[1] = swap32 (w1_t[1]);
    w1_t[2] = swap32 (w1_t[2]);
    w1_t[3] = swap32 (w1_t[3]);
    w2_t[0] = swap32 (w2_t[0]);
    w2_t[1] = swap32 (w2_t[1]);
    w2_t[2] = swap32 (w2_t[2]);
    w2_t[3] = swap32 (w2_t[3]);
    w3_t[0] = swap32 (w3_t[0]);
    w3_t[1] = swap32 (w3_t[1]);
    w3_t[2] = swap32 (w3_t[2]);
    w3_t[3] = swap32 (w3_t[3]);
    w4_t[0] = swap32 (w4_t[0]);
    w4_t[1] = swap32 (w4_t[1]);
    w4_t[2] = swap32 (w4_t[2]);
    w4_t[3] = swap32 (w4_t[3]);
    w5_t[0] = swap32 (w5_t[0]);
    w5_t[1] = swap32 (w5_t[1]);
    w5_t[2] = swap32 (w5_t[2]);
    w5_t[3] = swap32 (w5_t[3]);
    w6_t[0] = swap32 (w6_t[0]);
    w6_t[1] = swap32 (w6_t[1]);
    w6_t[2] = swap32 (w6_t[2]);
    w6_t[3] = swap32 (w6_t[3]);
    w7_t[0] = swap32 (w7_t[0]);
    w7_t[1] = swap32 (w7_t[1]);
    w7_t[2] = 0;
    w7_t[3] = pw_salt_len * 8;

    /**
     * sha512
     */

    u64x digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    sha512_transform (w0_t, w1_t, w2_t, w3_t, w4_t, w5_t, w6_t, w7_t, digest);

    const u32x r0 = l32_from_64 (digest[7]);
    const u32x r1 = h32_from_64 (digest[7]);
    const u32x r2 = l32_from_64 (digest[3]);
    const u32x r3 = h32_from_64 (digest[3]);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

__kernel void m15000_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m15000_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global const void *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
