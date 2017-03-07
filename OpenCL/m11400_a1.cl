/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible because of brances
//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i)])
#elif VECT_SIZE == 2
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1])
#elif VECT_SIZE == 4
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3])
#elif VECT_SIZE == 8
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7])
#elif VECT_SIZE == 16
#define uint_to_hex_lower8(i) (u32x) (l_bin2asc[(i).s0], l_bin2asc[(i).s1], l_bin2asc[(i).s2], l_bin2asc[(i).s3], l_bin2asc[(i).s4], l_bin2asc[(i).s5], l_bin2asc[(i).s6], l_bin2asc[(i).s7], l_bin2asc[(i).s8], l_bin2asc[(i).s9], l_bin2asc[(i).sa], l_bin2asc[(i).sb], l_bin2asc[(i).sc], l_bin2asc[(i).sd], l_bin2asc[(i).se], l_bin2asc[(i).sf])
#endif

u32 memcat32 (u32x block0[16], u32x block1[16], const u32 block_len, const u32x append0[4], const u32x append1[4], const u32x append2[4], const u32x append3[4], const u32 append_len)
{
  const u32 mod = block_len & 3;
  const u32 div = block_len / 4;

  #if defined IS_AMD || defined IS_GENERIC
  const int offset_minus_4 = 4 - mod;

  u32x append0_t[4];

  append0_t[0] = amd_bytealign (append0[0],          0, offset_minus_4);
  append0_t[1] = amd_bytealign (append0[1], append0[0], offset_minus_4);
  append0_t[2] = amd_bytealign (append0[2], append0[1], offset_minus_4);
  append0_t[3] = amd_bytealign (append0[3], append0[2], offset_minus_4);

  u32x append1_t[4];

  append1_t[0] = amd_bytealign (append1[0], append0[3], offset_minus_4);
  append1_t[1] = amd_bytealign (append1[1], append1[0], offset_minus_4);
  append1_t[2] = amd_bytealign (append1[2], append1[1], offset_minus_4);
  append1_t[3] = amd_bytealign (append1[3], append1[2], offset_minus_4);

  u32x append2_t[4];

  append2_t[0] = amd_bytealign (append2[0], append1[3], offset_minus_4);
  append2_t[1] = amd_bytealign (append2[1], append2[0], offset_minus_4);
  append2_t[2] = amd_bytealign (append2[2], append2[1], offset_minus_4);
  append2_t[3] = amd_bytealign (append2[3], append2[2], offset_minus_4);

  u32x append3_t[4];

  append3_t[0] = amd_bytealign (append3[0], append2[3], offset_minus_4);
  append3_t[1] = amd_bytealign (append3[1], append3[0], offset_minus_4);
  append3_t[2] = amd_bytealign (append3[2], append3[1], offset_minus_4);
  append3_t[3] = amd_bytealign (append3[3], append3[2], offset_minus_4);

  u32x append4_t[4];

  append4_t[0] = amd_bytealign (         0, append3[3], offset_minus_4);
  append4_t[1] = 0;
  append4_t[2] = 0;
  append4_t[3] = 0;

  if (mod == 0)
  {
    append0_t[0] = append0[0];
    append0_t[1] = append0[1];
    append0_t[2] = append0[2];
    append0_t[3] = append0[3];

    append1_t[0] = append1[0];
    append1_t[1] = append1[1];
    append1_t[2] = append1[2];
    append1_t[3] = append1[3];

    append2_t[0] = append2[0];
    append2_t[1] = append2[1];
    append2_t[2] = append2[2];
    append2_t[3] = append2[3];

    append3_t[0] = append3[0];
    append3_t[1] = append3[1];
    append3_t[2] = append3[2];
    append3_t[3] = append3[3];

    append4_t[0] = 0;
    append4_t[1] = 0;
    append4_t[2] = 0;
    append4_t[3] = 0;
  }
  #endif

  #ifdef IS_NV

  const int offset_minus_4 = 4 - mod;

  const int selector = (0x76543210 >> (offset_minus_4 * 4)) & 0xffff;

  u32x append0_t[4];

  append0_t[0] = __byte_perm (         0, append0[0], selector);
  append0_t[1] = __byte_perm (append0[0], append0[1], selector);
  append0_t[2] = __byte_perm (append0[1], append0[2], selector);
  append0_t[3] = __byte_perm (append0[2], append0[3], selector);

  u32x append1_t[4];

  append1_t[0] = __byte_perm (append0[3], append1[0], selector);
  append1_t[1] = __byte_perm (append1[0], append1[1], selector);
  append1_t[2] = __byte_perm (append1[1], append1[2], selector);
  append1_t[3] = __byte_perm (append1[2], append1[3], selector);

  u32x append2_t[4];

  append2_t[0] = __byte_perm (append1[3], append2[0], selector);
  append2_t[1] = __byte_perm (append2[0], append2[1], selector);
  append2_t[2] = __byte_perm (append2[1], append2[2], selector);
  append2_t[3] = __byte_perm (append2[2], append2[3], selector);

  u32x append3_t[4];

  append3_t[0] = __byte_perm (append2[3], append3[0], selector);
  append3_t[1] = __byte_perm (append3[0], append3[1], selector);
  append3_t[2] = __byte_perm (append3[1], append3[2], selector);
  append3_t[3] = __byte_perm (append3[2], append3[3], selector);

  u32x append4_t[4];

  append4_t[0] = __byte_perm (append3[3],          0, selector);
  append4_t[1] = 0;
  append4_t[2] = 0;
  append4_t[3] = 0;
  #endif

  switch (div)
  {
    case  0:  block0[ 0] |= append0_t[0];
              block0[ 1]  = append0_t[1];
              block0[ 2]  = append0_t[2];
              block0[ 3]  = append0_t[3];

              block0[ 4]  = append1_t[0];
              block0[ 5]  = append1_t[1];
              block0[ 6]  = append1_t[2];
              block0[ 7]  = append1_t[3];

              block0[ 8]  = append2_t[0];
              block0[ 9]  = append2_t[1];
              block0[10]  = append2_t[2];
              block0[11]  = append2_t[3];

              block0[12]  = append3_t[0];
              block0[13]  = append3_t[1];
              block0[14]  = append3_t[2];
              block0[15]  = append3_t[3];

              block1[ 0]  = append4_t[0];
              block1[ 1]  = append4_t[1];
              block1[ 2]  = append4_t[2];
              block1[ 3]  = append4_t[3];
              break;

    case  1:  block0[ 1] |= append0_t[0];
              block0[ 2]  = append0_t[1];
              block0[ 3]  = append0_t[2];
              block0[ 4]  = append0_t[3];

              block0[ 5]  = append1_t[0];
              block0[ 6]  = append1_t[1];
              block0[ 7]  = append1_t[2];
              block0[ 8]  = append1_t[3];

              block0[ 9]  = append2_t[0];
              block0[10]  = append2_t[1];
              block0[11]  = append2_t[2];
              block0[12]  = append2_t[3];

              block0[13]  = append3_t[0];
              block0[14]  = append3_t[1];
              block0[15]  = append3_t[2];
              block1[ 0]  = append3_t[3];

              block1[ 1]  = append4_t[0];
              block1[ 2]  = append4_t[1];
              block1[ 3]  = append4_t[2];
              block1[ 4]  = append4_t[3];
              break;

    case  2:  block0[ 2] |= append0_t[0];
              block0[ 3]  = append0_t[1];
              block0[ 4]  = append0_t[2];
              block0[ 5]  = append0_t[3];

              block0[ 6]  = append1_t[0];
              block0[ 7]  = append1_t[1];
              block0[ 8]  = append1_t[2];
              block0[ 9]  = append1_t[3];

              block0[10]  = append2_t[0];
              block0[11]  = append2_t[1];
              block0[12]  = append2_t[2];
              block0[13]  = append2_t[3];

              block0[14]  = append3_t[0];
              block0[15]  = append3_t[1];
              block1[ 0]  = append3_t[2];
              block1[ 1]  = append3_t[3];

              block1[ 2]  = append4_t[0];
              block1[ 3]  = append4_t[1];
              block1[ 4]  = append4_t[2];
              block1[ 5]  = append4_t[3];
              break;

    case  3:  block0[ 3] |= append0_t[0];
              block0[ 4]  = append0_t[1];
              block0[ 5]  = append0_t[2];
              block0[ 6]  = append0_t[3];

              block0[ 7]  = append1_t[0];
              block0[ 8]  = append1_t[1];
              block0[ 9]  = append1_t[2];
              block0[10]  = append1_t[3];

              block0[11]  = append2_t[0];
              block0[12]  = append2_t[1];
              block0[13]  = append2_t[2];
              block0[14]  = append2_t[3];

              block0[15]  = append3_t[0];
              block1[ 0]  = append3_t[1];
              block1[ 1]  = append3_t[2];
              block1[ 2]  = append3_t[3];

              block1[ 3]  = append4_t[0];
              block1[ 4]  = append4_t[1];
              block1[ 5]  = append4_t[2];
              block1[ 6]  = append4_t[3];
              break;

    case  4:  block0[ 4] |= append0_t[0];
              block0[ 5]  = append0_t[1];
              block0[ 6]  = append0_t[2];
              block0[ 7]  = append0_t[3];

              block0[ 8]  = append1_t[0];
              block0[ 9]  = append1_t[1];
              block0[10]  = append1_t[2];
              block0[11]  = append1_t[3];

              block0[12]  = append2_t[0];
              block0[13]  = append2_t[1];
              block0[14]  = append2_t[2];
              block0[15]  = append2_t[3];

              block1[ 0]  = append3_t[0];
              block1[ 1]  = append3_t[1];
              block1[ 2]  = append3_t[2];
              block1[ 3]  = append3_t[3];

              block1[ 4]  = append4_t[0];
              block1[ 5]  = append4_t[1];
              block1[ 6]  = append4_t[2];
              block1[ 7]  = append4_t[3];
              break;

    case  5:  block0[ 5] |= append0_t[0];
              block0[ 6]  = append0_t[1];
              block0[ 7]  = append0_t[2];
              block0[ 8]  = append0_t[3];

              block0[ 9]  = append1_t[0];
              block0[10]  = append1_t[1];
              block0[11]  = append1_t[2];
              block0[12]  = append1_t[3];

              block0[13]  = append2_t[0];
              block0[14]  = append2_t[1];
              block0[15]  = append2_t[2];
              block1[ 0]  = append2_t[3];

              block1[ 1]  = append3_t[0];
              block1[ 2]  = append3_t[1];
              block1[ 3]  = append3_t[2];
              block1[ 4]  = append3_t[3];

              block1[ 5]  = append4_t[0];
              block1[ 6]  = append4_t[1];
              block1[ 7]  = append4_t[2];
              block1[ 8]  = append4_t[3];
              break;

    case  6:  block0[ 6] |= append0_t[0];
              block0[ 7]  = append0_t[1];
              block0[ 8]  = append0_t[2];
              block0[ 9]  = append0_t[3];

              block0[10]  = append1_t[0];
              block0[11]  = append1_t[1];
              block0[12]  = append1_t[2];
              block0[13]  = append1_t[3];

              block0[14]  = append2_t[0];
              block0[15]  = append2_t[1];
              block1[ 0]  = append2_t[2];
              block1[ 1]  = append2_t[3];

              block1[ 2]  = append3_t[0];
              block1[ 3]  = append3_t[1];
              block1[ 4]  = append3_t[2];
              block1[ 5]  = append3_t[3];

              block1[ 6]  = append4_t[0];
              block1[ 7]  = append4_t[1];
              block1[ 8]  = append4_t[2];
              block1[ 9]  = append4_t[3];
              break;

    case  7:  block0[ 7] |= append0_t[0];
              block0[ 8]  = append0_t[1];
              block0[ 9]  = append0_t[2];
              block0[10]  = append0_t[3];

              block0[11]  = append1_t[0];
              block0[12]  = append1_t[1];
              block0[13]  = append1_t[2];
              block0[14]  = append1_t[3];

              block0[15]  = append2_t[0];
              block1[ 0]  = append2_t[1];
              block1[ 1]  = append2_t[2];
              block1[ 2]  = append2_t[3];

              block1[ 3]  = append3_t[0];
              block1[ 4]  = append3_t[1];
              block1[ 5]  = append3_t[2];
              block1[ 6]  = append3_t[3];

              block1[ 7]  = append4_t[0];
              block1[ 8]  = append4_t[1];
              block1[ 9]  = append4_t[2];
              block1[10]  = append4_t[3];
              break;

    case  8:  block0[ 8] |= append0_t[0];
              block0[ 9]  = append0_t[1];
              block0[10]  = append0_t[2];
              block0[11]  = append0_t[3];

              block0[12]  = append1_t[0];
              block0[13]  = append1_t[1];
              block0[14]  = append1_t[2];
              block0[15]  = append1_t[3];

              block1[ 0]  = append2_t[0];
              block1[ 1]  = append2_t[1];
              block1[ 2]  = append2_t[2];
              block1[ 3]  = append2_t[3];

              block1[ 4]  = append3_t[0];
              block1[ 5]  = append3_t[1];
              block1[ 6]  = append3_t[2];
              block1[ 7]  = append3_t[3];

              block1[ 8]  = append4_t[0];
              block1[ 9]  = append4_t[1];
              block1[10]  = append4_t[2];
              block1[11]  = append4_t[3];
              break;

    case  9:  block0[ 9] |= append0_t[0];
              block0[10]  = append0_t[1];
              block0[11]  = append0_t[2];
              block0[12]  = append0_t[3];

              block0[13]  = append1_t[0];
              block0[14]  = append1_t[1];
              block0[15]  = append1_t[2];
              block1[ 0]  = append1_t[3];

              block1[ 1]  = append2_t[0];
              block1[ 2]  = append2_t[1];
              block1[ 3]  = append2_t[2];
              block1[ 4]  = append2_t[3];

              block1[ 5]  = append3_t[0];
              block1[ 6]  = append3_t[1];
              block1[ 7]  = append3_t[2];
              block1[ 8]  = append3_t[3];

              block1[ 9]  = append4_t[0];
              block1[10]  = append4_t[1];
              block1[11]  = append4_t[2];
              block1[12]  = append4_t[3];
              break;

    case 10:  block0[10] |= append0_t[0];
              block0[11]  = append0_t[1];
              block0[12]  = append0_t[2];
              block0[13]  = append0_t[3];

              block0[14]  = append1_t[0];
              block0[15]  = append1_t[1];
              block1[ 0]  = append1_t[2];
              block1[ 1]  = append1_t[3];

              block1[ 2]  = append2_t[0];
              block1[ 3]  = append2_t[1];
              block1[ 4]  = append2_t[2];
              block1[ 5]  = append2_t[3];

              block1[ 6]  = append3_t[0];
              block1[ 7]  = append3_t[1];
              block1[ 8]  = append3_t[2];
              block1[ 9]  = append3_t[3];

              block1[10]  = append4_t[0];
              block1[11]  = append4_t[1];
              block1[12]  = append4_t[2];
              block1[13]  = append4_t[3];
              break;

    case 11:  block0[11] |= append0_t[0];
              block0[12]  = append0_t[1];
              block0[13]  = append0_t[2];
              block0[14]  = append0_t[3];

              block0[15]  = append1_t[0];
              block1[ 0]  = append1_t[1];
              block1[ 1]  = append1_t[2];
              block1[ 2]  = append1_t[3];

              block1[ 3]  = append2_t[0];
              block1[ 4]  = append2_t[1];
              block1[ 5]  = append2_t[2];
              block1[ 6]  = append2_t[3];

              block1[ 7]  = append3_t[0];
              block1[ 8]  = append3_t[1];
              block1[ 9]  = append3_t[2];
              block1[10]  = append3_t[3];

              block1[11]  = append4_t[0];
              block1[12]  = append4_t[1];
              block1[13]  = append4_t[2];
              block1[14]  = append4_t[3];
              break;

    case 12:  block0[12] |= append0_t[0];
              block0[13]  = append0_t[1];
              block0[14]  = append0_t[2];
              block0[15]  = append0_t[3];

              block1[ 0]  = append1_t[0];
              block1[ 1]  = append1_t[1];
              block1[ 2]  = append1_t[2];
              block1[ 3]  = append1_t[3];

              block1[ 4]  = append2_t[0];
              block1[ 5]  = append2_t[1];
              block1[ 6]  = append2_t[2];
              block1[ 7]  = append2_t[3];

              block1[ 8]  = append3_t[0];
              block1[ 9]  = append3_t[1];
              block1[10]  = append3_t[2];
              block1[11]  = append3_t[3];

              block1[12]  = append4_t[0];
              block1[13]  = append4_t[1];
              block1[14]  = append4_t[2];
              block1[15]  = append4_t[3];
              break;

    case 13:  block0[13] |= append0_t[0];
              block0[14]  = append0_t[1];
              block0[15]  = append0_t[2];
              block1[ 0]  = append0_t[3];

              block1[ 1]  = append1_t[0];
              block1[ 2]  = append1_t[1];
              block1[ 3]  = append1_t[2];
              block1[ 4]  = append1_t[3];

              block1[ 5]  = append2_t[0];
              block1[ 6]  = append2_t[1];
              block1[ 7]  = append2_t[2];
              block1[ 8]  = append2_t[3];

              block1[ 9]  = append3_t[0];
              block1[10]  = append3_t[1];
              block1[11]  = append3_t[2];
              block1[12]  = append3_t[3];

              block1[13]  = append4_t[0];
              block1[14]  = append4_t[1];
              block1[15]  = append4_t[2];
              break;

    case 14:  block0[14] |= append0_t[0];
              block0[15]  = append0_t[1];
              block1[ 0]  = append0_t[2];
              block1[ 1]  = append0_t[3];

              block1[ 2]  = append1_t[0];
              block1[ 3]  = append1_t[1];
              block1[ 4]  = append1_t[2];
              block1[ 5]  = append1_t[3];

              block1[ 6]  = append2_t[0];
              block1[ 7]  = append2_t[1];
              block1[ 8]  = append2_t[2];
              block1[ 9]  = append2_t[3];

              block1[10]  = append3_t[0];
              block1[11]  = append3_t[1];
              block1[12]  = append3_t[2];
              block1[13]  = append3_t[3];

              block1[14]  = append4_t[0];
              block1[15]  = append4_t[1];
              break;

    case 15:  block0[15] |= append0_t[0];
              block1[ 0]  = append0_t[1];
              block1[ 1]  = append0_t[2];
              block1[ 2]  = append0_t[3];

              block1[ 3]  = append1_t[1];
              block1[ 4]  = append1_t[2];
              block1[ 5]  = append1_t[3];
              block1[ 6]  = append1_t[0];

              block1[ 7]  = append2_t[0];
              block1[ 8]  = append2_t[1];
              block1[ 9]  = append2_t[2];
              block1[10]  = append2_t[3];

              block1[11]  = append3_t[0];
              block1[12]  = append3_t[1];
              block1[13]  = append3_t[2];
              block1[14]  = append3_t[3];

              block1[15]  = append4_t[0];
              break;

    case 16:  block1[ 0] |= append0_t[0];
              block1[ 1]  = append0_t[1];
              block1[ 2]  = append0_t[2];
              block1[ 3]  = append0_t[3];

              block1[ 4]  = append1_t[0];
              block1[ 5]  = append1_t[1];
              block1[ 6]  = append1_t[2];
              block1[ 7]  = append1_t[3];

              block1[ 8]  = append2_t[0];
              block1[ 9]  = append2_t[1];
              block1[10]  = append2_t[2];
              block1[11]  = append2_t[3];

              block1[12]  = append3_t[0];
              block1[13]  = append3_t[1];
              block1[14]  = append3_t[2];
              block1[15]  = append3_t[3];
              break;

    case 17:  block1[ 1] |= append0_t[0];
              block1[ 2]  = append0_t[1];
              block1[ 3]  = append0_t[2];
              block1[ 4]  = append0_t[3];

              block1[ 5]  = append1_t[0];
              block1[ 6]  = append1_t[1];
              block1[ 7]  = append1_t[2];
              block1[ 8]  = append1_t[3];

              block1[ 9]  = append2_t[0];
              block1[10]  = append2_t[1];
              block1[11]  = append2_t[2];
              block1[12]  = append2_t[3];

              block1[13]  = append3_t[0];
              block1[14]  = append3_t[1];
              block1[15]  = append3_t[2];
              break;

    case 18:  block1[ 2] |= append0_t[0];
              block1[ 3]  = append0_t[1];
              block1[ 4]  = append0_t[2];
              block1[ 5]  = append0_t[3];

              block1[ 6]  = append1_t[0];
              block1[ 7]  = append1_t[1];
              block1[ 8]  = append1_t[2];
              block1[ 9]  = append1_t[3];

              block1[10]  = append2_t[0];
              block1[11]  = append2_t[1];
              block1[12]  = append2_t[2];
              block1[13]  = append2_t[3];

              block1[14]  = append3_t[0];
              block1[15]  = append3_t[1];
              break;

    case 19:  block1[ 3] |= append0_t[0];
              block1[ 4]  = append0_t[1];
              block1[ 5]  = append0_t[2];
              block1[ 6]  = append0_t[3];

              block1[ 7]  = append1_t[0];
              block1[ 8]  = append1_t[1];
              block1[ 9]  = append1_t[2];
              block1[10]  = append1_t[3];

              block1[11]  = append2_t[0];
              block1[12]  = append2_t[1];
              block1[13]  = append2_t[2];
              block1[14]  = append2_t[3];

              block1[15]  = append3_t[0];
              break;

    case 20:  block1[ 4] |= append0_t[0];
              block1[ 5]  = append0_t[1];
              block1[ 6]  = append0_t[2];
              block1[ 7]  = append0_t[3];

              block1[ 8]  = append1_t[0];
              block1[ 9]  = append1_t[1];
              block1[10]  = append1_t[2];
              block1[11]  = append1_t[3];

              block1[12]  = append2_t[0];
              block1[13]  = append2_t[1];
              block1[14]  = append2_t[2];
              block1[15]  = append2_t[3];
              break;

    case 21:  block1[ 5] |= append0_t[0];
              block1[ 6]  = append0_t[1];
              block1[ 7]  = append0_t[2];
              block1[ 8]  = append0_t[3];

              block1[ 9]  = append1_t[0];
              block1[10]  = append1_t[1];
              block1[11]  = append1_t[2];
              block1[12]  = append1_t[3];

              block1[13]  = append2_t[0];
              block1[14]  = append2_t[1];
              block1[15]  = append2_t[2];
              break;

    case 22:  block1[ 6] |= append0_t[0];
              block1[ 7]  = append0_t[1];
              block1[ 8]  = append0_t[2];
              block1[ 9]  = append0_t[3];

              block1[10]  = append1_t[0];
              block1[11]  = append1_t[1];
              block1[12]  = append1_t[2];
              block1[13]  = append1_t[3];

              block1[14]  = append2_t[0];
              block1[15]  = append2_t[1];
              break;

    case 23:  block1[ 7] |= append0_t[0];
              block1[ 8]  = append0_t[1];
              block1[ 9]  = append0_t[2];
              block1[10]  = append0_t[3];

              block1[11]  = append1_t[0];
              block1[12]  = append1_t[1];
              block1[13]  = append1_t[2];
              block1[14]  = append1_t[3];

              block1[15]  = append2_t[0];
              break;

    case 24:  block1[ 8] |= append0_t[0];
              block1[ 9]  = append0_t[1];
              block1[10]  = append0_t[2];
              block1[11]  = append0_t[3];

              block1[12]  = append1_t[0];
              block1[13]  = append1_t[1];
              block1[14]  = append1_t[2];
              block1[15]  = append1_t[3];
              break;

    case 25:  block1[ 9] |= append0_t[0];
              block1[10]  = append0_t[1];
              block1[11]  = append0_t[2];
              block1[12]  = append0_t[3];

              block1[13]  = append1_t[0];
              block1[14]  = append1_t[1];
              block1[15]  = append1_t[2];
              break;

    case 26:  block1[10] |= append0_t[0];
              block1[11]  = append0_t[1];
              block1[12]  = append0_t[2];
              block1[13]  = append0_t[3];

              block1[14]  = append1_t[0];
              block1[15]  = append1_t[1];
              break;

    case 27:  block1[11] |= append0_t[0];
              block1[12]  = append0_t[1];
              block1[13]  = append0_t[2];
              block1[14]  = append0_t[3];

              block1[15]  = append1_t[0];
              break;

    case 28:  block1[12] |= append0_t[0];
              block1[13]  = append0_t[1];
              block1[14]  = append0_t[2];
              block1[15]  = append0_t[3];
              break;

    case 29:  block1[13] |= append0_t[0];
              block1[14]  = append0_t[1];
              block1[15]  = append0_t[2];
              break;

    case 30:  block1[14] |= append0_t[0];
              block1[15]  = append0_t[1];
              break;
  }

  u32 new_len = block_len + append_len;

  return new_len;
}

__kernel void m11400_m04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global sip_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

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

  const u32 pw_l_len = pws[gid].pw_len;

  /**
   * salt
   */

  const u32 salt_len = esalt_bufs[digests_offset].salt_len; // not a bug, we need to get it from the esalt

  u32 salt_buf0[16];
  u32 salt_buf1[16];

  salt_buf0[ 0] = esalt_bufs[digests_offset].salt_buf[ 0];
  salt_buf0[ 1] = esalt_bufs[digests_offset].salt_buf[ 1];
  salt_buf0[ 2] = esalt_bufs[digests_offset].salt_buf[ 2];
  salt_buf0[ 3] = esalt_bufs[digests_offset].salt_buf[ 3];
  salt_buf0[ 4] = esalt_bufs[digests_offset].salt_buf[ 4];
  salt_buf0[ 5] = esalt_bufs[digests_offset].salt_buf[ 5];
  salt_buf0[ 6] = esalt_bufs[digests_offset].salt_buf[ 6];
  salt_buf0[ 7] = esalt_bufs[digests_offset].salt_buf[ 7];
  salt_buf0[ 8] = esalt_bufs[digests_offset].salt_buf[ 8];
  salt_buf0[ 9] = esalt_bufs[digests_offset].salt_buf[ 9];
  salt_buf0[10] = esalt_bufs[digests_offset].salt_buf[10];
  salt_buf0[11] = esalt_bufs[digests_offset].salt_buf[11];
  salt_buf0[12] = esalt_bufs[digests_offset].salt_buf[12];
  salt_buf0[13] = esalt_bufs[digests_offset].salt_buf[13];
  salt_buf0[14] = esalt_bufs[digests_offset].salt_buf[14];
  salt_buf0[15] = esalt_bufs[digests_offset].salt_buf[15];
  salt_buf1[ 0] = esalt_bufs[digests_offset].salt_buf[16];
  salt_buf1[ 1] = esalt_bufs[digests_offset].salt_buf[17];
  salt_buf1[ 2] = esalt_bufs[digests_offset].salt_buf[18];
  salt_buf1[ 3] = esalt_bufs[digests_offset].salt_buf[19];
  salt_buf1[ 4] = esalt_bufs[digests_offset].salt_buf[20];
  salt_buf1[ 5] = esalt_bufs[digests_offset].salt_buf[21];
  salt_buf1[ 6] = esalt_bufs[digests_offset].salt_buf[22];
  salt_buf1[ 7] = esalt_bufs[digests_offset].salt_buf[23];
  salt_buf1[ 8] = esalt_bufs[digests_offset].salt_buf[24];
  salt_buf1[ 9] = esalt_bufs[digests_offset].salt_buf[25];
  salt_buf1[10] = esalt_bufs[digests_offset].salt_buf[26];
  salt_buf1[11] = esalt_bufs[digests_offset].salt_buf[27];
  salt_buf1[12] = esalt_bufs[digests_offset].salt_buf[28];
  salt_buf1[13] = esalt_bufs[digests_offset].salt_buf[29];
  salt_buf1[14] = 0;
  salt_buf1[15] = 0;

  /**
   * esalt
   */

  const u32 esalt_len = esalt_bufs[digests_offset].esalt_len;

  u32 esalt_buf0[16];
  u32 esalt_buf1[16];
  u32 esalt_buf2[16];

  esalt_buf0[ 0] = esalt_bufs[digests_offset].esalt_buf[ 0];
  esalt_buf0[ 1] = esalt_bufs[digests_offset].esalt_buf[ 1];
  esalt_buf0[ 2] = esalt_bufs[digests_offset].esalt_buf[ 2];
  esalt_buf0[ 3] = esalt_bufs[digests_offset].esalt_buf[ 3];
  esalt_buf0[ 4] = esalt_bufs[digests_offset].esalt_buf[ 4];
  esalt_buf0[ 5] = esalt_bufs[digests_offset].esalt_buf[ 5];
  esalt_buf0[ 6] = esalt_bufs[digests_offset].esalt_buf[ 6];
  esalt_buf0[ 7] = esalt_bufs[digests_offset].esalt_buf[ 7];
  esalt_buf0[ 8] = esalt_bufs[digests_offset].esalt_buf[ 8];
  esalt_buf0[ 9] = esalt_bufs[digests_offset].esalt_buf[ 9];
  esalt_buf0[10] = esalt_bufs[digests_offset].esalt_buf[10];
  esalt_buf0[11] = esalt_bufs[digests_offset].esalt_buf[11];
  esalt_buf0[12] = esalt_bufs[digests_offset].esalt_buf[12];
  esalt_buf0[13] = esalt_bufs[digests_offset].esalt_buf[13];
  esalt_buf0[14] = esalt_bufs[digests_offset].esalt_buf[14];
  esalt_buf0[15] = esalt_bufs[digests_offset].esalt_buf[15];
  esalt_buf1[ 0] = esalt_bufs[digests_offset].esalt_buf[16];
  esalt_buf1[ 1] = esalt_bufs[digests_offset].esalt_buf[17];
  esalt_buf1[ 2] = esalt_bufs[digests_offset].esalt_buf[18];
  esalt_buf1[ 3] = esalt_bufs[digests_offset].esalt_buf[19];
  esalt_buf1[ 4] = esalt_bufs[digests_offset].esalt_buf[20];
  esalt_buf1[ 5] = esalt_bufs[digests_offset].esalt_buf[21];
  esalt_buf1[ 6] = esalt_bufs[digests_offset].esalt_buf[22];
  esalt_buf1[ 7] = esalt_bufs[digests_offset].esalt_buf[23];
  esalt_buf1[ 8] = esalt_bufs[digests_offset].esalt_buf[24];
  esalt_buf1[ 9] = esalt_bufs[digests_offset].esalt_buf[25];
  esalt_buf1[10] = esalt_bufs[digests_offset].esalt_buf[26];
  esalt_buf1[11] = esalt_bufs[digests_offset].esalt_buf[27];
  esalt_buf1[12] = esalt_bufs[digests_offset].esalt_buf[28];
  esalt_buf1[13] = esalt_bufs[digests_offset].esalt_buf[29];
  esalt_buf1[14] = esalt_bufs[digests_offset].esalt_buf[30];
  esalt_buf1[15] = esalt_bufs[digests_offset].esalt_buf[31];
  esalt_buf2[ 0] = esalt_bufs[digests_offset].esalt_buf[32];
  esalt_buf2[ 1] = esalt_bufs[digests_offset].esalt_buf[33];
  esalt_buf2[ 2] = esalt_bufs[digests_offset].esalt_buf[34];
  esalt_buf2[ 3] = esalt_bufs[digests_offset].esalt_buf[35];
  esalt_buf2[ 4] = esalt_bufs[digests_offset].esalt_buf[36];
  esalt_buf2[ 5] = esalt_bufs[digests_offset].esalt_buf[37];
  esalt_buf2[ 6] = 0;
  esalt_buf2[ 7] = 0;
  esalt_buf2[ 8] = 0;
  esalt_buf2[ 9] = 0;
  esalt_buf2[10] = 0;
  esalt_buf2[11] = 0;
  esalt_buf2[12] = 0;
  esalt_buf2[13] = 0;
  esalt_buf2[14] = 0;
  esalt_buf2[15] = 0;

  const u32 digest_esalt_len = 32 + esalt_len;
  const u32 remaining_bytes  = digest_esalt_len + 1 - 64; // substract previous block

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos);

    const u32x pw_len = pw_l_len + pw_r_len;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    const u32x pw_salt_len = salt_len + pw_len;

    /*
     * HA1 = md5 ($salt . $pass)
     */

    // append the pass to the salt

    u32x block0[16];
    u32x block1[16];

    block0[ 0] = salt_buf0[ 0];
    block0[ 1] = salt_buf0[ 1];
    block0[ 2] = salt_buf0[ 2];
    block0[ 3] = salt_buf0[ 3];
    block0[ 4] = salt_buf0[ 4];
    block0[ 5] = salt_buf0[ 5];
    block0[ 6] = salt_buf0[ 6];
    block0[ 7] = salt_buf0[ 7];
    block0[ 8] = salt_buf0[ 8];
    block0[ 9] = salt_buf0[ 9];
    block0[10] = salt_buf0[10];
    block0[11] = salt_buf0[11];
    block0[12] = salt_buf0[12];
    block0[13] = salt_buf0[13];
    block0[14] = salt_buf0[14];
    block0[15] = salt_buf0[15];
    block1[ 0] = salt_buf1[ 0];
    block1[ 1] = salt_buf1[ 1];
    block1[ 2] = salt_buf1[ 2];
    block1[ 3] = salt_buf1[ 3];
    block1[ 4] = salt_buf1[ 4];
    block1[ 5] = salt_buf1[ 5];
    block1[ 6] = salt_buf1[ 6];
    block1[ 7] = salt_buf1[ 7];
    block1[ 8] = salt_buf1[ 8];
    block1[ 9] = salt_buf1[ 9];
    block1[10] = salt_buf1[10];
    block1[11] = salt_buf1[11];
    block1[12] = salt_buf1[12];
    block1[13] = salt_buf1[13];
    block1[14] = salt_buf1[14];
    block1[15] = salt_buf1[15];

    u32 block_len = 0;

    block_len = memcat32 (block0, block1, salt_len, w0, w1, w2, w3, pw_len);

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = block0[ 0];
    w0_t[1] = block0[ 1];
    w0_t[2] = block0[ 2];
    w0_t[3] = block0[ 3];
    w1_t[0] = block0[ 4];
    w1_t[1] = block0[ 5];
    w1_t[2] = block0[ 6];
    w1_t[3] = block0[ 7];
    w2_t[0] = block0[ 8];
    w2_t[1] = block0[ 9];
    w2_t[2] = block0[10];
    w2_t[3] = block0[11];
    w3_t[0] = block0[12];
    w3_t[1] = block0[13];
    w3_t[2] = block0[14];
    w3_t[3] = block0[15];

    if (block_len < 56)
    {
      w3_t[2] = pw_salt_len * 8;
    }

    // md5

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    if (block_len > 55)
    {
      u32x r_a = a;
      u32x r_b = b;
      u32x r_c = c;
      u32x r_d = d;

      w0_t[0] = block1[ 0];
      w0_t[1] = block1[ 1];
      w0_t[2] = block1[ 2];
      w0_t[3] = block1[ 3];
      w1_t[0] = block1[ 4];
      w1_t[1] = block1[ 5];
      w1_t[2] = block1[ 6];
      w1_t[3] = block1[ 7];
      w2_t[0] = block1[ 8];
      w2_t[1] = block1[ 9];
      w2_t[2] = block1[10];
      w2_t[3] = block1[11];
      w3_t[0] = block1[12];
      w3_t[1] = block1[13];
      w3_t[2] = pw_salt_len * 8;
      w3_t[3] = 0;

      MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

      MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

      MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

      MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

      a += r_a;
      b += r_b;
      c += r_c;
      d += r_d;
    }

    /*
     * final = md5 ($HA1 . $esalt)
     * we have at least 2 MD5 blocks/transformations, but we might need 3
     */

    w0_t[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
    w0_t[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
    w0_t[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
    w0_t[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
    w1_t[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
    w1_t[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
    w1_t[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
    w1_t[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((d >> 24) & 255) << 16;
    w2_t[0] = esalt_buf0[0];
    w2_t[1] = esalt_buf0[1];
    w2_t[2] = esalt_buf0[2];
    w2_t[3] = esalt_buf0[3];
    w3_t[0] = esalt_buf0[4];
    w3_t[1] = esalt_buf0[5];
    w3_t[2] = esalt_buf0[6];
    w3_t[3] = esalt_buf0[7];

    // md5
    // 1st transform

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    u32x r_a = a;
    u32x r_b = b;
    u32x r_c = c;
    u32x r_d = d;

    // 2nd transform

    w0_t[0] = esalt_buf0[ 8];
    w0_t[1] = esalt_buf0[ 9];
    w0_t[2] = esalt_buf0[10];
    w0_t[3] = esalt_buf0[11];
    w1_t[0] = esalt_buf0[12];
    w1_t[1] = esalt_buf0[13];
    w1_t[2] = esalt_buf0[14];
    w1_t[3] = esalt_buf0[15];
    w2_t[0] = esalt_buf1[ 0];
    w2_t[1] = esalt_buf1[ 1];
    w2_t[2] = esalt_buf1[ 2];
    w2_t[3] = esalt_buf1[ 3];
    w3_t[0] = esalt_buf1[ 4];
    w3_t[1] = esalt_buf1[ 5];
    w3_t[2] = esalt_buf1[ 6];
    w3_t[3] = esalt_buf1[ 7];

    // it is the final block when no more than 55 bytes left

    if (remaining_bytes < 56)
    {
      // it is the last block !

      w3_t[2] = digest_esalt_len * 8;
    }

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    // sometimes (not rare at all) we need a third block :(

    if (remaining_bytes > 55)
    {
      // this is for sure the final block

      a += r_a;
      b += r_b;
      c += r_c;
      d += r_d;

      r_a = a;
      r_b = b;
      r_c = c;
      r_d = d;

      w0_t[0] = esalt_buf1[ 8];
      w0_t[1] = esalt_buf1[ 9];
      w0_t[2] = esalt_buf1[10];
      w0_t[3] = esalt_buf1[11];
      w1_t[0] = esalt_buf1[12];
      w1_t[1] = esalt_buf1[13];
      w1_t[2] = esalt_buf1[14];
      w1_t[3] = esalt_buf1[15];
      w2_t[0] = esalt_buf2[ 0];
      w2_t[1] = esalt_buf2[ 1];
      w2_t[2] = esalt_buf2[ 2];
      w2_t[3] = esalt_buf2[ 3];
      w3_t[0] = esalt_buf2[ 4];
      w3_t[1] = esalt_buf2[ 5];
      w3_t[2] = digest_esalt_len * 8;
      w3_t[3] = 0;

      MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

      MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

      MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

      MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);
    }

    a += r_a;
    b += r_b;
    c += r_c;
    d += r_d;

    COMPARE_M_SIMD (a, d, c, b);
  }
}

__kernel void m11400_m08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global sip_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m11400_m16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global sip_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m11400_s04 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global sip_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
  /**
   * modifier
   */

  const u32 gid = get_global_id (0);
  const u32 lid = get_local_id (0);
  const u32 lsz = get_local_size (0);

  /**
   * bin2asc table
   */

  __local u32 l_bin2asc[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    const u32 i0 = (i >> 0) & 15;
    const u32 i1 = (i >> 4) & 15;

    l_bin2asc[i] = ((i0 < 10) ? '0' + i0 : 'a' - 10 + i0) << 8
                 | ((i1 < 10) ? '0' + i1 : 'a' - 10 + i1) << 0;
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  if (gid >= gid_max) return;

  /**
   * base
   */

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

  const u32 pw_l_len = pws[gid].pw_len;

  /**
   * salt
   */

  const u32 salt_len = esalt_bufs[digests_offset].salt_len; // not a bug, we need to get it from the esalt

  u32 salt_buf0[16];
  u32 salt_buf1[16];

  salt_buf0[ 0] = esalt_bufs[digests_offset].salt_buf[ 0];
  salt_buf0[ 1] = esalt_bufs[digests_offset].salt_buf[ 1];
  salt_buf0[ 2] = esalt_bufs[digests_offset].salt_buf[ 2];
  salt_buf0[ 3] = esalt_bufs[digests_offset].salt_buf[ 3];
  salt_buf0[ 4] = esalt_bufs[digests_offset].salt_buf[ 4];
  salt_buf0[ 5] = esalt_bufs[digests_offset].salt_buf[ 5];
  salt_buf0[ 6] = esalt_bufs[digests_offset].salt_buf[ 6];
  salt_buf0[ 7] = esalt_bufs[digests_offset].salt_buf[ 7];
  salt_buf0[ 8] = esalt_bufs[digests_offset].salt_buf[ 8];
  salt_buf0[ 9] = esalt_bufs[digests_offset].salt_buf[ 9];
  salt_buf0[10] = esalt_bufs[digests_offset].salt_buf[10];
  salt_buf0[11] = esalt_bufs[digests_offset].salt_buf[11];
  salt_buf0[12] = esalt_bufs[digests_offset].salt_buf[12];
  salt_buf0[13] = esalt_bufs[digests_offset].salt_buf[13];
  salt_buf0[14] = esalt_bufs[digests_offset].salt_buf[14];
  salt_buf0[15] = esalt_bufs[digests_offset].salt_buf[15];
  salt_buf1[ 0] = esalt_bufs[digests_offset].salt_buf[16];
  salt_buf1[ 1] = esalt_bufs[digests_offset].salt_buf[17];
  salt_buf1[ 2] = esalt_bufs[digests_offset].salt_buf[18];
  salt_buf1[ 3] = esalt_bufs[digests_offset].salt_buf[19];
  salt_buf1[ 4] = esalt_bufs[digests_offset].salt_buf[20];
  salt_buf1[ 5] = esalt_bufs[digests_offset].salt_buf[21];
  salt_buf1[ 6] = esalt_bufs[digests_offset].salt_buf[22];
  salt_buf1[ 7] = esalt_bufs[digests_offset].salt_buf[23];
  salt_buf1[ 8] = esalt_bufs[digests_offset].salt_buf[24];
  salt_buf1[ 9] = esalt_bufs[digests_offset].salt_buf[25];
  salt_buf1[10] = esalt_bufs[digests_offset].salt_buf[26];
  salt_buf1[11] = esalt_bufs[digests_offset].salt_buf[27];
  salt_buf1[12] = esalt_bufs[digests_offset].salt_buf[28];
  salt_buf1[13] = esalt_bufs[digests_offset].salt_buf[29];
  salt_buf1[14] = 0;
  salt_buf1[15] = 0;

  /**
   * esalt
   */

  const u32 esalt_len = esalt_bufs[digests_offset].esalt_len;

  u32 esalt_buf0[16];
  u32 esalt_buf1[16];
  u32 esalt_buf2[16];

  esalt_buf0[ 0] = esalt_bufs[digests_offset].esalt_buf[ 0];
  esalt_buf0[ 1] = esalt_bufs[digests_offset].esalt_buf[ 1];
  esalt_buf0[ 2] = esalt_bufs[digests_offset].esalt_buf[ 2];
  esalt_buf0[ 3] = esalt_bufs[digests_offset].esalt_buf[ 3];
  esalt_buf0[ 4] = esalt_bufs[digests_offset].esalt_buf[ 4];
  esalt_buf0[ 5] = esalt_bufs[digests_offset].esalt_buf[ 5];
  esalt_buf0[ 6] = esalt_bufs[digests_offset].esalt_buf[ 6];
  esalt_buf0[ 7] = esalt_bufs[digests_offset].esalt_buf[ 7];
  esalt_buf0[ 8] = esalt_bufs[digests_offset].esalt_buf[ 8];
  esalt_buf0[ 9] = esalt_bufs[digests_offset].esalt_buf[ 9];
  esalt_buf0[10] = esalt_bufs[digests_offset].esalt_buf[10];
  esalt_buf0[11] = esalt_bufs[digests_offset].esalt_buf[11];
  esalt_buf0[12] = esalt_bufs[digests_offset].esalt_buf[12];
  esalt_buf0[13] = esalt_bufs[digests_offset].esalt_buf[13];
  esalt_buf0[14] = esalt_bufs[digests_offset].esalt_buf[14];
  esalt_buf0[15] = esalt_bufs[digests_offset].esalt_buf[15];
  esalt_buf1[ 0] = esalt_bufs[digests_offset].esalt_buf[16];
  esalt_buf1[ 1] = esalt_bufs[digests_offset].esalt_buf[17];
  esalt_buf1[ 2] = esalt_bufs[digests_offset].esalt_buf[18];
  esalt_buf1[ 3] = esalt_bufs[digests_offset].esalt_buf[19];
  esalt_buf1[ 4] = esalt_bufs[digests_offset].esalt_buf[20];
  esalt_buf1[ 5] = esalt_bufs[digests_offset].esalt_buf[21];
  esalt_buf1[ 6] = esalt_bufs[digests_offset].esalt_buf[22];
  esalt_buf1[ 7] = esalt_bufs[digests_offset].esalt_buf[23];
  esalt_buf1[ 8] = esalt_bufs[digests_offset].esalt_buf[24];
  esalt_buf1[ 9] = esalt_bufs[digests_offset].esalt_buf[25];
  esalt_buf1[10] = esalt_bufs[digests_offset].esalt_buf[26];
  esalt_buf1[11] = esalt_bufs[digests_offset].esalt_buf[27];
  esalt_buf1[12] = esalt_bufs[digests_offset].esalt_buf[28];
  esalt_buf1[13] = esalt_bufs[digests_offset].esalt_buf[29];
  esalt_buf1[14] = esalt_bufs[digests_offset].esalt_buf[30];
  esalt_buf1[15] = esalt_bufs[digests_offset].esalt_buf[31];
  esalt_buf2[ 0] = esalt_bufs[digests_offset].esalt_buf[32];
  esalt_buf2[ 1] = esalt_bufs[digests_offset].esalt_buf[33];
  esalt_buf2[ 2] = esalt_bufs[digests_offset].esalt_buf[34];
  esalt_buf2[ 3] = esalt_bufs[digests_offset].esalt_buf[35];
  esalt_buf2[ 4] = esalt_bufs[digests_offset].esalt_buf[36];
  esalt_buf2[ 5] = esalt_bufs[digests_offset].esalt_buf[37];
  esalt_buf2[ 6] = 0;
  esalt_buf2[ 7] = 0;
  esalt_buf2[ 8] = 0;
  esalt_buf2[ 9] = 0;
  esalt_buf2[10] = 0;
  esalt_buf2[11] = 0;
  esalt_buf2[12] = 0;
  esalt_buf2[13] = 0;
  esalt_buf2[14] = 0;
  esalt_buf2[15] = 0;

  const u32 digest_esalt_len = 32 + esalt_len;
  const u32 remaining_bytes  = digest_esalt_len + 1 - 64; // substract previous block

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
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos);

    const u32x pw_len = pw_l_len + pw_r_len;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    const u32x pw_salt_len = salt_len + pw_len;

    /*
     * HA1 = md5 ($salt . $pass)
     */

    // append the pass to the salt

    u32x block0[16];
    u32x block1[16];

    block0[ 0] = salt_buf0[ 0];
    block0[ 1] = salt_buf0[ 1];
    block0[ 2] = salt_buf0[ 2];
    block0[ 3] = salt_buf0[ 3];
    block0[ 4] = salt_buf0[ 4];
    block0[ 5] = salt_buf0[ 5];
    block0[ 6] = salt_buf0[ 6];
    block0[ 7] = salt_buf0[ 7];
    block0[ 8] = salt_buf0[ 8];
    block0[ 9] = salt_buf0[ 9];
    block0[10] = salt_buf0[10];
    block0[11] = salt_buf0[11];
    block0[12] = salt_buf0[12];
    block0[13] = salt_buf0[13];
    block0[14] = salt_buf0[14];
    block0[15] = salt_buf0[15];
    block1[ 0] = salt_buf1[ 0];
    block1[ 1] = salt_buf1[ 1];
    block1[ 2] = salt_buf1[ 2];
    block1[ 3] = salt_buf1[ 3];
    block1[ 4] = salt_buf1[ 4];
    block1[ 5] = salt_buf1[ 5];
    block1[ 6] = salt_buf1[ 6];
    block1[ 7] = salt_buf1[ 7];
    block1[ 8] = salt_buf1[ 8];
    block1[ 9] = salt_buf1[ 9];
    block1[10] = salt_buf1[10];
    block1[11] = salt_buf1[11];
    block1[12] = salt_buf1[12];
    block1[13] = salt_buf1[13];
    block1[14] = salt_buf1[14];
    block1[15] = salt_buf1[15];

    u32 block_len = 0;

    block_len = memcat32 (block0, block1, salt_len, w0, w1, w2, w3, pw_len);

    u32x w0_t[4];
    u32x w1_t[4];
    u32x w2_t[4];
    u32x w3_t[4];

    w0_t[0] = block0[ 0];
    w0_t[1] = block0[ 1];
    w0_t[2] = block0[ 2];
    w0_t[3] = block0[ 3];
    w1_t[0] = block0[ 4];
    w1_t[1] = block0[ 5];
    w1_t[2] = block0[ 6];
    w1_t[3] = block0[ 7];
    w2_t[0] = block0[ 8];
    w2_t[1] = block0[ 9];
    w2_t[2] = block0[10];
    w2_t[3] = block0[11];
    w3_t[0] = block0[12];
    w3_t[1] = block0[13];
    w3_t[2] = block0[14];
    w3_t[3] = block0[15];

    if (block_len < 56)
    {
      w3_t[2] = pw_salt_len * 8;
    }

    // md5

    u32x a = MD5M_A;
    u32x b = MD5M_B;
    u32x c = MD5M_C;
    u32x d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    if (block_len > 55)
    {
      u32x r_a = a;
      u32x r_b = b;
      u32x r_c = c;
      u32x r_d = d;

      w0_t[0] = block1[ 0];
      w0_t[1] = block1[ 1];
      w0_t[2] = block1[ 2];
      w0_t[3] = block1[ 3];
      w1_t[0] = block1[ 4];
      w1_t[1] = block1[ 5];
      w1_t[2] = block1[ 6];
      w1_t[3] = block1[ 7];
      w2_t[0] = block1[ 8];
      w2_t[1] = block1[ 9];
      w2_t[2] = block1[10];
      w2_t[3] = block1[11];
      w3_t[0] = block1[12];
      w3_t[1] = block1[13];
      w3_t[2] = pw_salt_len * 8;
      w3_t[3] = 0;

      MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

      MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

      MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

      MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

      a += r_a;
      b += r_b;
      c += r_c;
      d += r_d;
    }

    /*
     * final = md5 ($HA1 . $esalt)
     * we have at least 2 MD5 blocks/transformations, but we might need 3
     */

    w0_t[0] = uint_to_hex_lower8 ((a >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((a >>  8) & 255) << 16;
    w0_t[1] = uint_to_hex_lower8 ((a >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((a >> 24) & 255) << 16;
    w0_t[2] = uint_to_hex_lower8 ((b >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((b >>  8) & 255) << 16;
    w0_t[3] = uint_to_hex_lower8 ((b >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((b >> 24) & 255) << 16;
    w1_t[0] = uint_to_hex_lower8 ((c >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((c >>  8) & 255) << 16;
    w1_t[1] = uint_to_hex_lower8 ((c >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((c >> 24) & 255) << 16;
    w1_t[2] = uint_to_hex_lower8 ((d >>  0) & 255) <<  0
            | uint_to_hex_lower8 ((d >>  8) & 255) << 16;
    w1_t[3] = uint_to_hex_lower8 ((d >> 16) & 255) <<  0
            | uint_to_hex_lower8 ((d >> 24) & 255) << 16;
    w2_t[0] = esalt_buf0[0];
    w2_t[1] = esalt_buf0[1];
    w2_t[2] = esalt_buf0[2];
    w2_t[3] = esalt_buf0[3];
    w3_t[0] = esalt_buf0[4];
    w3_t[1] = esalt_buf0[5];
    w3_t[2] = esalt_buf0[6];
    w3_t[3] = esalt_buf0[7];

    // md5
    // 1st transform

    a = MD5M_A;
    b = MD5M_B;
    c = MD5M_C;
    d = MD5M_D;

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    a += MD5M_A;
    b += MD5M_B;
    c += MD5M_C;
    d += MD5M_D;

    u32x r_a = a;
    u32x r_b = b;
    u32x r_c = c;
    u32x r_d = d;

    // 2nd transform

    w0_t[0] = esalt_buf0[ 8];
    w0_t[1] = esalt_buf0[ 9];
    w0_t[2] = esalt_buf0[10];
    w0_t[3] = esalt_buf0[11];
    w1_t[0] = esalt_buf0[12];
    w1_t[1] = esalt_buf0[13];
    w1_t[2] = esalt_buf0[14];
    w1_t[3] = esalt_buf0[15];
    w2_t[0] = esalt_buf1[ 0];
    w2_t[1] = esalt_buf1[ 1];
    w2_t[2] = esalt_buf1[ 2];
    w2_t[3] = esalt_buf1[ 3];
    w3_t[0] = esalt_buf1[ 4];
    w3_t[1] = esalt_buf1[ 5];
    w3_t[2] = esalt_buf1[ 6];
    w3_t[3] = esalt_buf1[ 7];

    // it is the final block when no more than 55 bytes left

    if (remaining_bytes < 56)
    {
      // it is the last block !

      w3_t[2] = digest_esalt_len * 8;
    }

    MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
    MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
    MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
    MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
    MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

    MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
    MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
    MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
    MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
    MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

    MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
    MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
    MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
    MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
    MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

    MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
    MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
    MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
    MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
    MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);

    // sometimes (not rare at all) we need a third block :(

    if (remaining_bytes > 55)
    {
      // this is for sure the final block

      a += r_a;
      b += r_b;
      c += r_c;
      d += r_d;

      r_a = a;
      r_b = b;
      r_c = c;
      r_d = d;

      w0_t[0] = esalt_buf1[ 8];
      w0_t[1] = esalt_buf1[ 9];
      w0_t[2] = esalt_buf1[10];
      w0_t[3] = esalt_buf1[11];
      w1_t[0] = esalt_buf1[12];
      w1_t[1] = esalt_buf1[13];
      w1_t[2] = esalt_buf1[14];
      w1_t[3] = esalt_buf1[15];
      w2_t[0] = esalt_buf2[ 0];
      w2_t[1] = esalt_buf2[ 1];
      w2_t[2] = esalt_buf2[ 2];
      w2_t[3] = esalt_buf2[ 3];
      w3_t[0] = esalt_buf2[ 4];
      w3_t[1] = esalt_buf2[ 5];
      w3_t[2] = digest_esalt_len * 8;
      w3_t[3] = 0;

      MD5_STEP (MD5_Fo, a, b, c, d, w0_t[0], MD5C00, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w0_t[1], MD5C01, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w0_t[2], MD5C02, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w0_t[3], MD5C03, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w1_t[0], MD5C04, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w1_t[1], MD5C05, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w1_t[2], MD5C06, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w1_t[3], MD5C07, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w2_t[0], MD5C08, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w2_t[1], MD5C09, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w2_t[2], MD5C0a, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w2_t[3], MD5C0b, MD5S03);
      MD5_STEP (MD5_Fo, a, b, c, d, w3_t[0], MD5C0c, MD5S00);
      MD5_STEP (MD5_Fo, d, a, b, c, w3_t[1], MD5C0d, MD5S01);
      MD5_STEP (MD5_Fo, c, d, a, b, w3_t[2], MD5C0e, MD5S02);
      MD5_STEP (MD5_Fo, b, c, d, a, w3_t[3], MD5C0f, MD5S03);

      MD5_STEP (MD5_Go, a, b, c, d, w0_t[1], MD5C10, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w1_t[2], MD5C11, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w2_t[3], MD5C12, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w0_t[0], MD5C13, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w1_t[1], MD5C14, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w2_t[2], MD5C15, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w3_t[3], MD5C16, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w1_t[0], MD5C17, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w2_t[1], MD5C18, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w3_t[2], MD5C19, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w0_t[3], MD5C1a, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w2_t[0], MD5C1b, MD5S13);
      MD5_STEP (MD5_Go, a, b, c, d, w3_t[1], MD5C1c, MD5S10);
      MD5_STEP (MD5_Go, d, a, b, c, w0_t[2], MD5C1d, MD5S11);
      MD5_STEP (MD5_Go, c, d, a, b, w1_t[3], MD5C1e, MD5S12);
      MD5_STEP (MD5_Go, b, c, d, a, w3_t[0], MD5C1f, MD5S13);

      MD5_STEP (MD5_H , a, b, c, d, w1_t[1], MD5C20, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w2_t[0], MD5C21, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w2_t[3], MD5C22, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w3_t[2], MD5C23, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w0_t[1], MD5C24, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w1_t[0], MD5C25, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w1_t[3], MD5C26, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w2_t[2], MD5C27, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w3_t[1], MD5C28, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w0_t[0], MD5C29, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w0_t[3], MD5C2a, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w1_t[2], MD5C2b, MD5S23);
      MD5_STEP (MD5_H , a, b, c, d, w2_t[1], MD5C2c, MD5S20);
      MD5_STEP (MD5_H , d, a, b, c, w3_t[0], MD5C2d, MD5S21);
      MD5_STEP (MD5_H , c, d, a, b, w3_t[3], MD5C2e, MD5S22);
      MD5_STEP (MD5_H , b, c, d, a, w0_t[2], MD5C2f, MD5S23);

      MD5_STEP (MD5_I , a, b, c, d, w0_t[0], MD5C30, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w1_t[3], MD5C31, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w3_t[2], MD5C32, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w1_t[1], MD5C33, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w3_t[0], MD5C34, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w0_t[3], MD5C35, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w2_t[2], MD5C36, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w0_t[1], MD5C37, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w2_t[0], MD5C38, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w3_t[3], MD5C39, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w1_t[2], MD5C3a, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w3_t[1], MD5C3b, MD5S33);
      MD5_STEP (MD5_I , a, b, c, d, w1_t[0], MD5C3c, MD5S30);
      MD5_STEP (MD5_I , d, a, b, c, w2_t[3], MD5C3d, MD5S31);
      MD5_STEP (MD5_I , c, d, a, b, w0_t[2], MD5C3e, MD5S32);
      MD5_STEP (MD5_I , b, c, d, a, w2_t[1], MD5C3f, MD5S33);
    }

    a += r_a;
    b += r_b;
    c += r_c;
    d += r_d;

    COMPARE_S_SIMD (a, d, c, b);
  }
}

__kernel void m11400_s08 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global sip_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}

__kernel void m11400_s16 (__global pw_t *pws, __global const kernel_rule_t *rules_buf, __global const comb_t *combs_buf, __global const bf_t *bfs_buf, __global void *tmps, __global void *hooks, __global const u32 *bitmaps_buf_s1_a, __global const u32 *bitmaps_buf_s1_b, __global const u32 *bitmaps_buf_s1_c, __global const u32 *bitmaps_buf_s1_d, __global const u32 *bitmaps_buf_s2_a, __global const u32 *bitmaps_buf_s2_b, __global const u32 *bitmaps_buf_s2_c, __global const u32 *bitmaps_buf_s2_d, __global plain_t *plains_buf, __global const digest_t *digests_buf, __global u32 *hashes_shown, __global const salt_t *salt_bufs, __global sip_t *esalt_bufs, __global u32 *d_return_buf, __global u32 *d_scryptV0_buf, __global u32 *d_scryptV1_buf, __global u32 *d_scryptV2_buf, __global u32 *d_scryptV3_buf, const u32 bitmap_mask, const u32 bitmap_shift1, const u32 bitmap_shift2, const u32 salt_pos, const u32 loop_pos, const u32 loop_cnt, const u32 il_cnt, const u32 digests_cnt, const u32 digests_offset, const u32 combs_mode, const u32 gid_max)
{
}
