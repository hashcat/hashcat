/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

#define ROUND(v)                              \
{                                             \
  a ^= (((a & 0x3f) + add) * (v)) + (a << 8); \
  b += (b << 8) ^ a;                          \
  add += v;                                   \
}

#define CODE_PRE                                                  \
{                                                                 \
  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)      \
  {                                                               \
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];             \
                                                                  \
    const u32x w0 = w0l | w0r;                                    \
                                                                  \
    u32x a = MYSQL323_A;                                          \
    u32x b = MYSQL323_B;                                          \
                                                                  \
    u32x add = 7;                                                 \

#define CODE_LOOP(rest)                                           \
                                                                  \
    int i;                                                        \
    int j;                                                        \
                                                                  \
    for (i = 0, j = 1; i <= (int) (rest) - 4; i += 4, j += 1)     \
    {                                                             \
      const u32 wj = w[j];                                        \
                                                                  \
      ROUND ((wj >>  0) & 0xff);                                  \
      ROUND ((wj >>  8) & 0xff);                                  \
      ROUND ((wj >> 16) & 0xff);                                  \
      ROUND ((wj >> 24) & 0xff);                                  \
    }                                                             \
                                                                  \
    const u32 wj = w[j];                                          \
                                                                  \
    const u32 left = (rest) - i;                                  \
                                                                  \
    if (left == 3)                                                \
    {                                                             \
      ROUND ((wj >>  0) & 0xff);                                  \
      ROUND ((wj >>  8) & 0xff);                                  \
      ROUND ((wj >> 16) & 0xff);                                  \
    }                                                             \
    else if (left == 2)                                           \
    {                                                             \
      ROUND ((wj >>  0) & 0xff);                                  \
      ROUND ((wj >>  8) & 0xff);                                  \
    }                                                             \
    else if (left == 1)                                           \
    {                                                             \
      ROUND ((wj >>  0) & 0xff);                                  \
    }

#define CODE_POST_M                                               \
                                                                  \
    a &= 0x7fffffff;                                              \
    b &= 0x7fffffff;                                              \
                                                                  \
    u32x z = 0;                                                   \
                                                                  \
    COMPARE_M_SIMD (a, b, z, z);                                  \
  }                                                               \
}

#define CODE_POST_S                                               \
                                                                  \
    a &= 0x7fffffff;                                              \
    b &= 0x7fffffff;                                              \
                                                                  \
    u32x z = 0;                                                   \
                                                                  \
    COMPARE_S_SIMD (a, b, z, z);                                  \
  }                                                               \
}

DECLSPEC void m00200m (u32 *w, const u32 pw_len, KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * loop
   */

  u32 w0l = w[0];

  switch (pw_len)
  {
    case  1:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff);
      CODE_POST_M;
      break;

    case  2:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff);
      CODE_POST_M;
      break;

    case  3:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff);
      CODE_POST_M;
      break;

    case  4:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      CODE_POST_M;
      break;

    case  5:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff);
      CODE_POST_M;
      break;

    case  6:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff);
      CODE_POST_M;
      break;

    case  7:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff);
      CODE_POST_M;
      break;

    case  8:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      CODE_POST_M;
      break;

    case  9:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff);
      CODE_POST_M;
      break;

    case 10:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff);
      CODE_POST_M;
      break;

    case 11:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff);
      CODE_POST_M;
      break;

    case 12:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      CODE_POST_M;
      break;

    case 13:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      ROUND ((w[3] >>  0) & 0xff);
      CODE_POST_M;
      break;

    case 14:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      ROUND ((w[3] >>  0) & 0xff); ROUND ((w[3] >>  8) & 0xff);
      CODE_POST_M;
      break;

    case 15:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      ROUND ((w[3] >>  0) & 0xff); ROUND ((w[3] >>  8) & 0xff); ROUND ((w[3] >> 16) & 0xff);
      CODE_POST_M;
      break;

    case 16:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      ROUND ((w[3] >>  0) & 0xff); ROUND ((w[3] >>  8) & 0xff); ROUND ((w[3] >> 16) & 0xff); ROUND ((w[3] >> 24) & 0xff);
      CODE_POST_M;
      break;

    default:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      CODE_LOOP (pw_len - 4);
      CODE_POST_M;
      break;
  }
}

DECLSPEC void m00200s (u32 *w, const u32 pw_len, KERN_ATTR_VECTOR ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  u32 w0l = w[0];

  switch (pw_len)
  {
    case  1:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff);
      CODE_POST_S;
      break;

    case  2:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff);
      CODE_POST_S;
      break;

    case  3:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff);
      CODE_POST_S;
      break;

    case  4:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      CODE_POST_S;
      break;

    case  5:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff);
      CODE_POST_S;
      break;

    case  6:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff);
      CODE_POST_S;
      break;

    case  7:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff);
      CODE_POST_S;
      break;

    case  8:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      CODE_POST_S;
      break;

    case  9:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff);
      CODE_POST_S;
      break;

    case 10:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff);
      CODE_POST_S;
      break;

    case 11:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff);
      CODE_POST_S;
      break;

    case 12:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      CODE_POST_S;
      break;

    case 13:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      ROUND ((w[3] >>  0) & 0xff);
      CODE_POST_S;
      break;

    case 14:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      ROUND ((w[3] >>  0) & 0xff); ROUND ((w[3] >>  8) & 0xff);
      CODE_POST_S;
      break;

    case 15:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      ROUND ((w[3] >>  0) & 0xff); ROUND ((w[3] >>  8) & 0xff); ROUND ((w[3] >> 16) & 0xff);
      CODE_POST_S;
      break;

    case 16:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      ROUND ((w[1] >>  0) & 0xff); ROUND ((w[1] >>  8) & 0xff); ROUND ((w[1] >> 16) & 0xff); ROUND ((w[1] >> 24) & 0xff);
      ROUND ((w[2] >>  0) & 0xff); ROUND ((w[2] >>  8) & 0xff); ROUND ((w[2] >> 16) & 0xff); ROUND ((w[2] >> 24) & 0xff);
      ROUND ((w[3] >>  0) & 0xff); ROUND ((w[3] >>  8) & 0xff); ROUND ((w[3] >> 16) & 0xff); ROUND ((w[3] >> 24) & 0xff);
      CODE_POST_S;
      break;

    default:
      CODE_PRE;
      ROUND ((w0   >>  0) & 0xff); ROUND ((w0   >>  8) & 0xff); ROUND ((w0   >> 16) & 0xff); ROUND ((w0   >> 24) & 0xff);
      CODE_LOOP (pw_len - 4);
      CODE_POST_S;
      break;
  }
}

__kernel void m00200_m04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00200m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00200_m08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00200m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00200_m16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00200m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00200_s04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = 0;
  w[ 5] = 0;
  w[ 6] = 0;
  w[ 7] = 0;
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00200s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00200_s08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00200s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}

__kernel void m00200_s16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 w[16];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * main
   */

  m00200s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_scryptV0_buf, d_scryptV1_buf, d_scryptV2_buf, d_scryptV3_buf, bitmap_mask, bitmap_shift1, bitmap_shift2, salt_pos, loop_pos, loop_cnt, il_cnt, digests_cnt, digests_offset, combs_mode, gid_max);
}
