/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

#define ROUND(v)                              \
{                                             \
  a ^= (((a & 0x3f) + add) * (v)) + (a << 8); \
  b += (b << 8) ^ a;                          \
  add += v;                                   \
}

#define CODE_PRE                                                  \
{                                                                 \
  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)      \
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
      ROUND (unpack_v8a_from_v32 (wj));                           \
      ROUND (unpack_v8b_from_v32 (wj));                           \
      ROUND (unpack_v8c_from_v32 (wj));                           \
      ROUND (unpack_v8d_from_v32 (wj));                           \
    }                                                             \
                                                                  \
    const u32 wj = w[j];                                          \
                                                                  \
    const u32 left = (rest) - i;                                  \
                                                                  \
    if (left == 3)                                                \
    {                                                             \
      ROUND (unpack_v8a_from_v32 (wj));                           \
      ROUND (unpack_v8b_from_v32 (wj));                           \
      ROUND (unpack_v8c_from_v32 (wj));                           \
    }                                                             \
    else if (left == 2)                                           \
    {                                                             \
      ROUND (unpack_v8a_from_v32 (wj));                           \
      ROUND (unpack_v8b_from_v32 (wj));                           \
    }                                                             \
    else if (left == 1)                                           \
    {                                                             \
      ROUND (unpack_v8a_from_v32 (wj));                           \
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

DECLSPEC void m00200m (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  u32 w0l = w[0];

  CODE_PRE;

  switch (pw_len)
  {
    case  1:
      ROUND (unpack_v8a_from_v32 (  w0));
      break;

    case  2:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0));
      break;

    case  3:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0));
      break;

    case  4:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      break;

    case  5:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1]));
      break;

    case  6:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1]));
      break;

    case  7:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1]));
      break;

    case  8:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      break;

    case  9:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2]));
      break;

    case 10:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2]));
      break;

    case 11:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2]));
      break;

    case 12:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      break;

    case 13:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      ROUND (unpack_v8a_from_v32 (w[3]));
      break;

    case 14:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      ROUND (unpack_v8a_from_v32 (w[3])); ROUND (unpack_v8b_from_v32 (w[3]));
      break;

    case 15:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      ROUND (unpack_v8a_from_v32 (w[3])); ROUND (unpack_v8b_from_v32 (w[3])); ROUND (unpack_v8c_from_v32 (w[3]));
      break;

    case 16:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      ROUND (unpack_v8a_from_v32 (w[3])); ROUND (unpack_v8b_from_v32 (w[3])); ROUND (unpack_v8c_from_v32 (w[3])); ROUND (unpack_v8d_from_v32 (w[3]));
      break;

    default:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      CODE_LOOP (pw_len - 4);
      break;
  }

  CODE_POST_M;
}

DECLSPEC void m00200s (PRIVATE_AS u32 *w, const u32 pw_len, KERN_ATTR_FUNC_VECTOR ())
{
  /**
   * modifiers are taken from args
   */

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    0,
    0
  };

  /**
   * loop
   */

  u32 w0l = w[0];

  CODE_PRE;

  switch (pw_len)
  {
    case  1:
      ROUND (unpack_v8a_from_v32 (  w0));
      break;

    case  2:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0));
      break;

    case  3:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0));
      break;

    case  4:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      break;

    case  5:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1]));
      break;

    case  6:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1]));
      break;

    case  7:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1]));
      break;

    case  8:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      break;

    case  9:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2]));
      break;

    case 10:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2]));
      break;

    case 11:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2]));
      break;

    case 12:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      break;

    case 13:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      ROUND (unpack_v8a_from_v32 (w[3]));
      break;

    case 14:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      ROUND (unpack_v8a_from_v32 (w[3])); ROUND (unpack_v8b_from_v32 (w[3]));
      break;

    case 15:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      ROUND (unpack_v8a_from_v32 (w[3])); ROUND (unpack_v8b_from_v32 (w[3])); ROUND (unpack_v8c_from_v32 (w[3]));
      break;

    case 16:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      ROUND (unpack_v8a_from_v32 (w[1])); ROUND (unpack_v8b_from_v32 (w[1])); ROUND (unpack_v8c_from_v32 (w[1])); ROUND (unpack_v8d_from_v32 (w[1]));
      ROUND (unpack_v8a_from_v32 (w[2])); ROUND (unpack_v8b_from_v32 (w[2])); ROUND (unpack_v8c_from_v32 (w[2])); ROUND (unpack_v8d_from_v32 (w[2]));
      ROUND (unpack_v8a_from_v32 (w[3])); ROUND (unpack_v8b_from_v32 (w[3])); ROUND (unpack_v8c_from_v32 (w[3])); ROUND (unpack_v8d_from_v32 (w[3]));
      break;

    default:
      ROUND (unpack_v8a_from_v32 (  w0)); ROUND (unpack_v8b_from_v32 (  w0)); ROUND (unpack_v8c_from_v32 (  w0)); ROUND (unpack_v8d_from_v32 (  w0));
      CODE_LOOP (pw_len - 4);
      break;
  }

  CODE_POST_S;
}

KERNEL_FQ void m00200_m04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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

  m00200m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m00200_m08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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

  m00200m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m00200_m16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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

  m00200m (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m00200_s04 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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

  m00200s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m00200_s08 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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

  m00200s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}

KERNEL_FQ void m00200_s16 (KERN_ATTR_VECTOR ())
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

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

  m00200s (w, pw_len, pws, rules_buf, combs_buf, words_buf_r, tmps, hooks, bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d, bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d, plains_buf, digests_buf, hashes_shown, salt_bufs, esalt_bufs, d_return_buf, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, kernel_param, gid, lid, lsz);
}
