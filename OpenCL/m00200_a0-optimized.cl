/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

KERNEL_FQ void m00200_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x w_t[16];

    w_t[ 0] = w0[0];
    w_t[ 1] = w0[1];
    w_t[ 2] = w0[2];
    w_t[ 3] = w0[3];
    w_t[ 4] = w1[0];
    w_t[ 5] = w1[1];
    w_t[ 6] = w1[2];
    w_t[ 7] = w1[3];
    w_t[ 8] = 0;
    w_t[ 9] = 0;
    w_t[10] = 0;
    w_t[11] = 0;
    w_t[12] = 0;
    w_t[13] = 0;
    w_t[14] = 0;
    w_t[15] = 0;

    u32x a = MYSQL323_A;
    u32x b = MYSQL323_B;
    u32x c = 0;
    u32x d = 0;

    u32x add = 7;

    #define ROUND(v)                              \
    {                                             \
      a ^= (((a & 0x3f) + add) * (v)) + (a << 8); \
      b += (b << 8) ^ a;                          \
      add += v;                                   \
    }

    int i;
    int j;

    for (i = 0, j = 0; i <= (int) out_len - 4; i += 4, j += 1)
    {
      const u32x wj = w_t[j];

      ROUND (unpack_v8a_from_v32 (wj));
      ROUND (unpack_v8b_from_v32 (wj));
      ROUND (unpack_v8c_from_v32 (wj));
      ROUND (unpack_v8d_from_v32 (wj));
    }

    const u32x wj = w_t[j];

    const u32 left = out_len - i;

    if (left == 3)
    {
      ROUND (unpack_v8a_from_v32 (wj));
      ROUND (unpack_v8b_from_v32 (wj));
      ROUND (unpack_v8c_from_v32 (wj));
    }
    else if (left == 2)
    {
      ROUND (unpack_v8a_from_v32 (wj));
      ROUND (unpack_v8b_from_v32 (wj));
    }
    else if (left == 1)
    {
      ROUND (unpack_v8a_from_v32 (wj));
    }

    a &= 0x7fffffff;
    b &= 0x7fffffff;

    u32x z = 0;

    COMPARE_M_SIMD (a, b, z, z);
  }
}

KERNEL_FQ void m00200_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m00200_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m00200_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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

  const u32 pw_len = pws[gid].pw_len & 63;

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

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    u32x w_t[16];

    w_t[ 0] = w0[0];
    w_t[ 1] = w0[1];
    w_t[ 2] = w0[2];
    w_t[ 3] = w0[3];
    w_t[ 4] = w1[0];
    w_t[ 5] = w1[1];
    w_t[ 6] = w1[2];
    w_t[ 7] = w1[3];
    w_t[ 8] = 0;
    w_t[ 9] = 0;
    w_t[10] = 0;
    w_t[11] = 0;
    w_t[12] = 0;
    w_t[13] = 0;
    w_t[14] = 0;
    w_t[15] = 0;

    u32x a = MYSQL323_A;
    u32x b = MYSQL323_B;
    u32x c = 0;
    u32x d = 0;

    u32x add = 7;

    #define ROUND(v)                              \
    {                                             \
      a ^= (((a & 0x3f) + add) * (v)) + (a << 8); \
      b += (b << 8) ^ a;                          \
      add += v;                                   \
    }

    int i;
    int j;

    for (i = 0, j = 0; i <= (int) out_len - 4; i += 4, j += 1)
    {
      const u32x wj = w_t[j];

      ROUND (unpack_v8a_from_v32 (wj));
      ROUND (unpack_v8b_from_v32 (wj));
      ROUND (unpack_v8c_from_v32 (wj));
      ROUND (unpack_v8d_from_v32 (wj));
    }

    const u32x wj = w_t[j];

    const u32 left = out_len - i;

    if (left == 3)
    {
      ROUND (unpack_v8a_from_v32 (wj));
      ROUND (unpack_v8b_from_v32 (wj));
      ROUND (unpack_v8c_from_v32 (wj));
    }
    else if (left == 2)
    {
      ROUND (unpack_v8a_from_v32 (wj));
      ROUND (unpack_v8b_from_v32 (wj));
    }
    else if (left == 1)
    {
      ROUND (unpack_v8a_from_v32 (wj));
    }

    a &= 0x7fffffff;
    b &= 0x7fffffff;

    u32x z = 0;

    COMPARE_S_SIMD (a, b, z, z);
  }
}

KERNEL_FQ void m00200_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m00200_s16 (KERN_ATTR_RULES ())
{
}
