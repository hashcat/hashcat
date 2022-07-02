/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//too much register pressure
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

DECLSPEC u32 MurmurHash (const u32 seed, PRIVATE_AS const u32 *w, const u32 pw_len)
{
  u32 hash = seed;

  #define M 0x7fd652ad
  #define R 16

  hash += 0xdeadbeef;

  const u32 blocks = pw_len / 4;

  if (pw_len >= 4)
  {
    for (u32 i = 0; i < blocks; i++)
    {
      const u32 tmp = (hash + w[i]) * M;

      hash = tmp ^ (tmp >> R);
    }
  }

  const u32 tmp = (hash + w[blocks]) * M;

  hash = (pw_len & 3) ? (tmp ^ (tmp >> R)) : hash;

  hash *= M;
  hash ^= hash >> 10;
  hash *= M;
  hash ^= hash >> 17;

  #undef M
  #undef R

  return hash;
}

KERNEL_FQ void m25700_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * seed
   */

  const u32 seed = salt_bufs[SALT_POS_HOST].salt_buf[0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32 pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32 wordl0[4] = { 0 };
    u32 wordl1[4] = { 0 };
    u32 wordl2[4] = { 0 };
    u32 wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32 wordr0[4] = { 0 };
    u32 wordr1[4] = { 0 };
    u32 wordr2[4] = { 0 };
    u32 wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32 w[16];

    w[ 0] = wordl0[0] | wordr0[0];
    w[ 1] = wordl0[1] | wordr0[1];
    w[ 2] = wordl0[2] | wordr0[2];
    w[ 3] = wordl0[3] | wordr0[3];
    w[ 4] = wordl1[0] | wordr1[0];
    w[ 5] = wordl1[1] | wordr1[1];
    w[ 6] = wordl1[2] | wordr1[2];
    w[ 7] = wordl1[3] | wordr1[3];
    w[ 8] = wordl2[0] | wordr2[0];
    w[ 9] = wordl2[1] | wordr2[1];
    w[10] = wordl2[2] | wordr2[2];
    w[11] = wordl2[3] | wordr2[3];
    w[12] = wordl3[0] | wordr3[0];
    w[13] = wordl3[1] | wordr3[1];
    w[14] = wordl3[2] | wordr3[2];
    w[15] = wordl3[3] | wordr3[3];

    const u32 r = MurmurHash (seed, w, pw_len);

    const u32 z = 0;

    COMPARE_M_SIMD (r, z, z, z);
  }
}

KERNEL_FQ void m25700_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m25700_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m25700_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * seed
   */

  const u32 seed = salt_bufs[SALT_POS_HOST].salt_buf[0];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    0,
    0,
    0
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32 pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32 wordl0[4] = { 0 };
    u32 wordl1[4] = { 0 };
    u32 wordl2[4] = { 0 };
    u32 wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32 wordr0[4] = { 0 };
    u32 wordr1[4] = { 0 };
    u32 wordr2[4] = { 0 };
    u32 wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32 w[16];

    w[ 0] = wordl0[0] | wordr0[0];
    w[ 1] = wordl0[1] | wordr0[1];
    w[ 2] = wordl0[2] | wordr0[2];
    w[ 3] = wordl0[3] | wordr0[3];
    w[ 4] = wordl1[0] | wordr1[0];
    w[ 5] = wordl1[1] | wordr1[1];
    w[ 6] = wordl1[2] | wordr1[2];
    w[ 7] = wordl1[3] | wordr1[3];
    w[ 8] = wordl2[0] | wordr2[0];
    w[ 9] = wordl2[1] | wordr2[1];
    w[10] = wordl2[2] | wordr2[2];
    w[11] = wordl2[3] | wordr2[3];
    w[12] = wordl3[0] | wordr3[0];
    w[13] = wordl3[1] | wordr3[1];
    w[14] = wordl3[2] | wordr3[2];
    w[15] = wordl3[3] | wordr3[3];

    const u32 r = MurmurHash (seed, w, pw_len);

    const u32 z = 0;

    COMPARE_S_SIMD (r, z, z, z);
  }
}

KERNEL_FQ void m25700_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m25700_s16 (KERN_ATTR_BASIC ())
{
}
