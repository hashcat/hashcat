/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible to simd
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

#define SIPROUND(v0,v1,v2,v3)   \
  (v0) += (v1);                 \
  (v1)  = hc_rotl64 ((v1), 13); \
  (v1) ^= (v0);                 \
  (v0)  = hc_rotl64 ((v0), 32); \
  (v2) += (v3);                 \
  (v3)  = hc_rotl64 ((v3), 16); \
  (v3) ^= (v2);                 \
  (v0) += (v3);                 \
  (v3)  = hc_rotl64 ((v3), 21); \
  (v3) ^= (v0);                 \
  (v2) += (v1);                 \
  (v1)  = hc_rotl64 ((v1), 17); \
  (v1) ^= (v2);                 \
  (v2)  = hc_rotl64 ((v2), 32)

KERNEL_FQ void m10100_m04 (KERN_ATTR_BASIC ())
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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u64x v0p = SIPHASHM_0;
  u64x v1p = SIPHASHM_1;
  u64x v2p = SIPHASHM_2;
  u64x v3p = SIPHASHM_3;

  v0p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[1], salt_bufs[SALT_POS_HOST].salt_buf[0]);
  v1p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[3], salt_bufs[SALT_POS_HOST].salt_buf[2]);
  v2p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[1], salt_bufs[SALT_POS_HOST].salt_buf[0]);
  v3p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[3], salt_bufs[SALT_POS_HOST].salt_buf[2]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

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

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
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

    /**
     * siphash
     */

    switch (pw_len / 8)
    {
      case 0: w0[1] |= pw_len << 24; break;
      case 1: w0[3] |= pw_len << 24; break;
      case 2: w1[1] |= pw_len << 24; break;
      case 3: w1[3] |= pw_len << 24; break;
    }

    u64x v0 = v0p;
    u64x v1 = v1p;
    u64x v2 = v2p;
    u64x v3 = v3p;

    int i;
    int j;

    for (i = 0, j = 0; i <= pw_len && i < 16; i += 8, j += 2)
    {
      u64x m = hl32_to_64 (w0[j + 1], w0[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    for (       j = 0; i <= pw_len && i < 32; i += 8, j += 2)
    {
      u64x m = hl32_to_64 (w1[j + 1], w1[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    v2 ^= 0xff;

    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);

    const u64x v = v0 ^ v1 ^ v2 ^ v3;

    const u32x a = l32_from_64 (v);
    const u32x b = h32_from_64 (v);

    const u32x z = 0;

    COMPARE_M_SIMD (a, b, z, z);
  }
}

KERNEL_FQ void m10100_m08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m10100_m16 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m10100_s04 (KERN_ATTR_BASIC ())
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

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * salt
   */

  u64x v0p = SIPHASHM_0;
  u64x v1p = SIPHASHM_1;
  u64x v2p = SIPHASHM_2;
  u64x v3p = SIPHASHM_3;

  v0p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[1], salt_bufs[SALT_POS_HOST].salt_buf[0]);
  v1p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[3], salt_bufs[SALT_POS_HOST].salt_buf[2]);
  v2p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[1], salt_bufs[SALT_POS_HOST].salt_buf[0]);
  v3p ^= hl32_to_64 (salt_bufs[SALT_POS_HOST].salt_buf[3], salt_bufs[SALT_POS_HOST].salt_buf[2]);

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
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

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

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
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

    /**
     * siphash
     */

    switch (pw_len / 8)
    {
      case 0: w0[1] |= pw_len << 24; break;
      case 1: w0[3] |= pw_len << 24; break;
      case 2: w1[1] |= pw_len << 24; break;
      case 3: w1[3] |= pw_len << 24; break;
    }

    u64x v0 = v0p;
    u64x v1 = v1p;
    u64x v2 = v2p;
    u64x v3 = v3p;

    int i;
    int j;

    for (i = 0, j = 0; i <= pw_len && i < 16; i += 8, j += 2)
    {
      u64x m = hl32_to_64 (w0[j + 1], w0[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    for (       j = 0; i <= pw_len && i < 32; i += 8, j += 2)
    {
      u64x m = hl32_to_64 (w1[j + 1], w1[j + 0]);

      v3 ^= m;

      SIPROUND (v0, v1, v2, v3);
      SIPROUND (v0, v1, v2, v3);

      v0 ^= m;
    }

    v2 ^= 0xff;

    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);
    SIPROUND (v0, v1, v2, v3);

    const u64x v = v0 ^ v1 ^ v2 ^ v3;

    const u32x a = l32_from_64 (v);
    const u32x b = h32_from_64 (v);

    const u32x z = 0;

    COMPARE_S_SIMD (a, b, z, z);
  }
}

KERNEL_FQ void m10100_s08 (KERN_ATTR_BASIC ())
{
}

KERNEL_FQ void m10100_s16 (KERN_ATTR_BASIC ())
{
}
