/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_cipher_rc4.cl)
#endif

typedef struct rc4
{
  u32 dropN;
  u32 ct_len;
  u32 pt_len;
  u32 pt_off;

  u32 pt[2];
  u32 ct[16];

} rc4_t;

CONSTANT_VK u32 pt_masks[16] =
{
  0x00000000,
  0x000000FF,
  0x0000FFFF,
  0x00FFFFFF,
  0xFFFFFFFF,
  0x000000FF,
  0x0000FFFF,
  0x00FFFFFF,
  0xFFFFFFFF,
  0x000000FF,
  0x0000FFFF,
  0x00FFFFFF,
  0xFFFFFFFF,
  0x000000FF,
  0,
  0
};

KERNEL_FQ KERNEL_FA void m33502_m04 (KERN_ATTR_ESALT (rc4_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * shared
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  /**
   * loop
   */

  const u32 dropN  = esalt_bufs[DIGESTS_OFFSET_HOST].dropN;
  const u32 pt_len = esalt_bufs[DIGESTS_OFFSET_HOST].pt_len;

  const u32 ct[4] =
  {
    esalt_bufs[DIGESTS_OFFSET_HOST].ct[0],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct[1],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct[2],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct[3]
  };

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

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];

    rc4_init_104 (S, w0, lid);

    u32 out[4];

    u8 i = 0;
    u8 j = 0;

    if (dropN > 0)
    {
      rc4_dropN (S, &i, &j, dropN, lid);
    }

    rc4_next_16 (S, i, j, ct, out, lid);

    if (pt_len == 13)
    {
      out[3] &= pt_masks[1];
    }
    else
    {
      out[3] = 0;

      if (pt_len < 9)
      {
        out[2] = 0;

        if (pt_len < 5)
        {
          out[1] = 0;

          if (pt_len >= 1 && pt_len <= 3)
          {
            out[0] &= pt_masks[pt_len];
          }
        }
        else if (pt_len <= 7)
        {
          out[1] &= pt_masks[pt_len];
        }
      }
      else if (pt_len <= 11)
      {
        out[2] &= pt_masks[pt_len];
      }
    }

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ KERNEL_FA void m33502_m08 (KERN_ATTR_ESALT (rc4_t))
{
}

KERNEL_FQ KERNEL_FA void m33502_m16 (KERN_ATTR_ESALT (rc4_t))
{
}

KERNEL_FQ KERNEL_FA void m33502_s04 (KERN_ATTR_ESALT (rc4_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[ 0];
  pw_buf0[1] = pws[gid].i[ 1];
  pw_buf0[2] = pws[gid].i[ 2];
  pw_buf0[3] = pws[gid].i[ 3];
  pw_buf1[0] = pws[gid].i[ 4];
  pw_buf1[1] = pws[gid].i[ 5];
  pw_buf1[2] = pws[gid].i[ 6];
  pw_buf1[3] = pws[gid].i[ 7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * shared
   */

  LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  const u32 dropN  = esalt_bufs[DIGESTS_OFFSET_HOST].dropN;
  const u32 pt_len = esalt_bufs[DIGESTS_OFFSET_HOST].pt_len;

  const u32 ct[4] =
  {
    esalt_bufs[DIGESTS_OFFSET_HOST].ct[0],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct[1],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct[2],
    esalt_bufs[DIGESTS_OFFSET_HOST].ct[3]
  };

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

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];

    rc4_init_104 (S, w0, lid);

    u32 out[4];

    u8 i = 0;
    u8 j = 0;

    if (dropN > 0)
    {
      rc4_dropN (S, &i, &j, dropN, lid);
    }

    rc4_next_16 (S, i, j, ct, out, lid);

    if (pt_len == 13)
    {
      out[3] &= pt_masks[1];
    }
    else
    {
      out[3] = 0;

      if (pt_len < 9)
      {
        out[2] = 0;

        if (pt_len < 5)
        {
          out[1] = 0;

          if (pt_len >= 1 && pt_len <= 3)
          {
            out[0] &= pt_masks[pt_len];
          }
        }
        else if (pt_len <= 7)
        {
          out[1] &= pt_masks[pt_len];
        }
      }
      else if (pt_len <= 11)
      {
        out[2] &= pt_masks[pt_len];
      }
    }

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ KERNEL_FA void m33502_s08 (KERN_ATTR_ESALT (rc4_t))
{
}

KERNEL_FQ KERNEL_FA void m33502_s16 (KERN_ATTR_ESALT (rc4_t))
{
}
