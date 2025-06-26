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
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
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

CONSTANT_VK u32 pt_masks[8] =
{
  0x00000000,
  0x000000FF,
  0x0000FFFF,
  0x00FFFFFF,
  0xFFFFFFFF,
  0x000000FF,
  0,
  0
};

KERNEL_FQ KERNEL_FA void m33500_m04 (KERN_ATTR_RULES_ESALT (rc4_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4] = { 0 };

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = 0;
  pw_buf0[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

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
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };

    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    rc4_init_40 (S, w0, lid);

    u32 out[4];

    u8 i = 0;
    u8 j = 0;

    if (dropN > 0)
    {
      rc4_dropN (S, &i, &j, dropN, lid);
    }

    rc4_next_16 (S, i, j, ct, out, lid);

    if (pt_len == 5)
    {
      out[1] &= pt_masks[1];
    }
    else
    {
      out[1] = 0;

      if (pt_len >= 1 && pt_len <= 3)
      {
        out[0] &= pt_masks[pt_len];
      }
    }

    out[2] = out[3] = 0;

    COMPARE_M_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ KERNEL_FA void m33500_m08 (KERN_ATTR_RULES_ESALT (rc4_t))
{
}

KERNEL_FQ KERNEL_FA void m33500_m16 (KERN_ATTR_RULES_ESALT (rc4_t))
{
}

KERNEL_FQ KERNEL_FA void m33500_s04 (KERN_ATTR_RULES_ESALT (rc4_t))
{
  /**
   * base
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4] = { 0 };

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = 0;
  pw_buf0[3] = 0;

  const u32 pw_len = pws[gid].pw_len & 63;

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
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };

    apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    /**
     * pdf
     */

    rc4_init_40 (S, w0, lid);

    u32 out[4];

    u8 i = 0;
    u8 j = 0;

    if (dropN > 0)
    {
      rc4_dropN (S, &i, &j, dropN, lid);
    }

    rc4_next_16 (S, i, j, ct, out, lid);

    if (pt_len == 5)
    {
      out[1] &= pt_masks[1];
    }
    else
    {
      out[1] = 0;

      if (pt_len >= 1 && pt_len <= 3)
      {
        out[0] &= pt_masks[pt_len];
      }
    }

    out[2] = out[3] = 0;

    COMPARE_S_SIMD (out[0], out[1], out[2], out[3]);
  }
}

KERNEL_FQ KERNEL_FA void m33500_s08 (KERN_ATTR_RULES_ESALT (rc4_t))
{
}

KERNEL_FQ KERNEL_FA void m33500_s16 (KERN_ATTR_RULES_ESALT (rc4_t))
{
}
