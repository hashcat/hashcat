/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//incompatible because of branches
//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_checksum_crc.cl)
#endif

KERNEL_FQ KERNEL_FA void m11500_mxx (KERN_ATTR_BASIC ())
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

  /**
   * salt
   */

  const u32 iv = salt_bufs[SALT_POS_HOST].salt_buf[0];

  /**
   * base
   */

  u32x a_ref;

  if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
  {
    a_ref = crc32_global (pws[gid].i, pws[gid].pw_len, iv);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32x a;

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      a = crc32_global (combs_buf[il_pos].i, combs_buf[il_pos].pw_len, a_ref);
    }
    else
    {
      a = crc32_global (combs_buf[il_pos].i, combs_buf[il_pos].pw_len, iv);

      a = crc32_global (pws[gid].i, pws[gid].pw_len, a);
    }

    u32x z = 0;

    COMPARE_M_SCALAR (a, z, z, z);
  }
}

KERNEL_FQ KERNEL_FA void m11500_sxx (KERN_ATTR_BASIC ())
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

  /**
   * salt
   */

  const u32 iv = salt_bufs[SALT_POS_HOST].salt_buf[0];

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
   * base
   */

  u32x a_ref;

  if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
  {
    a_ref = crc32_global (pws[gid].i, pws[gid].pw_len, iv);
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    u32x a;

    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      a = crc32_global (combs_buf[il_pos].i, combs_buf[il_pos].pw_len, a_ref);
    }
    else
    {
      a = crc32_global (combs_buf[il_pos].i, combs_buf[il_pos].pw_len, iv);

      a = crc32_global (pws[gid].i, pws[gid].pw_len, a);
    }

    u32x z = 0;

    COMPARE_S_SCALAR (a, z, z, z);
  }
}
