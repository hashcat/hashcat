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

  u32x a_ref = crc32_global (pws[gid].i, pws[gid].pw_len, iv);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // -a 12 puts the base word inside the amplifier instead of beside it, so a candidate is five
    // pieces: mask, base word, mask, second word, mask. The state precomputed outside this loop ends
    // with the base word and is only reusable while the base word still starts the candidate.

    u32x a_pre = a_ref;

    if (COMBS_IS_MIDDLE)
    {
      a_pre = crc32_global (COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, iv);
      a_pre = crc32_global (pws[gid].i,            pws[gid].pw_len,            a_pre);
      a_pre = crc32_global (COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, a_pre);
      a_pre = crc32_global (COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, a_pre);
    }

    u32x a = crc32_global (COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, a_pre);

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

  const u32x a_ref = crc32_global (pws[gid].i, pws[gid].pw_len, iv);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // -a 12 puts the base word inside the amplifier instead of beside it, so a candidate is five
    // pieces: mask, base word, mask, second word, mask. The state precomputed outside this loop ends
    // with the base word and is only reusable while the base word still starts the candidate.

    u32x a_pre = a_ref;

    if (COMBS_IS_MIDDLE)
    {
      a_pre = crc32_global (COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, iv);
      a_pre = crc32_global (pws[gid].i,            pws[gid].pw_len,            a_pre);
      a_pre = crc32_global (COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, a_pre);
      a_pre = crc32_global (COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, a_pre);
    }

    u32x a = crc32_global (COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, a_pre);

    u32x z = 0;

    COMPARE_S_SCALAR (a, z, z, z);
  }
}
