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

typedef struct crc64
{
  u64 iv;

} crc64_t;

KERNEL_FQ KERNEL_FA void m28000_mxx (KERN_ATTR_ESALT (crc64_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * CRC64Jones shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_crc64jonestab[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_crc64jonestab[i] = crc64jonestab[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_crc64jonestab = crc64jonestab;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * salt
   */

  const u64 iv = esalt_bufs[DIGESTS_OFFSET_HOST].iv;

  /**
   * base
   */

  u64 a_ref = crc64j_global (pws[gid].i, pws[gid].pw_len, iv, s_crc64jonestab);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // -a 12 puts the base word inside the amplifier instead of beside it, so a candidate is five
    // pieces: mask, base word, mask, second word, mask. The state precomputed outside this loop ends
    // with the base word and is only reusable while the base word still starts the candidate.

    u64 a_pre = a_ref;

    if (COMBS_IS_MIDDLE)
    {
      a_pre = crc64j_global (COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, iv,    s_crc64jonestab);
      a_pre = crc64j_global (pws[gid].i,            pws[gid].pw_len,            a_pre, s_crc64jonestab);
      a_pre = crc64j_global (COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, a_pre, s_crc64jonestab);
      a_pre = crc64j_global (COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, a_pre, s_crc64jonestab);
    }

    u64 a = crc64j_global (COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, a_pre, s_crc64jonestab);

    const u32 r0 = l32_from_64 (a);
    const u32 r1 = h32_from_64 (a);
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m28000_sxx (KERN_ATTR_ESALT (crc64_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * CRC64Jones shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u64 s_crc64jonestab[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_crc64jonestab[i] = crc64jonestab[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a *s_crc64jonestab = crc64jonestab;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * salt
   */

  const u64 iv = esalt_bufs[DIGESTS_OFFSET_HOST].iv;

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
   * base
   */

  u64 a_ref = crc64j_global (pws[gid].i, pws[gid].pw_len, iv, s_crc64jonestab);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // -a 12 puts the base word inside the amplifier instead of beside it, so a candidate is five
    // pieces: mask, base word, mask, second word, mask. The state precomputed outside this loop ends
    // with the base word and is only reusable while the base word still starts the candidate.

    u64 a_pre = a_ref;

    if (COMBS_IS_MIDDLE)
    {
      a_pre = crc64j_global (COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len, iv,    s_crc64jonestab);
      a_pre = crc64j_global (pws[gid].i,            pws[gid].pw_len,            a_pre, s_crc64jonestab);
      a_pre = crc64j_global (COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len, a_pre, s_crc64jonestab);
      a_pre = crc64j_global (COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len, a_pre, s_crc64jonestab);
    }

    u64 a = crc64j_global (COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len, a_pre, s_crc64jonestab);

    const u32 r0 = l32_from_64 (a);
    const u32 r1 = h32_from_64 (a);
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
