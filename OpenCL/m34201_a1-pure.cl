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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#endif

DECLSPEC u64 MurmurHash64A (PRIVATE_AS const u32 *data, const u32 len)
{
#define M 0xc6a4a7935bd1e995
#define R 47

  // Initialize hash
  u64 hash = len * M;

  // Twice the number of u64 blocks
  const u32 num_u32_blocks = (len / 8) * 2;

  // Loop over one u64 at a time
  u32 i = 0;
  while (i < num_u32_blocks)
  {
    // Reconstruct u64 from two u32s
    u64 k = hl32_to_64 (data[i + 1], data[i]);

    k *= M;
    k ^= k >> R;
    k *= M;

    hash ^= k;
    hash *= M;

    i += 2;
  }

  // Up to 7 overflow bytes
  const u32 overflow = len & 7;

  if (overflow > 4)
  {
    hash ^= hl32_to_64 (data[i + 1], data[i]);
    hash *= M;
  }
  else if (overflow > 0)
  {
    hash ^= hl32_to_64 (0, data[i]);
    hash *= M;
  }

  hash ^= hash >> R;
  hash *= M;
  hash ^= hash >> R;

#undef M
#undef R

  return hash;
}

KERNEL_FQ KERNEL_FA void m34201_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  PRIVATE_AS u8 combined_buf[256] = {0};
  PRIVATE_AS const u32 *comb_ptr = (PRIVATE_AS const u32 *) combined_buf;

  // copy left buffer
  GLOBAL_AS const u8 *left = (GLOBAL_AS const u8 *) pws[gid].i;
  // probably bad for performance
  for (u32 i = 0; i < pws[gid].pw_len; i++)
  {
    combined_buf[i] = left[i];
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // -a 12 puts the base word inside the amplifier instead of beside it, so the base word copied in
    // above no longer starts the candidate and all five pieces have to be copied per amplifier item.

    u32 comb_len = pws[gid].pw_len + combs_buf[il_pos].pw_len;

    if (COMBS_IS_MIDDLE)
    {
      comb_len = combs_copy_bytes (combined_buf, 0,        COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len);
      comb_len = combs_copy_bytes (combined_buf, comb_len, pws[gid].i,            pws[gid].pw_len);
      comb_len = combs_copy_bytes (combined_buf, comb_len, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      comb_len = combs_copy_bytes (combined_buf, comb_len, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
      comb_len = combs_copy_bytes (combined_buf, comb_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);
    }
    else
    {
      combs_copy_bytes (combined_buf, pws[gid].pw_len, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    }

    u64x hash = MurmurHash64A (comb_ptr, comb_len);

    const u32x r0 = l32_from_64 (hash);
    const u32x r1 = h32_from_64 (hash);
    const u32x z = 0;

    COMPARE_M_SCALAR (r0, r1, z, z);
  }
}

KERNEL_FQ KERNEL_FA void m34201_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  PRIVATE_AS u8 combined_buf[256] = {0};
  PRIVATE_AS const u32 *comb_ptr = (PRIVATE_AS const u32 *) combined_buf;

  // copy left buffer
  GLOBAL_AS const u8 *left = (GLOBAL_AS const u8 *) pws[gid].i;
  // probably bad for performance
  for (u32 i = 0; i < pws[gid].pw_len; i++)
  {
    combined_buf[i] = left[i];
  }

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

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    // -a 12 puts the base word inside the amplifier instead of beside it, so the base word copied in
    // above no longer starts the candidate and all five pieces have to be copied per amplifier item.

    u32 comb_len = pws[gid].pw_len + combs_buf[il_pos].pw_len;

    if (COMBS_IS_MIDDLE)
    {
      comb_len = combs_copy_bytes (combined_buf, 0,        COMBS_PRE  (il_pos).i, COMBS_PRE  (il_pos).pw_len);
      comb_len = combs_copy_bytes (combined_buf, comb_len, pws[gid].i,            pws[gid].pw_len);
      comb_len = combs_copy_bytes (combined_buf, comb_len, COMBS_MID  (il_pos).i, COMBS_MID  (il_pos).pw_len);
      comb_len = combs_copy_bytes (combined_buf, comb_len, COMBS_WORD (il_pos).i, COMBS_WORD (il_pos).pw_len);
      comb_len = combs_copy_bytes (combined_buf, comb_len, COMBS_POST (il_pos).i, COMBS_POST (il_pos).pw_len);
    }
    else
    {
      combs_copy_bytes (combined_buf, pws[gid].pw_len, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);
    }

    u64 hash = MurmurHash64A (comb_ptr, comb_len);

    const u32 r0 = l32_from_64 (hash);
    const u32 r1 = h32_from_64 (hash);
    const u32 z = 0;

    COMPARE_S_SCALAR (r0, r1, z, z);
  }
}
