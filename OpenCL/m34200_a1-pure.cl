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

DECLSPEC u64 MurmurHash64A (const u64 seed, PRIVATE_AS const u32 *data, const u32 len)
{
#define M 0xc6a4a7935bd1e995
#define R 47

  // Initialize hash
  u64 hash = seed ^ (len * M);

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

KERNEL_FQ KERNEL_FA void m34200_mxx (KERN_ATTR_BASIC ())
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

  if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
  {
    // copy left buffer
    GLOBAL_AS const u8 *left = (GLOBAL_AS const u8 *) pws[gid].i;
    // probably bad for performance
    for (u32 i = 0; i < pws[gid].pw_len; i++)
    {
      combined_buf[i] = left[i];
    }
  }

  /**
   * salt
   */

  // Reconstruct seed from two u32s
  const u32 seed_lo = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 seed_hi = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u64 seed = hl32_to_64 (seed_hi, seed_lo);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      // copy right buffer (combs after pws)
      GLOBAL_AS const u8 *right = (GLOBAL_AS const u8 *) combs_buf[il_pos].i;
      for (u32 i = 0; i < combs_buf[il_pos].pw_len; i++)
      {
        combined_buf[i + pws[gid].pw_len] = right[i];
      }
    }
    else
    {
      // copy combs first
      GLOBAL_AS const u8 *right = (GLOBAL_AS const u8 *) combs_buf[il_pos].i;
      for (u32 i = 0; i < combs_buf[il_pos].pw_len; i++)
      {
        combined_buf[i] = right[i];
      }

      // copy pws after combs
      GLOBAL_AS const u8 *left = (GLOBAL_AS const u8 *) pws[gid].i;
      for (u32 i = 0; i < pws[gid].pw_len; i++)
      {
        combined_buf[i + combs_buf[il_pos].pw_len] = left[i];
      }
    }

    u64x hash = MurmurHash64A (seed, comb_ptr, pws[gid].pw_len + combs_buf[il_pos].pw_len);

    const u32x r0 = l32_from_64 (hash);
    const u32x r1 = h32_from_64 (hash);
    const u32x z = 0;

    COMPARE_M_SCALAR (r0, r1, z, z);
  }
}

KERNEL_FQ KERNEL_FA void m34200_sxx (KERN_ATTR_BASIC ())
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

  if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
  {
    // copy left buffer
    GLOBAL_AS const u8 *left = (GLOBAL_AS const u8 *) pws[gid].i;
    // probably bad for performance
    for (u32 i = 0; i < pws[gid].pw_len; i++)
    {
      combined_buf[i] = left[i];
    }
  }

  /**
   * salt
   */

  // Reconstruct seed from two u32s
  const u32 seed_lo = salt_bufs[SALT_POS_HOST].salt_buf[0];
  const u32 seed_hi = salt_bufs[SALT_POS_HOST].salt_buf[1];
  const u64 seed = hl32_to_64 (seed_hi, seed_lo);

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
    if (COMBS_MODE == COMBINATOR_MODE_BASE_LEFT)
    {
      // copy right buffer (combs after pws)
      GLOBAL_AS const u8 *right = (GLOBAL_AS const u8 *) combs_buf[il_pos].i;
      for (u32 i = 0; i < combs_buf[il_pos].pw_len; i++)
      {
        combined_buf[i + pws[gid].pw_len] = right[i];
      }
    }
    else
    {
      // copy combs first
      GLOBAL_AS const u8 *right = (GLOBAL_AS const u8 *) combs_buf[il_pos].i;
      for (u32 i = 0; i < combs_buf[il_pos].pw_len; i++)
      {
        combined_buf[i] = right[i];
      }

      // copy pws after combs
      GLOBAL_AS const u8 *left = (GLOBAL_AS const u8 *) pws[gid].i;
      for (u32 i = 0; i < pws[gid].pw_len; i++)
      {
        combined_buf[i + combs_buf[il_pos].pw_len] = left[i];
      }
    }

    u64 hash = MurmurHash64A (seed, comb_ptr, pws[gid].pw_len + combs_buf[il_pos].pw_len);

    const u32 r0 = l32_from_64 (hash);
    const u32 r1 = h32_from_64 (hash);
    const u32 z = 0;

    COMPARE_S_SCALAR (r0, r1, z, z);
  }
}
