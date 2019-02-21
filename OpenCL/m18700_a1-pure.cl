/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_md5.cl"

__kernel void m18700_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 base = 0;

  for (u32 i = 0; i < pws[gid].pw_len; i++)
  {
    const u32 c32 = pws[gid].i[i / 4];

    const u32 c = (c32 >> ((i & 3) * 8)) & 0xff;

    base *= 31;
    base += c;
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    u32 hash = base;

    for (u32 i = 0; i < combs_buf[il_pos].pw_len; i++)
    {
      const u32 c32 = combs_buf[il_pos].i[i / 4];

      const u32 c = (c32 >> ((i & 3) * 8)) & 0xff;

      hash *= 31;
      hash += c;
    }

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m18700_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    0,
    0,
    0
  };

  /**
   * base
   */

  u32 base = 0;

  for (u32 i = 0; i < pws[gid].pw_len; i++)
  {
    const u32 c32 = pws[gid].i[i / 4];

    const u32 c = (c32 >> ((i & 3) * 8)) & 0xff;

    base *= 31;
    base += c;
  }

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    u32 hash = base;

    for (u32 i = 0; i < combs_buf[il_pos].pw_len; i++)
    {
      const u32 c32 = combs_buf[il_pos].i[i / 4];

      const u32 c = (c32 >> ((i & 3) * 8)) & 0xff;

      hash *= 31;
      hash += c;
    }

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
