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
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_md5.cl"

__kernel void m18700_mxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 hash = 0;

    for (u32 i = 0; i < tmp.pw_len; i++)
    {
      const u32 c32 = tmp.i[i / 4];

      const u32 c = (c32 >> ((i & 3) * 8)) & 0xff;

      hash *= 31;
      hash += c;
    }

    const u32 r0 = hash;
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m18700_sxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    u32 hash = 0;

    for (u32 i = 0; i < tmp.pw_len; i++)
    {
      const u32 c32 = tmp.i[i / 4];

      const u32 c = (c32 >> ((i & 3) * 8)) & 0xff;

      hash *= 31;
      hash += c;
    }

    const u32 r0 = hash;
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
