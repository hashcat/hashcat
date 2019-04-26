/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"
#endif

DECLSPEC u32x hashCode_w0 (const u32x init, const u32x w0, const u32 *w, const u32 pw_len)
{
  u32x hash = init;

  u32x tmp0 = w0;

  const u32 c0 = (pw_len > 4) ? 4 : pw_len;

  switch (c0)
  {
    case 1: hash += tmp0 & 0xff; tmp0 >>= 8; break;
    case 2: hash += tmp0 & 0xff; tmp0 >>= 8; hash *= 31;
            hash += tmp0 & 0xff; tmp0 >>= 8; break;
    case 3: hash += tmp0 & 0xff; tmp0 >>= 8; hash *= 31;
            hash += tmp0 & 0xff; tmp0 >>= 8; hash *= 31;
            hash += tmp0 & 0xff; tmp0 >>= 8; break;
    case 4: hash += tmp0 & 0xff; tmp0 >>= 8; hash *= 31;
            hash += tmp0 & 0xff; tmp0 >>= 8; hash *= 31;
            hash += tmp0 & 0xff; tmp0 >>= 8; hash *= 31;
            hash += tmp0 & 0xff; tmp0 >>= 8; break;
  }

  for (u32 i = 4; i < pw_len; i += 4)
  {
    u32 tmp = w[i / 4];

    const u32 left = pw_len - i;

    const u32 c = (left > 4) ? 4 : left;

    switch (c)
    {
      case 1:
        hash *= 31; hash += (tmp >>  0) & 0xff;
        break;
      case 2:
        hash *= 31; hash += (tmp >>  0) & 0xff;
        hash *= 31; hash += (tmp >>  8) & 0xff;
        break;
      case 3:
        hash *= 31; hash += (tmp >>  0) & 0xff;
        hash *= 31; hash += (tmp >>  8) & 0xff;
        hash *= 31; hash += (tmp >> 16) & 0xff;
        break;
      case 4:
        hash *= 31; hash += (tmp >>  0) & 0xff;
        hash *= 31; hash += (tmp >>  8) & 0xff;
        hash *= 31; hash += (tmp >> 16) & 0xff;
        hash *= 31; hash += (tmp >> 24) & 0xff;
        break;
    }
  }

  return hash;
}

KERNEL_FQ void m18700_mxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x hash = hashCode_w0 (0, w0, w, pw_len);

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m18700_sxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    u32x hash = hashCode_w0 (0, w0, w, pw_len);

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}
