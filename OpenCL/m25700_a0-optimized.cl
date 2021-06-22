/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp_optimized.h"
#include "inc_rp_optimized.cl"
#include "inc_simd.cl"
#endif

DECLSPEC u32 MurmurHash (const u32 seed, const u32 *w, const int pw_len)
{
  u32 hash = seed;

  #define M 0x7fd652ad
  #define R 16

  hash += 0xdeadbeef;

  int i;
  int j;

  for (i = 0, j = 0; i < pw_len - 3; i += 4, j += 1)
  {
    const u32 tmp = w[j];

    hash += tmp;
    hash *= M;
    hash ^= hash >> R;
  }

  if (pw_len & 3)
  {
    const u32 tmp = w[j];

    hash += tmp;
    hash *= M;
    hash ^= hash >> R;
  }

  hash *= M;
  hash ^= hash >> 10;
  hash *= M;
  hash ^= hash >> 17;

  #undef M
  #undef R

  return hash;
}

KERNEL_FQ void m25700_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * seed
   */

  const u32 seed = salt_bufs[SALT_POS].salt_buf[0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w[16] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w + 0, w + 4);

    u32x hash = MurmurHash (seed, w, out_len);

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m25700_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m25700_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m25700_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R0],
    0,
    0,
    0
  };

  /**
   * seed
   */

  const u32 seed = salt_bufs[SALT_POS].salt_buf[0];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    u32x w[16] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w + 0, w + 4);

    u32x hash = MurmurHash (seed, w, out_len);

    const u32x r0 = hash;
    const u32x r1 = 0;
    const u32x r2 = 0;
    const u32x r3 = 0;

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m25700_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m25700_s16 (KERN_ATTR_RULES ())
{
}
