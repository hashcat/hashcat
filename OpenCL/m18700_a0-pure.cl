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
#include M2S(INCLUDE_PATH/inc_rp_common.cl)
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

DECLSPEC u32 hashCode (const u32 init, PRIVATE_AS const u32 *w, const u32 pw_len)
{
  u32 hash = init;

  for (u32 i = 0; i < pw_len; i += 4)
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

KERNEL_FQ KERNEL_FA void m18700_mxx (KERN_ATTR_RULES ())
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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    const u32 hash = hashCode (0, tmp.i, tmp.pw_len);

    const u32 r0 = hash;
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ KERNEL_FA void m18700_sxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    const u32 hash = hashCode (0, tmp.i, tmp.pw_len);

    const u32 r0 = hash;
    const u32 r1 = 0;
    const u32 r2 = 0;
    const u32 r3 = 0;

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
