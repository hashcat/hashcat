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
#include "inc_scalar.cl"
#include "inc_hash_md5.cl"
#include "inc_bfacs_common.cl"
#endif

KERNEL_FQ void m24308_mxx (KERN_ATTR_ESALT (bfacs_t))
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

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, esalt_bufs[digests_offset].salt, BFACS_SALT_LEN);
  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx);

    const u32 md5_chk = ctx.h[0] ^ ctx.h[1] ^ ctx.h[2] ^ ctx.h[3];

    const u32 digest_tp0[4] = { md5_chk, 0, 0, 0 };

    if (check (digest_tp0,
               bitmaps_buf_s1_a, bitmaps_buf_s1_b, bitmaps_buf_s1_c, bitmaps_buf_s1_d,
               bitmaps_buf_s2_a, bitmaps_buf_s2_b, bitmaps_buf_s2_c, bitmaps_buf_s2_d,
               bitmap_mask,
               bitmap_shift1,
               bitmap_shift2))
    {
      int digest_pos = find_hash (digest_tp0, digests_cnt, &digests_buf[digests_offset]);

      if (digest_pos != -1)
      {
        u8 pw[256] = { 0 };

        for (u32 i = 0; i < pws[gid].pw_len; i++)
        {
          pw[i] = ((GLOBAL_AS u8 *)pws[gid].i)[i];
        }

        for (u32 i = 0; i < combs_buf[il_pos].pw_len; i++)
        {
          pw[i + pws[gid].pw_len] = ((GLOBAL_AS u8 *)combs_buf[il_pos].i)[i];
        }

        if (decrypt_check (&esalt_bufs[digests_offset], (u32 *)pw, pws[gid].pw_len + combs_buf[il_pos].pw_len))
        {
          const u32 final_hash_pos = digests_offset + digest_pos;

          if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)
          {
            mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, final_hash_pos, gid, il_pos, 0, 0);
          }
        }
      }
    }
  }
}

KERNEL_FQ void m24308_sxx (KERN_ATTR_ESALT (bfacs_t))
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

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, esalt_bufs[digests_offset].salt, BFACS_SALT_LEN);

  md5_update_global (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    md5_ctx_t ctx = ctx0;

    md5_update_global (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    md5_final (&ctx);

    const u32 md5_chk = ctx.h[0] ^ ctx.h[1] ^ ctx.h[2] ^ ctx.h[3];

    if (md5_chk == digests_buf[digests_offset].digest_buf[0])
    {
      u8 pw[256] = { 0 };

      for (u32 i = 0; i < pws[gid].pw_len; i++)
      {
        pw[i] = ((GLOBAL_AS u8 *)pws[gid].i)[i];
      }

      for (u32 i = 0; i < combs_buf[il_pos].pw_len; i++)
      {
        pw[i + pws[gid].pw_len] = ((GLOBAL_AS u8 *)combs_buf[il_pos].i)[i];
      }

      if (decrypt_check (&esalt_bufs[digests_offset], (u32 *)pw, pws[gid].pw_len + combs_buf[il_pos].pw_len))
      {
        if (atomic_inc (&hashes_shown[digests_offset]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
        }
      }
    }
  }
}
