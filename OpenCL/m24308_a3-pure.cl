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
#include "inc_bfacs_common.cl"
#endif

KERNEL_FQ void m24308_mxx (KERN_ATTR_VECTOR_ESALT (bfacs_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u32x zero = 0;

  /**
   * base
   */

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, esalt_bufs[digests_offset].salt, BFACS_SALT_LEN);

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    md5_ctx_vector_t ctx;

    md5_init_vector_from_scalar (&ctx, &ctx0);

    md5_update_vector (&ctx, w, pw_len);

    md5_final_vector (&ctx);

    const u32x md5_chk = ctx.h[0] ^ ctx.h[1] ^ ctx.h[2] ^ ctx.h[3];

    for (u32 v_pos = 0; v_pos < VECT_SIZE; v_pos++)
    {
      const u32 digest_tp0[4] = { VECTOR_ELEMENT(md5_chk, v_pos), 0, 0, 0 };

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
          u32 w_tmp[64];

          for (u32 i = 0; i < 64; i++)
          {
            w_tmp[i] = VECTOR_ELEMENT(w[i], v_pos);
          }

          if (decrypt_check (&esalt_bufs[digests_offset], w_tmp, pw_len))
          {
            const u32 final_hash_pos = digests_offset + digest_pos;

            if (vector_accessible (il_pos + v_pos, il_cnt, 0) && (atomic_inc (&hashes_shown[final_hash_pos]) == 0))
            {
              mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, final_hash_pos, gid, il_pos + v_pos, 0, 0);
            }
          }
        }
      }
    }
  }
}

KERNEL_FQ void m24308_sxx (KERN_ATTR_VECTOR_ESALT (bfacs_t))
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

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  md5_ctx_t ctx0;

  md5_init (&ctx0);

  md5_update_global (&ctx0, esalt_bufs[digests_offset].salt, BFACS_SALT_LEN);

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    md5_ctx_vector_t ctx;

    md5_init_vector_from_scalar (&ctx, &ctx0);

    md5_update_vector (&ctx, w, pw_len);

    md5_final_vector (&ctx);

    const u32x md5_chk = ctx.h[0] ^ ctx.h[1] ^ ctx.h[2] ^ ctx.h[3];

    for (u32 v_pos = 0; v_pos < VECT_SIZE; v_pos++)
    {
      if (VECTOR_ELEMENT(md5_chk, v_pos) == digests_buf[digests_offset].digest_buf[0])
      {
        u32 w_tmp[64];

        for (u32 i = 0; i < 64; i++)
        {
          w_tmp[i] = VECTOR_ELEMENT(w[i], v_pos);
        }

        if (decrypt_check (&esalt_bufs[digests_offset], w_tmp, pw_len))
        {
          if (atomic_inc (&hashes_shown[digests_offset]) == 0)
          {
            mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos + v_pos, 0, 0);
          }
        }
      }
    }
  }
}
