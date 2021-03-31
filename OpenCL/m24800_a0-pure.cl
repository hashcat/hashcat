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
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha1.cl"
#endif

KERNEL_FQ void m24800_mxx (KERN_ATTR_RULES ())
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

  u32 t[128] = { 0 };


  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    // we need to swap the endian before we convert to unicode.
    for (u32 i = 0, idx = 0; i < tmp.pw_len; i += 4, idx += 1)
    {
      tmp.i[idx] = hc_swap32(tmp.i[idx]);
    }

    // make it unicode.
    for(u32 i = 0, idx = 0; idx < tmp.pw_len; i += 2, idx += 1){
        make_utf16beN(&tmp.i[idx], &t[i], &t[i+1]);
    }

    // hash time
    sha1_hmac_ctx_t ctx;

    sha1_hmac_init (&ctx, t, tmp.pw_len * 2);

    sha1_hmac_update (&ctx, t, tmp.pw_len * 2);

    sha1_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m24800_sxx (KERN_ATTR_RULES ())
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
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  COPY_PW (pws[gid]);

  u32 t[128] = { 0 };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    // swap endian
    for (u32 i = 0, idx = 0; i < tmp.pw_len; i += 4, idx += 1)
    {
      tmp.i[idx] = hc_swap32(tmp.i[idx]);
    }

    // make it unicode.
    for(u32 i = 0, idx = 0; idx < tmp.pw_len; i += 2, idx += 1){
        make_utf16beN(&tmp.i[idx], &t[i], &t[i+1]);
    }

    // hash time
    sha1_hmac_ctx_t ctx;

    sha1_hmac_init (&ctx, t, tmp.pw_len*2);

    sha1_hmac_update (&ctx, t, tmp.pw_len*2);

    sha1_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
