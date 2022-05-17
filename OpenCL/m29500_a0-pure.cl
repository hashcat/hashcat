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
#include M2S(INCLUDE_PATH/inc_rp.h)
#include M2S(INCLUDE_PATH/inc_rp.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#endif


KERNEL_FQ void m29500_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */
  const u32 fixed[16] = 
  {
    0x636f6f6b,
    0x69652d73,
    0x65737369,
    0x6f6e0000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000
  };
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * base
   */
  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[16] = { 0 };
  #pragma unroll
  for (u32 id = 0; id < 16; id++)
  {
    s[id] = hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[id]);
  };

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);
      sha1_hmac_ctx_t ctx;
      sha1_hmac_init_swap (&ctx, tmp.i, tmp.pw_len);
      sha1_hmac_update (&ctx, fixed, 14);
      sha1_hmac_final (&ctx);
      u32 intermediate[16] = {0};
      intermediate[0] = ctx.opad.h[0];
      intermediate[1] = ctx.opad.h[1];
      intermediate[2] = ctx.opad.h[2];
      intermediate[3] = ctx.opad.h[3];
      intermediate[4] = ctx.opad.h[4];
      sha1_hmac_init (&ctx, intermediate, 16);  
      sha1_hmac_update (&ctx, s, salt_len);
      sha1_hmac_final (&ctx);
      const u32 r0 = ctx.opad.h[0]; 
      const u32 r1 = ctx.opad.h[1];
      const u32 r2 = ctx.opad.h[2];
      const u32 r3 = ctx.opad.h[3];
      COMPARE_M_SIMD (r0, r1, r2, r3);
   // };
  }
}

KERNEL_FQ void m29500_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */
  const u32 fixed[16] = 
  {
    0x636f6f6b,
    0x69652d73,
    0x65737369,
    0x6f6e0000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000,
    0x00000000
  };
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };
  
  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  u32 s[16] = { 0 };
  #pragma unroll
  for (u32 id = 0; id < 16; id++)
  {
    s[id] = hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[id]);
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
    

    sha1_hmac_ctx_t ctx;
    sha1_hmac_init_swap (&ctx, tmp.i, tmp.pw_len);
    sha1_hmac_update (&ctx, fixed, 14);
    sha1_hmac_final (&ctx);
    u32 intermediate[16] = {0};
    intermediate[0] = ctx.opad.h[0];
    intermediate[1] = ctx.opad.h[1];
    intermediate[2] = ctx.opad.h[2];
    intermediate[3] = ctx.opad.h[3];
    intermediate[4] = ctx.opad.h[4];
    sha1_hmac_init (&ctx, intermediate, 16);  
    sha1_hmac_update (&ctx, s, salt_len);
    sha1_hmac_final (&ctx);
    const u32 r0 = ctx.opad.h[0]; 
    const u32 r1 = ctx.opad.h[1];
    const u32 r2 = ctx.opad.h[2];
    const u32 r3 = ctx.opad.h[3];
    COMPARE_S_SIMD (r0, r1, r2, r3);
    
  }
}
