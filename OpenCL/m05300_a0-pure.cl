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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#endif

typedef struct ikepsk
{
  u32 nr_buf[16];
  u32 nr_len;

  u32 msg_buf[128];
  u32 msg_len[6];

} ikepsk_t;

KERNEL_FQ void m05300_mxx (KERN_ATTR_RULES_ESALT (ikepsk_t))
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

    md5_hmac_ctx_t ctx0;

    md5_hmac_init (&ctx0, tmp.i, tmp.pw_len);

    md5_hmac_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].nr_buf, esalt_bufs[DIGESTS_OFFSET_HOST].nr_len);

    md5_hmac_final (&ctx0);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx0.opad.h[0];
    w0[1] = ctx0.opad.h[1];
    w0[2] = ctx0.opad.h[2];
    w0[3] = ctx0.opad.h[3];
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_hmac_ctx_t ctx;

    md5_hmac_init_64 (&ctx, w0, w1, w2, w3);

    md5_hmac_update_global (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].msg_buf, esalt_bufs[DIGESTS_OFFSET_HOST].msg_len[5]);

    md5_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m05300_sxx (KERN_ATTR_RULES_ESALT (ikepsk_t))
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
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
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

    md5_hmac_ctx_t ctx0;

    md5_hmac_init (&ctx0, tmp.i, tmp.pw_len);

    md5_hmac_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].nr_buf, esalt_bufs[DIGESTS_OFFSET_HOST].nr_len);

    md5_hmac_final (&ctx0);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx0.opad.h[0];
    w0[1] = ctx0.opad.h[1];
    w0[2] = ctx0.opad.h[2];
    w0[3] = ctx0.opad.h[3];
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    md5_hmac_ctx_t ctx;

    md5_hmac_init_64 (&ctx, w0, w1, w2, w3);

    md5_hmac_update_global (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].msg_buf, esalt_bufs[DIGESTS_OFFSET_HOST].msg_len[5]);

    md5_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
