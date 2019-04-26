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
#include "inc_hash_md4.cl"
#include "inc_hash_md5.cl"
#endif

typedef struct netntlm
{
  u32 user_len;
  u32 domain_len;
  u32 srvchall_len;
  u32 clichall_len;

  u32 userdomain_buf[64];
  u32 chall_buf[256];

} netntlm_t;

KERNEL_FQ void m05600_mxx (KERN_ATTR_RULES_ESALT (netntlm_t))
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

    md4_ctx_t ctx1;

    md4_init (&ctx1);

    md4_update_utf16le (&ctx1, tmp.i, tmp.pw_len);

    md4_final (&ctx1);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx1.h[0];
    w0[1] = ctx1.h[1];
    w0[2] = ctx1.h[2];
    w0[3] = ctx1.h[3];
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

    md5_hmac_ctx_t ctx0;

    md5_hmac_init_64 (&ctx0, w0, w1, w2, w3);

    md5_hmac_update_global (&ctx0, esalt_bufs[digests_offset].userdomain_buf, esalt_bufs[digests_offset].user_len + esalt_bufs[digests_offset].domain_len);

    md5_hmac_final (&ctx0);

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

    md5_hmac_update_global (&ctx, esalt_bufs[digests_offset].chall_buf, esalt_bufs[digests_offset].srvchall_len + esalt_bufs[digests_offset].clichall_len);

    md5_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m05600_sxx (KERN_ATTR_RULES_ESALT (netntlm_t))
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
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
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

    md4_ctx_t ctx1;

    md4_init (&ctx1);

    md4_update_utf16le (&ctx1, tmp.i, tmp.pw_len);

    md4_final (&ctx1);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx1.h[0];
    w0[1] = ctx1.h[1];
    w0[2] = ctx1.h[2];
    w0[3] = ctx1.h[3];
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

    md5_hmac_ctx_t ctx0;

    md5_hmac_init_64 (&ctx0, w0, w1, w2, w3);

    md5_hmac_update_global (&ctx0, esalt_bufs[digests_offset].userdomain_buf, esalt_bufs[digests_offset].user_len + esalt_bufs[digests_offset].domain_len);

    md5_hmac_final (&ctx0);

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

    md5_hmac_update_global (&ctx, esalt_bufs[digests_offset].chall_buf, esalt_bufs[digests_offset].srvchall_len + esalt_bufs[digests_offset].clichall_len);

    md5_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
