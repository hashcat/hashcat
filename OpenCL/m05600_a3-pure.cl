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
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
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

KERNEL_FQ void m05600_mxx (KERN_ATTR_VECTOR_ESALT (netntlm_t))
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32 w0lr = w0l | w0r;

    w[0] = w0lr;

    md4_ctx_t ctx1;

    md4_init (&ctx1);

    md4_update_utf16le (&ctx1, w, pw_len);

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

    md5_hmac_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].userdomain_buf, esalt_bufs[DIGESTS_OFFSET_HOST].user_len + esalt_bufs[DIGESTS_OFFSET_HOST].domain_len);

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

    md5_hmac_update_global (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].chall_buf, esalt_bufs[DIGESTS_OFFSET_HOST].srvchall_len + esalt_bufs[DIGESTS_OFFSET_HOST].clichall_len);

    md5_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m05600_sxx (KERN_ATTR_VECTOR_ESALT (netntlm_t))
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

  const u32 pw_len = pws[gid].pw_len;

  u32 w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32 w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32 w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32 w0lr = w0l | w0r;

    w[0] = w0lr;

    md4_ctx_t ctx1;

    md4_init (&ctx1);

    md4_update_utf16le (&ctx1, w, pw_len);

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

    md5_hmac_update_global (&ctx0, esalt_bufs[DIGESTS_OFFSET_HOST].userdomain_buf, esalt_bufs[DIGESTS_OFFSET_HOST].user_len + esalt_bufs[DIGESTS_OFFSET_HOST].domain_len);

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

    md5_hmac_update_global (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].chall_buf, esalt_bufs[DIGESTS_OFFSET_HOST].srvchall_len + esalt_bufs[DIGESTS_OFFSET_HOST].clichall_len);

    md5_hmac_final (&ctx);

    const u32 r0 = ctx.opad.h[DGST_R0];
    const u32 r1 = ctx.opad.h[DGST_R1];
    const u32 r2 = ctx.opad.h[DGST_R2];
    const u32 r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
