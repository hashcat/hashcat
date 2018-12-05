/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha1.cl"

__kernel void m05400_mxx (KERN_ATTR_VECTOR_ESALT (ikepsk_t))
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

  const u32 pw_len = pws[gid].pw_len & 255;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
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

    const u32x w0lr = w0l | w0r;

    w[0] = w0lr;

    sha1_hmac_ctx_t ctx0;

    sha1_hmac_init (&ctx0, w, pw_len);

    sha1_hmac_update_global_swap (&ctx0, esalt_bufs[digests_offset].nr_buf, esalt_bufs[digests_offset].nr_len);

    sha1_hmac_final (&ctx0);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx0.opad.h[0];
    w0[1] = ctx0.opad.h[1];
    w0[2] = ctx0.opad.h[2];
    w0[3] = ctx0.opad.h[3];
    w1[0] = ctx0.opad.h[4];
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

    sha1_hmac_ctx_t ctx;

    sha1_hmac_init_64 (&ctx, w0, w1, w2, w3);

    sha1_hmac_update_global_swap (&ctx, esalt_bufs[digests_offset].msg_buf, esalt_bufs[digests_offset].msg_len[5]);

    sha1_hmac_final (&ctx);

    const u32x r0 = ctx.opad.h[DGST_R0];
    const u32x r1 = ctx.opad.h[DGST_R1];
    const u32x r2 = ctx.opad.h[DGST_R2];
    const u32x r3 = ctx.opad.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

__kernel void m05400_sxx (KERN_ATTR_VECTOR_ESALT (ikepsk_t))
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

  const u32 pw_len = pws[gid].pw_len & 255;

  u32x w[64] = { 0 };

  for (int i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
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

    const u32x w0lr = w0l | w0r;

    w[0] = w0lr;

    sha1_hmac_ctx_t ctx0;

    sha1_hmac_init (&ctx0, w, pw_len);

    sha1_hmac_update_global_swap (&ctx0, esalt_bufs[digests_offset].nr_buf, esalt_bufs[digests_offset].nr_len);

    sha1_hmac_final (&ctx0);

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = ctx0.opad.h[0];
    w0[1] = ctx0.opad.h[1];
    w0[2] = ctx0.opad.h[2];
    w0[3] = ctx0.opad.h[3];
    w1[0] = ctx0.opad.h[4];
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

    sha1_hmac_ctx_t ctx;

    sha1_hmac_init_64 (&ctx, w0, w1, w2, w3);

    sha1_hmac_update_global_swap (&ctx, esalt_bufs[digests_offset].msg_buf, esalt_bufs[digests_offset].msg_len[5]);

    sha1_hmac_final (&ctx);

    const u32x r0 = ctx.opad.h[DGST_R0];
    const u32x r1 = ctx.opad.h[DGST_R1];
    const u32x r2 = ctx.opad.h[DGST_R2];
    const u32x r3 = ctx.opad.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
