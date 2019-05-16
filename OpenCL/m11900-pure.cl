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
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct pbkdf2_md5
{
  u32 salt_buf[64];

} pbkdf2_md5_t;

typedef struct pbkdf2_md5_tmp
{
  u32  ipad[4];
  u32  opad[4];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_md5_tmp_t;

DECLSPEC void hmac_md5_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];

  md5_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = 0x80;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 16) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];

  md5_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m11900_init (KERN_ATTR_TMPS_ESALT (pbkdf2_md5_tmp_t, pbkdf2_md5_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  md5_hmac_ctx_t md5_hmac_ctx;

  md5_hmac_init_global (&md5_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = md5_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = md5_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = md5_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = md5_hmac_ctx.ipad.h[3];

  tmps[gid].opad[0] = md5_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = md5_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = md5_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = md5_hmac_ctx.opad.h[3];

  md5_hmac_update_global (&md5_hmac_ctx, esalt_bufs[digests_offset].salt_buf, salt_bufs[salt_pos].salt_len);

  for (u32 i = 0, j = 1; i < 4; i += 4, j += 1)
  {
    md5_hmac_ctx_t md5_hmac_ctx2 = md5_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j << 24;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
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

    md5_hmac_update_64 (&md5_hmac_ctx2, w0, w1, w2, w3, 4);

    md5_hmac_final (&md5_hmac_ctx2);

    tmps[gid].dgst[i + 0] = md5_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = md5_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = md5_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = md5_hmac_ctx2.opad.h[3];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
  }
}

KERNEL_FQ void m11900_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_md5_tmp_t, pbkdf2_md5_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[4];
  u32x opad[4];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);

  for (u32 i = 0; i < 4; i += 4)
  {
    u32x dgst[4];
    u32x out[4];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = 0x80;
      w1[1] = 0;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = (64 + 16) * 8;
      w3[3] = 0;

      hmac_md5_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
  }
}

KERNEL_FQ void m11900_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_md5_tmp_t, pbkdf2_md5_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  const u64 lid = get_local_id (0);

  const u32 r0 = tmps[gid].out[DGST_R0];
  const u32 r1 = tmps[gid].out[DGST_R1];
  const u32 r2 = tmps[gid].out[DGST_R2];
  const u32 r3 = tmps[gid].out[DGST_R3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
