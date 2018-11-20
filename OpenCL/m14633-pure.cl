/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"
#include "inc_cipher_twofish.cl"

#include "inc_luks_af.cl"
#include "inc_luks_essiv.cl"
#include "inc_luks_xts.cl"

#include "inc_luks_twofish.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

#define MAX_ENTROPY 7.0

DECLSPEC void hmac_sha512_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, u64x *ipad, u64x *opad, u64x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);

  w0[0] = h32_from_64 (digest[0]);
  w0[1] = l32_from_64 (digest[0]);
  w0[2] = h32_from_64 (digest[1]);
  w0[3] = l32_from_64 (digest[1]);
  w1[0] = h32_from_64 (digest[2]);
  w1[1] = l32_from_64 (digest[2]);
  w1[2] = h32_from_64 (digest[3]);
  w1[3] = l32_from_64 (digest[3]);
  w2[0] = h32_from_64 (digest[4]);
  w2[1] = l32_from_64 (digest[4]);
  w2[2] = h32_from_64 (digest[5]);
  w2[3] = l32_from_64 (digest[5]);
  w3[0] = h32_from_64 (digest[6]);
  w3[1] = l32_from_64 (digest[6]);
  w3[2] = h32_from_64 (digest[7]);
  w3[3] = l32_from_64 (digest[7]);
  w4[0] = 0x80000000;
  w4[1] = 0;
  w4[2] = 0;
  w4[3] = 0;
  w5[0] = 0;
  w5[1] = 0;
  w5[2] = 0;
  w5[3] = 0;
  w6[0] = 0;
  w6[1] = 0;
  w6[2] = 0;
  w6[3] = 0;
  w7[0] = 0;
  w7[1] = 0;
  w7[2] = 0;
  w7[3] = (128 + 64) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha512_transform_vector (w0, w1, w2, w3, w4, w5, w6, w7, digest);
}

__kernel void m14633_init (KERN_ATTR_TMPS_ESALT (luks_tmp_t, luks_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_global_swap (&sha512_hmac_ctx, pws[gid].i, pws[gid].pw_len & 255);

  tmps[gid].ipad64[0] = sha512_hmac_ctx.ipad.h[0];
  tmps[gid].ipad64[1] = sha512_hmac_ctx.ipad.h[1];
  tmps[gid].ipad64[2] = sha512_hmac_ctx.ipad.h[2];
  tmps[gid].ipad64[3] = sha512_hmac_ctx.ipad.h[3];
  tmps[gid].ipad64[4] = sha512_hmac_ctx.ipad.h[4];
  tmps[gid].ipad64[5] = sha512_hmac_ctx.ipad.h[5];
  tmps[gid].ipad64[6] = sha512_hmac_ctx.ipad.h[6];
  tmps[gid].ipad64[7] = sha512_hmac_ctx.ipad.h[7];

  tmps[gid].opad64[0] = sha512_hmac_ctx.opad.h[0];
  tmps[gid].opad64[1] = sha512_hmac_ctx.opad.h[1];
  tmps[gid].opad64[2] = sha512_hmac_ctx.opad.h[2];
  tmps[gid].opad64[3] = sha512_hmac_ctx.opad.h[3];
  tmps[gid].opad64[4] = sha512_hmac_ctx.opad.h[4];
  tmps[gid].opad64[5] = sha512_hmac_ctx.opad.h[5];
  tmps[gid].opad64[6] = sha512_hmac_ctx.opad.h[6];
  tmps[gid].opad64[7] = sha512_hmac_ctx.opad.h[7];

  sha512_hmac_update_global_swap (&sha512_hmac_ctx, salt_bufs[digests_offset].salt_buf, salt_bufs[salt_pos].salt_len);

  const u32 key_size = esalt_bufs[digests_offset].key_size;

  for (u32 i = 0, j = 1; i < ((key_size / 8) / 4); i += 16, j += 1)
  {
    sha512_hmac_ctx_t sha512_hmac_ctx2 = sha512_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];
    u32 w4[4];
    u32 w5[4];
    u32 w6[4];
    u32 w7[4];

    w0[0] = j;
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
    w4[0] = 0;
    w4[1] = 0;
    w4[2] = 0;
    w4[3] = 0;
    w5[0] = 0;
    w5[1] = 0;
    w5[2] = 0;
    w5[3] = 0;
    w6[0] = 0;
    w6[1] = 0;
    w6[2] = 0;
    w6[3] = 0;
    w7[0] = 0;
    w7[1] = 0;
    w7[2] = 0;
    w7[3] = 0;

    sha512_hmac_update_128 (&sha512_hmac_ctx2, w0, w1, w2, w3, w4, w5, w6, w7, 4);

    sha512_hmac_final (&sha512_hmac_ctx2);

    tmps[gid].dgst64[i + 0] = sha512_hmac_ctx2.opad.h[0];
    tmps[gid].dgst64[i + 1] = sha512_hmac_ctx2.opad.h[1];
    tmps[gid].dgst64[i + 2] = sha512_hmac_ctx2.opad.h[2];
    tmps[gid].dgst64[i + 3] = sha512_hmac_ctx2.opad.h[3];
    tmps[gid].dgst64[i + 4] = sha512_hmac_ctx2.opad.h[4];
    tmps[gid].dgst64[i + 5] = sha512_hmac_ctx2.opad.h[5];
    tmps[gid].dgst64[i + 6] = sha512_hmac_ctx2.opad.h[6];
    tmps[gid].dgst64[i + 7] = sha512_hmac_ctx2.opad.h[7];

    tmps[gid].out64[i + 0] = tmps[gid].dgst64[i + 0];
    tmps[gid].out64[i + 1] = tmps[gid].dgst64[i + 1];
    tmps[gid].out64[i + 2] = tmps[gid].dgst64[i + 2];
    tmps[gid].out64[i + 3] = tmps[gid].dgst64[i + 3];
    tmps[gid].out64[i + 4] = tmps[gid].dgst64[i + 4];
    tmps[gid].out64[i + 5] = tmps[gid].dgst64[i + 5];
    tmps[gid].out64[i + 6] = tmps[gid].dgst64[i + 6];
    tmps[gid].out64[i + 7] = tmps[gid].dgst64[i + 7];
  }
}

__kernel void m14633_loop (KERN_ATTR_TMPS_ESALT (luks_tmp_t, luks_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u64x ipad[8];
  u64x opad[8];

  ipad[0] = pack64v (tmps, ipad64, gid, 0);
  ipad[1] = pack64v (tmps, ipad64, gid, 1);
  ipad[2] = pack64v (tmps, ipad64, gid, 2);
  ipad[3] = pack64v (tmps, ipad64, gid, 3);
  ipad[4] = pack64v (tmps, ipad64, gid, 4);
  ipad[5] = pack64v (tmps, ipad64, gid, 5);
  ipad[6] = pack64v (tmps, ipad64, gid, 6);
  ipad[7] = pack64v (tmps, ipad64, gid, 7);

  opad[0] = pack64v (tmps, opad64, gid, 0);
  opad[1] = pack64v (tmps, opad64, gid, 1);
  opad[2] = pack64v (tmps, opad64, gid, 2);
  opad[3] = pack64v (tmps, opad64, gid, 3);
  opad[4] = pack64v (tmps, opad64, gid, 4);
  opad[5] = pack64v (tmps, opad64, gid, 5);
  opad[6] = pack64v (tmps, opad64, gid, 6);
  opad[7] = pack64v (tmps, opad64, gid, 7);

  u32 key_size = esalt_bufs[digests_offset].key_size;

  for (u32 i = 0; i < ((key_size / 8) / 4); i += 16)
  {
    u64x dgst[8];
    u64x out[8];

    dgst[0] = pack64v (tmps, dgst64, gid, i + 0);
    dgst[1] = pack64v (tmps, dgst64, gid, i + 1);
    dgst[2] = pack64v (tmps, dgst64, gid, i + 2);
    dgst[3] = pack64v (tmps, dgst64, gid, i + 3);
    dgst[4] = pack64v (tmps, dgst64, gid, i + 4);
    dgst[5] = pack64v (tmps, dgst64, gid, i + 5);
    dgst[6] = pack64v (tmps, dgst64, gid, i + 6);
    dgst[7] = pack64v (tmps, dgst64, gid, i + 7);

    out[0] = pack64v (tmps, out64, gid, i + 0);
    out[1] = pack64v (tmps, out64, gid, i + 1);
    out[2] = pack64v (tmps, out64, gid, i + 2);
    out[3] = pack64v (tmps, out64, gid, i + 3);
    out[4] = pack64v (tmps, out64, gid, i + 4);
    out[5] = pack64v (tmps, out64, gid, i + 5);
    out[6] = pack64v (tmps, out64, gid, i + 6);
    out[7] = pack64v (tmps, out64, gid, i + 7);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];
      u32x w4[4];
      u32x w5[4];
      u32x w6[4];
      u32x w7[4];

      w0[0] = h32_from_64 (dgst[0]);
      w0[1] = l32_from_64 (dgst[0]);
      w0[2] = h32_from_64 (dgst[1]);
      w0[3] = l32_from_64 (dgst[1]);
      w1[0] = h32_from_64 (dgst[2]);
      w1[1] = l32_from_64 (dgst[2]);
      w1[2] = h32_from_64 (dgst[3]);
      w1[3] = l32_from_64 (dgst[3]);
      w2[0] = h32_from_64 (dgst[4]);
      w2[1] = l32_from_64 (dgst[4]);
      w2[2] = h32_from_64 (dgst[5]);
      w2[3] = l32_from_64 (dgst[5]);
      w3[0] = h32_from_64 (dgst[6]);
      w3[1] = l32_from_64 (dgst[6]);
      w3[2] = h32_from_64 (dgst[7]);
      w3[3] = l32_from_64 (dgst[7]);
      w4[0] = 0x80000000;
      w4[1] = 0;
      w4[2] = 0;
      w4[3] = 0;
      w5[0] = 0;
      w5[1] = 0;
      w5[2] = 0;
      w5[3] = 0;
      w6[0] = 0;
      w6[1] = 0;
      w6[2] = 0;
      w6[3] = 0;
      w7[0] = 0;
      w7[1] = 0;
      w7[2] = 0;
      w7[3] = (128 + 64) * 8;

      hmac_sha512_run_V (w0, w1, w2, w3, w4, w5, w6, w7, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpack64v (tmps, dgst64, gid, i + 0, dgst[0]);
    unpack64v (tmps, dgst64, gid, i + 1, dgst[1]);
    unpack64v (tmps, dgst64, gid, i + 2, dgst[2]);
    unpack64v (tmps, dgst64, gid, i + 3, dgst[3]);
    unpack64v (tmps, dgst64, gid, i + 4, dgst[4]);
    unpack64v (tmps, dgst64, gid, i + 5, dgst[5]);
    unpack64v (tmps, dgst64, gid, i + 6, dgst[6]);
    unpack64v (tmps, dgst64, gid, i + 7, dgst[7]);

    unpack64v (tmps, out64, gid, i + 0, out[0]);
    unpack64v (tmps, out64, gid, i + 1, out[1]);
    unpack64v (tmps, out64, gid, i + 2, out[2]);
    unpack64v (tmps, out64, gid, i + 3, out[3]);
    unpack64v (tmps, out64, gid, i + 4, out[4]);
    unpack64v (tmps, out64, gid, i + 5, out[5]);
    unpack64v (tmps, out64, gid, i + 6, out[6]);
    unpack64v (tmps, out64, gid, i + 7, out[7]);
  }
}

__kernel void m14633_comp (KERN_ATTR_TMPS_ESALT (luks_tmp_t, luks_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  // decrypt AF with first pbkdf2 result
  // merge AF to masterkey
  // decrypt first payload sector with masterkey

  u32 pt_buf[128];

  luks_af_sha512_then_twofish_decrypt (&esalt_bufs[digests_offset], &tmps[gid], pt_buf);

  // check entropy

  const float entropy = get_entropy (pt_buf, 128);

  if (entropy < MAX_ENTROPY)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0);
    }
  }
}
