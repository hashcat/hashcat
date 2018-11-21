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
#include "inc_hash_md4.cl"
#include "inc_hash_sha1.cl"
#include "inc_hash_sha512.cl"
#include "inc_cipher_aes.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

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

__kernel void m15900_init (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v2_t, dpapimk_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * main
   */

  u32 digest_context[5];

  if (esalt_bufs[digests_offset].context == 1)
  {
    /* local credentials */

    sha1_ctx_t ctx;

    sha1_init (&ctx);

    sha1_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len & 255);

    sha1_final (&ctx);

    digest_context[0] = ctx.h[0];
    digest_context[1] = ctx.h[1];
    digest_context[2] = ctx.h[2];
    digest_context[3] = ctx.h[3];
    digest_context[4] = ctx.h[4];
  }
  else if (esalt_bufs[digests_offset].context == 2)
  {
    /* domain credentials */

    md4_ctx_t ctx;

    md4_init (&ctx);

    md4_update_global_utf16le (&ctx, pws[gid].i, pws[gid].pw_len & 255);

    md4_final (&ctx);

    digest_context[0] = ctx.h[0];
    digest_context[1] = ctx.h[1];
    digest_context[2] = ctx.h[2];
    digest_context[3] = ctx.h[3];
    digest_context[4] = 0;

    digest_context[0] = swap32_S (digest_context[0]);
    digest_context[1] = swap32_S (digest_context[1]);
    digest_context[2] = swap32_S (digest_context[2]);
    digest_context[3] = swap32_S (digest_context[3]);
  }

  /* initialize hmac-sha1 */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = digest_context[0];
  w0[1] = digest_context[1];
  w0[2] = digest_context[2];
  w0[3] = digest_context[3];
  w1[0] = digest_context[4];
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

  sha1_hmac_update_global (&ctx, esalt_bufs[digests_offset].SID, esalt_bufs[digests_offset].SID_len);

  sha1_hmac_final (&ctx);

  u32 key[5];

  key[0] = ctx.opad.h[0];
  key[1] = ctx.opad.h[1];
  key[2] = ctx.opad.h[2];
  key[3] = ctx.opad.h[3];
  key[4] = ctx.opad.h[4];

  /* this key is used as password for pbkdf2-hmac-sha512 */

  tmps[gid].userKey[0] = key[0];
  tmps[gid].userKey[1] = key[1];
  tmps[gid].userKey[2] = key[2];
  tmps[gid].userKey[3] = key[3];
  tmps[gid].userKey[4] = key[4];

  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  w0[0] = key[0];
  w0[1] = key[1];
  w0[2] = key[2];
  w0[3] = key[3];
  w1[0] = key[4];
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

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_128 (&sha512_hmac_ctx, w0, w1, w2, w3, w5, w5, w6, w7);

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

  w0[0] = esalt_bufs[digests_offset].iv[0];
  w0[1] = esalt_bufs[digests_offset].iv[1];
  w0[2] = esalt_bufs[digests_offset].iv[2];
  w0[3] = esalt_bufs[digests_offset].iv[3];
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

  sha512_hmac_update_128 (&sha512_hmac_ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    sha512_hmac_ctx_t sha512_hmac_ctx2 = sha512_hmac_ctx;

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

__kernel void m15900_loop (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v2_t, dpapimk_t))
{
  /**
   * base
   */

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

  for (u32 i = 0; i < 8; i += 8)
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

      w0[0] = h32_from_64 (out[0]);
      w0[1] = l32_from_64 (out[0]);
      w0[2] = h32_from_64 (out[1]);
      w0[3] = l32_from_64 (out[1]);
      w1[0] = h32_from_64 (out[2]);
      w1[1] = l32_from_64 (out[2]);
      w1[2] = h32_from_64 (out[3]);
      w1[3] = l32_from_64 (out[3]);
      w2[0] = h32_from_64 (out[4]);
      w2[1] = l32_from_64 (out[4]);
      w2[2] = h32_from_64 (out[5]);
      w2[3] = l32_from_64 (out[5]);
      w3[0] = h32_from_64 (out[6]);
      w3[1] = l32_from_64 (out[6]);
      w3[2] = h32_from_64 (out[7]);
      w3[3] = l32_from_64 (out[7]);
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

__kernel void m15900_comp (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v2_t, dpapimk_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_td0[256];
  __local u32 s_td1[256];
  __local u32 s_td2[256];
  __local u32 s_td3[256];
  __local u32 s_td4[256];

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_td0 = td0;
  __constant u32a *s_td1 = td1;
  __constant u32a *s_td2 = td2;
  __constant u32a *s_td3 = td3;
  __constant u32a *s_td4 = td4;

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /**
   * main
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  /* Construct AES key */

  u32 key[8];

  key[0] = h32_from_64_S (tmps[gid].out64[0]);
  key[1] = l32_from_64_S (tmps[gid].out64[0]);
  key[2] = h32_from_64_S (tmps[gid].out64[1]);
  key[3] = l32_from_64_S (tmps[gid].out64[1]);
  key[4] = h32_from_64_S (tmps[gid].out64[2]);
  key[5] = l32_from_64_S (tmps[gid].out64[2]);
  key[6] = h32_from_64_S (tmps[gid].out64[3]);
  key[7] = l32_from_64_S (tmps[gid].out64[3]);

  u32 iv[4];

  iv[0] = h32_from_64_S (tmps[gid].out64[4]);
  iv[1] = l32_from_64_S (tmps[gid].out64[4]);
  iv[2] = h32_from_64_S (tmps[gid].out64[5]);
  iv[3] = l32_from_64_S (tmps[gid].out64[5]);

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4);

  /* 144 bytes */
  u32 decrypted[36] = { 0 };

  u32 contents_pos;
  u32 contents_off;
  u32 wx_off;

  for (wx_off = 0, contents_pos = 0, contents_off = 0; contents_pos < esalt_bufs[digests_offset].contents_len; wx_off += 4, contents_pos += 16, contents_off += 4)
  {
    u32 data[4];

    data[0] = esalt_bufs[digests_offset].contents[contents_off + 0];
    data[1] = esalt_bufs[digests_offset].contents[contents_off + 1];
    data[2] = esalt_bufs[digests_offset].contents[contents_off + 2];
    data[3] = esalt_bufs[digests_offset].contents[contents_off + 3];

    u32 out[4];

    AES256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    out[0] ^= iv[0];
    out[1] ^= iv[1];
    out[2] ^= iv[2];
    out[3] ^= iv[3];

    decrypted[wx_off + 0] = out[0];
    decrypted[wx_off + 1] = out[1];
    decrypted[wx_off + 2] = out[2];
    decrypted[wx_off + 3] = out[3];

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];

    if (contents_off == 32) break;
  }

  u32 hmacSalt[4];
  u32 expectedHmac[16];
  u32 lastKey[16];

  hmacSalt[0] = decrypted[0];
  hmacSalt[1] = decrypted[1];
  hmacSalt[2] = decrypted[2];
  hmacSalt[3] = decrypted[3];

  for(int i = 0; i < 16; i++)
  {
    expectedHmac[i] = decrypted[i + 4];
    lastKey[i]      = decrypted[i + 36 - 16];
  }

  w0[0] = tmps[gid].userKey[0];
  w0[1] = tmps[gid].userKey[1];
  w0[2] = tmps[gid].userKey[2];
  w0[3] = tmps[gid].userKey[3];
  w1[0] = tmps[gid].userKey[4];
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

  sha512_hmac_ctx_t ctx;

  sha512_hmac_init_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7);

  w0[0] = hmacSalt[0];
  w0[1] = hmacSalt[1];
  w0[2] = hmacSalt[2];
  w0[3] = hmacSalt[3];
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

  sha512_hmac_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 16);

  sha512_hmac_final (&ctx);

  w0[0] = h32_from_64_S (ctx.opad.h[0]);
  w0[1] = l32_from_64_S (ctx.opad.h[0]);
  w0[2] = h32_from_64_S (ctx.opad.h[1]);
  w0[3] = l32_from_64_S (ctx.opad.h[1]);
  w1[0] = h32_from_64_S (ctx.opad.h[2]);
  w1[1] = l32_from_64_S (ctx.opad.h[2]);
  w1[2] = h32_from_64_S (ctx.opad.h[3]);
  w1[3] = l32_from_64_S (ctx.opad.h[3]);
  w2[0] = h32_from_64_S (ctx.opad.h[4]);
  w2[1] = l32_from_64_S (ctx.opad.h[4]);
  w2[2] = h32_from_64_S (ctx.opad.h[5]);
  w2[3] = l32_from_64_S (ctx.opad.h[5]);
  w3[0] = h32_from_64_S (ctx.opad.h[6]);
  w3[1] = l32_from_64_S (ctx.opad.h[6]);
  w3[2] = h32_from_64_S (ctx.opad.h[7]);
  w3[3] = l32_from_64_S (ctx.opad.h[7]);
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

  sha512_hmac_init_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7);

  w0[0] = lastKey[ 0];
  w0[1] = lastKey[ 1];
  w0[2] = lastKey[ 2];
  w0[3] = lastKey[ 3];
  w1[0] = lastKey[ 4];
  w1[1] = lastKey[ 5];
  w1[2] = lastKey[ 6];
  w1[3] = lastKey[ 7];
  w2[0] = lastKey[ 8];
  w2[1] = lastKey[ 9];
  w2[2] = lastKey[10];
  w2[3] = lastKey[11];
  w3[0] = lastKey[12];
  w3[1] = lastKey[13];
  w3[2] = lastKey[14];
  w3[3] = lastKey[15];
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

  sha512_hmac_update_128 (&ctx, w0, w1, w2, w3, w4, w5, w6, w7, 64);

  sha512_hmac_final (&ctx);

  #define il_pos 0

  if ((expectedHmac[0] == h32_from_64_S (ctx.opad.h[0]))
   && (expectedHmac[1] == l32_from_64_S (ctx.opad.h[0]))
   && (expectedHmac[2] == h32_from_64_S (ctx.opad.h[1]))
   && (expectedHmac[3] == l32_from_64_S (ctx.opad.h[1])))
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos);
    }
  }
}
