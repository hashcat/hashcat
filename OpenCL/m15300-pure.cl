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
#include "inc_hash_md4.cl"
#include "inc_hash_sha1.cl"
#include "inc_cipher_des.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct dpapimk
{
  u32 context;

  u32 SID[32];
  u32 SID_len;
  u32 SID_offset;

  /* here only for possible
     forward compatibiliy
  */
  // u8 cipher_algo[16];
  // u8 hash_algo[16];

  u32 iv[4];
  u32 contents_len;
  u32 contents[128];

} dpapimk_t;

typedef struct dpapimk_tmp_v1
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[10];
  u32 out[10];

  u32 userKey[5];

} dpapimk_tmp_v1_t;

DECLSPEC void hmac_sha1_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80000000;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 20) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  sha1_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m15300_init (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v1_t, dpapimk_t))
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

    sha1_update_global_utf16le_swap (&ctx, pws[gid].i, pws[gid].pw_len);

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

    md4_update_global_utf16le (&ctx, pws[gid].i, pws[gid].pw_len);

    md4_final (&ctx);

    digest_context[0] = ctx.h[0];
    digest_context[1] = ctx.h[1];
    digest_context[2] = ctx.h[2];
    digest_context[3] = ctx.h[3];
    digest_context[4] = 0;

    digest_context[0] = hc_swap32_S (digest_context[0]);
    digest_context[1] = hc_swap32_S (digest_context[1]);
    digest_context[2] = hc_swap32_S (digest_context[2]);
    digest_context[3] = hc_swap32_S (digest_context[3]);
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

  /* this key is used as password for pbkdf2-hmac-sha1 */

  tmps[gid].userKey[0] = key[0];
  tmps[gid].userKey[1] = key[1];
  tmps[gid].userKey[2] = key[2];
  tmps[gid].userKey[3] = key[3];
  tmps[gid].userKey[4] = key[4];

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

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_64 (&sha1_hmac_ctx, w0, w1, w2, w3);

  tmps[gid].ipad[0] = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha1_hmac_ctx.opad.h[4];

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

  sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 16);

  for (u32 i = 0, j = 1; i < 8; i += 5, j += 1)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

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

    sha1_hmac_update_64 (&sha1_hmac_ctx2, w0, w1, w2, w3, 4);

    sha1_hmac_final (&sha1_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha1_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha1_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha1_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha1_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha1_hmac_ctx2.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
  }
}

KERNEL_FQ void m15300_loop (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v1_t, dpapimk_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[5];
  u32x opad[5];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);

  for (u32 i = 0; i < 8; i += 5)
  {
    u32x dgst[5];
    u32x out[5];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = 0x80000000;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 20) * 8;

      hmac_sha1_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
  }
}

KERNEL_FQ void m15300_comp (KERN_ATTR_TMPS_ESALT (dpapimk_tmp_v1_t, dpapimk_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * des shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_SPtrans[8][64];
  LOCAL_VK u32 s_skb[8][64];

  for (u32 i = lid; i < 64; i += lsz)
  {
    s_SPtrans[0][i] = c_SPtrans[0][i];
    s_SPtrans[1][i] = c_SPtrans[1][i];
    s_SPtrans[2][i] = c_SPtrans[2][i];
    s_SPtrans[3][i] = c_SPtrans[3][i];
    s_SPtrans[4][i] = c_SPtrans[4][i];
    s_SPtrans[5][i] = c_SPtrans[5][i];
    s_SPtrans[6][i] = c_SPtrans[6][i];
    s_SPtrans[7][i] = c_SPtrans[7][i];

    s_skb[0][i] = c_skb[0][i];
    s_skb[1][i] = c_skb[1][i];
    s_skb[2][i] = c_skb[2][i];
    s_skb[3][i] = c_skb[3][i];
    s_skb[4][i] = c_skb[4][i];
    s_skb[5][i] = c_skb[5][i];
    s_skb[6][i] = c_skb[6][i];
    s_skb[7][i] = c_skb[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= gid_max) return;

  /**
   * main
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 key[6];

  key[0] = hc_swap32_S (tmps[gid].out[0]);
  key[1] = hc_swap32_S (tmps[gid].out[1]);
  key[2] = hc_swap32_S (tmps[gid].out[2]);
  key[3] = hc_swap32_S (tmps[gid].out[3]);
  key[4] = hc_swap32_S (tmps[gid].out[4]);
  key[5] = hc_swap32_S (tmps[gid].out[5]);

  u32 iv[2];

  iv[0] = hc_swap32_S (tmps[gid].out[6]);
  iv[1] = hc_swap32_S (tmps[gid].out[7]);

  u32 decrypted[26];

  /* Construct 3DES keys */

  const u32 a = (key[0]);
  const u32 b = (key[1]);

  u32 Ka[16];
  u32 Kb[16];

  _des_crypt_keysetup (a, b, Ka, Kb, s_skb);

  const u32 c = (key[2]);
  const u32 d = (key[3]);

  u32 Kc[16];
  u32 Kd[16];

  _des_crypt_keysetup (c, d, Kc, Kd, s_skb);

  const u32 e = (key[4]);
  const u32 f = (key[5]);

  u32 Ke[16];
  u32 Kf[16];

  _des_crypt_keysetup (e, f, Ke, Kf, s_skb);

  u32 contents_pos;
  u32 contents_off;
  u32 wx_off;

  for (wx_off = 0, contents_pos = 0, contents_off = 0; contents_pos < esalt_bufs[digests_offset].contents_len; wx_off += 2, contents_pos += 8, contents_off += 2)
  {
    /* First Pass */

    u32 data[2];

    data[0] = hc_swap32_S (esalt_bufs[digests_offset].contents[contents_off + 0]);
    data[1] = hc_swap32_S (esalt_bufs[digests_offset].contents[contents_off + 1]);

    u32 p1[2];

    _des_crypt_decrypt (p1, data, Ke, Kf, s_SPtrans);

    /* Second Pass */

    u32 p2[2];

    _des_crypt_encrypt (p2, p1, Kc, Kd, s_SPtrans);

    /* Third Pass */

    u32 out[2];

    _des_crypt_decrypt (out, p2, Ka, Kb, s_SPtrans);

    out[0] ^= iv[0];
    out[1] ^= iv[1];

    decrypted[wx_off + 0] = out[0];
    decrypted[wx_off + 1] = out[1];

    iv[0] = data[0];
    iv[1] = data[1];
  }

  u32 hmacSalt[4];
  u32 expectedHmac[4];
  u32 lastKey[16];

  hmacSalt[0] = hc_swap32_S (decrypted[0]);
  hmacSalt[1] = hc_swap32_S (decrypted[1]);
  hmacSalt[2] = hc_swap32_S (decrypted[2]);
  hmacSalt[3] = hc_swap32_S (decrypted[3]);

  expectedHmac[0] = hc_swap32_S (decrypted[4 + 0]);
  expectedHmac[1] = hc_swap32_S (decrypted[4 + 1]);
  expectedHmac[2] = hc_swap32_S (decrypted[4 + 2]);
  expectedHmac[3] = hc_swap32_S (decrypted[4 + 3]);

  for(int i = 0; i < 16; i++)
  {
    lastKey[i] = decrypted[i + 26 - 16];
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

  sha1_hmac_ctx_t ctx;

  sha1_hmac_init_64 (&ctx, w0, w1, w2, w3);

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

  sha1_hmac_update_64 (&ctx, w0, w1, w2, w3, 16);

  sha1_hmac_final (&ctx);

  w0[0] = ctx.opad.h[0];
  w0[1] = ctx.opad.h[1];
  w0[2] = ctx.opad.h[2];
  w0[3] = ctx.opad.h[3];
  w1[0] = ctx.opad.h[4];
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

  sha1_hmac_init_64 (&ctx, w0, w1, w2, w3);

  w0[0] = hc_swap32_S (lastKey[ 0]);
  w0[1] = hc_swap32_S (lastKey[ 1]);
  w0[2] = hc_swap32_S (lastKey[ 2]);
  w0[3] = hc_swap32_S (lastKey[ 3]);
  w1[0] = hc_swap32_S (lastKey[ 4]);
  w1[1] = hc_swap32_S (lastKey[ 5]);
  w1[2] = hc_swap32_S (lastKey[ 6]);
  w1[3] = hc_swap32_S (lastKey[ 7]);
  w2[0] = hc_swap32_S (lastKey[ 8]);
  w2[1] = hc_swap32_S (lastKey[ 9]);
  w2[2] = hc_swap32_S (lastKey[10]);
  w2[3] = hc_swap32_S (lastKey[11]);
  w3[0] = hc_swap32_S (lastKey[12]);
  w3[1] = hc_swap32_S (lastKey[13]);
  w3[2] = hc_swap32_S (lastKey[14]);
  w3[3] = hc_swap32_S (lastKey[15]);

  sha1_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);

  sha1_hmac_final (&ctx);

  #define il_pos 0

  if ((expectedHmac[0] == ctx.opad.h[0])
   && (expectedHmac[1] == ctx.opad.h[1])
   && (expectedHmac[2] == ctx.opad.h[2])
   && (expectedHmac[3] == ctx.opad.h[3]))
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset + 0, gid, il_pos, 0, 0);
    }
  }
}
