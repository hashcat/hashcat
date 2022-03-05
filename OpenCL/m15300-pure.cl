/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_md4.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct dpapimk_tmp_v1
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[10];
  u32 out[10];

  u32 userKey[5];

} dpapimk_tmp_v1_t;

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

DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
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

  if (gid >= GID_CNT) return;

  /**
   * main
   */

  u32 digest_context[5];

  if (esalt_bufs[DIGESTS_OFFSET_HOST].context == 1)
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
  else if (esalt_bufs[DIGESTS_OFFSET_HOST].context == 2)
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

  sha1_hmac_update_global (&ctx, esalt_bufs[DIGESTS_OFFSET_HOST].SID, esalt_bufs[DIGESTS_OFFSET_HOST].SID_len);

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

  w0[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  w0[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];
  w0[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[2];
  w0[3] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[3];
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

  if ((gid * VECT_SIZE) >= GID_CNT) return;

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

    for (u32 j = 0; j < LOOP_CNT; j++)
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

  if (gid >= GID_CNT) return;

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

  u32 p1[2];
  u32 p2[2];
  u32 out[2];

  u32 hmac_data[4];

  hmac_data[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[0]);
  hmac_data[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[1]);
  hmac_data[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[2]);
  hmac_data[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[3]);

  u32 expected_key[4];

  expected_key[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[4]);
  expected_key[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[5]);
  expected_key[2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[6]);
  expected_key[3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[7]);

  u32 last_iv[2];

  last_iv[0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[8]);
  last_iv[1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[9]);

  u32 last_key[16];

  last_key[ 0] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[10]);
  last_key[ 1] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[11]);
  last_key[ 2] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[12]);
  last_key[ 3] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[13]);
  last_key[ 4] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[14]);
  last_key[ 5] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[15]);
  last_key[ 6] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[16]);
  last_key[ 7] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[17]);
  last_key[ 8] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[18]);
  last_key[ 9] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[19]);
  last_key[10] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[20]);
  last_key[11] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[21]);
  last_key[12] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[22]);
  last_key[13] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[23]);
  last_key[14] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[24]);
  last_key[15] = hc_swap32_S (esalt_bufs[DIGESTS_OFFSET_HOST].contents[25]);

  // hmac_data

  _des_crypt_decrypt (p1,  hmac_data + 0, Ke, Kf, s_SPtrans);
  _des_crypt_encrypt (p2,  p1,   Kc, Kd, s_SPtrans);
  _des_crypt_decrypt (out, p2,   Ka, Kb, s_SPtrans);

  out[0] ^= iv[0];
  out[1] ^= iv[1];

  iv[0] = hmac_data[0];
  iv[1] = hmac_data[1];

  hmac_data[0] = out[0];
  hmac_data[1] = out[1];

  _des_crypt_decrypt (p1,  hmac_data + 2, Ke, Kf, s_SPtrans);
  _des_crypt_encrypt (p2,  p1,   Kc, Kd, s_SPtrans);
  _des_crypt_decrypt (out, p2,   Ka, Kb, s_SPtrans);

  out[0] ^= iv[0];
  out[1] ^= iv[1];

  iv[0] = hmac_data[2];
  iv[1] = hmac_data[3];

  hmac_data[2] = out[0];
  hmac_data[3] = out[1];

  // expected_key

  _des_crypt_decrypt (p1,  expected_key + 0, Ke, Kf, s_SPtrans);
  _des_crypt_encrypt (p2,  p1,   Kc, Kd, s_SPtrans);
  _des_crypt_decrypt (out, p2,   Ka, Kb, s_SPtrans);

  out[0] ^= iv[0];
  out[1] ^= iv[1];

  iv[0] = expected_key[0];
  iv[1] = expected_key[1];

  expected_key[0] = out[0];
  expected_key[1] = out[1];

  _des_crypt_decrypt (p1,  expected_key + 2, Ke, Kf, s_SPtrans);
  _des_crypt_encrypt (p2,  p1,   Kc, Kd, s_SPtrans);
  _des_crypt_decrypt (out, p2,   Ka, Kb, s_SPtrans);

  out[0] ^= iv[0];
  out[1] ^= iv[1];

  iv[0] = expected_key[2];
  iv[1] = expected_key[3];

  expected_key[2] = out[0];
  expected_key[3] = out[1];

  // last_key

  iv[0] = last_iv[0];
  iv[1] = last_iv[1];

  for (int off = 0; off < 16; off += 2)
  {
    _des_crypt_decrypt (p1,  last_key + off, Ke, Kf, s_SPtrans);
    _des_crypt_encrypt (p2,  p1,   Kc, Kd, s_SPtrans);
    _des_crypt_decrypt (out, p2,   Ka, Kb, s_SPtrans);

    out[0] ^= iv[0];
    out[1] ^= iv[1];

    iv[0] = last_key[off + 0];
    iv[1] = last_key[off + 1];

    last_key[off + 0] = out[0];
    last_key[off + 1] = out[1];
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

  w0[0] = hc_swap32_S (hmac_data[0]);
  w0[1] = hc_swap32_S (hmac_data[1]);
  w0[2] = hc_swap32_S (hmac_data[2]);
  w0[3] = hc_swap32_S (hmac_data[3]);
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

  w0[0] = hc_swap32_S (last_key[ 0]);
  w0[1] = hc_swap32_S (last_key[ 1]);
  w0[2] = hc_swap32_S (last_key[ 2]);
  w0[3] = hc_swap32_S (last_key[ 3]);
  w1[0] = hc_swap32_S (last_key[ 4]);
  w1[1] = hc_swap32_S (last_key[ 5]);
  w1[2] = hc_swap32_S (last_key[ 6]);
  w1[3] = hc_swap32_S (last_key[ 7]);
  w2[0] = hc_swap32_S (last_key[ 8]);
  w2[1] = hc_swap32_S (last_key[ 9]);
  w2[2] = hc_swap32_S (last_key[10]);
  w2[3] = hc_swap32_S (last_key[11]);
  w3[0] = hc_swap32_S (last_key[12]);
  w3[1] = hc_swap32_S (last_key[13]);
  w3[2] = hc_swap32_S (last_key[14]);
  w3[3] = hc_swap32_S (last_key[15]);

  sha1_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);

  sha1_hmac_final (&ctx);

  #define il_pos 0

  if ((expected_key[0] == hc_swap32_S (ctx.opad.h[0]))
   && (expected_key[1] == hc_swap32_S (ctx.opad.h[1]))
   && (expected_key[2] == hc_swap32_S (ctx.opad.h[2]))
   && (expected_key[3] == hc_swap32_S (ctx.opad.h[3])))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
    }
  }
}
