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
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct odf12_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} odf12_tmp_t;

typedef struct odf12
{
  u32 iterations;
  u32 iv[4];
  u32 checksum[8];
  u32 encrypted_data[256];

} odf12_t;

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

KERNEL_FQ void m18400_init (KERN_ATTR_TMPS_ESALT (odf12_tmp_t, odf12_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_ctx_t sha256_ctx;

  sha256_init (&sha256_ctx);

  sha256_update_global_swap (&sha256_ctx, pws[gid].i, pws[gid].pw_len);

  sha256_final (&sha256_ctx);

  // hmac key = hashed passphrase
  u32 k0[4];
  u32 k1[4];
  u32 k2[4];
  u32 k3[4];

  k0[0] = sha256_ctx.h[0];
  k0[1] = sha256_ctx.h[1];
  k0[2] = sha256_ctx.h[2];
  k0[3] = sha256_ctx.h[3];
  k1[0] = sha256_ctx.h[4];
  k1[1] = sha256_ctx.h[5];
  k1[2] = sha256_ctx.h[6];
  k1[3] = sha256_ctx.h[7];
  k2[0] = 0;
  k2[1] = 0;
  k2[2] = 0;
  k2[3] = 0;
  k3[0] = 0;
  k3[1] = 0;
  k3[2] = 0;
  k3[3] = 0;

  // hmac message = salt
  u32 m0[4];
  u32 m1[4];
  u32 m2[4];
  u32 m3[4];

  m0[0] = hc_swap32_S (salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[0]);
  m0[1] = hc_swap32_S (salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[1]);
  m0[2] = hc_swap32_S (salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[2]);
  m0[3] = hc_swap32_S (salt_bufs[DIGESTS_OFFSET_HOST].salt_buf[3]);
  m1[0] = 0;
  m1[1] = 0;
  m1[2] = 0;
  m1[3] = 0;
  m2[0] = 0;
  m2[1] = 0;
  m2[2] = 0;
  m2[3] = 0;
  m3[0] = 0;
  m3[1] = 0;
  m3[2] = 0;
  m3[3] = 0;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_64 (&sha1_hmac_ctx, k0, k1, k2, k3);

  tmps[gid].ipad[0]  = sha1_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1]  = sha1_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2]  = sha1_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3]  = sha1_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4]  = sha1_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0]  = sha1_hmac_ctx.opad.h[0];
  tmps[gid].opad[1]  = sha1_hmac_ctx.opad.h[1];
  tmps[gid].opad[2]  = sha1_hmac_ctx.opad.h[2];
  tmps[gid].opad[3]  = sha1_hmac_ctx.opad.h[3];
  tmps[gid].opad[4]  = sha1_hmac_ctx.opad.h[4];

  // first pbkdf iteration; key stretching
  for (u32 i = 0, j = 1; i < 8; i += 5, j += 1)
  {
    m1[0] = j;

    sha1_hmac_ctx_t sha1_hmac_ctx_loop = sha1_hmac_ctx;

    sha1_hmac_update_64 (&sha1_hmac_ctx_loop, m0, m1, m2, m3, 20);

    sha1_hmac_final (&sha1_hmac_ctx_loop);

    tmps[gid].dgst[i + 0] = sha1_hmac_ctx_loop.opad.h[0];
    tmps[gid].dgst[i + 1] = sha1_hmac_ctx_loop.opad.h[1];
    tmps[gid].dgst[i + 2] = sha1_hmac_ctx_loop.opad.h[2];
    tmps[gid].dgst[i + 3] = sha1_hmac_ctx_loop.opad.h[3];
    tmps[gid].dgst[i + 4] = sha1_hmac_ctx_loop.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
  }
}

KERNEL_FQ void m18400_loop (KERN_ATTR_TMPS_ESALT (odf12_tmp_t, odf12_t))
{
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

  // key stretching
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

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
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

KERNEL_FQ void m18400_comp (KERN_ATTR_TMPS_ESALT (odf12_tmp_t, odf12_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
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

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 ukey[8];

  ukey[0] = hc_swap32_S (tmps[gid].out[0]);
  ukey[1] = hc_swap32_S (tmps[gid].out[1]);
  ukey[2] = hc_swap32_S (tmps[gid].out[2]);
  ukey[3] = hc_swap32_S (tmps[gid].out[3]);
  ukey[4] = hc_swap32_S (tmps[gid].out[4]);
  ukey[5] = hc_swap32_S (tmps[gid].out[5]);
  ukey[6] = hc_swap32_S (tmps[gid].out[6]);
  ukey[7] = hc_swap32_S (tmps[gid].out[7]);

  u32 ks[60];

  aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  GLOBAL_AS const odf12_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  u32 iv[4];

  iv[0] = es->iv[0];
  iv[1] = es->iv[1];
  iv[2] = es->iv[2];
  iv[3] = es->iv[3];

  u32 ct[4];

  u32 pt1[4];
  u32 pt2[4];
  u32 pt3[4];
  u32 pt4[4];

  sha256_ctx_t sha256_ctx;

  sha256_init (&sha256_ctx);

  // decrypt aes-cbc and calculate plaintext checksum at the same time
  for (int i = 0; i < 16; i++)
  {
    const int i16 = i * 16;

    ct[0] = es->encrypted_data[i16 + 0];
    ct[1] = es->encrypted_data[i16 + 1];
    ct[2] = es->encrypted_data[i16 + 2];
    ct[3] = es->encrypted_data[i16 + 3];

    aes256_decrypt (ks, ct, pt1, s_td0, s_td1, s_td2, s_td3, s_td4);

    pt1[0] ^= iv[0];
    pt1[1] ^= iv[1];
    pt1[2] ^= iv[2];
    pt1[3] ^= iv[3];

    iv[0] = ct[0];
    iv[1] = ct[1];
    iv[2] = ct[2];
    iv[3] = ct[3];

    ct[0] = es->encrypted_data[i16 + 4];
    ct[1] = es->encrypted_data[i16 + 5];
    ct[2] = es->encrypted_data[i16 + 6];
    ct[3] = es->encrypted_data[i16 + 7];

    aes256_decrypt (ks, ct, pt2, s_td0, s_td1, s_td2, s_td3, s_td4);

    pt2[0] ^= iv[0];
    pt2[1] ^= iv[1];
    pt2[2] ^= iv[2];
    pt2[3] ^= iv[3];

    iv[0] = ct[0];
    iv[1] = ct[1];
    iv[2] = ct[2];
    iv[3] = ct[3];

    ct[0] = es->encrypted_data[i16 +  8];
    ct[1] = es->encrypted_data[i16 +  9];
    ct[2] = es->encrypted_data[i16 + 10];
    ct[3] = es->encrypted_data[i16 + 11];

    aes256_decrypt (ks, ct, pt3, s_td0, s_td1, s_td2, s_td3, s_td4);

    pt3[0] ^= iv[0];
    pt3[1] ^= iv[1];
    pt3[2] ^= iv[2];
    pt3[3] ^= iv[3];

    iv[0] = ct[0];
    iv[1] = ct[1];
    iv[2] = ct[2];
    iv[3] = ct[3];

    ct[0] = es->encrypted_data[i16 + 12];
    ct[1] = es->encrypted_data[i16 + 13];
    ct[2] = es->encrypted_data[i16 + 14];
    ct[3] = es->encrypted_data[i16 + 15];

    aes256_decrypt (ks, ct, pt4, s_td0, s_td1, s_td2, s_td3, s_td4);

    pt4[0] ^= iv[0];
    pt4[1] ^= iv[1];
    pt4[2] ^= iv[2];
    pt4[3] ^= iv[3];

    iv[0] = ct[0];
    iv[1] = ct[1];
    iv[2] = ct[2];
    iv[3] = ct[3];

    pt1[0] = hc_swap32_S (pt1[0]);
    pt1[1] = hc_swap32_S (pt1[1]);
    pt1[2] = hc_swap32_S (pt1[2]);
    pt1[3] = hc_swap32_S (pt1[3]);

    pt2[0] = hc_swap32_S (pt2[0]);
    pt2[1] = hc_swap32_S (pt2[1]);
    pt2[2] = hc_swap32_S (pt2[2]);
    pt2[3] = hc_swap32_S (pt2[3]);

    pt3[0] = hc_swap32_S (pt3[0]);
    pt3[1] = hc_swap32_S (pt3[1]);
    pt3[2] = hc_swap32_S (pt3[2]);
    pt3[3] = hc_swap32_S (pt3[3]);

    pt4[0] = hc_swap32_S (pt4[0]);
    pt4[1] = hc_swap32_S (pt4[1]);
    pt4[2] = hc_swap32_S (pt4[2]);
    pt4[3] = hc_swap32_S (pt4[3]);

    sha256_update_64 (&sha256_ctx, pt1, pt2, pt3, pt4, 64);
  }

  sha256_final (&sha256_ctx);

  const u32 r0 = hc_swap32_S (sha256_ctx.h[0]);
  const u32 r1 = hc_swap32_S (sha256_ctx.h[1]);
  const u32 r2 = hc_swap32_S (sha256_ctx.h[2]);
  const u32 r3 = hc_swap32_S (sha256_ctx.h[3]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
