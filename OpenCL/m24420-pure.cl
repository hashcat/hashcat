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
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef enum pkcs_cipher {
  PKCS_CIPHER_3DES        = 1,
  PKCS_CIPHER_AES_128_CBC = 2,
  PKCS_CIPHER_AES_192_CBC = 3,
  PKCS_CIPHER_AES_256_CBC = 4,
} pkcs_cipher_t;

typedef struct pkcs_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pkcs_sha256_tmp_t;

typedef struct pkcs
{
  int cipher; // pkcs_cipher_t

  u32 data_buf[16384];
  int data_len;

  u32 iv_buf[4];

} pkcs_t;

DECLSPEC void hmac_sha256_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *ipad, PRIVATE_AS u32x *opad, PRIVATE_AS u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m24420_init (KERN_ATTR_TMPS_ESALT (pkcs_sha256_tmp_t, pkcs_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha256_hmac_ctx.opad.h[7];

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

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

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha256_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha256_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha256_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha256_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha256_hmac_ctx2.opad.h[4];
    tmps[gid].dgst[i + 5] = sha256_hmac_ctx2.opad.h[5];
    tmps[gid].dgst[i + 6] = sha256_hmac_ctx2.opad.h[6];
    tmps[gid].dgst[i + 7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
    tmps[gid].out[i + 5] = tmps[gid].dgst[i + 5];
    tmps[gid].out[i + 6] = tmps[gid].dgst[i + 6];
    tmps[gid].out[i + 7] = tmps[gid].dgst[i + 7];
  }
}

KERNEL_FQ void m24420_loop (KERN_ATTR_TMPS_ESALT (pkcs_sha256_tmp_t, pkcs_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);
  ipad[5] = packv (tmps, ipad, gid, 5);
  ipad[6] = packv (tmps, ipad, gid, 6);
  ipad[7] = packv (tmps, ipad, gid, 7);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);
  opad[5] = packv (tmps, opad, gid, 5);
  opad[6] = packv (tmps, opad, gid, 6);
  opad[7] = packv (tmps, opad, gid, 7);

  for (u32 i = 0; i < 8; i += 8)
  {
    u32x dgst[8];
    u32x out[8];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);
    dgst[5] = packv (tmps, dgst, gid, i + 5);
    dgst[6] = packv (tmps, dgst, gid, i + 6);
    dgst[7] = packv (tmps, dgst, gid, i + 7);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);
    out[5] = packv (tmps, out, gid, i + 5);
    out[6] = packv (tmps, out, gid, i + 6);
    out[7] = packv (tmps, out, gid, i + 7);

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
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);
    unpackv (tmps, dgst, gid, i + 5, dgst[5]);
    unpackv (tmps, dgst, gid, i + 6, dgst[6]);
    unpackv (tmps, dgst, gid, i + 7, dgst[7]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
    unpackv (tmps, out, gid, i + 5, out[5]);
    unpackv (tmps, out, gid, i + 6, out[6]);
    unpackv (tmps, out, gid, i + 7, out[7]);
  }
}

KERNEL_FQ void m24420_comp (KERN_ATTR_TMPS_ESALT (pkcs_sha256_tmp_t, pkcs_t))
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

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  #endif

  if (gid >= GID_CNT) return;

  u32 ukey[8];

  ukey[0] = tmps[gid].out[0];
  ukey[1] = tmps[gid].out[1];
  ukey[2] = tmps[gid].out[2];
  ukey[3] = tmps[gid].out[3];
  ukey[4] = tmps[gid].out[4];
  ukey[5] = tmps[gid].out[5];
  ukey[6] = tmps[gid].out[6];
  ukey[7] = tmps[gid].out[7];

  const int data_len = esalt_bufs[DIGESTS_OFFSET_HOST].data_len;

  const int last_pad_pos = data_len - 1;

  const int last_pad_elem = last_pad_pos / 4;

  const int cipher = esalt_bufs[DIGESTS_OFFSET_HOST].cipher;

  u32 iv[4];

  u32 enc[4];
  u32 dec[4];

  if (cipher == PKCS_CIPHER_3DES)
  {
    ukey[0] = hc_swap32_S (ukey[0]);
    ukey[1] = hc_swap32_S (ukey[1]);
    ukey[2] = hc_swap32_S (ukey[2]);
    ukey[3] = hc_swap32_S (ukey[3]);
    ukey[4] = hc_swap32_S (ukey[4]);
    ukey[5] = hc_swap32_S (ukey[5]);

    u32 K0[16];
    u32 K1[16];
    u32 K2[16];
    u32 K3[16];
    u32 K4[16];
    u32 K5[16];

    _des_crypt_keysetup (ukey[0], ukey[1], K0, K1, s_skb);
    _des_crypt_keysetup (ukey[2], ukey[3], K2, K3, s_skb);
    _des_crypt_keysetup (ukey[4], ukey[5], K4, K5, s_skb);

    // first check the padding

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 3];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 2];

    enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 1];
    enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 0];

    u32 p1[2];
    u32 p2[2];

    _des_crypt_decrypt (p1,  enc, K4, K5, s_SPtrans);
    _des_crypt_encrypt (p2,  p1,  K2, K3, s_SPtrans);
    _des_crypt_decrypt (dec, p2,  K0, K1, s_SPtrans);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];

    const int paddingv = pkcs_padding_bs8 (dec, 8);

    if (paddingv == -1) return;

    // second check (naive code) ASN.1 structure

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[0];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[1];

    enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
    enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];

    _des_crypt_decrypt (p1,  enc, K4, K5, s_SPtrans);
    _des_crypt_encrypt (p2,  p1,  K2, K3, s_SPtrans);
    _des_crypt_decrypt (dec, p2,  K0, K1, s_SPtrans);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];

    const int real_len = (data_len - 8) + paddingv;

    const int asn1_ok = asn1_detect (dec, real_len);

    if (asn1_ok == 0) return;
  }
  else if (cipher == PKCS_CIPHER_AES_128_CBC)
  {
    u32 ks[44];

    AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    // first check the padding

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 7];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 6];
    iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 5];
    iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 4];

    enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 3];
    enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 2];
    enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 1];
    enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 0];

    aes128_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int paddingv = pkcs_padding_bs16 (dec, 16);

    if (paddingv == -1) return;

    // second check (naive code) ASN.1 structure

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[0];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[1];
    iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[2];
    iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[3];

    enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
    enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];
    enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[2];
    enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[3];

    aes128_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int real_len = (data_len - 16) + paddingv;

    const int asn1_ok = asn1_detect (dec, real_len);

    if (asn1_ok == 0) return;
  }
  else if (cipher == PKCS_CIPHER_AES_192_CBC)
  {
    u32 ks[52];

    AES192_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    // first check the padding

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 7];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 6];
    iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 5];
    iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 4];

    enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 3];
    enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 2];
    enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 1];
    enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 0];

    aes192_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int paddingv = pkcs_padding_bs16 (dec, 16);

    if (paddingv == -1) return;

    // second check (naive code) ASN.1 structure

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[0];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[1];
    iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[2];
    iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[3];

    enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
    enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];
    enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[2];
    enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[3];

    aes192_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int real_len = (data_len - 16) + paddingv;

    const int asn1_ok = asn1_detect (dec, real_len);

    if (asn1_ok == 0) return;
  }
  else if (cipher == PKCS_CIPHER_AES_256_CBC)
  {
    u32 ks[60];

    AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    // first check the padding

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 7];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 6];
    iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 5];
    iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 4];

    enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 3];
    enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 2];
    enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 1];
    enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[last_pad_elem - 0];

    aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int paddingv = pkcs_padding_bs16 (dec, 16);

    if (paddingv == -1) return;

    // second check (naive code) ASN.1 structure

    iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[0];
    iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[1];
    iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[2];
    iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].iv_buf[3];

    enc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
    enc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];
    enc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[2];
    enc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[3];

    aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    dec[0] ^= iv[0];
    dec[1] ^= iv[1];
    dec[2] ^= iv[2];
    dec[3] ^= iv[3];

    const int real_len = (data_len - 16) + paddingv;

    const int asn1_ok = asn1_detect (dec, real_len);

    if (asn1_ok == 0) return;
  }
  else
  {
    return;
  }

  const u32 r0 = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[0];
  const u32 r1 = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[1];
  const u32 r2 = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[2];
  const u32 r3 = esalt_bufs[DIGESTS_OFFSET_HOST].data_buf[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
