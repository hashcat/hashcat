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
#include M2S(INCLUDE_PATH/inc_simd.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct iphone_passcode_tmp
{
  u32 key0[4];          // original key from pbkdf2
  u32 key1[4];          // original key from pbkdf2

  u32 iterated_key0[4]; // updated key from pbkdf2 with iterations
  u32 iterated_key1[4]; // updated key from pbkdf2 with iterations

  u32 iv[4];            // current iv

} iphone_passcode_tmp_t;

typedef struct iphone_passcode
{
  u32 uidkey[4];
  u32 classkey1[10];

} iphone_passcode_t;

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

KERNEL_FQ void m26500_init (KERN_ATTR_TMPS_ESALT (iphone_passcode_tmp_t, iphone_passcode_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_hmac_ctx_t sha1_hmac_ctx0;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx0, pws[gid].i, pws[gid].pw_len);

  sha1_hmac_update_global (&sha1_hmac_ctx0, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  // we can reuse context intermediate buffer values for pbkdf2

  sha1_hmac_ctx_t sha1_hmac_ctx1 = sha1_hmac_ctx0;
  sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx0;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = 1;
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

  sha1_hmac_update_64 (&sha1_hmac_ctx1, w0, w1, w2, w3, 4);

  sha1_hmac_final (&sha1_hmac_ctx1);

  w0[0] = 2;
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

  // save

  tmps[gid].key0[0] = hc_swap32_S (sha1_hmac_ctx1.opad.h[0]);
  tmps[gid].key0[1] = hc_swap32_S (sha1_hmac_ctx1.opad.h[1]);
  tmps[gid].key0[2] = hc_swap32_S (sha1_hmac_ctx1.opad.h[2]);
  tmps[gid].key0[3] = hc_swap32_S (sha1_hmac_ctx1.opad.h[3]);
  tmps[gid].key1[0] = hc_swap32_S (sha1_hmac_ctx1.opad.h[4]);
  tmps[gid].key1[1] = hc_swap32_S (sha1_hmac_ctx2.opad.h[0]);
  tmps[gid].key1[2] = hc_swap32_S (sha1_hmac_ctx2.opad.h[1]);
  tmps[gid].key1[3] = hc_swap32_S (sha1_hmac_ctx2.opad.h[2]);

  tmps[gid].iterated_key0[0] = tmps[gid].key0[0];
  tmps[gid].iterated_key0[1] = tmps[gid].key0[1];
  tmps[gid].iterated_key0[2] = tmps[gid].key0[2];
  tmps[gid].iterated_key0[3] = tmps[gid].key0[3];
  tmps[gid].iterated_key1[0] = tmps[gid].key1[0];
  tmps[gid].iterated_key1[1] = tmps[gid].key1[1];
  tmps[gid].iterated_key1[2] = tmps[gid].key1[2];
  tmps[gid].iterated_key1[3] = tmps[gid].key1[3];

  tmps[gid].iv[0] = 0;
  tmps[gid].iv[1] = 0;
  tmps[gid].iv[2] = 0;
  tmps[gid].iv[3] = 0;
}

KERNEL_FQ void m26500_loop (KERN_ATTR_TMPS_ESALT (iphone_passcode_tmp_t, iphone_passcode_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  // load stuff

  u32 key0[4];
  u32 key1[4];

  key0[0] = tmps[gid].key0[0];
  key0[1] = tmps[gid].key0[1];
  key0[2] = tmps[gid].key0[2];
  key0[3] = tmps[gid].key0[3];
  key1[0] = tmps[gid].key1[0];
  key1[1] = tmps[gid].key1[1];
  key1[2] = tmps[gid].key1[2];
  key1[3] = tmps[gid].key1[3];

  u32 iterated_key0[4];
  u32 iterated_key1[4];

  iterated_key0[0] = tmps[gid].iterated_key0[0];
  iterated_key0[1] = tmps[gid].iterated_key0[1];
  iterated_key0[2] = tmps[gid].iterated_key0[2];
  iterated_key0[3] = tmps[gid].iterated_key0[3];
  iterated_key1[0] = tmps[gid].iterated_key1[0];
  iterated_key1[1] = tmps[gid].iterated_key1[1];
  iterated_key1[2] = tmps[gid].iterated_key1[2];
  iterated_key1[3] = tmps[gid].iterated_key1[3];

  u32 iv[4];

  iv[0] = tmps[gid].iv[0];
  iv[1] = tmps[gid].iv[1];
  iv[2] = tmps[gid].iv[2];
  iv[3] = tmps[gid].iv[3];

  u32 ukey[4];

  ukey[0] = esalt_bufs[DIGESTS_OFFSET_HOST].uidkey[0];
  ukey[1] = esalt_bufs[DIGESTS_OFFSET_HOST].uidkey[1];
  ukey[2] = esalt_bufs[DIGESTS_OFFSET_HOST].uidkey[2];
  ukey[3] = esalt_bufs[DIGESTS_OFFSET_HOST].uidkey[3];

  u32 ks[44];

  AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  // here's what counts

  for (u32 i = 0, xorkey = LOOP_POS + 1; i < LOOP_CNT; i++, xorkey++)
  {
    u32 in[4];

    in[0] = key0[0] ^ iv[0] ^ xorkey;
    in[1] = key0[1] ^ iv[1] ^ xorkey;
    in[2] = key0[2] ^ iv[2] ^ xorkey;
    in[3] = key0[3] ^ iv[3] ^ xorkey;

    aes128_encrypt (ks, in, iv, s_te0, s_te1, s_te2, s_te3, s_te4);

    iterated_key0[0] ^= iv[0];
    iterated_key0[1] ^= iv[1];
    iterated_key0[2] ^= iv[2];
    iterated_key0[3] ^= iv[3];

    in[0] = key1[0] ^ iv[0] ^ xorkey;
    in[1] = key1[1] ^ iv[1] ^ xorkey;
    in[2] = key1[2] ^ iv[2] ^ xorkey;
    in[3] = key1[3] ^ iv[3] ^ xorkey;

    aes128_encrypt (ks, in, iv, s_te0, s_te1, s_te2, s_te3, s_te4);

    iterated_key1[0] ^= iv[0];
    iterated_key1[1] ^= iv[1];
    iterated_key1[2] ^= iv[2];
    iterated_key1[3] ^= iv[3];
  }

  tmps[gid].iterated_key0[0] = iterated_key0[0];
  tmps[gid].iterated_key0[1] = iterated_key0[1];
  tmps[gid].iterated_key0[2] = iterated_key0[2];
  tmps[gid].iterated_key0[3] = iterated_key0[3];
  tmps[gid].iterated_key1[0] = iterated_key1[0];
  tmps[gid].iterated_key1[1] = iterated_key1[1];
  tmps[gid].iterated_key1[2] = iterated_key1[2];
  tmps[gid].iterated_key1[3] = iterated_key1[3];

  tmps[gid].iv[0] = iv[0];
  tmps[gid].iv[1] = iv[1];
  tmps[gid].iv[2] = iv[2];
  tmps[gid].iv[3] = iv[3];
}

KERNEL_FQ void m26500_comp (KERN_ATTR_TMPS_ESALT (iphone_passcode_tmp_t, iphone_passcode_t))
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
   * aes
   */

  u32 ukey[8];

  ukey[0] = tmps[gid].iterated_key0[0];
  ukey[1] = tmps[gid].iterated_key0[1];
  ukey[2] = tmps[gid].iterated_key0[2];
  ukey[3] = tmps[gid].iterated_key0[3];
  ukey[4] = tmps[gid].iterated_key1[0];
  ukey[5] = tmps[gid].iterated_key1[1];
  ukey[6] = tmps[gid].iterated_key1[2];
  ukey[7] = tmps[gid].iterated_key1[3];

  u32 ks[60];

  aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 cipher[4];

  cipher[0] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[0];
  cipher[1] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[1];
  cipher[2] = 0;
  cipher[3] = 0;

  u32 lsb[8];

  lsb[0] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[8];
  lsb[1] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[9];
  lsb[2] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[6];
  lsb[3] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[7];
  lsb[4] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[4];
  lsb[5] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[5];
  lsb[6] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[2];
  lsb[7] = esalt_bufs[DIGESTS_OFFSET_HOST].classkey1[3];

  for (int j = 5; j >= 0; j--)
  {
    // 1st

    cipher[1] ^= (4 * j + 4);

    cipher[2] = lsb[0];
    cipher[3] = lsb[1];

    AES256_decrypt (ks, cipher, cipher, s_td0, s_td1, s_td2, s_td3, s_td4);

    lsb[0] = cipher[2];
    lsb[1] = cipher[3];

    // 2nd

    cipher[1] ^= (4 * j + 3);

    cipher[2] = lsb[2];
    cipher[3] = lsb[3];

    AES256_decrypt (ks, cipher, cipher, s_td0, s_td1, s_td2, s_td3, s_td4);

    lsb[2] = cipher[2];
    lsb[3] = cipher[3];

    // 3rd

    cipher[1] ^= (4 * j + 2);

    cipher[2] = lsb[4];
    cipher[3] = lsb[5];

    AES256_decrypt (ks, cipher, cipher, s_td0, s_td1, s_td2, s_td3, s_td4);

    lsb[4] = cipher[2];
    lsb[5] = cipher[3];

    // 4th

    cipher[1] ^= (4 * j + 1);

    cipher[2] = lsb[6];
    cipher[3] = lsb[7];

    AES256_decrypt (ks, cipher, cipher, s_td0, s_td1, s_td2, s_td3, s_td4);

    lsb[6] = cipher[2];
    lsb[7] = cipher[3];
  }

  if ((cipher[0] == 0xa6a6a6a6) && (cipher[1] == 0xa6a6a6a6))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}
