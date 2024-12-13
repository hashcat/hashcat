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
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct encdatavault
{
  u32 keychain[32];
  u32 iv[2];

  u32 ct[2];

  u32 algo;
  u32 version;

  u32 nb_keys;
  u32 key_len;

} encdatavault_t;

typedef struct encdatavault_tmp
{
  // key size can range between 128 and 1024 bit

  u32 ipad[8];
  u32 opad[8];

  u32 dgst[32];
  u32 out[32];

} encdatavault_tmp_t;

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

KERNEL_FQ void m29920_init (KERN_ATTR_TMPS_ESALT (encdatavault_tmp_t, encdatavault_t))
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

  sha256_hmac_update_global (&sha256_hmac_ctx, salt_bufs[DIGESTS_OFFSET_HOST].salt_buf, salt_bufs[DIGESTS_OFFSET_HOST].salt_len);

  const u32 key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_len;

  for (u32 i = 0, j = 1; i < (key_len / 4); i += 8, j += 1)
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

KERNEL_FQ void m29920_loop (KERN_ATTR_TMPS_ESALT (encdatavault_tmp_t, encdatavault_t))
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

  const u32 key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_len;

  for (u32 i = 0; i < (key_len / 4); i += 8)
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

KERNEL_FQ void m29920_comp (KERN_ATTR_TMPS_ESALT (encdatavault_tmp_t, encdatavault_t))
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

  // decrypt keychain using PBKDF2 key

  u32 ukey[4];

  ukey[0] = tmps[gid].out[0];
  ukey[1] = tmps[gid].out[1];
  ukey[2] = tmps[gid].out[2];
  ukey[3] = tmps[gid].out[3];

  u32 ks[44];

  AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  const u32 key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_len;

  #define ENC_MAX_KEY_NUM 8

  u32 ivs_keychain[ENC_MAX_KEY_NUM][2];

  ivs_keychain[0][0] = 0;
  ivs_keychain[0][1] = 0;

  for (int i = 1, j = 28; i < ENC_MAX_KEY_NUM; i += 1, j -= 4) // +4 is not a bug, 8/16 bytes are just discarded
  {
    ivs_keychain[i][0] = tmps[gid].out[j + 0];
    ivs_keychain[i][1] = tmps[gid].out[j + 1];
  }

  u32 ctr_keychain[ENC_MAX_KEY_NUM][4];

  #define ENC_KEYCHAIN_SIZE 128
  #define ENC_BLOCK_SIZE 16

  for (int i = 0, counter = 0; i < (ENC_KEYCHAIN_SIZE / ENC_BLOCK_SIZE); i++, counter++)
  {
    u32 in[4];

    in[0] = ivs_keychain[0][0];
    in[1] = ivs_keychain[0][1];
    in[2] = 0;
    in[3] = counter;

    u32 out[4];

    AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    ctr_keychain[i][0] = out[0];
    ctr_keychain[i][1] = out[1];
    ctr_keychain[i][2] = out[2];
    ctr_keychain[i][3] = out[3];

    for (int j = 1; j < ENC_MAX_KEY_NUM; j++)
    {
      in[0] = ivs_keychain[j][0];
      in[1] = ivs_keychain[j][1];
      in[2] = 0;
      in[3] = counter;

      AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

      ctr_keychain[i][0] ^= out[0];
      ctr_keychain[i][1] ^= out[1];
      ctr_keychain[i][2] ^= out[2];
      ctr_keychain[i][3] ^= out[3];
    }
  }

  u32 keychain[ENC_MAX_KEY_NUM][4];

  for (int i = 0, j = 0; i < (ENC_KEYCHAIN_SIZE / ENC_BLOCK_SIZE); i += 1, j += 4)
  {
    keychain[i][0] = ctr_keychain[i][0] ^ esalt_bufs[DIGESTS_OFFSET_HOST].keychain[j + 0];
    keychain[i][1] = ctr_keychain[i][1] ^ esalt_bufs[DIGESTS_OFFSET_HOST].keychain[j + 1];
    keychain[i][2] = ctr_keychain[i][2] ^ esalt_bufs[DIGESTS_OFFSET_HOST].keychain[j + 2];
    keychain[i][3] = ctr_keychain[i][3] ^ esalt_bufs[DIGESTS_OFFSET_HOST].keychain[j + 3];
  }

  // decrypt encrypted data using keychain key

  ukey[0] = keychain[0][0];
  ukey[1] = keychain[0][1];
  ukey[2] = keychain[0][2];
  ukey[3] = keychain[0][3];

  AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

  u32 ivs[ENC_MAX_KEY_NUM][2];

  ivs[0][0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  ivs[0][1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];

  for (int i = 1; i < esalt_bufs[DIGESTS_OFFSET_HOST].nb_keys; i += 1) // +4 is not a bug, 8/16 bytes are just discarded
  {
    ivs[i][0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0] ^ keychain[i][0];
    ivs[i][1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1] ^ keychain[i][1];
  }

  #define CTR_LEN 16

  u32 ctr[ENC_MAX_KEY_NUM][4];

  for (int i = 0, counter = 1; i < (CTR_LEN / ENC_BLOCK_SIZE); i++, counter++) // is always just 1 iteration here, but concept is needed for later kernels
  {
    u32 in[4];

    in[0] = ivs[0][0];
    in[1] = ivs[0][1];
    in[2] = 0;
    in[3] = counter;

    u32 out[4];

    AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    ctr[i][0] = out[0];
    ctr[i][1] = out[1];
    ctr[i][2] = out[2];
    ctr[i][3] = out[3];

    for (int j = 1; j < esalt_bufs[DIGESTS_OFFSET_HOST].nb_keys; j++)
    {
      in[0] = ivs[j][0];
      in[1] = ivs[j][1];
      in[2] = 0;
      in[3] = counter;

      AES128_encrypt (ks, in, out, s_te0, s_te1, s_te2, s_te3, s_te4);

      ctr[i][0] ^= out[0];
      ctr[i][1] ^= out[1];
      ctr[i][2] ^= out[2];
      ctr[i][3] ^= out[3];
    }
  }

  u32 ct[2];

  ct[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[0];
  ct[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ct[1];

  u32 pt[2];

  pt[0] = ct[0] ^ ctr[0][1];
  pt[1] = ct[1] ^ ctr[0][2];

  if ((pt[0] == 0xd2c3b4a1) && ((pt[1] & 0xffffff00) == 0))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
