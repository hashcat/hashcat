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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_des.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct dmg_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} dmg_tmp_t;

typedef struct dmg
{
  u32 iv[8];         // 32 bytes (only the first 8 are used by the format)

  u32 keyblob[16];   // 48 or 64 bytes
  int keyblob_len;

  u32 cno;
  u32 data_size;

  u32 chunk[2048];   // data chunk, up to 8192 bytes

  u32 zchunk[1024];  // zero chunk, up to 4096 bytes
  int zchunk_len;    // 0 if scp == 0

} dmg_t;

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

KERNEL_FQ KERNEL_FA void m38302_init (KERN_ATTR_TMPS_ESALT (dmg_tmp_t, dmg_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx, pws[gid].i, pws[gid].pw_len);

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

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  u32 key_elem = 6; /* 3DES: 24B = 6 u32 */

  for (u32 i = 0, j = 1; i < key_elem; i += 5, j += 1)
  {
    sha1_hmac_ctx_t sha1_hmac_ctx2 = sha1_hmac_ctx;

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

KERNEL_FQ KERNEL_FA void m38302_loop (KERN_ATTR_TMPS_ESALT (dmg_tmp_t, dmg_t))
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

  u32 key_elem = 6; /* 3DES: 24B = 6 u32 */

  for (u32 i = 0; i < key_elem; i += 5)
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

DECLSPEC void des3_ede_decrypt_block (PRIVATE_AS const u32 *ct, PRIVATE_AS u32 *pt, PRIVATE_AS const u32 *Kc1, PRIVATE_AS const u32 *Kd1, PRIVATE_AS const u32 *Kc2, PRIVATE_AS const u32 *Kd2, PRIVATE_AS const u32 *Kc3, PRIVATE_AS const u32 *Kd3, SHM_TYPE u32 (*s_SPtrans)[64])
{
  u32 t[2];

  _des_crypt_decrypt (t, ct, Kc3, Kd3, s_SPtrans); // D k3
  _des_crypt_encrypt (t, t,  Kc2, Kd2, s_SPtrans); // E k2
  _des_crypt_decrypt (pt, t, Kc1, Kd1, s_SPtrans); // D k1
}

// v2: CBC-decrypt data blocks with the given IV and look for a run of 8 zero bytes
// in the plaintext (a "chunk" of an encrypted DMG always contains one)

DECLSPEC bool dmg_v2_scan (GLOBAL_AS const u32 *data, const int data_len, PRIVATE_AS const u32 *ks, const int aes256, PRIVATE_AS u32 *iv, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  const int nblocks = data_len / 16;

  int run = 0;

  for (int i = 0; i < nblocks; i++)
  {
    u32 ct[4];

    ct[0] = data[i * 4 + 0];
    ct[1] = data[i * 4 + 1];
    ct[2] = data[i * 4 + 2];
    ct[3] = data[i * 4 + 3];

    u32 pt[4];

    if (aes256)
    {
      aes256_decrypt (ks, ct, pt, s_td0, s_td1, s_td2, s_td3, s_td4);
    }
    else
    {
      aes128_decrypt (ks, ct, pt, s_td0, s_td1, s_td2, s_td3, s_td4);
    }

    pt[0] ^= iv[0];
    pt[1] ^= iv[1];
    pt[2] ^= iv[2];
    pt[3] ^= iv[3];

    iv[0] = ct[0];
    iv[1] = ct[1];
    iv[2] = ct[2];
    iv[3] = ct[3];

    for (int j = 0; j < 4; j++)
    {
      const u32 w = pt[j];

      run = ((w >>  0) & 0xff) == 0 ? run + 1 : 0;
      if (run == 8) return true;

      run = ((w >>  8) & 0xff) == 0 ? run + 1 : 0;
      if (run == 8) return true;

      run = ((w >> 16) & 0xff) == 0 ? run + 1 : 0;
      if (run == 8) return true;

      run = ((w >> 24) & 0xff) == 0 ? run + 1 : 0;
      if (run == 8) return true;
    }
  }

  return false;
}

KERNEL_FQ KERNEL_FA void m38302_comp (KERN_ATTR_TMPS_ESALT (dmg_tmp_t, dmg_t))
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

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];

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
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_SPtrans)[64] = c_SPtrans;
  CONSTANT_AS u32a (*s_skb)[64]     = c_skb;

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;

  #endif

  if (gid >= GID_CNT) return;

  // the PBKDF2 output words are big-endian (sha1 digest order); the DES key setup
  // wants the 24 key bytes as little-endian words

  u32 Kc1[16];
  u32 Kd1[16];

  _des_crypt_keysetup (hc_swap32_S (tmps[gid].out[0]), hc_swap32_S (tmps[gid].out[1]), Kc1, Kd1, s_skb);

  u32 Kc2[16];
  u32 Kd2[16];

  _des_crypt_keysetup (hc_swap32_S (tmps[gid].out[2]), hc_swap32_S (tmps[gid].out[3]), Kc2, Kd2, s_skb);

  u32 Kc3[16];
  u32 Kd3[16];

  _des_crypt_keysetup (hc_swap32_S (tmps[gid].out[4]), hc_swap32_S (tmps[gid].out[5]), Kc3, Kd3, s_skb);

  GLOBAL_AS const dmg_t *dmg = &esalt_bufs[DIGESTS_OFFSET_HOST];

  // 3DES-CBC decrypt the first 32 bytes of the key blob with IV = iv[0..8);
  // the result holds the AES key (first 16 or 32 bytes, depending on blob size)
  // and the HMAC key (first 20 bytes)

  u32 prev[2];

  prev[0] = dmg->iv[0];
  prev[1] = dmg->iv[1];

  u32 key[8];

  for (int i = 0; i < 4; i++)
  {
    u32 ct[2];

    ct[0] = dmg->keyblob[i * 2 + 0];
    ct[1] = dmg->keyblob[i * 2 + 1];

    u32 pt[2];

    des3_ede_decrypt_block (ct, pt, Kc1, Kd1, Kc2, Kd2, Kc3, Kd3, s_SPtrans);

    pt[0] ^= prev[0];
    pt[1] ^= prev[1];

    prev[0] = ct[0];
    prev[1] = ct[1];

    key[i * 2 + 0] = pt[0];
    key[i * 2 + 1] = pt[1];
  }

  const int aes256 = (dmg->keyblob_len == 64) ? 1 : 0;

  u32 ks[60];

  if (aes256)
  {
    aes256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
  }
  else
  {
    aes128_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
  }

  // chunk IV = first 16 bytes of HMAC-SHA1 (hmac_key, BE32 (cno))

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init (&sha1_hmac_ctx, key, 20);

  u32 w[4];

  w[0] = hc_swap32_S (dmg->cno); // big-endian on the wire
  w[1] = 0;
  w[2] = 0;
  w[3] = 0;

  sha1_hmac_update (&sha1_hmac_ctx, w, 4);

  sha1_hmac_final (&sha1_hmac_ctx);

  u32 iv[4];

  iv[0] = hc_swap32_S (sha1_hmac_ctx.opad.h[0]);
  iv[1] = hc_swap32_S (sha1_hmac_ctx.opad.h[1]);
  iv[2] = hc_swap32_S (sha1_hmac_ctx.opad.h[2]);
  iv[3] = hc_swap32_S (sha1_hmac_ctx.opad.h[3]);

  if (dmg_v2_scan (dmg->chunk, dmg->data_size, ks, aes256, iv, s_td0, s_td1, s_td2, s_td3, s_td4) == false)
  {
    if (dmg->zchunk_len == 0) return;

    // scp == 1: also try the zero chunk, which uses chunk number 0

    sha1_hmac_init (&sha1_hmac_ctx, key, 20);

    w[0] = 0;
    w[1] = 0;
    w[2] = 0;
    w[3] = 0;

    sha1_hmac_update (&sha1_hmac_ctx, w, 4);

    sha1_hmac_final (&sha1_hmac_ctx);

    iv[0] = hc_swap32_S (sha1_hmac_ctx.opad.h[0]);
    iv[1] = hc_swap32_S (sha1_hmac_ctx.opad.h[1]);
    iv[2] = hc_swap32_S (sha1_hmac_ctx.opad.h[2]);
    iv[3] = hc_swap32_S (sha1_hmac_ctx.opad.h[3]);

    if (dmg_v2_scan (dmg->zchunk, dmg->zchunk_len, ks, aes256, iv, s_td0, s_td1, s_td2, s_td3, s_td4) == false) return;
  }

  // report MD5 of the key blob as identity (matches the host decoder)

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update_global (&md5_ctx, dmg->keyblob, dmg->keyblob_len);

  md5_final (&md5_ctx);

  const u32 r0 = md5_ctx.h[0];
  const u32 r1 = md5_ctx.h[1];
  const u32 r2 = md5_ctx.h[2];
  const u32 r3 = md5_ctx.h[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
