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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_camellia.cl)
#endif

// The lengths and the algorithm numbers of sys/geom/eli/g_eli.h and sys/opencrypto/cryptodev.h.
// AES-XTS is a provider's data cipher, never its metadata cipher: g_eli_crypto_decrypt () falls
// back to AES-CBC for the master key, so that is what a slot is read with here.

#define G_ELI_MKEYLEN       192
#define G_ELI_DATAIVKEYLEN  128
#define G_ELI_MAXMKEYS        2

#define CRYPTO_AES_CBC       11
#define CRYPTO_CAMELLIA_CBC  21
#define CRYPTO_AES_XTS       22

typedef struct geli
{
  u32 version;
  u32 ealgo;
  u32 keylen;
  u32 aalgo;
  u32 keys;
  u32 iterations;

  u32 mkeys[(G_ELI_MAXMKEYS * G_ELI_MKEYLEN) / 4];

} geli_t;

typedef struct pbkdf2_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} pbkdf2_sha512_tmp_t;

DECLSPEC void hmac_sha512_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u32x *w4, PRIVATE_AS u32x *w5, PRIVATE_AS u32x *w6, PRIVATE_AS u32x *w7, PRIVATE_AS u64x *ipad, PRIVATE_AS u64x *opad, PRIVATE_AS u64x *digest)
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

// HMAC-SHA512 over a message of at most 128 bytes under a key of at most 64, which covers every
// HMAC the check below needs: the one byte messages, the Data-Key and IV-Key pair, and the PBKDF2
// output under the empty key. w and msg hold their bytes as SHA-512 reads them, the first byte in
// the top of the first word, and the result is left in the eight words of out.

DECLSPEC void geli_hmac_sha512 (PRIVATE_AS const u32 *key, const int key_len, PRIVATE_AS const u32 *msg, const int msg_len, PRIVATE_AS u64 *out)
{
  sha512_hmac_ctx_t ctx;

  sha512_hmac_init (&ctx, key, key_len);

  sha512_hmac_update (&ctx, msg, msg_len);

  sha512_hmac_final (&ctx);

  out[0] = ctx.opad.h[0];
  out[1] = ctx.opad.h[1];
  out[2] = ctx.opad.h[2];
  out[3] = ctx.opad.h[3];
  out[4] = ctx.opad.h[4];
  out[5] = ctx.opad.h[5];
  out[6] = ctx.opad.h[6];
  out[7] = ctx.opad.h[7];
}

KERNEL_FQ KERNEL_FA void m38700_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, geli_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_hmac_ctx_t sha512_hmac_ctx;

  // eli_genkey_passphrase (): md_iterations of 0 is a provider the user asked to do without
  // PKCS#5v2, where the salt and the passphrase go straight into the HMAC that every other
  // provider feeds the PBKDF2 output to. There is no iteration to run, so the user key is final
  // here and the host leaves salt_iter at zero, which keeps the loop kernel from being launched.

  if (esalt_bufs[DIGESTS_OFFSET_HOST].iterations == 0)
  {
    u32 nokey[32];

    for (u32 i = 0; i < 32; i++) nokey[i] = 0;

    sha512_hmac_init (&sha512_hmac_ctx, nokey, 0);

    sha512_hmac_update_global_swap (&sha512_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);
    sha512_hmac_update_global_swap (&sha512_hmac_ctx, pws[gid].i, pws[gid].pw_len);

    sha512_hmac_final (&sha512_hmac_ctx);

    tmps[gid].out[0] = sha512_hmac_ctx.opad.h[0];
    tmps[gid].out[1] = sha512_hmac_ctx.opad.h[1];
    tmps[gid].out[2] = sha512_hmac_ctx.opad.h[2];
    tmps[gid].out[3] = sha512_hmac_ctx.opad.h[3];
    tmps[gid].out[4] = sha512_hmac_ctx.opad.h[4];
    tmps[gid].out[5] = sha512_hmac_ctx.opad.h[5];
    tmps[gid].out[6] = sha512_hmac_ctx.opad.h[6];
    tmps[gid].out[7] = sha512_hmac_ctx.opad.h[7];

    return;
  }

  sha512_hmac_init_global_swap (&sha512_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha512_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha512_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha512_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha512_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha512_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha512_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha512_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha512_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha512_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha512_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha512_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha512_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha512_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha512_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha512_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha512_hmac_ctx.opad.h[7];

  sha512_hmac_update_global_swap (&sha512_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  // the derived key is 64 bytes, which is one PBKDF2 block, so the counter is always 1

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

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

  sha512_hmac_update_128 (&sha512_hmac_ctx, w0, w1, w2, w3, w4, w5, w6, w7, 4);

  sha512_hmac_final (&sha512_hmac_ctx);

  tmps[gid].dgst[0] = sha512_hmac_ctx.opad.h[0];
  tmps[gid].dgst[1] = sha512_hmac_ctx.opad.h[1];
  tmps[gid].dgst[2] = sha512_hmac_ctx.opad.h[2];
  tmps[gid].dgst[3] = sha512_hmac_ctx.opad.h[3];
  tmps[gid].dgst[4] = sha512_hmac_ctx.opad.h[4];
  tmps[gid].dgst[5] = sha512_hmac_ctx.opad.h[5];
  tmps[gid].dgst[6] = sha512_hmac_ctx.opad.h[6];
  tmps[gid].dgst[7] = sha512_hmac_ctx.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}

KERNEL_FQ KERNEL_FA void m38700_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, geli_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  u64x ipad[8];
  u64x opad[8];

  ipad[0] = pack64v (tmps, ipad, gid, 0);
  ipad[1] = pack64v (tmps, ipad, gid, 1);
  ipad[2] = pack64v (tmps, ipad, gid, 2);
  ipad[3] = pack64v (tmps, ipad, gid, 3);
  ipad[4] = pack64v (tmps, ipad, gid, 4);
  ipad[5] = pack64v (tmps, ipad, gid, 5);
  ipad[6] = pack64v (tmps, ipad, gid, 6);
  ipad[7] = pack64v (tmps, ipad, gid, 7);

  opad[0] = pack64v (tmps, opad, gid, 0);
  opad[1] = pack64v (tmps, opad, gid, 1);
  opad[2] = pack64v (tmps, opad, gid, 2);
  opad[3] = pack64v (tmps, opad, gid, 3);
  opad[4] = pack64v (tmps, opad, gid, 4);
  opad[5] = pack64v (tmps, opad, gid, 5);
  opad[6] = pack64v (tmps, opad, gid, 6);
  opad[7] = pack64v (tmps, opad, gid, 7);

  u64x dgst[8];
  u64x out[8];

  dgst[0] = pack64v (tmps, dgst, gid, 0);
  dgst[1] = pack64v (tmps, dgst, gid, 1);
  dgst[2] = pack64v (tmps, dgst, gid, 2);
  dgst[3] = pack64v (tmps, dgst, gid, 3);
  dgst[4] = pack64v (tmps, dgst, gid, 4);
  dgst[5] = pack64v (tmps, dgst, gid, 5);
  dgst[6] = pack64v (tmps, dgst, gid, 6);
  dgst[7] = pack64v (tmps, dgst, gid, 7);

  out[0] = pack64v (tmps, out, gid, 0);
  out[1] = pack64v (tmps, out, gid, 1);
  out[2] = pack64v (tmps, out, gid, 2);
  out[3] = pack64v (tmps, out, gid, 3);
  out[4] = pack64v (tmps, out, gid, 4);
  out[5] = pack64v (tmps, out, gid, 5);
  out[6] = pack64v (tmps, out, gid, 6);
  out[7] = pack64v (tmps, out, gid, 7);

  for (u32 j = 0; j < LOOP_CNT; j++)
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

  unpack64v (tmps, dgst, gid, 0, dgst[0]);
  unpack64v (tmps, dgst, gid, 1, dgst[1]);
  unpack64v (tmps, dgst, gid, 2, dgst[2]);
  unpack64v (tmps, dgst, gid, 3, dgst[3]);
  unpack64v (tmps, dgst, gid, 4, dgst[4]);
  unpack64v (tmps, dgst, gid, 5, dgst[5]);
  unpack64v (tmps, dgst, gid, 6, dgst[6]);
  unpack64v (tmps, dgst, gid, 7, dgst[7]);

  unpack64v (tmps, out, gid, 0, out[0]);
  unpack64v (tmps, out, gid, 1, out[1]);
  unpack64v (tmps, out, gid, 2, out[2]);
  unpack64v (tmps, out, gid, 3, out[3]);
  unpack64v (tmps, out, gid, 4, out[4]);
  unpack64v (tmps, out, gid, 5, out[5]);
  unpack64v (tmps, out, gid, 6, out[6]);
  unpack64v (tmps, out, gid, 7, out[7]);
}

KERNEL_FQ KERNEL_FA void m38700_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, geli_t))
{
  /**
   * base
   */

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

  /**
   * the user key
   */

  // eli_genkey (): with PKCS#5v2 the user key is the HMAC of the PBKDF2 output under the empty
  // key, which is the HMAC context no keyfile ever updated. Without it the init kernel already
  // left the user key here.

  u64 userkey[8];

  if (esalt_bufs[DIGESTS_OFFSET_HOST].iterations == 0)
  {
    userkey[0] = tmps[gid].out[0];
    userkey[1] = tmps[gid].out[1];
    userkey[2] = tmps[gid].out[2];
    userkey[3] = tmps[gid].out[3];
    userkey[4] = tmps[gid].out[4];
    userkey[5] = tmps[gid].out[5];
    userkey[6] = tmps[gid].out[6];
    userkey[7] = tmps[gid].out[7];
  }
  else
  {
    u32 dkey[32];

    for (u32 i = 0; i < 32; i++) dkey[i] = 0;

    for (u32 i = 0; i < 8; i++)
    {
      dkey[(i * 2) + 0] = h32_from_64_S (tmps[gid].out[i]);
      dkey[(i * 2) + 1] = l32_from_64_S (tmps[gid].out[i]);
    }

    u32 nokey[32];

    for (u32 i = 0; i < 32; i++) nokey[i] = 0;

    geli_hmac_sha512 (nokey, 0, dkey, 64, userkey);
  }

  /**
   * the two keys the user key gives
   */

  // g_eli_mkey_decrypt () and g_eli_mkey_verify (): the master key slot is encrypted under
  // HMAC_SHA512 (Derived-Key, 1) and checked against HMAC_SHA512 (Derived-Key, 0)

  u32 uk[32];

  for (u32 i = 0; i < 32; i++) uk[i] = 0;

  for (u32 i = 0; i < 8; i++)
  {
    uk[(i * 2) + 0] = h32_from_64_S (userkey[i]);
    uk[(i * 2) + 1] = l32_from_64_S (userkey[i]);
  }

  u32 one[32];
  u32 zero[32];

  for (u32 i = 0; i < 32; i++)
  {
    one[i]  = 0;
    zero[i] = 0;
  }

  one[0] = 0x01000000;

  u64 enckey[8];
  u64 hmkey[8];

  geli_hmac_sha512 (uk, 64, one,  1, enckey);
  geli_hmac_sha512 (uk, 64, zero, 1, hmkey);

  // the second of the two is the key of the HMAC each slot is checked with, so it is laid out the
  // way an HMAC key is read

  u32 hk[32];

  for (u32 i = 0; i < 32; i++) hk[i] = 0;

  for (u32 i = 0; i < 8; i++)
  {
    hk[(i * 2) + 0] = h32_from_64_S (hmkey[i]);
    hk[(i * 2) + 1] = l32_from_64_S (hmkey[i]);
  }

  /**
   * the master key slots
   */

  const u32 ealgo  = esalt_bufs[DIGESTS_OFFSET_HOST].ealgo;
  const u32 keylen = esalt_bufs[DIGESTS_OFFSET_HOST].keylen;
  const u32 keys   = esalt_bufs[DIGESTS_OFFSET_HOST].keys;

  // the ciphers take their key and their block as little endian words, the first byte in the
  // lowest bits, which is the order the master key slots are already in

  u32 ukey[8];

  for (u32 i = 0; i < 4; i++)
  {
    ukey[(i * 2) + 0] = hc_swap32_S (h32_from_64_S (enckey[i]));
    ukey[(i * 2) + 1] = hc_swap32_S (l32_from_64_S (enckey[i]));
  }

  u32 ks[68];

  if ((ealgo == CRYPTO_AES_CBC) || (ealgo == CRYPTO_AES_XTS))
  {
    if (keylen == 128) aes128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
    if (keylen == 192) aes192_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
    if (keylen == 256) aes256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);
  }
  else if (ealgo == CRYPTO_CAMELLIA_CBC)
  {
    if (keylen == 128) camellia128_set_key (ks, ukey);
    if (keylen == 192) camellia192_set_key (ks, ukey);
    if (keylen == 256) camellia256_set_key (ks, ukey);
  }

  for (u32 nkey = 0; nkey < G_ELI_MAXMKEYS; nkey++)
  {
    if ((keys & (1 << nkey)) == 0) continue;

    u32 plain[G_ELI_MKEYLEN / 4];

    u32 iv[4];

    iv[0] = 0;
    iv[1] = 0;
    iv[2] = 0;
    iv[3] = 0;

    for (u32 off = 0; off < G_ELI_MKEYLEN / 4; off += 4)
    {
      u32 c[4];
      u32 p[4];

      c[0] = esalt_bufs[DIGESTS_OFFSET_HOST].mkeys[((nkey * G_ELI_MKEYLEN) / 4) + off + 0];
      c[1] = esalt_bufs[DIGESTS_OFFSET_HOST].mkeys[((nkey * G_ELI_MKEYLEN) / 4) + off + 1];
      c[2] = esalt_bufs[DIGESTS_OFFSET_HOST].mkeys[((nkey * G_ELI_MKEYLEN) / 4) + off + 2];
      c[3] = esalt_bufs[DIGESTS_OFFSET_HOST].mkeys[((nkey * G_ELI_MKEYLEN) / 4) + off + 3];

      if ((ealgo == CRYPTO_AES_CBC) || (ealgo == CRYPTO_AES_XTS))
      {
        if (keylen == 128) aes128_decrypt (ks, c, p, s_td0, s_td1, s_td2, s_td3, s_td4);
        if (keylen == 192) aes192_decrypt (ks, c, p, s_td0, s_td1, s_td2, s_td3, s_td4);
        if (keylen == 256) aes256_decrypt (ks, c, p, s_td0, s_td1, s_td2, s_td3, s_td4);

        p[0] ^= iv[0];
        p[1] ^= iv[1];
        p[2] ^= iv[2];
        p[3] ^= iv[3];
      }
      else if (ealgo == CRYPTO_CAMELLIA_CBC)
      {
        if (keylen == 128) camellia128_decrypt (ks, c, p);
        if (keylen == 192) camellia192_decrypt (ks, c, p);
        if (keylen == 256) camellia256_decrypt (ks, c, p);

        p[0] ^= iv[0];
        p[1] ^= iv[1];
        p[2] ^= iv[2];
        p[3] ^= iv[3];
      }
      else
      {
        // the null cipher, 16 in cryptodev.h and the only one the module lets through besides the
        // two above, where EVP_enc_null () left the slot as it is

        p[0] = c[0];
        p[1] = c[1];
        p[2] = c[2];
        p[3] = c[3];
      }

      plain[off + 0] = p[0];
      plain[off + 1] = p[1];
      plain[off + 2] = p[2];
      plain[off + 3] = p[3];

      iv[0] = c[0];
      iv[1] = c[1];
      iv[2] = c[2];
      iv[3] = c[3];
    }

    // the HMAC covers the Data-Key and the IV-Key, and the 64 bytes behind them are what it is
    // compared against

    u32 dataiv[G_ELI_DATAIVKEYLEN / 4];

    for (u32 i = 0; i < G_ELI_DATAIVKEYLEN / 4; i++) dataiv[i] = hc_swap32_S (plain[i]);

    u64 chmac[8];

    geli_hmac_sha512 (hk, 64, dataiv, G_ELI_DATAIVKEYLEN, chmac);

    u32 ok = 1;

    for (u32 i = 0; i < 8; i++)
    {
      if (h32_from_64_S (chmac[i]) != hc_swap32_S (plain[(G_ELI_DATAIVKEYLEN / 4) + (i * 2) + 0])) ok = 0;
      if (l32_from_64_S (chmac[i]) != hc_swap32_S (plain[(G_ELI_DATAIVKEYLEN / 4) + (i * 2) + 1])) ok = 0;
    }

    if (ok == 1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
      }
    }
  }
}
