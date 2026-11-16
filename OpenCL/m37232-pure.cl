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

typedef struct pbkdf2_sha256_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

  // the padded message block of the phase 2 U1, salt || INT32_BE (1), built once in init

  u32 msg[16];

} pbkdf2_sha256_tmp_t;

typedef struct blockio
{
  u32 cipher;

  u32 iv_buf[4];
  u32 ct_buf[4];

} blockio_t;

// an ascii hex digit, lower case, out of a nibble

#define HEXC(n) ((n) + 0x30 + ((((n) + 6) >> 4) * 0x27))

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

KERNEL_FQ KERNEL_FA void m37232_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, blockio_t))
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

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len;

  if (salt_len > 0)
  {
    sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_len);
  }

  // the phase 2 U1 message is the same salt with the block index appended, so the padded block
  // can be built once here. The salt is at most 50 bytes, it always fits a single block.

  u32 msg[16];

  for (u32 i = 0; i < 16; i++) msg[i] = 0;

  for (u32 i = 0; i < salt_len; i++)
  {
    const u32 b = (salt_bufs[SALT_POS_HOST].salt_buf[i / 4] >> ((i % 4) * 8)) & 0xff;

    msg[i / 4] |= b << (24 - ((i % 4) * 8));
  }

  msg[(salt_len + 3) / 4] |= 1 << (24 - (((salt_len + 3) % 4) * 8));

  msg[(salt_len + 4) / 4] |= 0x80 << (24 - (((salt_len + 4) % 4) * 8));

  msg[15] = (64 + salt_len + 4) * 8;

  for (u32 i = 0; i < 16; i++) tmps[gid].msg[i] = msg[i];

  // U1 of phase 1, one pbkdf2 block covers both the 16 bytes of phase 1 and the 32 of phase 2

  sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

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

  sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

  sha256_hmac_final (&sha256_hmac_ctx2);

  tmps[gid].dgst[0] = sha256_hmac_ctx2.opad.h[0];
  tmps[gid].dgst[1] = sha256_hmac_ctx2.opad.h[1];
  tmps[gid].dgst[2] = sha256_hmac_ctx2.opad.h[2];
  tmps[gid].dgst[3] = sha256_hmac_ctx2.opad.h[3];
  tmps[gid].dgst[4] = sha256_hmac_ctx2.opad.h[4];
  tmps[gid].dgst[5] = sha256_hmac_ctx2.opad.h[5];
  tmps[gid].dgst[6] = sha256_hmac_ctx2.opad.h[6];
  tmps[gid].dgst[7] = sha256_hmac_ctx2.opad.h[7];

  tmps[gid].out[0] = tmps[gid].dgst[0];
  tmps[gid].out[1] = tmps[gid].dgst[1];
  tmps[gid].out[2] = tmps[gid].dgst[2];
  tmps[gid].out[3] = tmps[gid].dgst[3];
  tmps[gid].out[4] = tmps[gid].dgst[4];
  tmps[gid].out[5] = tmps[gid].dgst[5];
  tmps[gid].out[6] = tmps[gid].dgst[6];
  tmps[gid].out[7] = tmps[gid].dgst[7];
}

KERNEL_FQ KERNEL_FA void m37232_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, blockio_t))
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

  u32x dgst[8];
  u32x out[8];

  dgst[0] = packv (tmps, dgst, gid, 0);
  dgst[1] = packv (tmps, dgst, gid, 1);
  dgst[2] = packv (tmps, dgst, gid, 2);
  dgst[3] = packv (tmps, dgst, gid, 3);
  dgst[4] = packv (tmps, dgst, gid, 4);
  dgst[5] = packv (tmps, dgst, gid, 5);
  dgst[6] = packv (tmps, dgst, gid, 6);
  dgst[7] = packv (tmps, dgst, gid, 7);

  out[0] = packv (tmps, out, gid, 0);
  out[1] = packv (tmps, out, gid, 1);
  out[2] = packv (tmps, out, gid, 2);
  out[3] = packv (tmps, out, gid, 3);
  out[4] = packv (tmps, out, gid, 4);
  out[5] = packv (tmps, out, gid, 5);
  out[6] = packv (tmps, out, gid, 6);
  out[7] = packv (tmps, out, gid, 7);

  // Block.io runs pbkdf2 twice over half the iterations each, and the key of phase 2 is the hex
  // encoding of the 16 bytes phase 1 produced. The phase switch sits at one fixed step of the
  // whole loop: the pads are rebuilt around the new key when the loop walks past it, and the step
  // itself is the U1 of phase 2.

  const u32 iter = salt_bufs[SALT_POS_HOST].salt_iter + 1;

  const u32 transition = (iter / 2) - 1;

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    if ((LOOP_POS + j) == transition)
    {
      u32x keyw[8];

      for (u32 i = 0, k = 0; i < 4; i += 1, k += 2)
      {
        const u32x b0 = (out[i] >> 24) & 0xff;
        const u32x b1 = (out[i] >> 16) & 0xff;
        const u32x b2 = (out[i] >>  8) & 0xff;
        const u32x b3 = (out[i] >>  0) & 0xff;

        const u32x h0 = b0 >> 4;
        const u32x l0 = b0 & 15;
        const u32x h1 = b1 >> 4;
        const u32x l1 = b1 & 15;
        const u32x h2 = b2 >> 4;
        const u32x l2 = b2 & 15;
        const u32x h3 = b3 >> 4;
        const u32x l3 = b3 & 15;

        keyw[k + 0] = (HEXC (h0) << 24) | (HEXC (l0) << 16) | (HEXC (h1) << 8) | HEXC (l1);
        keyw[k + 1] = (HEXC (h2) << 24) | (HEXC (l2) << 16) | (HEXC (h3) << 8) | HEXC (l3);
      }

      // rebuild the hmac pads around those 32 bytes

      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = keyw[0] ^ 0x36363636;
      w0[1] = keyw[1] ^ 0x36363636;
      w0[2] = keyw[2] ^ 0x36363636;
      w0[3] = keyw[3] ^ 0x36363636;
      w1[0] = keyw[4] ^ 0x36363636;
      w1[1] = keyw[5] ^ 0x36363636;
      w1[2] = keyw[6] ^ 0x36363636;
      w1[3] = keyw[7] ^ 0x36363636;
      w2[0] = 0x36363636;
      w2[1] = 0x36363636;
      w2[2] = 0x36363636;
      w2[3] = 0x36363636;
      w3[0] = 0x36363636;
      w3[1] = 0x36363636;
      w3[2] = 0x36363636;
      w3[3] = 0x36363636;

      ipad[0] = SHA256M_A;
      ipad[1] = SHA256M_B;
      ipad[2] = SHA256M_C;
      ipad[3] = SHA256M_D;
      ipad[4] = SHA256M_E;
      ipad[5] = SHA256M_F;
      ipad[6] = SHA256M_G;
      ipad[7] = SHA256M_H;

      sha256_transform_vector (w0, w1, w2, w3, ipad);

      w0[0] = keyw[0] ^ 0x5c5c5c5c;
      w0[1] = keyw[1] ^ 0x5c5c5c5c;
      w0[2] = keyw[2] ^ 0x5c5c5c5c;
      w0[3] = keyw[3] ^ 0x5c5c5c5c;
      w1[0] = keyw[4] ^ 0x5c5c5c5c;
      w1[1] = keyw[5] ^ 0x5c5c5c5c;
      w1[2] = keyw[6] ^ 0x5c5c5c5c;
      w1[3] = keyw[7] ^ 0x5c5c5c5c;
      w2[0] = 0x5c5c5c5c;
      w2[1] = 0x5c5c5c5c;
      w2[2] = 0x5c5c5c5c;
      w2[3] = 0x5c5c5c5c;
      w3[0] = 0x5c5c5c5c;
      w3[1] = 0x5c5c5c5c;
      w3[2] = 0x5c5c5c5c;
      w3[3] = 0x5c5c5c5c;

      opad[0] = SHA256M_A;
      opad[1] = SHA256M_B;
      opad[2] = SHA256M_C;
      opad[3] = SHA256M_D;
      opad[4] = SHA256M_E;
      opad[5] = SHA256M_F;
      opad[6] = SHA256M_G;
      opad[7] = SHA256M_H;

      sha256_transform_vector (w0, w1, w2, w3, opad);

      // U1 of phase 2 over the padded salt || INT32_BE (1) block from init

      w0[0] = packv (tmps, msg, gid,  0);
      w0[1] = packv (tmps, msg, gid,  1);
      w0[2] = packv (tmps, msg, gid,  2);
      w0[3] = packv (tmps, msg, gid,  3);
      w1[0] = packv (tmps, msg, gid,  4);
      w1[1] = packv (tmps, msg, gid,  5);
      w1[2] = packv (tmps, msg, gid,  6);
      w1[3] = packv (tmps, msg, gid,  7);
      w2[0] = packv (tmps, msg, gid,  8);
      w2[1] = packv (tmps, msg, gid,  9);
      w2[2] = packv (tmps, msg, gid, 10);
      w2[3] = packv (tmps, msg, gid, 11);
      w3[0] = packv (tmps, msg, gid, 12);
      w3[1] = packv (tmps, msg, gid, 13);
      w3[2] = packv (tmps, msg, gid, 14);
      w3[3] = packv (tmps, msg, gid, 15);

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] = dgst[0];
      out[1] = dgst[1];
      out[2] = dgst[2];
      out[3] = dgst[3];
      out[4] = dgst[4];
      out[5] = dgst[5];
      out[6] = dgst[6];
      out[7] = dgst[7];
    }
    else
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
  }

  unpackv (tmps, ipad, gid, 0, ipad[0]);
  unpackv (tmps, ipad, gid, 1, ipad[1]);
  unpackv (tmps, ipad, gid, 2, ipad[2]);
  unpackv (tmps, ipad, gid, 3, ipad[3]);
  unpackv (tmps, ipad, gid, 4, ipad[4]);
  unpackv (tmps, ipad, gid, 5, ipad[5]);
  unpackv (tmps, ipad, gid, 6, ipad[6]);
  unpackv (tmps, ipad, gid, 7, ipad[7]);

  unpackv (tmps, opad, gid, 0, opad[0]);
  unpackv (tmps, opad, gid, 1, opad[1]);
  unpackv (tmps, opad, gid, 2, opad[2]);
  unpackv (tmps, opad, gid, 3, opad[3]);
  unpackv (tmps, opad, gid, 4, opad[4]);
  unpackv (tmps, opad, gid, 5, opad[5]);
  unpackv (tmps, opad, gid, 6, opad[6]);
  unpackv (tmps, opad, gid, 7, opad[7]);

  unpackv (tmps, dgst, gid, 0, dgst[0]);
  unpackv (tmps, dgst, gid, 1, dgst[1]);
  unpackv (tmps, dgst, gid, 2, dgst[2]);
  unpackv (tmps, dgst, gid, 3, dgst[3]);
  unpackv (tmps, dgst, gid, 4, dgst[4]);
  unpackv (tmps, dgst, gid, 5, dgst[5]);
  unpackv (tmps, dgst, gid, 6, dgst[6]);
  unpackv (tmps, dgst, gid, 7, dgst[7]);

  unpackv (tmps, out, gid, 0, out[0]);
  unpackv (tmps, out, gid, 1, out[1]);
  unpackv (tmps, out, gid, 2, out[2]);
  unpackv (tmps, out, gid, 3, out[3]);
  unpackv (tmps, out, gid, 4, out[4]);
  unpackv (tmps, out, gid, 5, out[5]);
  unpackv (tmps, out, gid, 6, out[6]);
  unpackv (tmps, out, gid, 7, out[7]);
}

KERNEL_FQ KERNEL_FA void m37232_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, blockio_t))
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

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];

    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  #endif

  if (gid >= GID_CNT) return;

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const blockio_t *blockio = &esalt_bufs[digest_cur];

  u32 ukey[8];

  ukey[0] = tmps[gid].out[0];
  ukey[1] = tmps[gid].out[1];
  ukey[2] = tmps[gid].out[2];
  ukey[3] = tmps[gid].out[3];
  ukey[4] = tmps[gid].out[4];
  ukey[5] = tmps[gid].out[5];
  ukey[6] = tmps[gid].out[6];
  ukey[7] = tmps[gid].out[7];

  u32 ct[4];

  ct[0] = blockio->ct_buf[0];
  ct[1] = blockio->ct_buf[1];
  ct[2] = blockio->ct_buf[2];
  ct[3] = blockio->ct_buf[3];

  u32 ks[60];

  u32 pt[4];

  if (blockio->cipher == 2)
  {
    // GCM is a counter mode, the payload starts at the counter block nonce || 2

    AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    u32 ctr[4];

    ctr[0] = blockio->iv_buf[0];
    ctr[1] = blockio->iv_buf[1];
    ctr[2] = blockio->iv_buf[2];
    ctr[3] = 2;

    u32 ksm[4];

    AES256_encrypt (ks, ctr, ksm, s_te0, s_te1, s_te2, s_te3, s_te4);

    pt[0] = ct[0] ^ ksm[0];
    pt[1] = ct[1] ^ ksm[1];
    pt[2] = ct[2] ^ ksm[2];
    pt[3] = ct[3] ^ ksm[3];
  }
  else
  {
    AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    AES256_decrypt (ks, ct, pt, s_td0, s_td1, s_td2, s_td3, s_td4);

    if (blockio->cipher == 1)
    {
      pt[0] ^= blockio->iv_buf[0];
      pt[1] ^= blockio->iv_buf[1];
      pt[2] ^= blockio->iv_buf[2];
      pt[3] ^= blockio->iv_buf[3];
    }
  }

  // the encrypted passphrase is hex encoded, so every byte of the first plaintext block is one of
  // 0-9a-f

  for (u32 i = 0; i < 4; i++)
  {
    for (int s = 24; s >= 0; s -= 8)
    {
      const u32 b = (pt[i] >> s) & 0xff;

      const bool is_digit = (b >= 0x30) && (b <= 0x39);
      const bool is_lower = (b >= 0x61) && (b <= 0x66);

      if ((is_digit == false) && (is_lower == false)) return;
    }
  }

  const u32 r0 = ct[0];
  const u32 r1 = ct[1];
  const u32 r2 = ct[2];
  const u32 r3 = ct[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
