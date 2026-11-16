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
  u32 wrapped_aes_key[74];  // up to 296 bytes
  u32 wrapped_hmac_key[75]; // up to 300 bytes

  int wrapped_aes_key_len;
  int wrapped_hmac_key_len;

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

// v1 stage 1: the padded plaintext of a wrapped key blob always ends in a full block of
// eight 0x08 bytes, because the reversed inner buffer dropped afterwards must leave a
// multiple of 8. CBC decrypt of the last block needs only the last two ciphertext blocks.

DECLSPEC bool dmg_v1_last_block_ok (GLOBAL_AS const u32 *blob, const int blob_len, PRIVATE_AS const u32 *Kc1, PRIVATE_AS const u32 *Kd1, PRIVATE_AS const u32 *Kc2, PRIVATE_AS const u32 *Kd2, PRIVATE_AS const u32 *Kc3, PRIVATE_AS const u32 *Kd3, SHM_TYPE u32 (*s_SPtrans)[64])
{
  const int last = blob_len / 8 - 1;

  u32 ct[2];

  ct[0] = blob[last * 2 + 0];
  ct[1] = blob[last * 2 + 1];

  u32 pt[2];

  des3_ede_decrypt_block (ct, pt, Kc1, Kd1, Kc2, Kd2, Kc3, Kd3, s_SPtrans);

  pt[0] ^= blob[last * 2 - 2];
  pt[1] ^= blob[last * 2 - 1];

  if (pt[0] != 0x08080808) return false;
  if (pt[1] != 0x08080808) return false;

  return true;
}

DECLSPEC bool dmg_v1_unwrap (GLOBAL_AS const u32 *blob, const int blob_len, PRIVATE_AS const u32 *Kc1, PRIVATE_AS const u32 *Kd1, PRIVATE_AS const u32 *Kc2, PRIVATE_AS const u32 *Kd2, PRIVATE_AS const u32 *Kc3, PRIVATE_AS const u32 *Kd3, SHM_TYPE u32 (*s_SPtrans)[64])
{
  u8 temp1[304];
  u8 temp2[304];

  // stage 1: 3DES-CBC decrypt with the fixed wrap IV 4a dd a2 2c 79 e8 21 05

  u32 prev[2];

  prev[0] = 0x2ca2dd4a; // 4a dd a2 2c, little-endian
  prev[1] = 0x0521e879; // 79 e8 21 05, little-endian

  const int nblk = blob_len / 8;

  for (int i = 0; i < nblk; i++)
  {
    u32 ct[2];

    ct[0] = blob[i * 2 + 0];
    ct[1] = blob[i * 2 + 1];

    u32 pt[2];

    des3_ede_decrypt_block (ct, pt, Kc1, Kd1, Kc2, Kd2, Kc3, Kd3, s_SPtrans);

    pt[0] ^= prev[0];
    pt[1] ^= prev[1];

    prev[0] = ct[0];
    prev[1] = ct[1];

    temp1[i * 8 + 0] = (u8) (pt[0] >>  0);
    temp1[i * 8 + 1] = (u8) (pt[0] >>  8);
    temp1[i * 8 + 2] = (u8) (pt[0] >> 16);
    temp1[i * 8 + 3] = (u8) (pt[0] >> 24);
    temp1[i * 8 + 4] = (u8) (pt[1] >>  0);
    temp1[i * 8 + 5] = (u8) (pt[1] >>  8);
    temp1[i * 8 + 6] = (u8) (pt[1] >> 16);
    temp1[i * 8 + 7] = (u8) (pt[1] >> 24);
  }

  // PKCS#7 padding, block size 8

  const u8 pad1 = temp1[blob_len - 1];

  if (pad1 < 1 || pad1 > 8) return false;

  for (int i = 0; i < pad1; i++)
  {
    if (temp1[blob_len - 1 - i] != pad1) return false;
  }

  int outlen = blob_len - pad1;

  if (outlen < 16) return false;
  if ((outlen & 7) != 0) return false;

  // reverse the outlen bytes

  for (int i = 0; i < outlen; i++)
  {
    temp2[i] = temp1[outlen - 1 - i];
  }

  // stage 2: CBC decrypt temp2[8 .. outlen) with IV = temp2[0 .. 8)

  outlen -= 8;

  prev[0] = (u32) temp2[0]
          | (u32) temp2[1] <<  8
          | (u32) temp2[2] << 16
          | (u32) temp2[3] << 24;

  prev[1] = (u32) temp2[4]
          | (u32) temp2[5] <<  8
          | (u32) temp2[6] << 16
          | (u32) temp2[7] << 24;

  const int nblk2 = outlen / 8;

  for (int i = 0; i < nblk2; i++)
  {
    u32 ct[2];

    ct[0] = (u32) temp2[8 + i * 8 + 0]
          | (u32) temp2[8 + i * 8 + 1] <<  8
          | (u32) temp2[8 + i * 8 + 2] << 16
          | (u32) temp2[8 + i * 8 + 3] << 24;

    ct[1] = (u32) temp2[8 + i * 8 + 4]
          | (u32) temp2[8 + i * 8 + 5] <<  8
          | (u32) temp2[8 + i * 8 + 6] << 16
          | (u32) temp2[8 + i * 8 + 7] << 24;

    u32 pt[2];

    des3_ede_decrypt_block (ct, pt, Kc1, Kd1, Kc2, Kd2, Kc3, Kd3, s_SPtrans);

    pt[0] ^= prev[0];
    pt[1] ^= prev[1];

    prev[0] = ct[0];
    prev[1] = ct[1];

    temp1[i * 8 + 0] = (u8) (pt[0] >>  0);
    temp1[i * 8 + 1] = (u8) (pt[0] >>  8);
    temp1[i * 8 + 2] = (u8) (pt[0] >> 16);
    temp1[i * 8 + 3] = (u8) (pt[0] >> 24);
    temp1[i * 8 + 4] = (u8) (pt[1] >>  0);
    temp1[i * 8 + 5] = (u8) (pt[1] >>  8);
    temp1[i * 8 + 6] = (u8) (pt[1] >> 16);
    temp1[i * 8 + 7] = (u8) (pt[1] >> 24);
  }

  const u8 pad2 = temp1[outlen - 1];

  if (pad2 < 1 || pad2 > 8) return false;

  for (int i = 0; i < pad2; i++)
  {
    if (temp1[outlen - 1 - i] != pad2) return false;
  }

  return true;
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

  // cheap reject on the last block of each blob before the full unwrap

  if (dmg_v1_last_block_ok (dmg->wrapped_aes_key, dmg->wrapped_aes_key_len, Kc1, Kd1, Kc2, Kd2, Kc3, Kd3, s_SPtrans) == false) return;

  if (dmg_v1_last_block_ok (dmg->wrapped_hmac_key, dmg->wrapped_hmac_key_len, Kc1, Kd1, Kc2, Kd2, Kc3, Kd3, s_SPtrans) == false) return;

  if (dmg_v1_unwrap (dmg->wrapped_aes_key, dmg->wrapped_aes_key_len, Kc1, Kd1, Kc2, Kd2, Kc3, Kd3, s_SPtrans) == false) return;

  if (dmg_v1_unwrap (dmg->wrapped_hmac_key, dmg->wrapped_hmac_key_len, Kc1, Kd1, Kc2, Kd2, Kc3, Kd3, s_SPtrans) == false) return;

  // report MD5 of both wrapped key blobs as identity (matches the host decoder)

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update_global (&md5_ctx, dmg->wrapped_aes_key, dmg->wrapped_aes_key_len);
  md5_update_global (&md5_ctx, dmg->wrapped_hmac_key, dmg->wrapped_hmac_key_len);

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
