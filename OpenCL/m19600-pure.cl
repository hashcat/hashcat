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
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct krb5tgs_17
{
  u32 user[128];
  u32 domain[128];
  u32 account_info[512];
  u32 account_info_len;

  u32 checksum[3];
  u32 edata2[5120];
  u32 edata2_len;

} krb5tgs_17_t;

typedef struct krb5tgs_17_tmp
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[10];
  u32 out[10];

} krb5tgs_17_tmp_t;

DECLSPEC void aes128_encrypt_cbc (PRIVATE_AS const u32 *aes_ks, PRIVATE_AS u32 *aes_iv, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4)
{
  u32 data[4];

  data[0] = hc_swap32_S (in[0]);
  data[1] = hc_swap32_S (in[1]);
  data[2] = hc_swap32_S (in[2]);
  data[3] = hc_swap32_S (in[3]);

  data[0] ^= aes_iv[0];
  data[1] ^= aes_iv[1];
  data[2] ^= aes_iv[2];
  data[3] ^= aes_iv[3];

  aes128_encrypt (aes_ks, data, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  aes_iv[0] = out[0];
  aes_iv[1] = out[1];
  aes_iv[2] = out[2];
  aes_iv[3] = out[3];

  out[0] = hc_swap32_S (out[0]);
  out[1] = hc_swap32_S (out[1]);
  out[2] = hc_swap32_S (out[2]);
  out[3] = hc_swap32_S (out[3]);
}

DECLSPEC void aes128_decrypt_cbc (PRIVATE_AS const u32 *ks1, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, PRIVATE_AS u32 *essiv, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  aes128_decrypt (ks1, in, out, s_td0, s_td1, s_td2, s_td3, s_td4);

  out[0] ^= essiv[0];
  out[1] ^= essiv[1];
  out[2] ^= essiv[2];
  out[3] ^= essiv[3];

  essiv[0] = in[0];
  essiv[1] = in[1];
  essiv[2] = in[2];
  essiv[3] = in[3];
}

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

KERNEL_FQ void m19600_init (KERN_ATTR_TMPS_ESALT (krb5tgs_17_tmp_t, krb5tgs_17_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * main
   */

  /* initialize hmac-sha1 for pbkdf2(password, account, 4096, account_len) */

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

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, esalt_bufs[DIGESTS_OFFSET_HOST].account_info, esalt_bufs[DIGESTS_OFFSET_HOST].account_info_len);

 for (u32 i = 0, j = 1; i < 4; i += 5, j += 1)
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

KERNEL_FQ void m19600_loop (KERN_ATTR_TMPS_ESALT (krb5tgs_17_tmp_t, krb5tgs_17_t))
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

  for (u32 i = 0; i < 4; i += 5)
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

KERNEL_FQ void m19600_comp (KERN_ATTR_TMPS_ESALT (krb5tgs_17_tmp_t, krb5tgs_17_t))
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

  /*
    at this point, the output ('seed') will be used to generate AES keys:

    key_bytes = derive(seed, 'kerberos'.encode(), seedsize)

    'key_bytes' will be the AES key used to generate 'ke' and 'ki'
    'ke' will be the AES key to decrypt the ticket
    'ki' will be the key to compute the final HMAC
  */

  u32 nfolded[4];

  // we can precompute _nfold('kerberos', 16)
  nfolded[0] = 0x6b657262;
  nfolded[1] = 0x65726f73;
  nfolded[2] = 0x7b9b5b2b;
  nfolded[3] = 0x93132b93;

  // then aes_cbc encrypt this nfolded value with 'seed' as key along with a null IV
  u32 aes_key[4];

  aes_key[0] = hc_swap32_S (tmps[gid].out[0]);
  aes_key[1] = hc_swap32_S (tmps[gid].out[1]);
  aes_key[2] = hc_swap32_S (tmps[gid].out[2]);
  aes_key[3] = hc_swap32_S (tmps[gid].out[3]);

  u32 aes_iv[4];

  aes_iv[0] = 0;
  aes_iv[1] = 0;
  aes_iv[2] = 0;
  aes_iv[3] = 0;

  u32 aes_ks[44];

  aes128_set_encrypt_key (aes_ks, aes_key, s_te0, s_te1, s_te2, s_te3);

  u32 key_bytes[4];

  aes128_encrypt_cbc (aes_ks, aes_iv, nfolded, key_bytes, s_te0, s_te1, s_te2, s_te3, s_te4);

  /* we will now compute 'ki', having 'key_bytes' */

  u32 ki[4];

  key_bytes[0] = hc_swap32_S (key_bytes[0]);
  key_bytes[1] = hc_swap32_S (key_bytes[1]);
  key_bytes[2] = hc_swap32_S (key_bytes[2]);
  key_bytes[3] = hc_swap32_S (key_bytes[3]);

  // we can precompute _nfold(pack('>IB', 2, 0x55), 16)
  nfolded[0] = 0x62dc6e37;
  nfolded[1] = 0x1a63a809;
  nfolded[2] = 0x58ac562b;
  nfolded[3] = 0x15404ac5;

  aes_iv[0] = 0;
  aes_iv[1] = 0;
  aes_iv[2] = 0;
  aes_iv[3] = 0;

  // then aes_cbc encrypt this nfolded value with 'key_bytes' as key along with a null IV
  aes128_set_encrypt_key (aes_ks, key_bytes, s_te0, s_te1, s_te2, s_te3);

  aes128_encrypt_cbc (aes_ks, aes_iv, nfolded, ki, s_te0, s_te1, s_te2, s_te3, s_te4);

  /* we will now compute 'ke' */

  u32 ke[4];

  // we can precompute _nfold(pack('>IB', 2, 0xAA), 16)
  nfolded[0] = 0xb5b0582c;
  nfolded[1] = 0x14b6500a;
  nfolded[2] = 0xad56ab55;
  nfolded[3] = 0xaa80556a;

  aes_iv[0] = 0;
  aes_iv[1] = 0;
  aes_iv[2] = 0;
  aes_iv[3] = 0;

  // then aes_cbc encrypt this nfolded value with 'key_bytes' as key along with a null IV
  aes128_encrypt_cbc (aes_ks, aes_iv, nfolded, ke, s_te0, s_te1, s_te2, s_te3, s_te4);

  /*
      we now have 'ke' and 'ki'

      we will decrypt (with 'ke') the 32 first bytes to search for ASN.1 structs
      and if we find ASN.1 structs, we will compute the hmac (with 'ki')

      if length >= 128 bytes:
          length is on 2 bytes and type is \x63\x82 (encode_krb5_enc_tkt_part) and data is an ASN1 sequence \x30\x82
      else:
          length is on 1 byte and type is \x63\x81 and data is an ASN1 sequence \x30\x81

      next headers follow the same ASN1 "type-length-data" scheme
  */

  u32 first_blocks[16];

  u32 decrypted_block[4];

  first_blocks[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[0];
  first_blocks[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[1];
  first_blocks[2] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[2];
  first_blocks[3] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[3];

  first_blocks[4] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[4]; // possible ASN1 structs
  first_blocks[5] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[5];
  first_blocks[6] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[6]; // possible ASN1 structs
  first_blocks[7] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[7];

  /*
     we will decrypt them here in order to be able to compute hmac directly
     if ASN1 structs were to be found
  */
  first_blocks[8]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[8];
  first_blocks[9]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[9];
  first_blocks[10] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[10];
  first_blocks[11] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[11];

  first_blocks[12] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[12];
  first_blocks[13] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[13];
  first_blocks[14] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[14];
  first_blocks[15] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[15];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 aes_cts_decrypt_ks[44];

  AES128_set_decrypt_key (aes_cts_decrypt_ks, ke, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  aes_iv[0] = 0;
  aes_iv[1] = 0;
  aes_iv[2] = 0;
  aes_iv[3] = 0;

  aes128_decrypt_cbc (aes_cts_decrypt_ks, first_blocks, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

  w0[0] = hc_swap32_S (decrypted_block[0]);
  w0[1] = hc_swap32_S (decrypted_block[1]);
  w0[2] = hc_swap32_S (decrypted_block[2]);
  w0[3] = hc_swap32_S (decrypted_block[3]);

  aes128_decrypt_cbc (aes_cts_decrypt_ks, first_blocks + 4, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

  w1[0] = hc_swap32_S (decrypted_block[0]);
  w1[1] = hc_swap32_S (decrypted_block[1]);
  w1[2] = hc_swap32_S (decrypted_block[2]);
  w1[3] = hc_swap32_S (decrypted_block[3]);

  if (((decrypted_block[0] & 0xff00ffff) == 0x30008163) || ((decrypted_block[0] & 0x0000ffff) == 0x00008263))
  {
    if (((decrypted_block[2] & 0x00ffffff) == 0x00000503) || (decrypted_block[2] == 0x050307A0))
    {
      // now we decrypt all the ticket to verify checksum
      int block_position;

      int edata2_len = esalt_bufs[DIGESTS_OFFSET_HOST].edata2_len;

      int edata2_left;

      u32 block[16];

      int last_block_size = edata2_len % 16;

      if (last_block_size == 0)
      {
        last_block_size = 16;
      }

      int last_part = last_block_size + 16;

      int need = edata2_len - last_part;

      int last_block_cbc_position = (need - 16) / 4;

      // we need to decrypt also the 2 following blocks in order to be able to compute the hmac directly
      aes128_decrypt_cbc (aes_cts_decrypt_ks, first_blocks + 8, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

      w2[0] = hc_swap32_S (decrypted_block[0]);
      w2[1] = hc_swap32_S (decrypted_block[1]);
      w2[2] = hc_swap32_S (decrypted_block[2]);
      w2[3] = hc_swap32_S (decrypted_block[3]);

      aes128_decrypt_cbc (aes_cts_decrypt_ks, first_blocks + 12, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

      w3[0] = hc_swap32_S (decrypted_block[0]);
      w3[1] = hc_swap32_S (decrypted_block[1]);
      w3[2] = hc_swap32_S (decrypted_block[2]);
      w3[3] = hc_swap32_S (decrypted_block[3]);

      sha1_hmac_ctx_t sha1_hmac_ctx;

      /*
        hmac message = plaintext
        hmac key = ki
      */

      u32 k0[4];
      u32 k1[4];
      u32 k2[4];
      u32 k3[4];

      k0[0] = ki[0];
      k0[1] = ki[1];
      k0[2] = ki[2];
      k0[3] = ki[3];

      k1[0] = 0;
      k1[1] = 0;
      k1[2] = 0;
      k1[3] = 0;

      k2[0] = 0;
      k2[1] = 0;
      k2[2] = 0;
      k2[3] = 0;

      k3[0] = 0;
      k3[1] = 0;
      k3[2] = 0;
      k3[3] = 0;

      sha1_hmac_init_64 (&sha1_hmac_ctx, k0, k1, k2, k3);

      sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 64);

      block_position = 16;

      // first 4 blocks are already decrypted
      for (edata2_left = need - 64; edata2_left >= 64; edata2_left -= 64)
      {
        block[0]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  0];
        block[1]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  1];
        block[2]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  2];
        block[3]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  3];
        block[4]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  4];
        block[5]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  5];
        block[6]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  6];
        block[7]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  7];
        block[8]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  8];
        block[9]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  9];
        block[10] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 10];
        block[11] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 11];
        block[12] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 12];
        block[13] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 13];
        block[14] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 14];
        block[15] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 15];

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w0[0] = hc_swap32_S (decrypted_block[0]);
        w0[1] = hc_swap32_S (decrypted_block[1]);
        w0[2] = hc_swap32_S (decrypted_block[2]);
        w0[3] = hc_swap32_S (decrypted_block[3]);

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block + 4, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w1[0] = hc_swap32_S (decrypted_block[0]);
        w1[1] = hc_swap32_S (decrypted_block[1]);
        w1[2] = hc_swap32_S (decrypted_block[2]);
        w1[3] = hc_swap32_S (decrypted_block[3]);

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block + 8, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w2[0] = hc_swap32_S (decrypted_block[0]);
        w2[1] = hc_swap32_S (decrypted_block[1]);
        w2[2] = hc_swap32_S (decrypted_block[2]);
        w2[3] = hc_swap32_S (decrypted_block[3]);

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block + 12, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w3[0] = hc_swap32_S (decrypted_block[0]);
        w3[1] = hc_swap32_S (decrypted_block[1]);
        w3[2] = hc_swap32_S (decrypted_block[2]);
        w3[3] = hc_swap32_S (decrypted_block[3]);

        sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 64);

        block_position += 16;
      }

      if (edata2_left == 16)
      {
        block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 0];
        block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 1];
        block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 2];
        block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 3];

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w0[0] = hc_swap32_S (decrypted_block[0]);
        w0[1] = hc_swap32_S (decrypted_block[1]);
        w0[2] = hc_swap32_S (decrypted_block[2]);
        w0[3] = hc_swap32_S (decrypted_block[3]);

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

        block_position += 4;
      }
      else if (edata2_left == 32)
      {
        block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 0];
        block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 1];
        block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 2];
        block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 3];
        block[4] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 4];
        block[5] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 5];
        block[6] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 6];
        block[7] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 7];

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w0[0] = hc_swap32_S (decrypted_block[0]);
        w0[1] = hc_swap32_S (decrypted_block[1]);
        w0[2] = hc_swap32_S (decrypted_block[2]);
        w0[3] = hc_swap32_S (decrypted_block[3]);

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block + 4, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w1[0] = hc_swap32_S (decrypted_block[0]);
        w1[1] = hc_swap32_S (decrypted_block[1]);
        w1[2] = hc_swap32_S (decrypted_block[2]);
        w1[3] = hc_swap32_S (decrypted_block[3]);

        w2[0] = 0;
        w2[1] = 0;
        w2[2] = 0;
        w2[3] = 0;

        w3[0] = 0;
        w3[1] = 0;
        w3[2] = 0;
        w3[3] = 0;

        sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 32);

        block_position += 8;
      }
      else if (edata2_left == 48)
      {
        block[0]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  0];
        block[1]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  1];
        block[2]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  2];
        block[3]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  3];
        block[4]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  4];
        block[5]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  5];
        block[6]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  6];
        block[7]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  7];
        block[8]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  8];
        block[9]  = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position +  9];
        block[10] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 10];
        block[11] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 11];

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w0[0] = hc_swap32_S (decrypted_block[0]);
        w0[1] = hc_swap32_S (decrypted_block[1]);
        w0[2] = hc_swap32_S (decrypted_block[2]);
        w0[3] = hc_swap32_S (decrypted_block[3]);

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block + 4, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w1[0] = hc_swap32_S (decrypted_block[0]);
        w1[1] = hc_swap32_S (decrypted_block[1]);
        w1[2] = hc_swap32_S (decrypted_block[2]);
        w1[3] = hc_swap32_S (decrypted_block[3]);

        aes128_decrypt_cbc (aes_cts_decrypt_ks, block + 8, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

        w2[0] = hc_swap32_S (decrypted_block[0]);
        w2[1] = hc_swap32_S (decrypted_block[1]);
        w2[2] = hc_swap32_S (decrypted_block[2]);
        w2[3] = hc_swap32_S (decrypted_block[3]);

        w3[0] = 0;
        w3[1] = 0;
        w3[2] = 0;
        w3[3] = 0;

        sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 48);

        block_position += 12;
      }

      /*
        now all the ticket should be decrypted until block n-1 (not included)
        and n
      */

      // this is block n-2, it will be xored with the n-1 block later crafted
      u32 last_block_cbc[4];

      last_block_cbc[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_cbc_position + 0];
      last_block_cbc[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_cbc_position + 1];
      last_block_cbc[2] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_cbc_position + 2];
      last_block_cbc[3] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_cbc_position + 3];

      // n-1 block is decrypted separately from the previous blocks which were cbc decrypted
      block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 0];
      block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 1];
      block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 2];
      block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[block_position + 3];

      aes128_decrypt (aes_cts_decrypt_ks, block, decrypted_block, s_td0, s_td1, s_td2, s_td3, s_td4);

      u32 last_block[4];

      int last_block_position = (edata2_len - last_block_size) / 4;

      u32 n_1_crafted[4];

      u32 last_plaintext[4];

      last_plaintext[0] = 0;
      last_plaintext[1] = 0;
      last_plaintext[2] = 0;
      last_plaintext[3] = 0;

      /*
        n-1 block is first computed as follows:
          - fill n-1 block with the X first bytes of the encrypted last block (n)
            with X == length of last block
          - complete the rest of the block with

        Final block (n) is computed as follows:
          - fill with the X first bytes from n-1 block decrypted and xor them with last block (n)
            with X == length of last block
      */
      int remaining_blocks = last_block_size / 4;

      /*
        last block is not necessarily aligned on 4 bytes so we will have
        to shift values for the CTS crap...
      */
      u32 shift = last_block_size % 4;

      u32 mask;

      switch (remaining_blocks)
      {
        case 0:

          last_block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 0];

          mask = (0xffffffff >> ((4 - last_block_size) * 8));

          last_plaintext[0] = last_block[0] ^ (decrypted_block[0] & mask);
          last_plaintext[0] = hc_swap32_S (last_plaintext[0]);

          n_1_crafted[0] = (last_block[0] & mask) | (decrypted_block[0] & (mask ^ 0xffffffff));
          n_1_crafted[1] = decrypted_block[1];
          n_1_crafted[2] = decrypted_block[2];
          n_1_crafted[3] = decrypted_block[3];
          break;

        case 1:

          last_block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 0];

          if (shift == 0)
          {
            n_1_crafted[0] = last_block[0];
            n_1_crafted[1] = decrypted_block[1];
            n_1_crafted[2] = decrypted_block[2];
            n_1_crafted[3] = decrypted_block[3];

            last_plaintext[0] = last_block[0] ^ decrypted_block[0];
            last_plaintext[0] = hc_swap32_S (last_plaintext[0]);
          }
          else
          {
            last_block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 1];

            mask = (0xffffffff >> ((4 - (last_block_size % 4)) * 8));

            last_plaintext[0] = last_block[0] ^ decrypted_block[0];
            last_plaintext[1] = last_block[1] ^ (decrypted_block[1] & mask);

            last_plaintext[0] = hc_swap32_S (last_plaintext[0]);
            last_plaintext[1] = hc_swap32_S (last_plaintext[1]);

            n_1_crafted[0] = last_block[0];
            n_1_crafted[1] = (last_block[1] & mask) | (decrypted_block[1] & (mask ^ 0xffffffff));
            n_1_crafted[2] = decrypted_block[2];
            n_1_crafted[3] = decrypted_block[3];
          }
          break;

        case 2:

          last_block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 0];
          last_block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 1];

          if (shift == 0)
          {
            n_1_crafted[0] = last_block[0];
            n_1_crafted[1] = last_block[1];
            n_1_crafted[2] = decrypted_block[2];
            n_1_crafted[3] = decrypted_block[3];

            last_plaintext[0] = last_block[0] ^ decrypted_block[0];
            last_plaintext[1] = last_block[1] ^ decrypted_block[1];

            last_plaintext[0] = hc_swap32_S (last_plaintext[0]);
            last_plaintext[1] = hc_swap32_S (last_plaintext[1]);
          }
          else
          {
            last_block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 2];

            mask = (0xffffffff >> ((4 - (last_block_size % 4)) * 8));

            last_plaintext[0] = last_block[0] ^ decrypted_block[0];
            last_plaintext[1] = last_block[1] ^ decrypted_block[1];
            last_plaintext[2] = last_block[2] ^ (decrypted_block[2] & mask);

            last_plaintext[0] = hc_swap32_S (last_plaintext[0]);
            last_plaintext[1] = hc_swap32_S (last_plaintext[1]);
            last_plaintext[2] = hc_swap32_S (last_plaintext[2]);

            n_1_crafted[0] = last_block[0];
            n_1_crafted[1] = last_block[1];
            n_1_crafted[2] = (last_block[2] & mask) | (decrypted_block[2] & (mask ^ 0xffffffff));
            n_1_crafted[3] = decrypted_block[3];
          }
          break;

        case 3:

          last_block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 0];
          last_block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 1];
          last_block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 2];

          if (shift == 0)
          {
            n_1_crafted[0] = last_block[0];
            n_1_crafted[1] = last_block[1];
            n_1_crafted[2] = last_block[2];
            n_1_crafted[3] = decrypted_block[3];

            last_plaintext[0] = last_block[0] ^ decrypted_block[0];
            last_plaintext[1] = last_block[1] ^ decrypted_block[1];
            last_plaintext[2] = last_block[2] ^ decrypted_block[2];

            last_plaintext[0] = hc_swap32_S (last_plaintext[0]);
            last_plaintext[1] = hc_swap32_S (last_plaintext[1]);
            last_plaintext[2] = hc_swap32_S (last_plaintext[2]);
          }
          else
          {
            last_block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 3];

            mask = (0xffffffff >> ((4 - (last_block_size % 4)) * 8));

            last_plaintext[0] = last_block[0] ^ decrypted_block[0];
            last_plaintext[1] = last_block[1] ^ decrypted_block[1];
            last_plaintext[2] = last_block[2] ^ decrypted_block[2];
            last_plaintext[3] = last_block[3] ^ (decrypted_block[3] & mask);

            last_plaintext[0] = hc_swap32_S (last_plaintext[0]);
            last_plaintext[1] = hc_swap32_S (last_plaintext[1]);
            last_plaintext[2] = hc_swap32_S (last_plaintext[2]);
            last_plaintext[3] = hc_swap32_S (last_plaintext[3]);

            n_1_crafted[0] = last_block[0];
            n_1_crafted[1] = last_block[1];
            n_1_crafted[2] = last_block[2];
            n_1_crafted[3] = (last_block[3] & mask) | (decrypted_block[3] & (mask ^ 0xffffffff));
          }
          break;

        case 4:

          last_block[0] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 0];
          last_block[1] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 1];
          last_block[2] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 2];
          last_block[3] = esalt_bufs[DIGESTS_OFFSET_HOST].edata2[last_block_position + 3];

          n_1_crafted[0] = last_block[0];
          n_1_crafted[1] = last_block[1];
          n_1_crafted[2] = last_block[2];
          n_1_crafted[3] = last_block[3];

          last_plaintext[0] = last_block[0] ^ decrypted_block[0];
          last_plaintext[1] = last_block[1] ^ decrypted_block[1];
          last_plaintext[2] = last_block[2] ^ decrypted_block[2];
          last_plaintext[3] = last_block[3] ^ decrypted_block[3];

          last_plaintext[0] = hc_swap32_S (last_plaintext[0]);
          last_plaintext[1] = hc_swap32_S (last_plaintext[1]);
          last_plaintext[2] = hc_swap32_S (last_plaintext[2]);
          last_plaintext[3] = hc_swap32_S (last_plaintext[3]);
          break;

        default:
          return;
      }

      // then decrypt this newly created n-1 with 'ke'
      aes128_decrypt (aes_cts_decrypt_ks, n_1_crafted, n_1_crafted, s_td0, s_td1, s_td2, s_td3, s_td4);

      // then xor with the encrypted n-2 block
      n_1_crafted[0] ^= last_block_cbc[0];
      n_1_crafted[1] ^= last_block_cbc[1];
      n_1_crafted[2] ^= last_block_cbc[2];
      n_1_crafted[3] ^= last_block_cbc[3];

      w0[0] = hc_swap32_S (n_1_crafted[0]);
      w0[1] = hc_swap32_S (n_1_crafted[1]);
      w0[2] = hc_swap32_S (n_1_crafted[2]);
      w0[3] = hc_swap32_S (n_1_crafted[3]);

      w1[0] = last_plaintext[0];
      w1[1] = last_plaintext[1];
      w1[2] = last_plaintext[2];
      w1[3] = last_plaintext[3];

      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;

      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, 16 + last_block_size);

      sha1_hmac_final (&sha1_hmac_ctx);

      if (sha1_hmac_ctx.opad.h[0]   == esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0]
        && sha1_hmac_ctx.opad.h[1] == esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1]
        && sha1_hmac_ctx.opad.h[2] == esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2])
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          #define il_pos 0
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
        }
      }
    }
  }
}
