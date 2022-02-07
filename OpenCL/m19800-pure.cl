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

typedef struct krb5pa_17
{
  u32 user[128];
  u32 domain[128];
  u32 account_info[512];
  u32 account_info_len;

  u32 checksum[3];
  u32 enc_timestamp[32];
  u32 enc_timestamp_len;

} krb5pa_17_t;

typedef struct krb5pa_17_tmp
{
  u32 ipad[5];
  u32 opad[5];
  u32 dgst[10];
  u32 out[10];

} krb5pa_17_tmp_t;

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

KERNEL_FQ void m19800_init (KERN_ATTR_TMPS_ESALT (krb5pa_17_tmp_t, krb5pa_17_t))
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

KERNEL_FQ void m19800_loop (KERN_ATTR_TMPS_ESALT (krb5pa_17_tmp_t, krb5pa_17_t))
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

KERNEL_FQ void m19800_comp (KERN_ATTR_TMPS_ESALT (krb5pa_17_tmp_t, krb5pa_17_t))
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

  u32 out[4];

  aes128_encrypt_cbc (aes_ks, aes_iv, nfolded, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 key_bytes[4];

  key_bytes[0] = hc_swap32_S (out[0]);
  key_bytes[1] = hc_swap32_S (out[1]);
  key_bytes[2] = hc_swap32_S (out[2]);
  key_bytes[3] = hc_swap32_S (out[3]);

  // then aes_cbc encrypt this nfolded value with 'key_bytes' as key along with a null IV
  aes128_set_encrypt_key (aes_ks, key_bytes, s_te0, s_te1, s_te2, s_te3);

  /* we will now compute 'ke' */

  u32 ke[4];

  // we can precompute _nfold(pack('>IB', 1, 0xAA), 16)
  nfolded[0] = 0xae2c160b;
  nfolded[1] = 0x04ad5006;
  nfolded[2] = 0xab55aad5;
  nfolded[3] = 0x6a80355a;

  aes_iv[0] = 0;
  aes_iv[1] = 0;
  aes_iv[2] = 0;
  aes_iv[3] = 0;

  // then aes_cbc encrypt this nfolded value with 'key_bytes' as key along with a null IV
  aes128_encrypt_cbc (aes_ks, aes_iv, nfolded, out, s_te0, s_te1, s_te2, s_te3, s_te4);

  ke[0] = out[0];
  ke[1] = out[1];
  ke[2] = out[2];
  ke[3] = out[3];

  // Decode the CTS mode encryption by decrypting c_n-1 and swapping it with c_n
  u32 enc_blocks[12];

  u32 decrypted_block[4];

  // c_0
  enc_blocks[0] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[0];
  enc_blocks[1] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[1];
  enc_blocks[2] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[2];
  enc_blocks[3] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[3];

  // c_1 aka c_n-1 since there are guaranteed to be exactly 3 blocks
  enc_blocks[4] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[4];
  enc_blocks[5] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[5];
  enc_blocks[6] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[6];
  enc_blocks[7] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[7];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 aes_cts_decrypt_ks[44];

  AES128_set_decrypt_key (aes_cts_decrypt_ks, ke, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  // Our first decryption is the last block (currently in c_n-1) using the first portion of (c_n) as our IV, this allows us to get plaintext in one crypto operation
  aes_iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[ 8];
  aes_iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[ 9];
  aes_iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[10];
  aes_iv[3] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[11];

  aes128_decrypt_cbc (aes_cts_decrypt_ks, enc_blocks + 4, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

  w0[0] = hc_swap32_S (decrypted_block[0]);
  w0[1] = hc_swap32_S (decrypted_block[1]);
  w0[2] = hc_swap32_S (decrypted_block[2]);
  w0[3] = hc_swap32_S (decrypted_block[3]);

  // Move as much code as possible after this branch to avoid unnecessary computation on misses
  if (((w0[0] & 0xf0f0f0f0) == 0x30303030) && ((w0[1] & 0xffff0000) == 0x5aa10000))
  {
    // Decrypt c_n-1 without an IV for the padding blocks on c_n
    aes128_decrypt (aes_cts_decrypt_ks, enc_blocks + 4, decrypted_block, s_td0, s_td1, s_td2, s_td3, s_td4);

    w0[0] = decrypted_block[0];
    w0[1] = decrypted_block[1];
    w0[2] = decrypted_block[2];
    w0[3] = decrypted_block[3];

    int enc_timestamp_len = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp_len;
    int last_word_position = enc_timestamp_len / 4;

    // New c_1,  join c_n with result of the decrypted c_n-1
    int last_block_iter;

    for (last_block_iter = 4; last_block_iter < 8; last_block_iter++)
    {
      if (last_word_position > last_block_iter + 4)
      {
        enc_blocks[last_block_iter] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[last_block_iter + 4];
      }
      else if (last_word_position == last_block_iter + 4)
      {
        // Handle case when the split lands in the middle of a WORD
        switch (enc_timestamp_len % 4)
        {
          case 1:
            enc_blocks[last_block_iter] = (esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[last_block_iter + 4] & 0x000000ff) | (w0[last_block_iter - 4] & 0xffffff00);
            break;
          case 2:
            enc_blocks[last_block_iter] = (esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[last_block_iter + 4] & 0x0000ffff) | (w0[last_block_iter - 4] & 0xffff0000);
            break;
          case 3:
            enc_blocks[last_block_iter] = (esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[last_block_iter + 4] & 0x00ffffff) | (w0[last_block_iter - 4] & 0xff000000);
            break;
          default:
            enc_blocks[last_block_iter] = w0[last_block_iter - 4];
        }
      }
      else
      {
        enc_blocks[last_block_iter] = w0[last_block_iter - 4];
      }
    }

    // c_2 aka c_n which is now equal to the old c_n-1
    enc_blocks[8] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[4];
    enc_blocks[9] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[5];
    enc_blocks[10] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[6];
    enc_blocks[11] = esalt_bufs[DIGESTS_OFFSET_HOST].enc_timestamp[7];
    // Go ahead and decrypt all blocks now as a normal AES CBC operation
    aes_iv[0] = 0;
    aes_iv[1] = 0;
    aes_iv[2] = 0;
    aes_iv[3] = 0;

    aes128_decrypt_cbc (aes_cts_decrypt_ks, enc_blocks, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

    w0[0] = hc_swap32_S (decrypted_block[0]);
    w0[1] = hc_swap32_S (decrypted_block[1]);
    w0[2] = hc_swap32_S (decrypted_block[2]);
    w0[3] = hc_swap32_S (decrypted_block[3]);

    aes128_decrypt_cbc (aes_cts_decrypt_ks, enc_blocks + 4, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

    w1[0] = hc_swap32_S (decrypted_block[0]);
    w1[1] = hc_swap32_S (decrypted_block[1]);
    w1[2] = hc_swap32_S (decrypted_block[2]);
    w1[3] = hc_swap32_S (decrypted_block[3]);

    aes128_decrypt_cbc (aes_cts_decrypt_ks, enc_blocks + 8, decrypted_block, aes_iv, s_td0, s_td1, s_td2, s_td3, s_td4);

    w2[0] = hc_swap32_S (decrypted_block[0]);
    w2[1] = hc_swap32_S (decrypted_block[1]);
    w2[2] = hc_swap32_S (decrypted_block[2]);
    w2[3] = hc_swap32_S (decrypted_block[3]);

    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    /* we will now compute 'ki', having 'key_bytes' */

    u32 ki[8];

    // we can precompute _nfold(pack('>IB', 1, 0x55), 16)
    nfolded[0] = 0x5b582c16;
    nfolded[1] = 0x0a5aa805;
    nfolded[2] = 0x56ab55aa;
    nfolded[3] = 0xd5402ab5;

    aes_iv[0] = 0;
    aes_iv[1] = 0;
    aes_iv[2] = 0;
    aes_iv[3] = 0;

    // then aes_cbc encrypt this nfolded value with 'key_bytes' as key along with a null IV
    aes128_set_encrypt_key (aes_ks, key_bytes, s_te0, s_te1, s_te2, s_te3);

    aes128_encrypt_cbc (aes_ks, aes_iv, nfolded, out, s_te0, s_te1, s_te2, s_te3, s_te4);

    ki[0] = out[0];
    ki[1] = out[1];
    ki[2] = out[2];
    ki[3] = out[3];

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

    sha1_hmac_update_64 (&sha1_hmac_ctx, w0, w1, w2, w3, enc_timestamp_len);

    sha1_hmac_final (&sha1_hmac_ctx);

    // Compare checksum
    if ((sha1_hmac_ctx.opad.h[0] == esalt_bufs[DIGESTS_OFFSET_HOST].checksum[0])
     && (sha1_hmac_ctx.opad.h[1] == esalt_bufs[DIGESTS_OFFSET_HOST].checksum[1])
     && (sha1_hmac_ctx.opad.h[2] == esalt_bufs[DIGESTS_OFFSET_HOST].checksum[2]))
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        #define il_pos 0

        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, il_pos, 0, 0);
      }
    }
  }
}
