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
#include M2S(INCLUDE_PATH/inc_ecc_secp256k1.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_zip_inflate.cl)
#endif

typedef struct electrum
{
  secp256k1_t coords;

  u32 data_buf[256];

} electrum_t;

typedef struct electrum_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[8];
  u64  out[8];

} electrum_tmp_t;

#define MIN_ENTROPY 3.0
#define MAX_ENTROPY 6.0

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

KERNEL_FQ void m21800_init (KERN_ATTR_TMPS_ESALT (electrum_tmp_t, electrum_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_hmac_ctx_t sha512_hmac_ctx;

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

KERNEL_FQ void m21800_loop (KERN_ATTR_TMPS_ESALT (electrum_tmp_t, electrum_t))
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

KERNEL_FQ void m21800_comp (KERN_ATTR_TMPS_ESALT (electrum_tmp_t, electrum_t))
{
  const u64 gid = get_global_id  (0);
  const u64 lid = get_local_id   (0);
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
   * Start by copying/aligning the data
   */

  u64 out[8];

  out[0] = tmps[gid].out[0];
  out[1] = tmps[gid].out[1];
  out[2] = tmps[gid].out[2];
  out[3] = tmps[gid].out[3];
  out[4] = tmps[gid].out[4];
  out[5] = tmps[gid].out[5];
  out[6] = tmps[gid].out[6];
  out[7] = tmps[gid].out[7];

  /*
   * First calculate the modulo of the pbkdf2 hash with SECP256K1_N:
   */

  u32 a[16];

  a[ 0] = h32_from_64_S (out[0]);
  a[ 1] = l32_from_64_S (out[0]);
  a[ 2] = h32_from_64_S (out[1]);
  a[ 3] = l32_from_64_S (out[1]);
  a[ 4] = h32_from_64_S (out[2]);
  a[ 5] = l32_from_64_S (out[2]);
  a[ 6] = h32_from_64_S (out[3]);
  a[ 7] = l32_from_64_S (out[3]);
  a[ 8] = h32_from_64_S (out[4]);
  a[ 9] = l32_from_64_S (out[4]);
  a[10] = h32_from_64_S (out[5]);
  a[11] = l32_from_64_S (out[5]);
  a[12] = h32_from_64_S (out[6]);
  a[13] = l32_from_64_S (out[6]);
  a[14] = h32_from_64_S (out[7]);
  a[15] = l32_from_64_S (out[7]);

  mod_512 (a);

  // copy the last 256 bit (32 bytes) of modulo (a):

  u32 tweak[8];

  tweak[0] = a[15];
  tweak[1] = a[14];
  tweak[2] = a[13];
  tweak[3] = a[12];
  tweak[4] = a[11];
  tweak[5] = a[10];
  tweak[6] = a[ 9];
  tweak[7] = a[ 8];


  /*
   * the main secp256k1 point multiplication by a scalar/tweak:
   */

  GLOBAL_AS secp256k1_t *coords = (GLOBAL_AS secp256k1_t *) &esalt_bufs[DIGESTS_OFFSET_HOST].coords;

  u32 pubkey[64] = { 0 }; // for point_mul () we need: 1 + 32 bytes (for sha512 () we need more)

  point_mul (pubkey, tweak, coords);


  /*
   * sha512 () of the pubkey:
   */

  sha512_ctx_t sha512_ctx;

  sha512_init   (&sha512_ctx);
  sha512_update (&sha512_ctx, pubkey, 33); // 33 because of 32 byte curve point + sign
  sha512_final  (&sha512_ctx);

  // ... now we have the result in sha512_ctx.h[0]...sha512_ctx.h[7]

  u32 iv[4];

  iv[0] = h32_from_64_S (sha512_ctx.h[0]);
  iv[1] = l32_from_64_S (sha512_ctx.h[0]);
  iv[2] = h32_from_64_S (sha512_ctx.h[1]);
  iv[3] = l32_from_64_S (sha512_ctx.h[1]);

  iv[0] = hc_swap32_S (iv[0]);
  iv[1] = hc_swap32_S (iv[1]);
  iv[2] = hc_swap32_S (iv[2]);
  iv[3] = hc_swap32_S (iv[3]);

  u32 key[4];

  key[0] = h32_from_64_S (sha512_ctx.h[2]);
  key[1] = l32_from_64_S (sha512_ctx.h[2]);
  key[2] = h32_from_64_S (sha512_ctx.h[3]);
  key[3] = l32_from_64_S (sha512_ctx.h[3]);

  key[0] = hc_swap32_S (key[0]);
  key[1] = hc_swap32_S (key[1]);
  key[2] = hc_swap32_S (key[2]);
  key[3] = hc_swap32_S (key[3]);


  /*
   * AES decrypt the data_buf
   */

  // init AES

  #define KEYLEN 44

  u32 ks[KEYLEN];

  aes128_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  // #define AES_LEN 1024
  // in my tests it also worked with only 128 input bytes !
  #define AES_LEN       1024
  #define AES_LEN_DIV_4  256

  u32 buf_full[AES_LEN_DIV_4];

  // we need to run it at least once:

  GLOBAL_AS u32 *data_buf = (GLOBAL_AS u32 *) esalt_bufs[DIGESTS_OFFSET_HOST].data_buf;

  u32 data[4];

  data[0] = data_buf[0];
  data[1] = data_buf[1];
  data[2] = data_buf[2];
  data[3] = data_buf[3];

  u32 buf[4];

  aes128_decrypt (ks, data, buf, s_td0, s_td1, s_td2, s_td3, s_td4);

  buf[0] ^= iv[0];

  // early reject

  // changed: 17.11.2021
  // I had not cracked some sample Salt Type 5 wallets with known passwords provided by the owner.
  // It was necessary to remove this early rejection and add a new signature
  // The decrypted data was this: {"seed_version": ...
  //if ((buf[0] & 0x0006ffff) != 0x00049c78) return; // allow 0b100 or 0b101 at the end of 3rd byte

  buf[1] ^= iv[1];
  buf[2] ^= iv[2];
  buf[3] ^= iv[3];

  buf_full[0] = buf[0];
  buf_full[1] = buf[1];
  buf_full[2] = buf[2];
  buf_full[3] = buf[3];

  iv[0] = data[0];
  iv[1] = data[1];
  iv[2] = data[2];
  iv[3] = data[3];

  // for AES_LEN > 16 we need to loop

  for (int i = 16, j = 4; i < AES_LEN; i += 16, j += 4)
  {
    data[0] = data_buf[j + 0];
    data[1] = data_buf[j + 1];
    data[2] = data_buf[j + 2];
    data[3] = data_buf[j + 3];

    aes128_decrypt (ks, data, buf, s_td0, s_td1, s_td2, s_td3, s_td4);

    buf[0] ^= iv[0];
    buf[1] ^= iv[1];
    buf[2] ^= iv[2];
    buf[3] ^= iv[3];

    iv[0] = data[0];
    iv[1] = data[1];
    iv[2] = data[2];
    iv[3] = data[3];

    buf_full[j + 0] = buf[0];
    buf_full[j + 1] = buf[1];
    buf_full[j + 2] = buf[2];
    buf_full[j + 3] = buf[3];
  }

  /*
   * zlib inflate/decompress:
   */

  mz_stream infstream;

  infstream.opaque    = Z_NULL;

  // input:

  infstream.avail_in  = AES_LEN;
  infstream.next_in   = (u8 *) buf_full;

  // output:

  #define OUT_SIZE 1024

  u8 tmp[OUT_SIZE];

  infstream.avail_out = OUT_SIZE;
  infstream.next_out  = tmp;


  // decompress it:

  inflate_state pStream;

  mz_inflateInit2 (&infstream, MAX_WBITS, &pStream);

  const int zlib_ret = inflate (&infstream, Z_NO_FLUSH);

  if ((zlib_ret != MZ_OK) && (zlib_ret != MZ_STREAM_END))
  {
    return;
  }

  for (int i = 1; i < infstream.total_out; i++)
  {
    if (tmp[i] == '\t') continue;
    if (tmp[i] == '\r') continue;
    if (tmp[i] == '\n') continue;

    if (tmp[i] < 0x20)
    {
      // https://datatracker.ietf.org/doc/html/rfc7159
      // 7.  Strings
      // All Unicode characters may be placed within the
      // quotation marks, except for the characters that must be escaped:
      // quotation mark, reverse solidus, and the control characters (U+0000
      // through U+001F).

      if (tmp[i - 1] != '\\') return;
    }
  }

  /*
   * Check with some strange signature.
   * The main problem is that the (invalid) decrypted data processed by zlib often results in random patterns but with low entropy,
   * so that a simple entropy check is not sufficient
   */

  if (tmp[0] == '{')
  {
    int qcnt1 = 0;
    int ccnt1 = 0;

    for (int i = 1; i < 16; i++)
    {
      if (tmp[i] == '"') qcnt1++;
      if (tmp[i] == ':') ccnt1++;
    }

    int qcnt2 = 0;
    int ccnt2 = 0;

    for (int i = 1; i < infstream.total_out; i++)
    {
      if (tmp[i] == '"') qcnt2++;
      if (tmp[i] == ':') ccnt2++;
    }

    if ((qcnt1 >= 1) && (ccnt1 >= 1) && (qcnt2 >= 4) && (ccnt2 >= 3))
    {
      const float entropy = hc_get_entropy ((const u32 *) tmp, infstream.total_out / 4);

      if ((entropy >= MIN_ENTROPY) && (entropy <= MAX_ENTROPY))
      {
        if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
        }

        return;
      }
    }
  }

  /*
   * Verify if decompressed data is either:
   * - "{\n    \"" or
   * - "{\r\n    \""
   */

  if (((tmp[0] == 0x7b) && (tmp[1] == 0x0a) && (tmp[2] == 0x20) && (tmp[3] == 0x20) &&
       (tmp[4] == 0x20) && (tmp[5] == 0x20) && (tmp[6] == 0x22)) ||
      ((tmp[0] == 0x7b) && (tmp[1] == 0x0d) && (tmp[2] == 0x0a) && (tmp[3] == 0x20) &&
       (tmp[4] == 0x20) && (tmp[5] == 0x20) && (tmp[6] == 0x20) && (tmp[7] == 0x22)))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}
