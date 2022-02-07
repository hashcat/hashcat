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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct telegram_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[24];
  u64 out [24];

} telegram_tmp_t;

typedef struct telegram
{
  u32 data[72];

} telegram_t;

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

DECLSPEC void sha1_run (PRIVATE_AS u32 *w, PRIVATE_AS u32 *res)
{
  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = w[ 0];
  w0[1] = w[ 1];
  w0[2] = w[ 2];
  w0[3] = w[ 3];
  w1[0] = w[ 4];
  w1[1] = w[ 5];
  w1[2] = w[ 6];
  w1[3] = w[ 7];
  w2[0] = w[ 8];
  w2[1] = w[ 9];
  w2[2] = w[10];
  w2[3] = w[11];
  w3[0] = 0x80000000;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 48 * 8;

  u32 digest[5];

  digest[0] = SHA1M_A;
  digest[1] = SHA1M_B;
  digest[2] = SHA1M_C;
  digest[3] = SHA1M_D;
  digest[4] = SHA1M_E;

  sha1_transform (w0, w1, w2, w3, digest);

  res[0] = digest[0];
  res[1] = digest[1];
  res[2] = digest[2];
  res[3] = digest[3];
  res[4] = digest[4];
}

KERNEL_FQ void m24500_init (KERN_ATTR_TMPS_ESALT (telegram_tmp_t, telegram_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 salt_len = salt_bufs[SALT_POS_HOST].salt_len; // 32

  sha512_ctx_t sha512_ctx;

  sha512_init (&sha512_ctx);

  sha512_update_global      (&sha512_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_len);
  sha512_update_global_swap (&sha512_ctx, pws[gid].i, pws[gid].pw_len);
  sha512_update_global      (&sha512_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_len);

  sha512_final (&sha512_ctx);

  u32 w[32] = { 0 };

  w[ 0] = h32_from_64_S (sha512_ctx.h[0]);
  w[ 1] = l32_from_64_S (sha512_ctx.h[0]);
  w[ 2] = h32_from_64_S (sha512_ctx.h[1]);
  w[ 3] = l32_from_64_S (sha512_ctx.h[1]);
  w[ 4] = h32_from_64_S (sha512_ctx.h[2]);
  w[ 5] = l32_from_64_S (sha512_ctx.h[2]);
  w[ 6] = h32_from_64_S (sha512_ctx.h[3]);
  w[ 7] = l32_from_64_S (sha512_ctx.h[3]);
  w[ 8] = h32_from_64_S (sha512_ctx.h[4]);
  w[ 9] = l32_from_64_S (sha512_ctx.h[4]);
  w[10] = h32_from_64_S (sha512_ctx.h[5]);
  w[11] = l32_from_64_S (sha512_ctx.h[5]);
  w[12] = h32_from_64_S (sha512_ctx.h[6]);
  w[13] = l32_from_64_S (sha512_ctx.h[6]);
  w[14] = h32_from_64_S (sha512_ctx.h[7]);
  w[15] = l32_from_64_S (sha512_ctx.h[7]);

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init (&sha512_hmac_ctx, w, 64);

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

  sha512_hmac_update_global (&sha512_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  for (u32 i = 0, j = 1; i < 24; i += 8, j += 1)
  {
    sha512_hmac_ctx_t sha512_hmac_ctx2 = sha512_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];
    u32 w4[4];
    u32 w5[4];
    u32 w6[4];
    u32 w7[4];

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

    sha512_hmac_update_128 (&sha512_hmac_ctx2, w0, w1, w2, w3, w4, w5, w6, w7, 4);

    sha512_hmac_final (&sha512_hmac_ctx2);

    tmps[gid].dgst[i + 0] = sha512_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha512_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha512_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha512_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha512_hmac_ctx2.opad.h[4];
    tmps[gid].dgst[i + 5] = sha512_hmac_ctx2.opad.h[5];
    tmps[gid].dgst[i + 6] = sha512_hmac_ctx2.opad.h[6];
    tmps[gid].dgst[i + 7] = sha512_hmac_ctx2.opad.h[7];

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

KERNEL_FQ void m24500_loop (KERN_ATTR_TMPS_ESALT (telegram_tmp_t, telegram_t))
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

  for (u32 i = 0; i < 24; i += 8)
  {
    u64x dgst[8];
    u64x out[8];

    dgst[0] = pack64v (tmps, dgst, gid, i + 0);
    dgst[1] = pack64v (tmps, dgst, gid, i + 1);
    dgst[2] = pack64v (tmps, dgst, gid, i + 2);
    dgst[3] = pack64v (tmps, dgst, gid, i + 3);
    dgst[4] = pack64v (tmps, dgst, gid, i + 4);
    dgst[5] = pack64v (tmps, dgst, gid, i + 5);
    dgst[6] = pack64v (tmps, dgst, gid, i + 6);
    dgst[7] = pack64v (tmps, dgst, gid, i + 7);

    out[0] = pack64v (tmps, out, gid, i + 0);
    out[1] = pack64v (tmps, out, gid, i + 1);
    out[2] = pack64v (tmps, out, gid, i + 2);
    out[3] = pack64v (tmps, out, gid, i + 3);
    out[4] = pack64v (tmps, out, gid, i + 4);
    out[5] = pack64v (tmps, out, gid, i + 5);
    out[6] = pack64v (tmps, out, gid, i + 6);
    out[7] = pack64v (tmps, out, gid, i + 7);

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

    unpack64v (tmps, dgst, gid, i + 0, dgst[0]);
    unpack64v (tmps, dgst, gid, i + 1, dgst[1]);
    unpack64v (tmps, dgst, gid, i + 2, dgst[2]);
    unpack64v (tmps, dgst, gid, i + 3, dgst[3]);
    unpack64v (tmps, dgst, gid, i + 4, dgst[4]);
    unpack64v (tmps, dgst, gid, i + 5, dgst[5]);
    unpack64v (tmps, dgst, gid, i + 6, dgst[6]);
    unpack64v (tmps, dgst, gid, i + 7, dgst[7]);

    unpack64v (tmps, out, gid, i + 0, out[0]);
    unpack64v (tmps, out, gid, i + 1, out[1]);
    unpack64v (tmps, out, gid, i + 2, out[2]);
    unpack64v (tmps, out, gid, i + 3, out[3]);
    unpack64v (tmps, out, gid, i + 4, out[4]);
    unpack64v (tmps, out, gid, i + 5, out[5]);
    unpack64v (tmps, out, gid, i + 6, out[6]);
    unpack64v (tmps, out, gid, i + 7, out[7]);
  }
}

KERNEL_FQ void m24500_comp (KERN_ATTR_TMPS_ESALT (telegram_tmp_t, telegram_t))
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

  u32 data_key[4];

  data_key[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[0];
  data_key[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[1];
  data_key[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[2];
  data_key[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[3];

  u32 data_a[12];
  u32 data_b[12];
  u32 data_c[12];
  u32 data_d[12];

  data_a[ 0] = data_key[0];
  data_a[ 1] = data_key[1];
  data_a[ 2] = data_key[2];
  data_a[ 3] = data_key[3];

  data_b[ 4] = data_key[0];
  data_b[ 5] = data_key[1];
  data_b[ 6] = data_key[2];
  data_b[ 7] = data_key[3];

  data_c[ 8] = data_key[0];
  data_c[ 9] = data_key[1];
  data_c[10] = data_key[2];
  data_c[11] = data_key[3];

  data_d[ 0] = data_key[0];
  data_d[ 1] = data_key[1];
  data_d[ 2] = data_key[2];
  data_d[ 3] = data_key[3];

  data_a[ 4] = h32_from_64_S (tmps[gid].out[ 1]); // not a bug: out[0] is ignored
  data_a[ 5] = l32_from_64_S (tmps[gid].out[ 1]);
  data_a[ 6] = h32_from_64_S (tmps[gid].out[ 2]);
  data_a[ 7] = l32_from_64_S (tmps[gid].out[ 2]);
  data_a[ 8] = h32_from_64_S (tmps[gid].out[ 3]);
  data_a[ 9] = l32_from_64_S (tmps[gid].out[ 3]);
  data_a[10] = h32_from_64_S (tmps[gid].out[ 4]);
  data_a[11] = l32_from_64_S (tmps[gid].out[ 4]);

  data_b[ 0] = h32_from_64_S (tmps[gid].out[ 5]);
  data_b[ 1] = l32_from_64_S (tmps[gid].out[ 5]);
  data_b[ 2] = h32_from_64_S (tmps[gid].out[ 6]);
  data_b[ 3] = l32_from_64_S (tmps[gid].out[ 6]);

  data_b[ 8] = h32_from_64_S (tmps[gid].out[ 7]);
  data_b[ 9] = l32_from_64_S (tmps[gid].out[ 7]);
  data_b[10] = h32_from_64_S (tmps[gid].out[ 8]);
  data_b[11] = l32_from_64_S (tmps[gid].out[ 8]);

  data_c[ 0] = h32_from_64_S (tmps[gid].out[ 9]);
  data_c[ 1] = l32_from_64_S (tmps[gid].out[ 9]);
  data_c[ 2] = h32_from_64_S (tmps[gid].out[10]);
  data_c[ 3] = l32_from_64_S (tmps[gid].out[10]);
  data_c[ 4] = h32_from_64_S (tmps[gid].out[11]);
  data_c[ 5] = l32_from_64_S (tmps[gid].out[11]);
  data_c[ 6] = h32_from_64_S (tmps[gid].out[12]);
  data_c[ 7] = l32_from_64_S (tmps[gid].out[12]);

  data_d[ 4] = h32_from_64_S (tmps[gid].out[13]);
  data_d[ 5] = l32_from_64_S (tmps[gid].out[13]);
  data_d[ 6] = h32_from_64_S (tmps[gid].out[14]);
  data_d[ 7] = l32_from_64_S (tmps[gid].out[14]);
  data_d[ 8] = h32_from_64_S (tmps[gid].out[15]);
  data_d[ 9] = l32_from_64_S (tmps[gid].out[15]);
  data_d[10] = h32_from_64_S (tmps[gid].out[16]);
  data_d[11] = l32_from_64_S (tmps[gid].out[16]);

  // hash (SHA1 ()) the data_*:

  u32 a[5];

  sha1_run (data_a, a);

  u32 b[5];

  sha1_run (data_b, b);

  u32 c[5];

  sha1_run (data_c, c);

  u32 d[5];

  sha1_run (data_d, d);

  // set up AES key and AES IV:

  u32 key[8];

  key[0] = a[0];
  key[1] = a[1];
  key[2] = b[2];
  key[3] = b[3];
  key[4] = b[4];
  key[5] = c[1];
  key[6] = c[2];
  key[7] = c[3];

  u32 iv[8];

  iv[0] = a[2];
  iv[1] = a[3];
  iv[2] = a[4];
  iv[3] = b[0];
  iv[4] = b[1];
  iv[5] = c[4];
  iv[6] = d[0];
  iv[7] = d[1];

  // decrypt with AES-IGE:

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 x_prev[4];

  x_prev[0] = iv[0];
  x_prev[1] = iv[1];
  x_prev[2] = iv[2];
  x_prev[3] = iv[3];

  u32 y_prev[4];

  y_prev[0] = iv[4];
  y_prev[1] = iv[5];
  y_prev[2] = iv[6];
  y_prev[3] = iv[7];

  u32 out[80] = { 0 }; // 64-byte aligned for SHA1

  for (int i = 0; i < 68; i += 4)
  {
    u32 x[4];

    x[0] = esalt_bufs[DIGESTS_OFFSET_HOST].data[4 + i];
    x[1] = esalt_bufs[DIGESTS_OFFSET_HOST].data[5 + i];
    x[2] = esalt_bufs[DIGESTS_OFFSET_HOST].data[6 + i];
    x[3] = esalt_bufs[DIGESTS_OFFSET_HOST].data[7 + i];

    u32 y[4];

    y[0] = x[0] ^ y_prev[0];
    y[1] = x[1] ^ y_prev[1];
    y[2] = x[2] ^ y_prev[2];
    y[3] = x[3] ^ y_prev[3];

    u32 dec[4];

    AES256_decrypt (ks, y, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    y_prev[0] = dec[0] ^ x_prev[0];
    y_prev[1] = dec[1] ^ x_prev[1];
    y_prev[2] = dec[2] ^ x_prev[2];
    y_prev[3] = dec[3] ^ x_prev[3];

    out[i + 0] = y_prev[0];
    out[i + 1] = y_prev[1];
    out[i + 2] = y_prev[2];
    out[i + 3] = y_prev[3];

    x_prev[0] = x[0];
    x_prev[1] = x[1];
    x_prev[2] = x[2];
    x_prev[3] = x[3];
  }

  // final SHA1 checksum of the decrypted data (out):

  sha1_ctx_t ctx;

  sha1_init   (&ctx);
  sha1_update (&ctx, out, 272);
  sha1_final  (&ctx);

  const u32 r0 = ctx.h[0];
  const u32 r1 = ctx.h[1];
  const u32 r2 = ctx.h[2];
  const u32 r3 = ctx.h[3];

  // verify:

  if (r0 == data_key[0] &&
      r1 == data_key[1] &&
      r2 == data_key[2] &&
      r3 == data_key[3])
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
