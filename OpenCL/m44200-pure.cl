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
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct sollet
{
  u32 nonce[6];
  u32 ct[4];

} sollet_t;

#define SALSA20_C0 0x61707865
#define SALSA20_C1 0x3320646e
#define SALSA20_C2 0x79622d32
#define SALSA20_C3 0x6b206574

#define SALSA20_QR(a,b,c,d)          \
{                                    \
  b ^= hc_rotl32_S ((a) + (d),  7);  \
  c ^= hc_rotl32_S ((b) + (a),  9);  \
  d ^= hc_rotl32_S ((c) + (b), 13);  \
  a ^= hc_rotl32_S ((d) + (c), 18);  \
}

DECLSPEC void salsa20_20 (PRIVATE_AS u32 *x)
{
  for (int i = 0; i < 10; i++)
  {
    SALSA20_QR (x[ 0], x[ 4], x[ 8], x[12]);
    SALSA20_QR (x[ 5], x[ 9], x[13], x[ 1]);
    SALSA20_QR (x[10], x[14], x[ 2], x[ 6]);
    SALSA20_QR (x[15], x[ 3], x[ 7], x[11]);

    SALSA20_QR (x[ 0], x[ 1], x[ 2], x[ 3]);
    SALSA20_QR (x[ 5], x[ 6], x[ 7], x[ 4]);
    SALSA20_QR (x[10], x[11], x[ 8], x[ 9]);
    SALSA20_QR (x[15], x[12], x[13], x[14]);
  }
}

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

KERNEL_FQ KERNEL_FA void m44200_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, sollet_t))
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

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
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

KERNEL_FQ KERNEL_FA void m44200_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, sollet_t))
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

  for (u32 i = 0; i < 8; i += 8)
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

KERNEL_FQ KERNEL_FA void m44200_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, sollet_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const sollet_t *sollet = &esalt_bufs[digest_cur];

  // the PBKDF2 output is the secretbox key, which XSalsa20 reads in little endian words

  u32 k[8];

  k[0] = hc_swap32_S (tmps[gid].out[0]);
  k[1] = hc_swap32_S (tmps[gid].out[1]);
  k[2] = hc_swap32_S (tmps[gid].out[2]);
  k[3] = hc_swap32_S (tmps[gid].out[3]);
  k[4] = hc_swap32_S (tmps[gid].out[4]);
  k[5] = hc_swap32_S (tmps[gid].out[5]);
  k[6] = hc_swap32_S (tmps[gid].out[6]);
  k[7] = hc_swap32_S (tmps[gid].out[7]);

  // HSalsa20 of the key and the first 16 bytes of the nonce gives the subkey

  u32 x[16];

  x[ 0] = SALSA20_C0;
  x[ 1] = k[0];
  x[ 2] = k[1];
  x[ 3] = k[2];
  x[ 4] = k[3];
  x[ 5] = SALSA20_C1;
  x[ 6] = sollet->nonce[0];
  x[ 7] = sollet->nonce[1];
  x[ 8] = sollet->nonce[2];
  x[ 9] = sollet->nonce[3];
  x[10] = SALSA20_C2;
  x[11] = k[4];
  x[12] = k[5];
  x[13] = k[6];
  x[14] = k[7];
  x[15] = SALSA20_C3;

  salsa20_20 (x);

  // Salsa20 block 0 under the subkey and the last 8 bytes of the nonce. Its first 32 bytes are the
  // Poly1305 key, and the next 16 encrypt the start of the message.

  u32 y[16];

  y[ 0] = SALSA20_C0;
  y[ 1] = x[ 0];
  y[ 2] = x[ 5];
  y[ 3] = x[10];
  y[ 4] = x[15];
  y[ 5] = SALSA20_C1;
  y[ 6] = sollet->nonce[4];
  y[ 7] = sollet->nonce[5];
  y[ 8] = 0;
  y[ 9] = 0;
  y[10] = SALSA20_C2;
  y[11] = x[ 6];
  y[12] = x[ 7];
  y[13] = x[ 8];
  y[14] = x[ 9];
  y[15] = SALSA20_C3;

  u32 z[16];

  for (int i = 0; i < 16; i++) z[i] = y[i];

  salsa20_20 (z);

  u32 pt[4];

  pt[0] = sollet->ct[0] ^ (z[ 8] + y[ 8]);
  pt[1] = sollet->ct[1] ^ (z[ 9] + y[ 9]);
  pt[2] = sollet->ct[2] ^ (z[10] + y[10]);
  pt[3] = sollet->ct[3] ^ (z[11] + y[11]);

  // {"mnemonic":" and the first 3 letters of a BIP39 word

  if (pt[0] != 0x6e6d227b) return;
  if (pt[1] != 0x6e6f6d65) return;
  if (pt[2] != 0x3a226369) return;

  if (((pt[3] >>  0) & 0xff) != 0x22) return;

  const u32 c1 = (pt[3] >>  8) & 0xff;
  const u32 c2 = (pt[3] >> 16) & 0xff;
  const u32 c3 = (pt[3] >> 24) & 0xff;

  if ((c1 < 0x61) || (c1 > 0x7a)) return;
  if ((c2 < 0x61) || (c2 > 0x7a)) return;
  if ((c3 < 0x61) || (c3 > 0x7a)) return;

  // the ciphertext block stands in for a digest, as in hash-modes 26610 and 37230

  const u32 r0 = sollet->ct[0];
  const u32 r1 = sollet->ct[1];
  const u32 r2 = sollet->ct[2];
  const u32 r3 = sollet->ct[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
