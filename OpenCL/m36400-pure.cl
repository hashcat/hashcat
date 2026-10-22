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
#include M2S(INCLUDE_PATH/inc_cipher_blowfish.cl)
#endif

typedef struct kwallet_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[8];
  u64 out[8];

} kwallet_tmp_t;

typedef struct kwallet
{
  u32 ct[16];
  u32 ct_len;

} kwallet_t;

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

// KWallet stores no checksum, so a key is judged by whether the decrypted header
// looks like one. Byte 8..11 of the plaintext is a big endian payload size that has
// to fit inside the file, and the payload itself is a QMap serialization that always
// carries a lot of zero bytes. That is exactly the test kwallet does on open, and
// the same one JtR's kwallet format uses.
//
// pt points at the plaintext word holding file offset 12, i.e. 13 words / 52 bytes.

DECLSPEC int kwallet_verify_plain (PRIVATE_AS const u32 *pt, const u32 fsize, const u32 ct_len)
{
  if (fsize > (ct_len - 12)) return 0;

  const u32 lim = (fsize < 52) ? fsize : 52;

  u32 n = 0;

  for (u32 i = 0; i < lim; i++)
  {
    const u32 b = (pt[i >> 2] >> (24 - ((i & 3) << 3))) & 0xff;

    if (b == 0) n++;
  }

  return (n >= 12); // seen in practice was 30 to 32 zero bytes out of 52
}

KERNEL_FQ KERNEL_FA void m36400_init (KERN_ATTR_TMPS_ESALT (kwallet_tmp_t, kwallet_t))
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

  sha512_hmac_update_global (&sha512_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  // the derived key is 56 byte, so a single PBKDF2 block is enough

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

KERNEL_FQ KERNEL_FA void m36400_loop (KERN_ATTR_TMPS_ESALT (kwallet_tmp_t, kwallet_t))
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

KERNEL_FQ KERNEL_FA FIXED_THREAD_COUNT(FIXED_LOCAL_SIZE_COMP) void m36400_comp (KERN_ATTR_TMPS_ESALT (kwallet_tmp_t, kwallet_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  /**
   * blowfish setkey, the first 56 byte of the PBKDF2 output are the key
   */

  u32 E[14];

  E[ 0] = h32_from_64_S (tmps[gid].out[0]);
  E[ 1] = l32_from_64_S (tmps[gid].out[0]);
  E[ 2] = h32_from_64_S (tmps[gid].out[1]);
  E[ 3] = l32_from_64_S (tmps[gid].out[1]);
  E[ 4] = h32_from_64_S (tmps[gid].out[2]);
  E[ 5] = l32_from_64_S (tmps[gid].out[2]);
  E[ 6] = h32_from_64_S (tmps[gid].out[3]);
  E[ 7] = l32_from_64_S (tmps[gid].out[3]);
  E[ 8] = h32_from_64_S (tmps[gid].out[4]);
  E[ 9] = l32_from_64_S (tmps[gid].out[4]);
  E[10] = h32_from_64_S (tmps[gid].out[5]);
  E[11] = l32_from_64_S (tmps[gid].out[5]);
  E[12] = h32_from_64_S (tmps[gid].out[6]);
  E[13] = l32_from_64_S (tmps[gid].out[6]);

  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE_COMP][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE_COMP][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE_COMP][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE_COMP][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE_COMP * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE_COMP * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE_COMP * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE_COMP * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  u32 P[18];

  blowfish_set_key (E, 14, P, S0, S1, S2, S3);

  GLOBAL_AS const kwallet_t *es = &esalt_bufs[DIGESTS_OFFSET_HOST];

  /**
   * KWallet's own Blowfish is byte swapped per 32 bit word before it enters the
   * cipher, which is a bug in KDE that the on disk format is now stuck with. Files
   * written by a fixed build exist too, so both layouts have to be tried.
   */

  int cracked = 0;

  for (int swapped = 1; swapped >= 0; swapped--)
  {
    u32 w[16];

    for (int i = 0; i < 16; i++)
    {
      w[i] = swapped ? hc_swap32_S (es->ct[i]) : es->ct[i];
    }

    // CBC over byte 8..63, the first block is the IV

    u32 prev0 = w[0];
    u32 prev1 = w[1];

    u32 pt[14];

    for (int j = 2; j < 16; j += 2)
    {
      const u32 c0 = w[j + 0];
      const u32 c1 = w[j + 1];

      u32 d0 = c0;
      u32 d1 = c1;

      BF_DECRYPT (d0, d1);

      pt[j - 2] = d0 ^ prev0;
      pt[j - 1] = d1 ^ prev1;

      prev0 = c0;
      prev1 = c1;
    }

    const u32 fsize = swapped ? hc_swap32_S (pt[0]) : pt[0];

    if (kwallet_verify_plain (pt + 1, fsize, es->ct_len))
    {
      cracked = 1;

      break;
    }
  }

  if (cracked)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
