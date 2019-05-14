/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"
#include "inc_cipher_aes.cl"
#include "inc_cipher_serpent.cl"
#include "inc_cipher_twofish.cl"
#include "inc_diskcryptor_xts.cl"
#endif

typedef struct pbkdf2_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

} pbkdf2_sha512_tmp_t;

typedef struct diskcryptor_esalt
{
  u32 salt_buf[512];

} diskcryptor_esalt_t;

DECLSPEC void hmac_sha512_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *w4, u32x *w5, u32x *w6, u32x *w7, u64x *ipad, u64x *opad, u64x *digest)
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

KERNEL_FQ void m20013_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, diskcryptor_esalt_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_global_utf16le_swap (&sha512_hmac_ctx, pws[gid].i, pws[gid].pw_len);

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

  sha512_hmac_update_global_swap (&sha512_hmac_ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

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

KERNEL_FQ void m20013_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, diskcryptor_esalt_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

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

    for (u32 j = 0; j < loop_cnt; j++)
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

KERNEL_FQ void m20013_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha512_tmp_t, diskcryptor_esalt_t))
{
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

  if (gid >= gid_max) return;

  #define il_pos 0

  u32 ukey1[8];

  ukey1[0] = hc_swap32_S (h32_from_64_S (tmps[gid].out[0]));
  ukey1[1] = hc_swap32_S (l32_from_64_S (tmps[gid].out[0]));
  ukey1[2] = hc_swap32_S (h32_from_64_S (tmps[gid].out[1]));
  ukey1[3] = hc_swap32_S (l32_from_64_S (tmps[gid].out[1]));
  ukey1[4] = hc_swap32_S (h32_from_64_S (tmps[gid].out[2]));
  ukey1[5] = hc_swap32_S (l32_from_64_S (tmps[gid].out[2]));
  ukey1[6] = hc_swap32_S (h32_from_64_S (tmps[gid].out[3]));
  ukey1[7] = hc_swap32_S (l32_from_64_S (tmps[gid].out[3]));

  u32 ukey2[8];

  ukey2[0] = hc_swap32_S (h32_from_64_S (tmps[gid].out[4]));
  ukey2[1] = hc_swap32_S (l32_from_64_S (tmps[gid].out[4]));
  ukey2[2] = hc_swap32_S (h32_from_64_S (tmps[gid].out[5]));
  ukey2[3] = hc_swap32_S (l32_from_64_S (tmps[gid].out[5]));
  ukey2[4] = hc_swap32_S (h32_from_64_S (tmps[gid].out[6]));
  ukey2[5] = hc_swap32_S (l32_from_64_S (tmps[gid].out[6]));
  ukey2[6] = hc_swap32_S (h32_from_64_S (tmps[gid].out[7]));
  ukey2[7] = hc_swap32_S (l32_from_64_S (tmps[gid].out[7]));

  if (dcrp_verify_header_serpent (digests_buf[digests_offset].digest_buf, ukey1, ukey2) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
    }
  }

  if (dcrp_verify_header_twofish (digests_buf[digests_offset].digest_buf, ukey1, ukey2) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
    }
  }

  if (dcrp_verify_header_aes (digests_buf[digests_offset].digest_buf, ukey1, ukey2, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
    }
  }

  u32 ukey3[8];

  ukey3[0] = hc_swap32_S (h32_from_64_S (tmps[gid].out[ 8]));
  ukey3[1] = hc_swap32_S (l32_from_64_S (tmps[gid].out[ 8]));
  ukey3[2] = hc_swap32_S (h32_from_64_S (tmps[gid].out[ 9]));
  ukey3[3] = hc_swap32_S (l32_from_64_S (tmps[gid].out[ 9]));
  ukey3[4] = hc_swap32_S (h32_from_64_S (tmps[gid].out[10]));
  ukey3[5] = hc_swap32_S (l32_from_64_S (tmps[gid].out[10]));
  ukey3[6] = hc_swap32_S (h32_from_64_S (tmps[gid].out[11]));
  ukey3[7] = hc_swap32_S (l32_from_64_S (tmps[gid].out[11]));

  u32 ukey4[8];

  ukey4[0] = hc_swap32_S (h32_from_64_S (tmps[gid].out[12]));
  ukey4[1] = hc_swap32_S (l32_from_64_S (tmps[gid].out[12]));
  ukey4[2] = hc_swap32_S (h32_from_64_S (tmps[gid].out[13]));
  ukey4[3] = hc_swap32_S (l32_from_64_S (tmps[gid].out[13]));
  ukey4[4] = hc_swap32_S (h32_from_64_S (tmps[gid].out[14]));
  ukey4[5] = hc_swap32_S (l32_from_64_S (tmps[gid].out[14]));
  ukey4[6] = hc_swap32_S (h32_from_64_S (tmps[gid].out[15]));
  ukey4[7] = hc_swap32_S (l32_from_64_S (tmps[gid].out[15]));

  if (dcrp_verify_header_serpent_aes (digests_buf[digests_offset].digest_buf, ukey1, ukey2, ukey3, ukey4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
    }
  }

  if (dcrp_verify_header_twofish_serpent (digests_buf[digests_offset].digest_buf, ukey1, ukey2, ukey3, ukey4) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
    }
  }

  if (dcrp_verify_header_aes_twofish (digests_buf[digests_offset].digest_buf, ukey1, ukey2, ukey3, ukey4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
    }
  }

  u32 ukey5[8];

  ukey5[0] = hc_swap32_S (h32_from_64_S (tmps[gid].out[16]));
  ukey5[1] = hc_swap32_S (l32_from_64_S (tmps[gid].out[16]));
  ukey5[2] = hc_swap32_S (h32_from_64_S (tmps[gid].out[17]));
  ukey5[3] = hc_swap32_S (l32_from_64_S (tmps[gid].out[17]));
  ukey5[4] = hc_swap32_S (h32_from_64_S (tmps[gid].out[18]));
  ukey5[5] = hc_swap32_S (l32_from_64_S (tmps[gid].out[18]));
  ukey5[6] = hc_swap32_S (h32_from_64_S (tmps[gid].out[19]));
  ukey5[7] = hc_swap32_S (l32_from_64_S (tmps[gid].out[19]));

  u32 ukey6[8];

  ukey6[0] = hc_swap32_S (h32_from_64_S (tmps[gid].out[20]));
  ukey6[1] = hc_swap32_S (l32_from_64_S (tmps[gid].out[20]));
  ukey6[2] = hc_swap32_S (h32_from_64_S (tmps[gid].out[21]));
  ukey6[3] = hc_swap32_S (l32_from_64_S (tmps[gid].out[21]));
  ukey6[4] = hc_swap32_S (h32_from_64_S (tmps[gid].out[22]));
  ukey6[5] = hc_swap32_S (l32_from_64_S (tmps[gid].out[22]));
  ukey6[6] = hc_swap32_S (h32_from_64_S (tmps[gid].out[23]));
  ukey6[7] = hc_swap32_S (l32_from_64_S (tmps[gid].out[23]));

  if (dcrp_verify_header_serpent_twofish_aes (digests_buf[digests_offset].digest_buf, ukey1, ukey2, ukey3, ukey4, ukey5, ukey6, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
    }
  }

  if (dcrp_verify_header_aes_twofish_serpent (digests_buf[digests_offset].digest_buf, ukey1, ukey2, ukey3, ukey4, ukey5, ukey6, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[digests_offset]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, digests_offset, gid, il_pos, 0, 0);
    }
  }
}
