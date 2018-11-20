/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"
#include "inc_hash_sha1.cl"
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

DECLSPEC void make_kn (u32 *k)
{
  u32 kl[4];
  u32 kr[4];

  kl[0] = (k[0] << 1) & 0xfefefefe;
  kl[1] = (k[1] << 1) & 0xfefefefe;
  kl[2] = (k[2] << 1) & 0xfefefefe;
  kl[3] = (k[3] << 1) & 0xfefefefe;

  kr[0] = (k[0] >> 7) & 0x01010101;
  kr[1] = (k[1] >> 7) & 0x01010101;
  kr[2] = (k[2] >> 7) & 0x01010101;
  kr[3] = (k[3] >> 7) & 0x01010101;

  const u32 c = kr[0] & 1;

  kr[0] = kr[0] >> 8 | kr[1] << 24;
  kr[1] = kr[1] >> 8 | kr[2] << 24;
  kr[2] = kr[2] >> 8 | kr[3] << 24;
  kr[3] = kr[3] >> 8;

  k[0] = kl[0] | kr[0];
  k[1] = kl[1] | kr[1];
  k[2] = kl[2] | kr[2];
  k[3] = kl[3] | kr[3];

  k[3] ^= c * 0x87000000;
}

DECLSPEC void hmac_sha1_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
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

__kernel void m02500_init (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_eapol_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init_global_swap (&sha1_hmac_ctx, pws[gid].i, pws[gid].pw_len & 255);

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

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  for (u32 i = 0, j = 1; i < 8; i += 5, j += 1)
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

__kernel void m02500_loop (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_eapol_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

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

  for (u32 i = 0; i < 8; i += 5)
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

    for (u32 j = 0; j < loop_cnt; j++)
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

__kernel void m02500_comp (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_eapol_t))
{
  // not in use here, special case...
}

__kernel void m02500_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_eapol_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= gid_max) return;

  u32 out[8];

  out[0] = tmps[gid].out[0];
  out[1] = tmps[gid].out[1];
  out[2] = tmps[gid].out[2];
  out[3] = tmps[gid].out[3];
  out[4] = tmps[gid].out[4];
  out[5] = tmps[gid].out[5];
  out[6] = tmps[gid].out[6];
  out[7] = tmps[gid].out[7];

  const u32 digest_pos = loop_pos;

  const u32 digest_cur = digests_offset + digest_pos;

  __global const wpa_eapol_t *wpa_eapol = &esalt_bufs[digest_cur];

  u32 pke[32];

  pke[ 0] = wpa_eapol->pke[ 0];
  pke[ 1] = wpa_eapol->pke[ 1];
  pke[ 2] = wpa_eapol->pke[ 2];
  pke[ 3] = wpa_eapol->pke[ 3];
  pke[ 4] = wpa_eapol->pke[ 4];
  pke[ 5] = wpa_eapol->pke[ 5];
  pke[ 6] = wpa_eapol->pke[ 6];
  pke[ 7] = wpa_eapol->pke[ 7];
  pke[ 8] = wpa_eapol->pke[ 8];
  pke[ 9] = wpa_eapol->pke[ 9];
  pke[10] = wpa_eapol->pke[10];
  pke[11] = wpa_eapol->pke[11];
  pke[12] = wpa_eapol->pke[12];
  pke[13] = wpa_eapol->pke[13];
  pke[14] = wpa_eapol->pke[14];
  pke[15] = wpa_eapol->pke[15];
  pke[16] = wpa_eapol->pke[16];
  pke[17] = wpa_eapol->pke[17];
  pke[18] = wpa_eapol->pke[18];
  pke[19] = wpa_eapol->pke[19];
  pke[20] = wpa_eapol->pke[20];
  pke[21] = wpa_eapol->pke[21];
  pke[22] = wpa_eapol->pke[22];
  pke[23] = wpa_eapol->pke[23];
  pke[24] = wpa_eapol->pke[24];
  pke[25] = wpa_eapol->pke[25];
  pke[26] = wpa_eapol->pke[26];
  pke[27] = wpa_eapol->pke[27];
  pke[28] = wpa_eapol->pke[28];
  pke[29] = wpa_eapol->pke[29];
  pke[30] = wpa_eapol->pke[30];
  pke[31] = wpa_eapol->pke[31];

  u32 to;

  if (wpa_eapol->nonce_compare < 0)
  {
    to = pke[15] << 24
       | pke[16] >>  8;
  }
  else
  {
    to = pke[23] << 24
       | pke[24] >>  8;
  }

  const u32 nonce_error_corrections = wpa_eapol->nonce_error_corrections;

  if (wpa_eapol->detected_le == 1)
  {
    for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
    {
      u32 t = to;

      t -= nonce_error_corrections / 2;
      t += nonce_error_correction;

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = (pke[15] & ~0x000000ff) | (t >> 24);
        pke[16] = (pke[16] & ~0xffffff00) | (t <<  8);
      }
      else
      {
        pke[23] = (pke[23] & ~0x000000ff) | (t >> 24);
        pke[24] = (pke[24] & ~0xffffff00) | (t <<  8);
      }

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = out[5];
      w1[2] = out[6];
      w1[3] = out[7];
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      u32 keymic[4];

      keymic[0] = 0;
      keymic[1] = 0;
      keymic[2] = 0;
      keymic[3] = 0;

      sha1_hmac_ctx_t ctx1;

      sha1_hmac_init_64 (&ctx1, w0, w1, w2, w3);

      ctx1.ipad.w0[0] = pke[ 0];
      ctx1.ipad.w0[1] = pke[ 1];
      ctx1.ipad.w0[2] = pke[ 2];
      ctx1.ipad.w0[3] = pke[ 3];
      ctx1.ipad.w1[0] = pke[ 4];
      ctx1.ipad.w1[1] = pke[ 5];
      ctx1.ipad.w1[2] = pke[ 6];
      ctx1.ipad.w1[3] = pke[ 7];
      ctx1.ipad.w2[0] = pke[ 8];
      ctx1.ipad.w2[1] = pke[ 9];
      ctx1.ipad.w2[2] = pke[10];
      ctx1.ipad.w2[3] = pke[11];
      ctx1.ipad.w3[0] = pke[12];
      ctx1.ipad.w3[1] = pke[13];
      ctx1.ipad.w3[2] = pke[14];
      ctx1.ipad.w3[3] = pke[15];

      sha1_transform (ctx1.ipad.w0, ctx1.ipad.w1, ctx1.ipad.w2, ctx1.ipad.w3, ctx1.ipad.h);

      ctx1.ipad.w0[0] = pke[16];
      ctx1.ipad.w0[1] = pke[17];
      ctx1.ipad.w0[2] = pke[18];
      ctx1.ipad.w0[3] = pke[19];
      ctx1.ipad.w1[0] = pke[20];
      ctx1.ipad.w1[1] = pke[21];
      ctx1.ipad.w1[2] = pke[22];
      ctx1.ipad.w1[3] = pke[23];
      ctx1.ipad.w2[0] = pke[24];
      ctx1.ipad.w2[1] = pke[25];
      ctx1.ipad.w2[2] = pke[26];
      ctx1.ipad.w2[3] = pke[27];
      ctx1.ipad.w3[0] = pke[28];
      ctx1.ipad.w3[1] = pke[29];
      ctx1.ipad.w3[2] = pke[30];
      ctx1.ipad.w3[3] = pke[31];

      ctx1.ipad.len += 100;

      sha1_hmac_final (&ctx1);

      u32 digest[4];

      digest[0] = ctx1.opad.h[0];
      digest[1] = ctx1.opad.h[1];
      digest[2] = ctx1.opad.h[2];
      digest[3] = ctx1.opad.h[3];

      u32 t0[4];
      u32 t1[4];
      u32 t2[4];
      u32 t3[4];

      t0[0] = swap32_S (digest[0]);
      t0[1] = swap32_S (digest[1]);
      t0[2] = swap32_S (digest[2]);
      t0[3] = swap32_S (digest[3]);
      t1[0] = 0;
      t1[1] = 0;
      t1[2] = 0;
      t1[3] = 0;
      t2[0] = 0;
      t2[1] = 0;
      t2[2] = 0;
      t2[3] = 0;
      t3[0] = 0;
      t3[1] = 0;
      t3[2] = 0;
      t3[3] = 0;

      md5_hmac_ctx_t ctx2;

      md5_hmac_init_64 (&ctx2, t0, t1, t2, t3);

      md5_hmac_update_global (&ctx2, wpa_eapol->eapol, wpa_eapol->eapol_len);

      md5_hmac_final (&ctx2);

      keymic[0] = ctx2.opad.h[0];
      keymic[1] = ctx2.opad.h[1];
      keymic[2] = ctx2.opad.h[2];
      keymic[3] = ctx2.opad.h[3];

      /**
       * final compare
       */

      if ((keymic[0] == wpa_eapol->keymic[0])
       && (keymic[1] == wpa_eapol->keymic[1])
       && (keymic[2] == wpa_eapol->keymic[2])
       && (keymic[3] == wpa_eapol->keymic[3]))
      {
        if (atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, digest_cur, gid, 0);
        }
      }
    }
  }

  if (wpa_eapol->detected_be == 1)
  {
    for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
    {
      u32 t = to;

      t = swap32_S (t);

      t -= nonce_error_corrections / 2;
      t += nonce_error_correction;

      t = swap32_S (t);

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = (pke[15] & ~0x000000ff) | (t >> 24);
        pke[16] = (pke[16] & ~0xffffff00) | (t <<  8);
      }
      else
      {
        pke[23] = (pke[23] & ~0x000000ff) | (t >> 24);
        pke[24] = (pke[24] & ~0xffffff00) | (t <<  8);
      }

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = out[5];
      w1[2] = out[6];
      w1[3] = out[7];
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      u32 keymic[4];

      keymic[0] = 0;
      keymic[1] = 0;
      keymic[2] = 0;
      keymic[3] = 0;

      sha1_hmac_ctx_t ctx1;

      sha1_hmac_init_64 (&ctx1, w0, w1, w2, w3);

      ctx1.ipad.w0[0] = pke[ 0];
      ctx1.ipad.w0[1] = pke[ 1];
      ctx1.ipad.w0[2] = pke[ 2];
      ctx1.ipad.w0[3] = pke[ 3];
      ctx1.ipad.w1[0] = pke[ 4];
      ctx1.ipad.w1[1] = pke[ 5];
      ctx1.ipad.w1[2] = pke[ 6];
      ctx1.ipad.w1[3] = pke[ 7];
      ctx1.ipad.w2[0] = pke[ 8];
      ctx1.ipad.w2[1] = pke[ 9];
      ctx1.ipad.w2[2] = pke[10];
      ctx1.ipad.w2[3] = pke[11];
      ctx1.ipad.w3[0] = pke[12];
      ctx1.ipad.w3[1] = pke[13];
      ctx1.ipad.w3[2] = pke[14];
      ctx1.ipad.w3[3] = pke[15];

      sha1_transform (ctx1.ipad.w0, ctx1.ipad.w1, ctx1.ipad.w2, ctx1.ipad.w3, ctx1.ipad.h);

      ctx1.ipad.w0[0] = pke[16];
      ctx1.ipad.w0[1] = pke[17];
      ctx1.ipad.w0[2] = pke[18];
      ctx1.ipad.w0[3] = pke[19];
      ctx1.ipad.w1[0] = pke[20];
      ctx1.ipad.w1[1] = pke[21];
      ctx1.ipad.w1[2] = pke[22];
      ctx1.ipad.w1[3] = pke[23];
      ctx1.ipad.w2[0] = pke[24];
      ctx1.ipad.w2[1] = pke[25];
      ctx1.ipad.w2[2] = pke[26];
      ctx1.ipad.w2[3] = pke[27];
      ctx1.ipad.w3[0] = pke[28];
      ctx1.ipad.w3[1] = pke[29];
      ctx1.ipad.w3[2] = pke[30];
      ctx1.ipad.w3[3] = pke[31];

      ctx1.ipad.len += 100;

      sha1_hmac_final (&ctx1);

      u32 digest[4];

      digest[0] = ctx1.opad.h[0];
      digest[1] = ctx1.opad.h[1];
      digest[2] = ctx1.opad.h[2];
      digest[3] = ctx1.opad.h[3];

      u32 t0[4];
      u32 t1[4];
      u32 t2[4];
      u32 t3[4];

      t0[0] = swap32_S (digest[0]);
      t0[1] = swap32_S (digest[1]);
      t0[2] = swap32_S (digest[2]);
      t0[3] = swap32_S (digest[3]);
      t1[0] = 0;
      t1[1] = 0;
      t1[2] = 0;
      t1[3] = 0;
      t2[0] = 0;
      t2[1] = 0;
      t2[2] = 0;
      t2[3] = 0;
      t3[0] = 0;
      t3[1] = 0;
      t3[2] = 0;
      t3[3] = 0;

      md5_hmac_ctx_t ctx2;

      md5_hmac_init_64 (&ctx2, t0, t1, t2, t3);

      md5_hmac_update_global (&ctx2, wpa_eapol->eapol, wpa_eapol->eapol_len);

      md5_hmac_final (&ctx2);

      keymic[0] = ctx2.opad.h[0];
      keymic[1] = ctx2.opad.h[1];
      keymic[2] = ctx2.opad.h[2];
      keymic[3] = ctx2.opad.h[3];

      /**
       * final compare
       */

      if ((keymic[0] == wpa_eapol->keymic[0])
       && (keymic[1] == wpa_eapol->keymic[1])
       && (keymic[2] == wpa_eapol->keymic[2])
       && (keymic[3] == wpa_eapol->keymic[3]))
      {
        if (atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, digest_cur, gid, 0);
        }
      }
    }
  }
}

__kernel void m02500_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_eapol_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= gid_max) return;

  u32 out[8];

  out[0] = tmps[gid].out[0];
  out[1] = tmps[gid].out[1];
  out[2] = tmps[gid].out[2];
  out[3] = tmps[gid].out[3];
  out[4] = tmps[gid].out[4];
  out[5] = tmps[gid].out[5];
  out[6] = tmps[gid].out[6];
  out[7] = tmps[gid].out[7];

  const u32 digest_pos = loop_pos;

  const u32 digest_cur = digests_offset + digest_pos;

  __global const wpa_eapol_t *wpa_eapol = &esalt_bufs[digest_cur];

  u32 pke[32];

  pke[ 0] = wpa_eapol->pke[ 0];
  pke[ 1] = wpa_eapol->pke[ 1];
  pke[ 2] = wpa_eapol->pke[ 2];
  pke[ 3] = wpa_eapol->pke[ 3];
  pke[ 4] = wpa_eapol->pke[ 4];
  pke[ 5] = wpa_eapol->pke[ 5];
  pke[ 6] = wpa_eapol->pke[ 6];
  pke[ 7] = wpa_eapol->pke[ 7];
  pke[ 8] = wpa_eapol->pke[ 8];
  pke[ 9] = wpa_eapol->pke[ 9];
  pke[10] = wpa_eapol->pke[10];
  pke[11] = wpa_eapol->pke[11];
  pke[12] = wpa_eapol->pke[12];
  pke[13] = wpa_eapol->pke[13];
  pke[14] = wpa_eapol->pke[14];
  pke[15] = wpa_eapol->pke[15];
  pke[16] = wpa_eapol->pke[16];
  pke[17] = wpa_eapol->pke[17];
  pke[18] = wpa_eapol->pke[18];
  pke[19] = wpa_eapol->pke[19];
  pke[20] = wpa_eapol->pke[20];
  pke[21] = wpa_eapol->pke[21];
  pke[22] = wpa_eapol->pke[22];
  pke[23] = wpa_eapol->pke[23];
  pke[24] = wpa_eapol->pke[24];
  pke[25] = wpa_eapol->pke[25];
  pke[26] = wpa_eapol->pke[26];
  pke[27] = wpa_eapol->pke[27];
  pke[28] = wpa_eapol->pke[28];
  pke[29] = wpa_eapol->pke[29];
  pke[30] = wpa_eapol->pke[30];
  pke[31] = wpa_eapol->pke[31];

  u32 to;

  if (wpa_eapol->nonce_compare < 0)
  {
    to = pke[15] << 24
       | pke[16] >>  8;
  }
  else
  {
    to = pke[23] << 24
       | pke[24] >>  8;
  }

  const u32 nonce_error_corrections = wpa_eapol->nonce_error_corrections;

  if (wpa_eapol->detected_le == 1)
  {
    for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
    {
      u32 t = to;

      t -= nonce_error_corrections / 2;
      t += nonce_error_correction;

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = (pke[15] & ~0x000000ff) | (t >> 24);
        pke[16] = (pke[16] & ~0xffffff00) | (t <<  8);
      }
      else
      {
        pke[23] = (pke[23] & ~0x000000ff) | (t >> 24);
        pke[24] = (pke[24] & ~0xffffff00) | (t <<  8);
      }

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = out[5];
      w1[2] = out[6];
      w1[3] = out[7];
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      u32 keymic[4];

      keymic[0] = 0;
      keymic[1] = 0;
      keymic[2] = 0;
      keymic[3] = 0;

      sha1_hmac_ctx_t ctx1;

      sha1_hmac_init_64 (&ctx1, w0, w1, w2, w3);

      ctx1.ipad.w0[0] = pke[ 0];
      ctx1.ipad.w0[1] = pke[ 1];
      ctx1.ipad.w0[2] = pke[ 2];
      ctx1.ipad.w0[3] = pke[ 3];
      ctx1.ipad.w1[0] = pke[ 4];
      ctx1.ipad.w1[1] = pke[ 5];
      ctx1.ipad.w1[2] = pke[ 6];
      ctx1.ipad.w1[3] = pke[ 7];
      ctx1.ipad.w2[0] = pke[ 8];
      ctx1.ipad.w2[1] = pke[ 9];
      ctx1.ipad.w2[2] = pke[10];
      ctx1.ipad.w2[3] = pke[11];
      ctx1.ipad.w3[0] = pke[12];
      ctx1.ipad.w3[1] = pke[13];
      ctx1.ipad.w3[2] = pke[14];
      ctx1.ipad.w3[3] = pke[15];

      sha1_transform (ctx1.ipad.w0, ctx1.ipad.w1, ctx1.ipad.w2, ctx1.ipad.w3, ctx1.ipad.h);

      ctx1.ipad.w0[0] = pke[16];
      ctx1.ipad.w0[1] = pke[17];
      ctx1.ipad.w0[2] = pke[18];
      ctx1.ipad.w0[3] = pke[19];
      ctx1.ipad.w1[0] = pke[20];
      ctx1.ipad.w1[1] = pke[21];
      ctx1.ipad.w1[2] = pke[22];
      ctx1.ipad.w1[3] = pke[23];
      ctx1.ipad.w2[0] = pke[24];
      ctx1.ipad.w2[1] = pke[25];
      ctx1.ipad.w2[2] = pke[26];
      ctx1.ipad.w2[3] = pke[27];
      ctx1.ipad.w3[0] = pke[28];
      ctx1.ipad.w3[1] = pke[29];
      ctx1.ipad.w3[2] = pke[30];
      ctx1.ipad.w3[3] = pke[31];

      ctx1.ipad.len += 100;

      sha1_hmac_final (&ctx1);

      u32 digest[4];

      digest[0] = ctx1.opad.h[0];
      digest[1] = ctx1.opad.h[1];
      digest[2] = ctx1.opad.h[2];
      digest[3] = ctx1.opad.h[3];

      u32 t0[4];
      u32 t1[4];
      u32 t2[4];
      u32 t3[4];

      t0[0] = digest[0];
      t0[1] = digest[1];
      t0[2] = digest[2];
      t0[3] = digest[3];
      t1[0] = 0;
      t1[1] = 0;
      t1[2] = 0;
      t1[3] = 0;
      t2[0] = 0;
      t2[1] = 0;
      t2[2] = 0;
      t2[3] = 0;
      t3[0] = 0;
      t3[1] = 0;
      t3[2] = 0;
      t3[3] = 0;

      sha1_hmac_ctx_t ctx2;

      sha1_hmac_init_64 (&ctx2, t0, t1, t2, t3);

      sha1_hmac_update_global (&ctx2, wpa_eapol->eapol, wpa_eapol->eapol_len);

      sha1_hmac_final (&ctx2);

      keymic[0] = ctx2.opad.h[0];
      keymic[1] = ctx2.opad.h[1];
      keymic[2] = ctx2.opad.h[2];
      keymic[3] = ctx2.opad.h[3];

      /**
       * final compare
       */

      if ((keymic[0] == wpa_eapol->keymic[0])
       && (keymic[1] == wpa_eapol->keymic[1])
       && (keymic[2] == wpa_eapol->keymic[2])
       && (keymic[3] == wpa_eapol->keymic[3]))
      {
        if (atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, digest_cur, gid, 0);
        }
      }
    }
  }

  if (wpa_eapol->detected_be == 1)
  {
    for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
    {
      u32 t = to;

      t = swap32_S (t);

      t -= nonce_error_corrections / 2;
      t += nonce_error_correction;

      t = swap32_S (t);

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = (pke[15] & ~0x000000ff) | (t >> 24);
        pke[16] = (pke[16] & ~0xffffff00) | (t <<  8);
      }
      else
      {
        pke[23] = (pke[23] & ~0x000000ff) | (t >> 24);
        pke[24] = (pke[24] & ~0xffffff00) | (t <<  8);
      }

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = out[5];
      w1[2] = out[6];
      w1[3] = out[7];
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      u32 keymic[4];

      keymic[0] = 0;
      keymic[1] = 0;
      keymic[2] = 0;
      keymic[3] = 0;

      sha1_hmac_ctx_t ctx1;

      sha1_hmac_init_64 (&ctx1, w0, w1, w2, w3);

      ctx1.ipad.w0[0] = pke[ 0];
      ctx1.ipad.w0[1] = pke[ 1];
      ctx1.ipad.w0[2] = pke[ 2];
      ctx1.ipad.w0[3] = pke[ 3];
      ctx1.ipad.w1[0] = pke[ 4];
      ctx1.ipad.w1[1] = pke[ 5];
      ctx1.ipad.w1[2] = pke[ 6];
      ctx1.ipad.w1[3] = pke[ 7];
      ctx1.ipad.w2[0] = pke[ 8];
      ctx1.ipad.w2[1] = pke[ 9];
      ctx1.ipad.w2[2] = pke[10];
      ctx1.ipad.w2[3] = pke[11];
      ctx1.ipad.w3[0] = pke[12];
      ctx1.ipad.w3[1] = pke[13];
      ctx1.ipad.w3[2] = pke[14];
      ctx1.ipad.w3[3] = pke[15];

      sha1_transform (ctx1.ipad.w0, ctx1.ipad.w1, ctx1.ipad.w2, ctx1.ipad.w3, ctx1.ipad.h);

      ctx1.ipad.w0[0] = pke[16];
      ctx1.ipad.w0[1] = pke[17];
      ctx1.ipad.w0[2] = pke[18];
      ctx1.ipad.w0[3] = pke[19];
      ctx1.ipad.w1[0] = pke[20];
      ctx1.ipad.w1[1] = pke[21];
      ctx1.ipad.w1[2] = pke[22];
      ctx1.ipad.w1[3] = pke[23];
      ctx1.ipad.w2[0] = pke[24];
      ctx1.ipad.w2[1] = pke[25];
      ctx1.ipad.w2[2] = pke[26];
      ctx1.ipad.w2[3] = pke[27];
      ctx1.ipad.w3[0] = pke[28];
      ctx1.ipad.w3[1] = pke[29];
      ctx1.ipad.w3[2] = pke[30];
      ctx1.ipad.w3[3] = pke[31];

      ctx1.ipad.len += 100;

      sha1_hmac_final (&ctx1);

      u32 digest[4];

      digest[0] = ctx1.opad.h[0];
      digest[1] = ctx1.opad.h[1];
      digest[2] = ctx1.opad.h[2];
      digest[3] = ctx1.opad.h[3];

      u32 t0[4];
      u32 t1[4];
      u32 t2[4];
      u32 t3[4];

      t0[0] = digest[0];
      t0[1] = digest[1];
      t0[2] = digest[2];
      t0[3] = digest[3];
      t1[0] = 0;
      t1[1] = 0;
      t1[2] = 0;
      t1[3] = 0;
      t2[0] = 0;
      t2[1] = 0;
      t2[2] = 0;
      t2[3] = 0;
      t3[0] = 0;
      t3[1] = 0;
      t3[2] = 0;
      t3[3] = 0;

      sha1_hmac_ctx_t ctx2;

      sha1_hmac_init_64 (&ctx2, t0, t1, t2, t3);

      sha1_hmac_update_global (&ctx2, wpa_eapol->eapol, wpa_eapol->eapol_len);

      sha1_hmac_final (&ctx2);

      keymic[0] = ctx2.opad.h[0];
      keymic[1] = ctx2.opad.h[1];
      keymic[2] = ctx2.opad.h[2];
      keymic[3] = ctx2.opad.h[3];

      /**
       * final compare
       */

      if ((keymic[0] == wpa_eapol->keymic[0])
       && (keymic[1] == wpa_eapol->keymic[1])
       && (keymic[2] == wpa_eapol->keymic[2])
       && (keymic[3] == wpa_eapol->keymic[3]))
      {
        if (atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, digest_cur, gid, 0);
        }
      }
    }
  }
}

__kernel void m02500_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pbkdf2_tmp_t, wpa_eapol_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  __local u32 s_td0[256];
  __local u32 s_td1[256];
  __local u32 s_td2[256];
  __local u32 s_td3[256];
  __local u32 s_td4[256];

  __local u32 s_te0[256];
  __local u32 s_te1[256];
  __local u32 s_te2[256];
  __local u32 s_te3[256];
  __local u32 s_te4[256];

  for (MAYBE_VOLATILE u32 i = lid; i < 256; i += lsz)
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

  barrier (CLK_LOCAL_MEM_FENCE);

  #else

  __constant u32a *s_td0 = td0;
  __constant u32a *s_td1 = td1;
  __constant u32a *s_td2 = td2;
  __constant u32a *s_td3 = td3;
  __constant u32a *s_td4 = td4;

  __constant u32a *s_te0 = te0;
  __constant u32a *s_te1 = te1;
  __constant u32a *s_te2 = te2;
  __constant u32a *s_te3 = te3;
  __constant u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  u32 out[8];

  out[0] = tmps[gid].out[0];
  out[1] = tmps[gid].out[1];
  out[2] = tmps[gid].out[2];
  out[3] = tmps[gid].out[3];
  out[4] = tmps[gid].out[4];
  out[5] = tmps[gid].out[5];
  out[6] = tmps[gid].out[6];
  out[7] = tmps[gid].out[7];

  const u32 digest_pos = loop_pos;

  const u32 digest_cur = digests_offset + digest_pos;

  __global const wpa_eapol_t *wpa_eapol = &esalt_bufs[digest_cur];

  u32 pke[32];

  pke[ 0] = wpa_eapol->pke[ 0];
  pke[ 1] = wpa_eapol->pke[ 1];
  pke[ 2] = wpa_eapol->pke[ 2];
  pke[ 3] = wpa_eapol->pke[ 3];
  pke[ 4] = wpa_eapol->pke[ 4];
  pke[ 5] = wpa_eapol->pke[ 5];
  pke[ 6] = wpa_eapol->pke[ 6];
  pke[ 7] = wpa_eapol->pke[ 7];
  pke[ 8] = wpa_eapol->pke[ 8];
  pke[ 9] = wpa_eapol->pke[ 9];
  pke[10] = wpa_eapol->pke[10];
  pke[11] = wpa_eapol->pke[11];
  pke[12] = wpa_eapol->pke[12];
  pke[13] = wpa_eapol->pke[13];
  pke[14] = wpa_eapol->pke[14];
  pke[15] = wpa_eapol->pke[15];
  pke[16] = wpa_eapol->pke[16];
  pke[17] = wpa_eapol->pke[17];
  pke[18] = wpa_eapol->pke[18];
  pke[19] = wpa_eapol->pke[19];
  pke[20] = wpa_eapol->pke[20];
  pke[21] = wpa_eapol->pke[21];
  pke[22] = wpa_eapol->pke[22];
  pke[23] = wpa_eapol->pke[23];
  pke[24] = wpa_eapol->pke[24];
  pke[25] = wpa_eapol->pke[25];
  pke[26] = wpa_eapol->pke[26];
  pke[27] = wpa_eapol->pke[27];
  pke[28] = wpa_eapol->pke[28];
  pke[29] = wpa_eapol->pke[29];
  pke[30] = wpa_eapol->pke[30];
  pke[31] = wpa_eapol->pke[31];

  u32 to;

  if (wpa_eapol->nonce_compare < 0)
  {
    to = pke[15] << 24
       | pke[16] >>  8;
  }
  else
  {
    to = pke[23] << 24
       | pke[24] >>  8;
  }

  const u32 nonce_error_corrections = wpa_eapol->nonce_error_corrections;

  if (wpa_eapol->detected_le == 1)
  {
    for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
    {
      u32 t = to;

      t -= nonce_error_corrections / 2;
      t += nonce_error_correction;

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = (pke[15] & ~0x000000ff) | (t >> 24);
        pke[16] = (pke[16] & ~0xffffff00) | (t <<  8);
      }
      else
      {
        pke[23] = (pke[23] & ~0x000000ff) | (t >> 24);
        pke[24] = (pke[24] & ~0xffffff00) | (t <<  8);
      }

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = out[5];
      w1[2] = out[6];
      w1[3] = out[7];
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      u32 keymic[4];

      keymic[0] = 0;
      keymic[1] = 0;
      keymic[2] = 0;
      keymic[3] = 0;

      sha256_hmac_ctx_t ctx1;

      sha256_hmac_init_64 (&ctx1, w0, w1, w2, w3);

      ctx1.ipad.w0[0] = pke[ 0];
      ctx1.ipad.w0[1] = pke[ 1];
      ctx1.ipad.w0[2] = pke[ 2];
      ctx1.ipad.w0[3] = pke[ 3];
      ctx1.ipad.w1[0] = pke[ 4];
      ctx1.ipad.w1[1] = pke[ 5];
      ctx1.ipad.w1[2] = pke[ 6];
      ctx1.ipad.w1[3] = pke[ 7];
      ctx1.ipad.w2[0] = pke[ 8];
      ctx1.ipad.w2[1] = pke[ 9];
      ctx1.ipad.w2[2] = pke[10];
      ctx1.ipad.w2[3] = pke[11];
      ctx1.ipad.w3[0] = pke[12];
      ctx1.ipad.w3[1] = pke[13];
      ctx1.ipad.w3[2] = pke[14];
      ctx1.ipad.w3[3] = pke[15];

      sha256_transform (ctx1.ipad.w0, ctx1.ipad.w1, ctx1.ipad.w2, ctx1.ipad.w3, ctx1.ipad.h);

      ctx1.ipad.w0[0] = pke[16];
      ctx1.ipad.w0[1] = pke[17];
      ctx1.ipad.w0[2] = pke[18];
      ctx1.ipad.w0[3] = pke[19];
      ctx1.ipad.w1[0] = pke[20];
      ctx1.ipad.w1[1] = pke[21];
      ctx1.ipad.w1[2] = pke[22];
      ctx1.ipad.w1[3] = pke[23];
      ctx1.ipad.w2[0] = pke[24];
      ctx1.ipad.w2[1] = pke[25];
      ctx1.ipad.w2[2] = pke[26];
      ctx1.ipad.w2[3] = pke[27];
      ctx1.ipad.w3[0] = pke[28];
      ctx1.ipad.w3[1] = pke[29];
      ctx1.ipad.w3[2] = pke[30];
      ctx1.ipad.w3[3] = pke[31];

      ctx1.ipad.len += 102;

      sha256_hmac_final (&ctx1);

      u32 digest[4];

      digest[0] = swap32_S (ctx1.opad.h[0]);
      digest[1] = swap32_S (ctx1.opad.h[1]);
      digest[2] = swap32_S (ctx1.opad.h[2]);
      digest[3] = swap32_S (ctx1.opad.h[3]);

      // AES CMAC

      u32 ks[44];

      aes128_set_encrypt_key (ks, digest, s_te0, s_te1, s_te2, s_te3, s_te4);

      u32 m[4];

      m[0] = 0;
      m[1] = 0;
      m[2] = 0;
      m[3] = 0;

      u32 iv[4];

      iv[0] = 0;
      iv[1] = 0;
      iv[2] = 0;
      iv[3] = 0;

      int eapol_left;
      int eapol_idx;

      for (eapol_left = wpa_eapol->eapol_len, eapol_idx = 0; eapol_left > 16; eapol_left -= 16, eapol_idx += 4)
      {
        m[0] = wpa_eapol->eapol[eapol_idx + 0] ^ iv[0];
        m[1] = wpa_eapol->eapol[eapol_idx + 1] ^ iv[1];
        m[2] = wpa_eapol->eapol[eapol_idx + 2] ^ iv[2];
        m[3] = wpa_eapol->eapol[eapol_idx + 3] ^ iv[3];

        aes128_encrypt (ks, m, iv, s_te0, s_te1, s_te2, s_te3, s_te4);
      }

      m[0] = wpa_eapol->eapol[eapol_idx + 0];
      m[1] = wpa_eapol->eapol[eapol_idx + 1];
      m[2] = wpa_eapol->eapol[eapol_idx + 2];
      m[3] = wpa_eapol->eapol[eapol_idx + 3];

      u32 k[4];

      k[0] = 0;
      k[1] = 0;
      k[2] = 0;
      k[3] = 0;

      aes128_encrypt (ks, k, k, s_te0, s_te1, s_te2, s_te3, s_te4);

      make_kn (k);

      if (eapol_left < 16)
      {
        make_kn (k);
      }

      m[0] ^= k[0];
      m[1] ^= k[1];
      m[2] ^= k[2];
      m[3] ^= k[3];

      m[0] ^= iv[0];
      m[1] ^= iv[1];
      m[2] ^= iv[2];
      m[3] ^= iv[3];

      aes128_encrypt (ks, m, keymic, s_te0, s_te1, s_te2, s_te3, s_te4);

      /**
       * final compare
       */

      if ((keymic[0] == wpa_eapol->keymic[0])
       && (keymic[1] == wpa_eapol->keymic[1])
       && (keymic[2] == wpa_eapol->keymic[2])
       && (keymic[3] == wpa_eapol->keymic[3]))
      {
        if (atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, digest_cur, gid, 0);
        }
      }
    }
  }

  if (wpa_eapol->detected_be == 1)
  {
    for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
    {
      u32 t = to;

      t = swap32_S (t);

      t -= nonce_error_corrections / 2;
      t += nonce_error_correction;

      t = swap32_S (t);

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = (pke[15] & ~0x000000ff) | (t >> 24);
        pke[16] = (pke[16] & ~0xffffff00) | (t <<  8);
      }
      else
      {
        pke[23] = (pke[23] & ~0x000000ff) | (t >> 24);
        pke[24] = (pke[24] & ~0xffffff00) | (t <<  8);
      }

      u32 w0[4];
      u32 w1[4];
      u32 w2[4];
      u32 w3[4];

      w0[0] = out[0];
      w0[1] = out[1];
      w0[2] = out[2];
      w0[3] = out[3];
      w1[0] = out[4];
      w1[1] = out[5];
      w1[2] = out[6];
      w1[3] = out[7];
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = 0;

      u32 keymic[4];

      keymic[0] = 0;
      keymic[1] = 0;
      keymic[2] = 0;
      keymic[3] = 0;

      sha256_hmac_ctx_t ctx1;

      sha256_hmac_init_64 (&ctx1, w0, w1, w2, w3);

      ctx1.ipad.w0[0] = pke[ 0];
      ctx1.ipad.w0[1] = pke[ 1];
      ctx1.ipad.w0[2] = pke[ 2];
      ctx1.ipad.w0[3] = pke[ 3];
      ctx1.ipad.w1[0] = pke[ 4];
      ctx1.ipad.w1[1] = pke[ 5];
      ctx1.ipad.w1[2] = pke[ 6];
      ctx1.ipad.w1[3] = pke[ 7];
      ctx1.ipad.w2[0] = pke[ 8];
      ctx1.ipad.w2[1] = pke[ 9];
      ctx1.ipad.w2[2] = pke[10];
      ctx1.ipad.w2[3] = pke[11];
      ctx1.ipad.w3[0] = pke[12];
      ctx1.ipad.w3[1] = pke[13];
      ctx1.ipad.w3[2] = pke[14];
      ctx1.ipad.w3[3] = pke[15];

      sha256_transform (ctx1.ipad.w0, ctx1.ipad.w1, ctx1.ipad.w2, ctx1.ipad.w3, ctx1.ipad.h);

      ctx1.ipad.w0[0] = pke[16];
      ctx1.ipad.w0[1] = pke[17];
      ctx1.ipad.w0[2] = pke[18];
      ctx1.ipad.w0[3] = pke[19];
      ctx1.ipad.w1[0] = pke[20];
      ctx1.ipad.w1[1] = pke[21];
      ctx1.ipad.w1[2] = pke[22];
      ctx1.ipad.w1[3] = pke[23];
      ctx1.ipad.w2[0] = pke[24];
      ctx1.ipad.w2[1] = pke[25];
      ctx1.ipad.w2[2] = pke[26];
      ctx1.ipad.w2[3] = pke[27];
      ctx1.ipad.w3[0] = pke[28];
      ctx1.ipad.w3[1] = pke[29];
      ctx1.ipad.w3[2] = pke[30];
      ctx1.ipad.w3[3] = pke[31];

      ctx1.ipad.len += 102;

      sha256_hmac_final (&ctx1);

      u32 digest[4];

      digest[0] = swap32_S (ctx1.opad.h[0]);
      digest[1] = swap32_S (ctx1.opad.h[1]);
      digest[2] = swap32_S (ctx1.opad.h[2]);
      digest[3] = swap32_S (ctx1.opad.h[3]);

      // AES CMAC

      u32 ks[44];

      aes128_set_encrypt_key (ks, digest, s_te0, s_te1, s_te2, s_te3, s_te4);

      u32 m[4];

      m[0] = 0;
      m[1] = 0;
      m[2] = 0;
      m[3] = 0;

      u32 iv[4];

      iv[0] = 0;
      iv[1] = 0;
      iv[2] = 0;
      iv[3] = 0;

      int eapol_left;
      int eapol_idx;

      for (eapol_left = wpa_eapol->eapol_len, eapol_idx = 0; eapol_left > 16; eapol_left -= 16, eapol_idx += 4)
      {
        m[0] = wpa_eapol->eapol[eapol_idx + 0] ^ iv[0];
        m[1] = wpa_eapol->eapol[eapol_idx + 1] ^ iv[1];
        m[2] = wpa_eapol->eapol[eapol_idx + 2] ^ iv[2];
        m[3] = wpa_eapol->eapol[eapol_idx + 3] ^ iv[3];

        aes128_encrypt (ks, m, iv, s_te0, s_te1, s_te2, s_te3, s_te4);
      }

      m[0] = wpa_eapol->eapol[eapol_idx + 0];
      m[1] = wpa_eapol->eapol[eapol_idx + 1];
      m[2] = wpa_eapol->eapol[eapol_idx + 2];
      m[3] = wpa_eapol->eapol[eapol_idx + 3];

      u32 k[4];

      k[0] = 0;
      k[1] = 0;
      k[2] = 0;
      k[3] = 0;

      aes128_encrypt (ks, k, k, s_te0, s_te1, s_te2, s_te3, s_te4);

      make_kn (k);

      if (eapol_left < 16)
      {
        make_kn (k);
      }

      m[0] ^= k[0];
      m[1] ^= k[1];
      m[2] ^= k[2];
      m[3] ^= k[3];

      m[0] ^= iv[0];
      m[1] ^= iv[1];
      m[2] ^= iv[2];
      m[3] ^= iv[3];

      aes128_encrypt (ks, m, keymic, s_te0, s_te1, s_te2, s_te3, s_te4);

      /**
       * final compare
       */

      if ((keymic[0] == wpa_eapol->keymic[0])
       && (keymic[1] == wpa_eapol->keymic[1])
       && (keymic[2] == wpa_eapol->keymic[2])
       && (keymic[3] == wpa_eapol->keymic[3]))
      {
        if (atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, digest_pos, digest_cur, gid, 0);
        }
      }
    }
  }
}
