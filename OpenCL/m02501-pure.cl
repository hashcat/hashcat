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
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha1.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#else
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_simd.h"
#include "inc_hash_md5.h"
#include "inc_hash_sha1.h"
#include "inc_hash_sha256.h"
#include "inc_cipher_aes.h"
#endif

typedef struct wpa_pmk_tmp
{
  u32 out[8];

} wpa_pmk_tmp_t;

typedef struct wpa_eapol
{
  u32  pke[32];
  u32  eapol[64 + 16];
  u16  eapol_len;
  u8   message_pair;
  int  message_pair_chgd;
  u8   keyver;
  u8   orig_mac_ap[6];
  u8   orig_mac_sta[6];
  u8   orig_nonce_ap[32];
  u8   orig_nonce_sta[32];
  u8   essid_len;
  u8   essid[32];
  u32  keymic[4];
  int  nonce_compare;
  int  nonce_error_corrections;
  int  detected_le;
  int  detected_be;

} wpa_eapol_t;

#ifdef KERNEL_STATIC
DECLSPEC u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8 (const u8 *hex)
{
  u8 v = 0;

  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);

  return (v);
}
#endif

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

KERNEL_FQ void m02501_init (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 in[16];

  in[ 0] = pws[gid].i[ 0];
  in[ 1] = pws[gid].i[ 1];
  in[ 2] = pws[gid].i[ 2];
  in[ 3] = pws[gid].i[ 3];
  in[ 4] = pws[gid].i[ 4];
  in[ 5] = pws[gid].i[ 5];
  in[ 6] = pws[gid].i[ 6];
  in[ 7] = pws[gid].i[ 7];
  in[ 8] = pws[gid].i[ 8];
  in[ 9] = pws[gid].i[ 9];
  in[10] = pws[gid].i[10];
  in[11] = pws[gid].i[11];
  in[12] = pws[gid].i[12];
  in[13] = pws[gid].i[13];
  in[14] = pws[gid].i[14];
  in[15] = pws[gid].i[15];

  u8 *in_ptr = (u8 *) in;

  u32 out[8];

  u8 *out_ptr = (u8 *) out;

  for (int i = 0, j = 0; i < 32; i += 1, j += 2)
  {
    out_ptr[i] = hex_to_u8 (in_ptr + j);
  }

  tmps[gid].out[0] = hc_swap32_S (out[0]);
  tmps[gid].out[1] = hc_swap32_S (out[1]);
  tmps[gid].out[2] = hc_swap32_S (out[2]);
  tmps[gid].out[3] = hc_swap32_S (out[3]);
  tmps[gid].out[4] = hc_swap32_S (out[4]);
  tmps[gid].out[5] = hc_swap32_S (out[5]);
  tmps[gid].out[6] = hc_swap32_S (out[6]);
  tmps[gid].out[7] = hc_swap32_S (out[7]);
}

KERNEL_FQ void m02501_loop (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;
}

KERNEL_FQ void m02501_comp (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t))
{
  // not in use here, special case...
}

KERNEL_FQ void m02501_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 out0[4];
  u32 out1[4];

  out0[0] = tmps[gid].out[0];
  out0[1] = tmps[gid].out[1];
  out0[2] = tmps[gid].out[2];
  out0[3] = tmps[gid].out[3];
  out1[0] = tmps[gid].out[4];
  out1[1] = tmps[gid].out[5];
  out1[2] = tmps[gid].out[6];
  out1[3] = tmps[gid].out[7];

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const wpa_eapol_t *wpa_eapol = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if (wpa_eapol->keyver != 1) return;

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

  u32 z[4];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  u32 to;

  u32 m0;
  u32 m1;

  if (wpa_eapol->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff;
    m1 = pke[16] & ~0xffffff00;

    to = pke[15] << 24
       | pke[16] >>  8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff;
    m1 = pke[24] & ~0xffffff00;

    to = pke[23] << 24
       | pke[24] >>  8;
  }

  u32 bo_loops = wpa_eapol->detected_le + wpa_eapol->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nonce_error_corrections = wpa_eapol->nonce_error_corrections;

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    for (u32 bo_pos = 0; bo_pos < bo_loops; bo_pos++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa_eapol->detected_le == 1)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (wpa_eapol->detected_be == 1)
        {
          t = hc_swap32_S (t);

          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;

          t = hc_swap32_S (t);
        }
      }
      else
      {
        if (bo_pos == 0)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (bo_pos == 1)
        {
          t = hc_swap32_S (t);

          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;

          t = hc_swap32_S (t);
        }
      }

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t <<  8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t <<  8);
      }

      sha1_hmac_ctx_t ctx1;

      sha1_hmac_init_64 (&ctx1, out0, out1, z, z);

      sha1_hmac_update (&ctx1, pke, 100);

      sha1_hmac_final (&ctx1);

      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      md5_hmac_ctx_t ctx2;

      md5_hmac_init_64 (&ctx2, ctx1.opad.h, z, z, z);

      md5_hmac_update_global (&ctx2, wpa_eapol->eapol, wpa_eapol->eapol_len);

      md5_hmac_final (&ctx2);

      /**
       * final compare
       */

      if ((ctx2.opad.h[0] == wpa_eapol->keymic[0])
       && (ctx2.opad.h[1] == wpa_eapol->keymic[1])
       && (ctx2.opad.h[2] == wpa_eapol->keymic[2])
       && (ctx2.opad.h[3] == wpa_eapol->keymic[3]))
      {
        if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ void m02501_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 out0[4];
  u32 out1[4];

  out0[0] = tmps[gid].out[0];
  out0[1] = tmps[gid].out[1];
  out0[2] = tmps[gid].out[2];
  out0[3] = tmps[gid].out[3];
  out1[0] = tmps[gid].out[4];
  out1[1] = tmps[gid].out[5];
  out1[2] = tmps[gid].out[6];
  out1[3] = tmps[gid].out[7];

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const wpa_eapol_t *wpa_eapol = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if (wpa_eapol->keyver != 2) return;

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

  u32 z[4];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  u32 to;

  u32 m0;
  u32 m1;

  if (wpa_eapol->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff;
    m1 = pke[16] & ~0xffffff00;

    to = pke[15] << 24
       | pke[16] >>  8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff;
    m1 = pke[24] & ~0xffffff00;

    to = pke[23] << 24
       | pke[24] >>  8;
  }

  u32 bo_loops = wpa_eapol->detected_le + wpa_eapol->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nonce_error_corrections = wpa_eapol->nonce_error_corrections;

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    for (u32 bo_pos = 0; bo_pos < bo_loops; bo_pos++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa_eapol->detected_le == 1)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (wpa_eapol->detected_be == 1)
        {
          t = hc_swap32_S (t);

          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;

          t = hc_swap32_S (t);
        }
      }
      else
      {
        if (bo_pos == 0)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (bo_pos == 1)
        {
          t = hc_swap32_S (t);

          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;

          t = hc_swap32_S (t);
        }
      }

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t <<  8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t <<  8);
      }

      sha1_hmac_ctx_t ctx1;

      sha1_hmac_init_64 (&ctx1, out0, out1, z, z);

      sha1_hmac_update (&ctx1, pke, 100);

      sha1_hmac_final (&ctx1);

      sha1_hmac_ctx_t ctx2;

      sha1_hmac_init_64 (&ctx2, ctx1.opad.h, z, z, z);

      sha1_hmac_update_global (&ctx2, wpa_eapol->eapol, wpa_eapol->eapol_len);

      sha1_hmac_final (&ctx2);

      /**
       * final compare
       */

      if ((ctx2.opad.h[0] == wpa_eapol->keymic[0])
       && (ctx2.opad.h[1] == wpa_eapol->keymic[1])
       && (ctx2.opad.h[2] == wpa_eapol->keymic[2])
       && (ctx2.opad.h[3] == wpa_eapol->keymic[3]))
      {
        if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ void m02501_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_eapol_t))
{
  /**
   * aes shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 out0[4];
  u32 out1[4];

  out0[0] = tmps[gid].out[0];
  out0[1] = tmps[gid].out[1];
  out0[2] = tmps[gid].out[2];
  out0[3] = tmps[gid].out[3];
  out1[0] = tmps[gid].out[4];
  out1[1] = tmps[gid].out[5];
  out1[2] = tmps[gid].out[6];
  out1[3] = tmps[gid].out[7];

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const wpa_eapol_t *wpa_eapol = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if (wpa_eapol->keyver != 3) return;

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

  u32 z[4];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  u32 to;

  u32 m0;
  u32 m1;

  if (wpa_eapol->nonce_compare < 0)
  {
    m0 = pke[15] & ~0x000000ff;
    m1 = pke[16] & ~0xffffff00;

    to = pke[15] << 24
       | pke[16] >>  8;
  }
  else
  {
    m0 = pke[23] & ~0x000000ff;
    m1 = pke[24] & ~0xffffff00;

    to = pke[23] << 24
       | pke[24] >>  8;
  }

  u32 bo_loops = wpa_eapol->detected_le + wpa_eapol->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nonce_error_corrections = wpa_eapol->nonce_error_corrections;

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    for (u32 bo_pos = 0; bo_pos < bo_loops; bo_pos++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa_eapol->detected_le == 1)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (wpa_eapol->detected_be == 1)
        {
          t = hc_swap32_S (t);

          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;

          t = hc_swap32_S (t);
        }
      }
      else
      {
        if (bo_pos == 0)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (bo_pos == 1)
        {
          t = hc_swap32_S (t);

          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;

          t = hc_swap32_S (t);
        }
      }

      if (wpa_eapol->nonce_compare < 0)
      {
        pke[15] = m0 | (t >> 24);
        pke[16] = m1 | (t <<  8);
      }
      else
      {
        pke[23] = m0 | (t >> 24);
        pke[24] = m1 | (t <<  8);
      }

      sha256_hmac_ctx_t ctx1;

      sha256_hmac_init_64 (&ctx1, out0, out1, z, z);

      sha256_hmac_update (&ctx1, pke, 102);

      sha256_hmac_final (&ctx1);

      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      // AES CMAC

      u32 ks[44];

      aes128_set_encrypt_key (ks, ctx1.opad.h, s_te0, s_te1, s_te2, s_te3);

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

      u32 keymic[4];

      keymic[0] = 0;
      keymic[1] = 0;
      keymic[2] = 0;
      keymic[3] = 0;

      aes128_encrypt (ks, m, keymic, s_te0, s_te1, s_te2, s_te3, s_te4);

      /**
       * final compare
       */

      if ((keymic[0] == wpa_eapol->keymic[0])
       && (keymic[1] == wpa_eapol->keymic[1])
       && (keymic[2] == wpa_eapol->keymic[2])
       && (keymic[3] == wpa_eapol->keymic[3]))
      {
        if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
        }
      }
    }
  }
}
