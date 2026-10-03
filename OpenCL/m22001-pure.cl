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

// The host compiles this file into the module that wants its helpers. There DECLSPEC says the
// function is part of what the core offers a plugin, and these are not: they are the module's own
// copy of a kernel and they stay inside it. inc_rp_common.cl says the same thing the same way.
//
// A module takes the helpers it wants and leaves the rest, so the ones it left have to be allowed to
// go unused.

#ifdef IS_NATIVE
#undef DECLSPEC
#define DECLSPEC static MAYBE_UNUSED
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct wpa_pmk_tmp
{
  u32 out[8];

} wpa_pmk_tmp_t;

// A WPA2 M2 frame can pass 256 bytes once the RSN extension element is present, so the limit on a
// stored EAPOL frame follows the frame rather than the old hccapx field it was inherited from.

#define WPA_EAPOL_LEN_MAX 512

typedef struct wpa
{
  u32  essid_buf[16];
  u32  essid_len;

  u32  mac_ap[2];
  u32  mac_sta[2];

  u32  type;            // 1 = PMKID, 2 = EAPOL, 3 = FT PMKID, 4 = FT EAPOL

  // FT specific

  u32  mdid;

  u32  r0khid[12];
  u32  r0khid_len;

  u32  r1khid[12];
  u32  r1khid_len;

  // Each KDF input is built on the host and sized to the longest ESSID and key holder ID the format
  // allows, not to a SHA-256 block, because the kernel hashes only the bytes it was given.

  u32  pke_r0[25];      // 19 + ESSID (32) + R0KH-ID (48) = 99 bytes
  u32  pke_r1[16];      // 15 + R1KH-ID (48)              = 63 bytes

  // PMKID specific

  u32  pmkid[4];
  u32  pmkid_data[19];  // 20 bytes for a PMKID, 28 + R1KH-ID (48) = 76 for an FT PMKID

  // EAPOL specific

  u32  keymic[4];
  u32  anonce[8];

  u32  keyver;

  u32  eapol[(WPA_EAPOL_LEN_MAX / 4) + 16];
  u32  eapol_len;

  u32  pke[32];

  int  message_pair_chgd;
  u32  message_pair;

  int  nonce_error_corrections_chgd;
  int  nonce_error_corrections;

  int  nonce_compare;
  int  detected_le;
  int  detected_be;

} wpa_t;

#ifdef KERNEL_STATIC
DECLSPEC u8 hex_convert (const u8 c)
{
  return (c & 15) + (c >> 6) * 9;
}

DECLSPEC u8 hex_to_u8 (PRIVATE_AS const u8 *hex)
{
  u8 v = 0;

  v |= ((u8) hex_convert (hex[1]) << 0);
  v |= ((u8) hex_convert (hex[0]) << 4);

  return (v);
}
#endif

DECLSPEC void make_kn (PRIVATE_AS u32 *k)
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

DECLSPEC void hmac_sha1_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS const u32x *ipad, PRIVATE_AS const u32x *opad, PRIVATE_AS u32x *digest)
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

KERNEL_FQ KERNEL_FA void m22001_init (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
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

  u32 out[8];

  PRIVATE_AS u8 *in_ptr  = (PRIVATE_AS u8 *) in;
  PRIVATE_AS u8 *out_ptr = (PRIVATE_AS u8 *) out;

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

KERNEL_FQ KERNEL_FA void m22001_loop (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
{
  // not in use here, special case...
}

KERNEL_FQ KERNEL_FA void m22001_comp (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
{
  // not in use here, special case...
}

KERNEL_FQ KERNEL_FA void m22001_aux1 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
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

  GLOBAL_AS const wpa_t *wpa = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if ((wpa->type != 2) && (wpa->keyver != 1)) return;

  u32 pke[32];

  pke[ 0] = wpa->pke[ 0];
  pke[ 1] = wpa->pke[ 1];
  pke[ 2] = wpa->pke[ 2];
  pke[ 3] = wpa->pke[ 3];
  pke[ 4] = wpa->pke[ 4];
  pke[ 5] = wpa->pke[ 5];
  pke[ 6] = wpa->pke[ 6];
  pke[ 7] = wpa->pke[ 7];
  pke[ 8] = wpa->pke[ 8];
  pke[ 9] = wpa->pke[ 9];
  pke[10] = wpa->pke[10];
  pke[11] = wpa->pke[11];
  pke[12] = wpa->pke[12];
  pke[13] = wpa->pke[13];
  pke[14] = wpa->pke[14];
  pke[15] = wpa->pke[15];
  pke[16] = wpa->pke[16];
  pke[17] = wpa->pke[17];
  pke[18] = wpa->pke[18];
  pke[19] = wpa->pke[19];
  pke[20] = wpa->pke[20];
  pke[21] = wpa->pke[21];
  pke[22] = wpa->pke[22];
  pke[23] = wpa->pke[23];
  pke[24] = wpa->pke[24];
  pke[25] = wpa->pke[25];
  pke[26] = wpa->pke[26];
  pke[27] = wpa->pke[27];
  pke[28] = wpa->pke[28];
  pke[29] = wpa->pke[29];
  pke[30] = wpa->pke[30];
  pke[31] = wpa->pke[31];

  u32 z[4];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  u32 to;

  u32 m0;
  u32 m1;

  if (wpa->nonce_compare < 0)
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

  u32 bo_loops = wpa->detected_le + wpa->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nonce_error_corrections = wpa->nonce_error_corrections;

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    for (u32 bo_pos = 0; bo_pos < bo_loops; bo_pos++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa->detected_le == 1)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (wpa->detected_be == 1)
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

      if (wpa->nonce_compare < 0)
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

      md5_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);

      md5_hmac_final (&ctx2);

      ctx2.opad.h[0] = hc_swap32_S (ctx2.opad.h[0]);
      ctx2.opad.h[1] = hc_swap32_S (ctx2.opad.h[1]);
      ctx2.opad.h[2] = hc_swap32_S (ctx2.opad.h[2]);
      ctx2.opad.h[3] = hc_swap32_S (ctx2.opad.h[3]);

      /**
       * final compare
       */

      if ((ctx2.opad.h[0] == wpa->keymic[0])
       && (ctx2.opad.h[1] == wpa->keymic[1])
       && (ctx2.opad.h[2] == wpa->keymic[2])
       && (ctx2.opad.h[3] == wpa->keymic[3]))
      {
        if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m22001_aux2 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
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

  GLOBAL_AS const wpa_t *wpa = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if ((wpa->type != 2) && (wpa->keyver != 2)) return;

  u32 pke[32];

  pke[ 0] = wpa->pke[ 0];
  pke[ 1] = wpa->pke[ 1];
  pke[ 2] = wpa->pke[ 2];
  pke[ 3] = wpa->pke[ 3];
  pke[ 4] = wpa->pke[ 4];
  pke[ 5] = wpa->pke[ 5];
  pke[ 6] = wpa->pke[ 6];
  pke[ 7] = wpa->pke[ 7];
  pke[ 8] = wpa->pke[ 8];
  pke[ 9] = wpa->pke[ 9];
  pke[10] = wpa->pke[10];
  pke[11] = wpa->pke[11];
  pke[12] = wpa->pke[12];
  pke[13] = wpa->pke[13];
  pke[14] = wpa->pke[14];
  pke[15] = wpa->pke[15];
  pke[16] = wpa->pke[16];
  pke[17] = wpa->pke[17];
  pke[18] = wpa->pke[18];
  pke[19] = wpa->pke[19];
  pke[20] = wpa->pke[20];
  pke[21] = wpa->pke[21];
  pke[22] = wpa->pke[22];
  pke[23] = wpa->pke[23];
  pke[24] = wpa->pke[24];
  pke[25] = wpa->pke[25];
  pke[26] = wpa->pke[26];
  pke[27] = wpa->pke[27];
  pke[28] = wpa->pke[28];
  pke[29] = wpa->pke[29];
  pke[30] = wpa->pke[30];
  pke[31] = wpa->pke[31];

  u32 z[4];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  u32 to;

  u32 m0;
  u32 m1;

  if (wpa->nonce_compare < 0)
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

  u32 bo_loops = wpa->detected_le + wpa->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nonce_error_corrections = wpa->nonce_error_corrections;

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    for (u32 bo_pos = 0; bo_pos < bo_loops; bo_pos++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa->detected_le == 1)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (wpa->detected_be == 1)
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

      if (wpa->nonce_compare < 0)
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

      sha1_hmac_update_global (&ctx2, wpa->eapol, wpa->eapol_len);

      sha1_hmac_final (&ctx2);

      /**
       * final compare
       */

      if ((ctx2.opad.h[0] == wpa->keymic[0])
       && (ctx2.opad.h[1] == wpa->keymic[1])
       && (ctx2.opad.h[2] == wpa->keymic[2])
       && (ctx2.opad.h[3] == wpa->keymic[3]))
      {
        if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m22001_aux3 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
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

  GLOBAL_AS const wpa_t *wpa = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if ((wpa->type != 2) && (wpa->keyver != 3)) return;

  u32 pke[32];

  pke[ 0] = wpa->pke[ 0];
  pke[ 1] = wpa->pke[ 1];
  pke[ 2] = wpa->pke[ 2];
  pke[ 3] = wpa->pke[ 3];
  pke[ 4] = wpa->pke[ 4];
  pke[ 5] = wpa->pke[ 5];
  pke[ 6] = wpa->pke[ 6];
  pke[ 7] = wpa->pke[ 7];
  pke[ 8] = wpa->pke[ 8];
  pke[ 9] = wpa->pke[ 9];
  pke[10] = wpa->pke[10];
  pke[11] = wpa->pke[11];
  pke[12] = wpa->pke[12];
  pke[13] = wpa->pke[13];
  pke[14] = wpa->pke[14];
  pke[15] = wpa->pke[15];
  pke[16] = wpa->pke[16];
  pke[17] = wpa->pke[17];
  pke[18] = wpa->pke[18];
  pke[19] = wpa->pke[19];
  pke[20] = wpa->pke[20];
  pke[21] = wpa->pke[21];
  pke[22] = wpa->pke[22];
  pke[23] = wpa->pke[23];
  pke[24] = wpa->pke[24];
  pke[25] = wpa->pke[25];
  pke[26] = wpa->pke[26];
  pke[27] = wpa->pke[27];
  pke[28] = wpa->pke[28];
  pke[29] = wpa->pke[29];
  pke[30] = wpa->pke[30];
  pke[31] = wpa->pke[31];

  u32 z[4];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  u32 to;

  u32 m0;
  u32 m1;

  if (wpa->nonce_compare < 0)
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

  u32 bo_loops = wpa->detected_le + wpa->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nonce_error_corrections = wpa->nonce_error_corrections;

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    for (u32 bo_pos = 0; bo_pos < bo_loops; bo_pos++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa->detected_le == 1)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (wpa->detected_be == 1)
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

      if (wpa->nonce_compare < 0)
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

      // AES CMAC

      u32 ks[44];

      AES128_set_encrypt_key (ks, ctx1.opad.h, s_te0, s_te1, s_te2, s_te3);

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

      for (eapol_left = wpa->eapol_len, eapol_idx = 0; eapol_left > 16; eapol_left -= 16, eapol_idx += 4)
      {
        m[0] = wpa->eapol[eapol_idx + 0] ^ iv[0];
        m[1] = wpa->eapol[eapol_idx + 1] ^ iv[1];
        m[2] = wpa->eapol[eapol_idx + 2] ^ iv[2];
        m[3] = wpa->eapol[eapol_idx + 3] ^ iv[3];

        aes128_encrypt (ks, m, iv, s_te0, s_te1, s_te2, s_te3, s_te4);
      }

      m[0] = wpa->eapol[eapol_idx + 0];
      m[1] = wpa->eapol[eapol_idx + 1];
      m[2] = wpa->eapol[eapol_idx + 2];
      m[3] = wpa->eapol[eapol_idx + 3];

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

      m[0] = hc_swap32_S (m[0]);
      m[1] = hc_swap32_S (m[1]);
      m[2] = hc_swap32_S (m[2]);
      m[3] = hc_swap32_S (m[3]);

      u32 keymic[4];

      AES128_encrypt (ks, m, keymic, s_te0, s_te1, s_te2, s_te3, s_te4);

      /**
       * final compare
       */

      if ((keymic[0] == wpa->keymic[0])
       && (keymic[1] == wpa->keymic[1])
       && (keymic[2] == wpa->keymic[2])
       && (keymic[3] == wpa->keymic[3]))
      {
        if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
        }
      }
    }
  }
}

KERNEL_FQ KERNEL_FA void m22001_aux4 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 w[16];

  w[ 0] = tmps[gid].out[0];
  w[ 1] = tmps[gid].out[1];
  w[ 2] = tmps[gid].out[2];
  w[ 3] = tmps[gid].out[3];
  w[ 4] = tmps[gid].out[4];
  w[ 5] = tmps[gid].out[5];
  w[ 6] = tmps[gid].out[6];
  w[ 7] = tmps[gid].out[7];
  w[ 8] = 0;
  w[ 9] = 0;
  w[10] = 0;
  w[11] = 0;
  w[12] = 0;
  w[13] = 0;
  w[14] = 0;
  w[15] = 0;

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const wpa_t *wpa = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if (wpa->type != 1) return;

  sha1_hmac_ctx_t sha1_hmac_ctx;

  sha1_hmac_init (&sha1_hmac_ctx, w, 32);

  sha1_hmac_update_global_swap (&sha1_hmac_ctx, wpa->pmkid_data, 20);

  sha1_hmac_final (&sha1_hmac_ctx);

  const u32 r0 = sha1_hmac_ctx.opad.h[0];
  const u32 r1 = sha1_hmac_ctx.opad.h[1];
  const u32 r2 = sha1_hmac_ctx.opad.h[2];
  const u32 r3 = sha1_hmac_ctx.opad.h[3];

  #ifdef KERNEL_STATIC

  #define il_pos 0
  #include COMPARE_M

  #else

  if ((hc_swap32_S (r0) == wpa->pmkid[0])
   && (hc_swap32_S (r1) == wpa->pmkid[1])
   && (hc_swap32_S (r2) == wpa->pmkid[2])
   && (hc_swap32_S (r3) == wpa->pmkid[3]))
  {
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
    }
  }

  #endif
}

KERNEL_FQ KERNEL_FA void m22001_aux5 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const wpa_t *wpa = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if (wpa->type != 3) return;

  // step 1: compute PMK-R0-Name salt = KDF-384(PMK, COUNTER || "FT-R0" || ESSIDlength || ESSID || MDID || R0KH-IDlength || R0KH-ID || MAC-CLIENT || SIZE(384)) [32:47]

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

  u32 pke[32];

  pke[ 0] = wpa->pke_r0[ 0];
  pke[ 1] = wpa->pke_r0[ 1];
  pke[ 2] = wpa->pke_r0[ 2];
  pke[ 3] = wpa->pke_r0[ 3];
  pke[ 4] = wpa->pke_r0[ 4];
  pke[ 5] = wpa->pke_r0[ 5];
  pke[ 6] = wpa->pke_r0[ 6];
  pke[ 7] = wpa->pke_r0[ 7];
  pke[ 8] = wpa->pke_r0[ 8];
  pke[ 9] = wpa->pke_r0[ 9];
  pke[10] = wpa->pke_r0[10];
  pke[11] = wpa->pke_r0[11];
  pke[12] = wpa->pke_r0[12];
  pke[13] = wpa->pke_r0[13];
  pke[14] = wpa->pke_r0[14];
  pke[15] = wpa->pke_r0[15];
  pke[16] = wpa->pke_r0[16];
  pke[17] = wpa->pke_r0[17];
  pke[18] = wpa->pke_r0[18];
  pke[19] = wpa->pke_r0[19];
  pke[20] = wpa->pke_r0[20];
  pke[21] = wpa->pke_r0[21];
  pke[22] = wpa->pke_r0[22];
  pke[23] = wpa->pke_r0[23];
  pke[24] = wpa->pke_r0[24];

  u32 z[4];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  sha256_hmac_ctx_t ctx1;

  sha256_hmac_init_64 (&ctx1, out0, out1, z, z);

  // 19 = 2(ctr+pad) + 5("FT-R0") + 1(ESSIDlen) + 2(MDID) + 1(R0KHIDlen) + 6(STA-MAC) + 2(size)
  sha256_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);

  sha256_hmac_final (&ctx1);

  // Step 2: compute pmkr0_name

  pke[ 0] = 0x46542d52;                                        // "FT-R"
  pke[ 1] = 0x304e0000 | (ctx1.opad.h[0] >> 16);               // "0N"
  pke[ 2] = (ctx1.opad.h[0] << 16) | (ctx1.opad.h[1] >> 16);
  pke[ 3] = (ctx1.opad.h[1] << 16) | (ctx1.opad.h[2] >> 16);
  pke[ 4] = (ctx1.opad.h[2] << 16) | (ctx1.opad.h[3] >> 16);
  pke[ 5] = (ctx1.opad.h[3] << 16) ;
  pke[ 6] = 0;
  pke[ 7] = 0;
  pke[ 8] = 0;
  pke[ 9] = 0;
  pke[10] = 0;
  pke[11] = 0;
  pke[12] = 0;
  pke[13] = 0;
  pke[14] = 0;
  pke[15] = 0;
  pke[16] = 0;
  pke[17] = 0;
  pke[18] = 0;
  pke[19] = 0;
  pke[20] = 0;
  pke[21] = 0;
  pke[22] = 0;
  pke[23] = 0;
  pke[24] = 0;
  pke[25] = 0;
  pke[26] = 0;
  pke[27] = 0;
  pke[28] = 0;
  pke[29] = 0;
  pke[30] = 0;
  pke[31] = 0;

  sha256_ctx_t ctx2;

  sha256_init (&ctx2);

  // 22 = 6("FT-R0N") + 16(PMK-R0-Name salt)
  sha256_update (&ctx2, pke, 22);

  sha256_final (&ctx2);

  // step3: calc pmkr1_name (pmkid)

  pke[ 0] = wpa->pmkid_data[ 0];
  pke[ 1] = wpa->pmkid_data[ 1] | (ctx2.h[0] >> 16);
  pke[ 2] = wpa->pmkid_data[ 2] | (ctx2.h[0] << 16) | (ctx2.h[1] >> 16);
  pke[ 3] = wpa->pmkid_data[ 3] | (ctx2.h[1] << 16) | (ctx2.h[2] >> 16);
  pke[ 4] = wpa->pmkid_data[ 4] | (ctx2.h[2] << 16) | (ctx2.h[3] >> 16);
  pke[ 5] = wpa->pmkid_data[ 5] | (ctx2.h[3] << 16);
  pke[ 6] = wpa->pmkid_data[ 6];
  pke[ 7] = wpa->pmkid_data[ 7];
  pke[ 8] = wpa->pmkid_data[ 8];
  pke[ 9] = wpa->pmkid_data[ 9];
  pke[10] = wpa->pmkid_data[10];
  pke[11] = wpa->pmkid_data[11];
  pke[12] = wpa->pmkid_data[12];
  pke[13] = wpa->pmkid_data[13];
  pke[14] = wpa->pmkid_data[14];
  pke[15] = wpa->pmkid_data[15];
  pke[16] = wpa->pmkid_data[16];
  pke[17] = wpa->pmkid_data[17];
  pke[18] = wpa->pmkid_data[18];

  sha256_init (&ctx2);

  // 28 = 6("FT-R1N") + 16(pmkr0_name) + 6(STA-MAC)
  sha256_update (&ctx2, pke, 28 + wpa->r1khid_len);

  sha256_final (&ctx2);

  const u32 r0 = ctx2.h[0];
  const u32 r1 = ctx2.h[1];
  const u32 r2 = ctx2.h[2];
  const u32 r3 = ctx2.h[3];

  #ifdef KERNEL_STATIC

  #define il_pos 0
  #include COMPARE_M

  #else

  if ((hc_swap32_S (r0) == wpa->pmkid[0])
   && (hc_swap32_S (r1) == wpa->pmkid[1])
   && (hc_swap32_S (r2) == wpa->pmkid[2])
   && (hc_swap32_S (r3) == wpa->pmkid[3]))
  {
    if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
    }
  }

  #endif
}

KERNEL_FQ KERNEL_FA void m22001_aux6 (KERN_ATTR_TMPS_ESALT (wpa_pmk_tmp_t, wpa_t))
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

  const u32 digest_pos = LOOP_POS;

  const u32 digest_cur = DIGESTS_OFFSET_HOST + digest_pos;

  GLOBAL_AS const wpa_t *wpa = &esalt_bufs[digest_cur];

  // this can occur on -a 9 because we are ignoring module_deep_comp_kernel()
  if ((wpa->type != 4) || (wpa->keyver != 3)) return;

  // step 1: compute PMK-R0 = KDF-384(PMK, COUNTER || "FT-R0" || ESSIDlength || ESSID || MDID || R0KH-IDlength || R0KH-ID || MAC-CLIENT || SIZE(384)) [0:31]

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

  u32 pke[32];

  pke[ 0] = wpa->pke_r0[ 0];
  pke[ 1] = wpa->pke_r0[ 1];
  pke[ 2] = wpa->pke_r0[ 2];
  pke[ 3] = wpa->pke_r0[ 3];
  pke[ 4] = wpa->pke_r0[ 4];
  pke[ 5] = wpa->pke_r0[ 5];
  pke[ 6] = wpa->pke_r0[ 6];
  pke[ 7] = wpa->pke_r0[ 7];
  pke[ 8] = wpa->pke_r0[ 8];
  pke[ 9] = wpa->pke_r0[ 9];
  pke[10] = wpa->pke_r0[10];
  pke[11] = wpa->pke_r0[11];
  pke[12] = wpa->pke_r0[12];
  pke[13] = wpa->pke_r0[13];
  pke[14] = wpa->pke_r0[14];
  pke[15] = wpa->pke_r0[15];
  pke[16] = wpa->pke_r0[16];
  pke[17] = wpa->pke_r0[17];
  pke[18] = wpa->pke_r0[18];
  pke[19] = wpa->pke_r0[19];
  pke[20] = wpa->pke_r0[20];
  pke[21] = wpa->pke_r0[21];
  pke[22] = wpa->pke_r0[22];
  pke[23] = wpa->pke_r0[23];
  pke[24] = wpa->pke_r0[24];

  u32 z[4];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  sha256_hmac_ctx_t ctx1;

  sha256_hmac_init_64 (&ctx1, out0, out1, z, z);

  // 19 = 2(ctr+pad) + 5("FT-R0") + 1(ESSIDlen) + 2(MDID) + 1(R0KHIDlen) + 6(STA-MAC) + 2(size)
  sha256_hmac_update (&ctx1, pke, 19 + wpa->essid_len + wpa->r0khid_len);

  sha256_hmac_final (&ctx1);

  // step 2: compute PMK-R1 = KDF-256(PMK-R0, COUNTER || "FT-R1" || R1KH-ID || MAC-CLIENT || SIZE(256))

  out0[0] = ctx1.opad.h[0];
  out0[1] = ctx1.opad.h[1];
  out0[2] = ctx1.opad.h[2];
  out0[3] = ctx1.opad.h[3];
  out1[0] = ctx1.opad.h[4];
  out1[1] = ctx1.opad.h[5];
  out1[2] = ctx1.opad.h[6];
  out1[3] = ctx1.opad.h[7];

  pke[ 0] = wpa->pke_r1[ 0];
  pke[ 1] = wpa->pke_r1[ 1];
  pke[ 2] = wpa->pke_r1[ 2];
  pke[ 3] = wpa->pke_r1[ 3];
  pke[ 4] = wpa->pke_r1[ 4];
  pke[ 5] = wpa->pke_r1[ 5];
  pke[ 6] = wpa->pke_r1[ 6];
  pke[ 7] = wpa->pke_r1[ 7];
  pke[ 8] = wpa->pke_r1[ 8];
  pke[ 9] = wpa->pke_r1[ 9];
  pke[10] = wpa->pke_r1[10];
  pke[11] = wpa->pke_r1[11];
  pke[12] = wpa->pke_r1[12];
  pke[13] = wpa->pke_r1[13];
  pke[14] = wpa->pke_r1[14];
  pke[15] = wpa->pke_r1[15];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  sha256_hmac_init_64 (&ctx1, out0, out1, z, z);

  // 15 = 2(ctr+pad) + 5("FT-R1") + 0(r1khid, variable) + 6(STA-MAC) + 2(size)
  sha256_hmac_update (&ctx1, pke, 15 + wpa->r1khid_len);

  sha256_hmac_final (&ctx1);

  // step 3: compute PTK = KDF-384(PMK-R1, COUNTER || "FT-PTK" || NONCE-CLIENT || NONCE-AP || MAC-AP || MAC-CLIENT || SIZE(384))

  out0[0] = ctx1.opad.h[0];
  out0[1] = ctx1.opad.h[1];
  out0[2] = ctx1.opad.h[2];
  out0[3] = ctx1.opad.h[3];
  out1[0] = ctx1.opad.h[4];
  out1[1] = ctx1.opad.h[5];
  out1[2] = ctx1.opad.h[6];
  out1[3] = ctx1.opad.h[7];

  pke[ 0] = wpa->pke[ 0];
  pke[ 1] = wpa->pke[ 1];
  pke[ 2] = wpa->pke[ 2];
  pke[ 3] = wpa->pke[ 3];
  pke[ 4] = wpa->pke[ 4];
  pke[ 5] = wpa->pke[ 5];
  pke[ 6] = wpa->pke[ 6];
  pke[ 7] = wpa->pke[ 7];
  pke[ 8] = wpa->pke[ 8];
  pke[ 9] = wpa->pke[ 9];
  pke[10] = wpa->pke[10];
  pke[11] = wpa->pke[11];
  pke[12] = wpa->pke[12];
  pke[13] = wpa->pke[13];
  pke[14] = wpa->pke[14];
  pke[15] = wpa->pke[15];
  pke[16] = wpa->pke[16];
  pke[17] = wpa->pke[17];
  pke[18] = wpa->pke[18];
  pke[19] = wpa->pke[19];
  pke[20] = wpa->pke[20];
  pke[21] = wpa->pke[21];
  pke[22] = wpa->pke[22];
  pke[23] = wpa->pke[23];
  pke[24] = wpa->pke[24];
  pke[25] = wpa->pke[25];
  pke[26] = wpa->pke[26];
  pke[27] = wpa->pke[27];
  pke[28] = wpa->pke[28];
  pke[29] = wpa->pke[29];
  pke[30] = wpa->pke[30];
  pke[31] = wpa->pke[31];

  z[0] = 0;
  z[1] = 0;
  z[2] = 0;
  z[3] = 0;

  // fixing nonce due to driver bugs
  u32 to = pke[17];

  u32 bo_loops = wpa->detected_le + wpa->detected_be;

  bo_loops = (bo_loops == 0) ? 2 : bo_loops;

  const u32 nonce_error_corrections = wpa->nonce_error_corrections;

  for (u32 nonce_error_correction = 0; nonce_error_correction <= nonce_error_corrections; nonce_error_correction++)
  {
    for (u32 bo_pos = 0; bo_pos < bo_loops; bo_pos++)
    {
      u32 t = to;

      if (bo_loops == 1)
      {
        if (wpa->detected_le == 1)
        {
          t -= nonce_error_corrections / 2;
          t += nonce_error_correction;
        }
        else if (wpa->detected_be == 1)
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

      pke[17] = t;

      sha256_hmac_init_64 (&ctx1, out0, out1, z, z);

      // 86 = 2(ctr+pad) + 6("FT-PTK") + 32(SNonce) + 32(ANonce) + 6(AP-MAC) + 6(STA-MAC) + 2(size)
      sha256_hmac_update (&ctx1, pke, 86);

      sha256_hmac_final (&ctx1);

      ctx1.opad.h[0] = hc_swap32_S (ctx1.opad.h[0]);
      ctx1.opad.h[1] = hc_swap32_S (ctx1.opad.h[1]);
      ctx1.opad.h[2] = hc_swap32_S (ctx1.opad.h[2]);
      ctx1.opad.h[3] = hc_swap32_S (ctx1.opad.h[3]);

      // step 4: MIC = AES-CMAC(PTK, EAPOL)

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

      for (eapol_left = wpa->eapol_len, eapol_idx = 0; eapol_left > 16; eapol_left -= 16, eapol_idx += 4)
      {
        m[0] = wpa->eapol[eapol_idx + 0] ^ iv[0];
        m[1] = wpa->eapol[eapol_idx + 1] ^ iv[1];
        m[2] = wpa->eapol[eapol_idx + 2] ^ iv[2];
        m[3] = wpa->eapol[eapol_idx + 3] ^ iv[3];

        aes128_encrypt (ks, m, iv, s_te0, s_te1, s_te2, s_te3, s_te4);
      }

      m[0] = wpa->eapol[eapol_idx + 0];
      m[1] = wpa->eapol[eapol_idx + 1];
      m[2] = wpa->eapol[eapol_idx + 2];
      m[3] = wpa->eapol[eapol_idx + 3];

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

      keymic[0] = hc_swap32_S (keymic[0]);
      keymic[1] = hc_swap32_S (keymic[1]);
      keymic[2] = hc_swap32_S (keymic[2]);
      keymic[3] = hc_swap32_S (keymic[3]);

      if ((keymic[0] == wpa->keymic[0])
       && (keymic[1] == wpa->keymic[1])
       && (keymic[2] == wpa->keymic[2])
       && (keymic[3] == wpa->keymic[3]))
      {
        if (hc_atomic_inc (&hashes_shown[digest_cur]) == 0)
        {
          mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, digest_pos, digest_cur, gid, 0, 0, 0);
        }
      }
    }
  }
}
