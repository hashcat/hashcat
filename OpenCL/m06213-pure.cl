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
#include "inc_hash_ripemd160.cl"
#include "inc_cipher_aes.cl"
#include "inc_cipher_twofish.cl"
#include "inc_cipher_serpent.cl"
#endif

typedef struct tc
{
  u32 salt_buf[32];
  u32 data_buf[112];
  u32 keyfile_buf[16];
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

} tc_t;

#ifdef KERNEL_STATIC
#include "inc_truecrypt_keyfile.cl"
#include "inc_truecrypt_crc32.cl"
#include "inc_truecrypt_xts.cl"
#endif

typedef struct tc_tmp
{
  u32 ipad[16];
  u32 opad[16];

  u32 dgst[64];
  u32 out[64];

} tc_tmp_t;

DECLSPEC void hmac_ripemd160_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];

  ripemd160_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = 0x80;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = (64 + 20) * 8;
  w3[3] = 0;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];

  ripemd160_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m06213_init (KERN_ATTR_TMPS_ESALT (tc_tmp_t, tc_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * keyboard layout shared
   */

  const int keyboard_layout_mapping_cnt = esalt_bufs[digests_offset].keyboard_layout_mapping_cnt;

  LOCAL_VK keyboard_layout_mapping_t s_keyboard_layout_mapping_buf[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_keyboard_layout_mapping_buf[i] = esalt_bufs[digests_offset].keyboard_layout_mapping_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = pws[gid].i[ 0];
  w0[1] = pws[gid].i[ 1];
  w0[2] = pws[gid].i[ 2];
  w0[3] = pws[gid].i[ 3];
  w1[0] = pws[gid].i[ 4];
  w1[1] = pws[gid].i[ 5];
  w1[2] = pws[gid].i[ 6];
  w1[3] = pws[gid].i[ 7];
  w2[0] = pws[gid].i[ 8];
  w2[1] = pws[gid].i[ 9];
  w2[2] = pws[gid].i[10];
  w2[3] = pws[gid].i[11];
  w3[0] = pws[gid].i[12];
  w3[1] = pws[gid].i[13];
  w3[2] = pws[gid].i[14];
  w3[3] = pws[gid].i[15];

  const u32 pw_len = pws[gid].pw_len;

  hc_execute_keyboard_layout_mapping (w0, w1, w2, w3, pw_len, s_keyboard_layout_mapping_buf, keyboard_layout_mapping_cnt);

  w0[0] = u8add (w0[0], esalt_bufs[digests_offset].keyfile_buf[ 0]);
  w0[1] = u8add (w0[1], esalt_bufs[digests_offset].keyfile_buf[ 1]);
  w0[2] = u8add (w0[2], esalt_bufs[digests_offset].keyfile_buf[ 2]);
  w0[3] = u8add (w0[3], esalt_bufs[digests_offset].keyfile_buf[ 3]);
  w1[0] = u8add (w1[0], esalt_bufs[digests_offset].keyfile_buf[ 4]);
  w1[1] = u8add (w1[1], esalt_bufs[digests_offset].keyfile_buf[ 5]);
  w1[2] = u8add (w1[2], esalt_bufs[digests_offset].keyfile_buf[ 6]);
  w1[3] = u8add (w1[3], esalt_bufs[digests_offset].keyfile_buf[ 7]);
  w2[0] = u8add (w2[0], esalt_bufs[digests_offset].keyfile_buf[ 8]);
  w2[1] = u8add (w2[1], esalt_bufs[digests_offset].keyfile_buf[ 9]);
  w2[2] = u8add (w2[2], esalt_bufs[digests_offset].keyfile_buf[10]);
  w2[3] = u8add (w2[3], esalt_bufs[digests_offset].keyfile_buf[11]);
  w3[0] = u8add (w3[0], esalt_bufs[digests_offset].keyfile_buf[12]);
  w3[1] = u8add (w3[1], esalt_bufs[digests_offset].keyfile_buf[13]);
  w3[2] = u8add (w3[2], esalt_bufs[digests_offset].keyfile_buf[14]);
  w3[3] = u8add (w3[3], esalt_bufs[digests_offset].keyfile_buf[15]);

  ripemd160_hmac_ctx_t ripemd160_hmac_ctx;

  ripemd160_hmac_init_64 (&ripemd160_hmac_ctx, w0, w1, w2, w3);

  tmps[gid].ipad[0] = ripemd160_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = ripemd160_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = ripemd160_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = ripemd160_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = ripemd160_hmac_ctx.ipad.h[4];

  tmps[gid].opad[0] = ripemd160_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = ripemd160_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = ripemd160_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = ripemd160_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = ripemd160_hmac_ctx.opad.h[4];

  ripemd160_hmac_update_global (&ripemd160_hmac_ctx, esalt_bufs[digests_offset].salt_buf, 64);

  for (u32 i = 0, j = 1; i < 48; i += 5, j += 1)
  {
    ripemd160_hmac_ctx_t ripemd160_hmac_ctx2 = ripemd160_hmac_ctx;

    w0[0] = j << 24;
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

    ripemd160_hmac_update_64 (&ripemd160_hmac_ctx2, w0, w1, w2, w3, 4);

    ripemd160_hmac_final (&ripemd160_hmac_ctx2);

    tmps[gid].dgst[i + 0] = ripemd160_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = ripemd160_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = ripemd160_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = ripemd160_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = ripemd160_hmac_ctx2.opad.h[4];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
  }
}

KERNEL_FQ void m06213_loop (KERN_ATTR_TMPS_ESALT (tc_tmp_t, tc_t))
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

  for (u32 i = 0; i < 48; i += 5)
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
      w1[1] = 0x80;
      w1[2] = 0;
      w1[3] = 0;
      w2[0] = 0;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = (64 + 20) * 8;
      w3[3] = 0;

      hmac_ripemd160_run_V (w0, w1, w2, w3, ipad, opad, dgst);

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

KERNEL_FQ void m06213_comp (KERN_ATTR_TMPS_ESALT (tc_tmp_t, tc_t))
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

  u32 ukey1[8];

  ukey1[0] = tmps[gid].out[ 0];
  ukey1[1] = tmps[gid].out[ 1];
  ukey1[2] = tmps[gid].out[ 2];
  ukey1[3] = tmps[gid].out[ 3];
  ukey1[4] = tmps[gid].out[ 4];
  ukey1[5] = tmps[gid].out[ 5];
  ukey1[6] = tmps[gid].out[ 6];
  ukey1[7] = tmps[gid].out[ 7];

  u32 ukey2[8];

  ukey2[0] = tmps[gid].out[ 8];
  ukey2[1] = tmps[gid].out[ 9];
  ukey2[2] = tmps[gid].out[10];
  ukey2[3] = tmps[gid].out[11];
  ukey2[4] = tmps[gid].out[12];
  ukey2[5] = tmps[gid].out[13];
  ukey2[6] = tmps[gid].out[14];
  ukey2[7] = tmps[gid].out[15];

  if (verify_header_serpent (esalt_bufs[0].data_buf, esalt_bufs[0].signature, ukey1, ukey2) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }

  if (verify_header_twofish (esalt_bufs[0].data_buf, esalt_bufs[0].signature, ukey1, ukey2) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }

  if (verify_header_aes (esalt_bufs[0].data_buf, esalt_bufs[0].signature, ukey1, ukey2, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }

  u32 ukey3[8];

  ukey3[0] = tmps[gid].out[16];
  ukey3[1] = tmps[gid].out[17];
  ukey3[2] = tmps[gid].out[18];
  ukey3[3] = tmps[gid].out[19];
  ukey3[4] = tmps[gid].out[20];
  ukey3[5] = tmps[gid].out[21];
  ukey3[6] = tmps[gid].out[22];
  ukey3[7] = tmps[gid].out[23];

  u32 ukey4[8];

  ukey4[0] = tmps[gid].out[24];
  ukey4[1] = tmps[gid].out[25];
  ukey4[2] = tmps[gid].out[26];
  ukey4[3] = tmps[gid].out[27];
  ukey4[4] = tmps[gid].out[28];
  ukey4[5] = tmps[gid].out[29];
  ukey4[6] = tmps[gid].out[30];
  ukey4[7] = tmps[gid].out[31];

  if (verify_header_serpent_aes (esalt_bufs[0].data_buf, esalt_bufs[0].signature, ukey1, ukey2, ukey3, ukey4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }

  if (verify_header_twofish_serpent (esalt_bufs[0].data_buf, esalt_bufs[0].signature, ukey1, ukey2, ukey3, ukey4) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }

  if (verify_header_aes_twofish (esalt_bufs[0].data_buf, esalt_bufs[0].signature, ukey1, ukey2, ukey3, ukey4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }

  u32 ukey5[8];

  ukey5[0] = tmps[gid].out[32];
  ukey5[1] = tmps[gid].out[33];
  ukey5[2] = tmps[gid].out[34];
  ukey5[3] = tmps[gid].out[35];
  ukey5[4] = tmps[gid].out[36];
  ukey5[5] = tmps[gid].out[37];
  ukey5[6] = tmps[gid].out[38];
  ukey5[7] = tmps[gid].out[39];

  u32 ukey6[8];

  ukey6[0] = tmps[gid].out[40];
  ukey6[1] = tmps[gid].out[41];
  ukey6[2] = tmps[gid].out[42];
  ukey6[3] = tmps[gid].out[43];
  ukey6[4] = tmps[gid].out[44];
  ukey6[5] = tmps[gid].out[45];
  ukey6[6] = tmps[gid].out[46];
  ukey6[7] = tmps[gid].out[47];

  if (verify_header_serpent_twofish_aes (esalt_bufs[0].data_buf, esalt_bufs[0].signature, ukey1, ukey2, ukey3, ukey4, ukey5, ukey6, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }

  if (verify_header_aes_twofish_serpent (esalt_bufs[0].data_buf, esalt_bufs[0].signature, ukey1, ukey2, ukey3, ukey4, ukey5, ukey6, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }
}
