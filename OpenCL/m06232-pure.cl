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
#include "inc_hash_whirlpool.cl"
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

DECLSPEC void hmac_whirlpool_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest, SHM_TYPE u32 (*s_Ch)[256], SHM_TYPE u32 (*s_Cl)[256])
{
  digest[ 0] = ipad[ 0];
  digest[ 1] = ipad[ 1];
  digest[ 2] = ipad[ 2];
  digest[ 3] = ipad[ 3];
  digest[ 4] = ipad[ 4];
  digest[ 5] = ipad[ 5];
  digest[ 6] = ipad[ 6];
  digest[ 7] = ipad[ 7];
  digest[ 8] = ipad[ 8];
  digest[ 9] = ipad[ 9];
  digest[10] = ipad[10];
  digest[11] = ipad[11];
  digest[12] = ipad[12];
  digest[13] = ipad[13];
  digest[14] = ipad[14];
  digest[15] = ipad[15];

  whirlpool_transform_vector (w0, w1, w2, w3, digest, s_Ch, s_Cl);

  w0[0] = 0x80000000;
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
  w3[3] = (64 + 64) * 8;

  whirlpool_transform_vector (w0, w1, w2, w3, digest, s_Ch, s_Cl);

  w0[0] = digest[ 0];
  w0[1] = digest[ 1];
  w0[2] = digest[ 2];
  w0[3] = digest[ 3];
  w1[0] = digest[ 4];
  w1[1] = digest[ 5];
  w1[2] = digest[ 6];
  w1[3] = digest[ 7];
  w2[0] = digest[ 8];
  w2[1] = digest[ 9];
  w2[2] = digest[10];
  w2[3] = digest[11];
  w3[0] = digest[12];
  w3[1] = digest[13];
  w3[2] = digest[14];
  w3[3] = digest[15];

  digest[ 0] = opad[ 0];
  digest[ 1] = opad[ 1];
  digest[ 2] = opad[ 2];
  digest[ 3] = opad[ 3];
  digest[ 4] = opad[ 4];
  digest[ 5] = opad[ 5];
  digest[ 6] = opad[ 6];
  digest[ 7] = opad[ 7];
  digest[ 8] = opad[ 8];
  digest[ 9] = opad[ 9];
  digest[10] = opad[10];
  digest[11] = opad[11];
  digest[12] = opad[12];
  digest[13] = opad[13];
  digest[14] = opad[14];
  digest[15] = opad[15];

  whirlpool_transform_vector (w0, w1, w2, w3, digest, s_Ch, s_Cl);

  w0[0] = 0x80000000;
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
  w3[3] = (64 + 64) * 8;

  whirlpool_transform_vector (w0, w1, w2, w3, digest, s_Ch, s_Cl);
}

KERNEL_FQ void m06232_init (KERN_ATTR_TMPS_ESALT (tc_tmp_t, tc_t))
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

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_Ch[8][256];
  LOCAL_VK u32 s_Cl[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_Ch[0][i] = Ch[0][i];
    s_Ch[1][i] = Ch[1][i];
    s_Ch[2][i] = Ch[2][i];
    s_Ch[3][i] = Ch[3][i];
    s_Ch[4][i] = Ch[4][i];
    s_Ch[5][i] = Ch[5][i];
    s_Ch[6][i] = Ch[6][i];
    s_Ch[7][i] = Ch[7][i];

    s_Cl[0][i] = Cl[0][i];
    s_Cl[1][i] = Cl[1][i];
    s_Cl[2][i] = Cl[2][i];
    s_Cl[3][i] = Cl[3][i];
    s_Cl[4][i] = Cl[4][i];
    s_Cl[5][i] = Cl[5][i];
    s_Cl[6][i] = Cl[6][i];
    s_Cl[7][i] = Cl[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_Ch)[256] = Ch;
  CONSTANT_AS u32a (*s_Cl)[256] = Cl;

  #endif

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

  w0[0] = hc_swap32_S (w0[0]);
  w0[1] = hc_swap32_S (w0[1]);
  w0[2] = hc_swap32_S (w0[2]);
  w0[3] = hc_swap32_S (w0[3]);
  w1[0] = hc_swap32_S (w1[0]);
  w1[1] = hc_swap32_S (w1[1]);
  w1[2] = hc_swap32_S (w1[2]);
  w1[3] = hc_swap32_S (w1[3]);
  w2[0] = hc_swap32_S (w2[0]);
  w2[1] = hc_swap32_S (w2[1]);
  w2[2] = hc_swap32_S (w2[2]);
  w2[3] = hc_swap32_S (w2[3]);
  w3[0] = hc_swap32_S (w3[0]);
  w3[1] = hc_swap32_S (w3[1]);
  w3[2] = hc_swap32_S (w3[2]);
  w3[3] = hc_swap32_S (w3[3]);

  whirlpool_hmac_ctx_t whirlpool_hmac_ctx;

  whirlpool_hmac_init_64 (&whirlpool_hmac_ctx, w0, w1, w2, w3, s_Ch, s_Cl);

  tmps[gid].ipad[ 0] = whirlpool_hmac_ctx.ipad.h[ 0];
  tmps[gid].ipad[ 1] = whirlpool_hmac_ctx.ipad.h[ 1];
  tmps[gid].ipad[ 2] = whirlpool_hmac_ctx.ipad.h[ 2];
  tmps[gid].ipad[ 3] = whirlpool_hmac_ctx.ipad.h[ 3];
  tmps[gid].ipad[ 4] = whirlpool_hmac_ctx.ipad.h[ 4];
  tmps[gid].ipad[ 5] = whirlpool_hmac_ctx.ipad.h[ 5];
  tmps[gid].ipad[ 6] = whirlpool_hmac_ctx.ipad.h[ 6];
  tmps[gid].ipad[ 7] = whirlpool_hmac_ctx.ipad.h[ 7];
  tmps[gid].ipad[ 8] = whirlpool_hmac_ctx.ipad.h[ 8];
  tmps[gid].ipad[ 9] = whirlpool_hmac_ctx.ipad.h[ 9];
  tmps[gid].ipad[10] = whirlpool_hmac_ctx.ipad.h[10];
  tmps[gid].ipad[11] = whirlpool_hmac_ctx.ipad.h[11];
  tmps[gid].ipad[12] = whirlpool_hmac_ctx.ipad.h[12];
  tmps[gid].ipad[13] = whirlpool_hmac_ctx.ipad.h[13];
  tmps[gid].ipad[14] = whirlpool_hmac_ctx.ipad.h[14];
  tmps[gid].ipad[15] = whirlpool_hmac_ctx.ipad.h[15];

  tmps[gid].opad[ 0] = whirlpool_hmac_ctx.opad.h[ 0];
  tmps[gid].opad[ 1] = whirlpool_hmac_ctx.opad.h[ 1];
  tmps[gid].opad[ 2] = whirlpool_hmac_ctx.opad.h[ 2];
  tmps[gid].opad[ 3] = whirlpool_hmac_ctx.opad.h[ 3];
  tmps[gid].opad[ 4] = whirlpool_hmac_ctx.opad.h[ 4];
  tmps[gid].opad[ 5] = whirlpool_hmac_ctx.opad.h[ 5];
  tmps[gid].opad[ 6] = whirlpool_hmac_ctx.opad.h[ 6];
  tmps[gid].opad[ 7] = whirlpool_hmac_ctx.opad.h[ 7];
  tmps[gid].opad[ 8] = whirlpool_hmac_ctx.opad.h[ 8];
  tmps[gid].opad[ 9] = whirlpool_hmac_ctx.opad.h[ 9];
  tmps[gid].opad[10] = whirlpool_hmac_ctx.opad.h[10];
  tmps[gid].opad[11] = whirlpool_hmac_ctx.opad.h[11];
  tmps[gid].opad[12] = whirlpool_hmac_ctx.opad.h[12];
  tmps[gid].opad[13] = whirlpool_hmac_ctx.opad.h[13];
  tmps[gid].opad[14] = whirlpool_hmac_ctx.opad.h[14];
  tmps[gid].opad[15] = whirlpool_hmac_ctx.opad.h[15];

  whirlpool_hmac_update_global_swap (&whirlpool_hmac_ctx, esalt_bufs[digests_offset].salt_buf, 64);

  for (u32 i = 0, j = 1; i < 32; i += 16, j += 1)
  {
    whirlpool_hmac_ctx_t whirlpool_hmac_ctx2 = whirlpool_hmac_ctx;

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

    whirlpool_hmac_update_64 (&whirlpool_hmac_ctx2, w0, w1, w2, w3, 4);

    whirlpool_hmac_final (&whirlpool_hmac_ctx2);

    tmps[gid].dgst[i +  0] = whirlpool_hmac_ctx2.opad.h[ 0];
    tmps[gid].dgst[i +  1] = whirlpool_hmac_ctx2.opad.h[ 1];
    tmps[gid].dgst[i +  2] = whirlpool_hmac_ctx2.opad.h[ 2];
    tmps[gid].dgst[i +  3] = whirlpool_hmac_ctx2.opad.h[ 3];
    tmps[gid].dgst[i +  4] = whirlpool_hmac_ctx2.opad.h[ 4];
    tmps[gid].dgst[i +  5] = whirlpool_hmac_ctx2.opad.h[ 5];
    tmps[gid].dgst[i +  6] = whirlpool_hmac_ctx2.opad.h[ 6];
    tmps[gid].dgst[i +  7] = whirlpool_hmac_ctx2.opad.h[ 7];
    tmps[gid].dgst[i +  8] = whirlpool_hmac_ctx2.opad.h[ 8];
    tmps[gid].dgst[i +  9] = whirlpool_hmac_ctx2.opad.h[ 9];
    tmps[gid].dgst[i + 10] = whirlpool_hmac_ctx2.opad.h[10];
    tmps[gid].dgst[i + 11] = whirlpool_hmac_ctx2.opad.h[11];
    tmps[gid].dgst[i + 12] = whirlpool_hmac_ctx2.opad.h[12];
    tmps[gid].dgst[i + 13] = whirlpool_hmac_ctx2.opad.h[13];
    tmps[gid].dgst[i + 14] = whirlpool_hmac_ctx2.opad.h[14];
    tmps[gid].dgst[i + 15] = whirlpool_hmac_ctx2.opad.h[15];

    tmps[gid].out[i +  0] = tmps[gid].dgst[i +  0];
    tmps[gid].out[i +  1] = tmps[gid].dgst[i +  1];
    tmps[gid].out[i +  2] = tmps[gid].dgst[i +  2];
    tmps[gid].out[i +  3] = tmps[gid].dgst[i +  3];
    tmps[gid].out[i +  4] = tmps[gid].dgst[i +  4];
    tmps[gid].out[i +  5] = tmps[gid].dgst[i +  5];
    tmps[gid].out[i +  6] = tmps[gid].dgst[i +  6];
    tmps[gid].out[i +  7] = tmps[gid].dgst[i +  7];
    tmps[gid].out[i +  8] = tmps[gid].dgst[i +  8];
    tmps[gid].out[i +  9] = tmps[gid].dgst[i +  9];
    tmps[gid].out[i + 10] = tmps[gid].dgst[i + 10];
    tmps[gid].out[i + 11] = tmps[gid].dgst[i + 11];
    tmps[gid].out[i + 12] = tmps[gid].dgst[i + 12];
    tmps[gid].out[i + 13] = tmps[gid].dgst[i + 13];
    tmps[gid].out[i + 14] = tmps[gid].dgst[i + 14];
    tmps[gid].out[i + 15] = tmps[gid].dgst[i + 15];
  }
}

KERNEL_FQ void m06232_loop (KERN_ATTR_TMPS_ESALT (tc_tmp_t, tc_t))
{
  /**
   * Whirlpool shared
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  #ifdef REAL_SHM

  LOCAL_VK u32 s_Ch[8][256];
  LOCAL_VK u32 s_Cl[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_Ch[0][i] = Ch[0][i];
    s_Ch[1][i] = Ch[1][i];
    s_Ch[2][i] = Ch[2][i];
    s_Ch[3][i] = Ch[3][i];
    s_Ch[4][i] = Ch[4][i];
    s_Ch[5][i] = Ch[5][i];
    s_Ch[6][i] = Ch[6][i];
    s_Ch[7][i] = Ch[7][i];

    s_Cl[0][i] = Cl[0][i];
    s_Cl[1][i] = Cl[1][i];
    s_Cl[2][i] = Cl[2][i];
    s_Cl[3][i] = Cl[3][i];
    s_Cl[4][i] = Cl[4][i];
    s_Cl[5][i] = Cl[5][i];
    s_Cl[6][i] = Cl[6][i];
    s_Cl[7][i] = Cl[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_Ch)[256] = Ch;
  CONSTANT_AS u32a (*s_Cl)[256] = Cl;

  #endif

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[16];
  u32x opad[16];

  ipad[ 0] = packv (tmps, ipad, gid,  0);
  ipad[ 1] = packv (tmps, ipad, gid,  1);
  ipad[ 2] = packv (tmps, ipad, gid,  2);
  ipad[ 3] = packv (tmps, ipad, gid,  3);
  ipad[ 4] = packv (tmps, ipad, gid,  4);
  ipad[ 5] = packv (tmps, ipad, gid,  5);
  ipad[ 6] = packv (tmps, ipad, gid,  6);
  ipad[ 7] = packv (tmps, ipad, gid,  7);
  ipad[ 8] = packv (tmps, ipad, gid,  8);
  ipad[ 9] = packv (tmps, ipad, gid,  9);
  ipad[10] = packv (tmps, ipad, gid, 10);
  ipad[11] = packv (tmps, ipad, gid, 11);
  ipad[12] = packv (tmps, ipad, gid, 12);
  ipad[13] = packv (tmps, ipad, gid, 13);
  ipad[14] = packv (tmps, ipad, gid, 14);
  ipad[15] = packv (tmps, ipad, gid, 15);

  opad[ 0] = packv (tmps, opad, gid,  0);
  opad[ 1] = packv (tmps, opad, gid,  1);
  opad[ 2] = packv (tmps, opad, gid,  2);
  opad[ 3] = packv (tmps, opad, gid,  3);
  opad[ 4] = packv (tmps, opad, gid,  4);
  opad[ 5] = packv (tmps, opad, gid,  5);
  opad[ 6] = packv (tmps, opad, gid,  6);
  opad[ 7] = packv (tmps, opad, gid,  7);
  opad[ 8] = packv (tmps, opad, gid,  8);
  opad[ 9] = packv (tmps, opad, gid,  9);
  opad[10] = packv (tmps, opad, gid, 10);
  opad[11] = packv (tmps, opad, gid, 11);
  opad[12] = packv (tmps, opad, gid, 12);
  opad[13] = packv (tmps, opad, gid, 13);
  opad[14] = packv (tmps, opad, gid, 14);
  opad[15] = packv (tmps, opad, gid, 15);

  for (u32 i = 0; i < 32; i += 16)
  {
    u32x dgst[16];
    u32x out[16];

    dgst[ 0] = packv (tmps, dgst, gid, i +  0);
    dgst[ 1] = packv (tmps, dgst, gid, i +  1);
    dgst[ 2] = packv (tmps, dgst, gid, i +  2);
    dgst[ 3] = packv (tmps, dgst, gid, i +  3);
    dgst[ 4] = packv (tmps, dgst, gid, i +  4);
    dgst[ 5] = packv (tmps, dgst, gid, i +  5);
    dgst[ 6] = packv (tmps, dgst, gid, i +  6);
    dgst[ 7] = packv (tmps, dgst, gid, i +  7);
    dgst[ 8] = packv (tmps, dgst, gid, i +  8);
    dgst[ 9] = packv (tmps, dgst, gid, i +  9);
    dgst[10] = packv (tmps, dgst, gid, i + 10);
    dgst[11] = packv (tmps, dgst, gid, i + 11);
    dgst[12] = packv (tmps, dgst, gid, i + 12);
    dgst[13] = packv (tmps, dgst, gid, i + 13);
    dgst[14] = packv (tmps, dgst, gid, i + 14);
    dgst[15] = packv (tmps, dgst, gid, i + 15);

    out[ 0] = packv (tmps, out, gid, i +  0);
    out[ 1] = packv (tmps, out, gid, i +  1);
    out[ 2] = packv (tmps, out, gid, i +  2);
    out[ 3] = packv (tmps, out, gid, i +  3);
    out[ 4] = packv (tmps, out, gid, i +  4);
    out[ 5] = packv (tmps, out, gid, i +  5);
    out[ 6] = packv (tmps, out, gid, i +  6);
    out[ 7] = packv (tmps, out, gid, i +  7);
    out[ 8] = packv (tmps, out, gid, i +  8);
    out[ 9] = packv (tmps, out, gid, i +  9);
    out[10] = packv (tmps, out, gid, i + 10);
    out[11] = packv (tmps, out, gid, i + 11);
    out[12] = packv (tmps, out, gid, i + 12);
    out[13] = packv (tmps, out, gid, i + 13);
    out[14] = packv (tmps, out, gid, i + 14);
    out[15] = packv (tmps, out, gid, i + 15);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[ 0];
      w0[1] = dgst[ 1];
      w0[2] = dgst[ 2];
      w0[3] = dgst[ 3];
      w1[0] = dgst[ 4];
      w1[1] = dgst[ 5];
      w1[2] = dgst[ 6];
      w1[3] = dgst[ 7];
      w2[0] = dgst[ 8];
      w2[1] = dgst[ 9];
      w2[2] = dgst[10];
      w2[3] = dgst[11];
      w3[0] = dgst[12];
      w3[1] = dgst[13];
      w3[2] = dgst[14];
      w3[3] = dgst[15];

      hmac_whirlpool_run_V (w0, w1, w2, w3, ipad, opad, dgst, s_Ch, s_Cl);

      out[ 0] ^= dgst[ 0];
      out[ 1] ^= dgst[ 1];
      out[ 2] ^= dgst[ 2];
      out[ 3] ^= dgst[ 3];
      out[ 4] ^= dgst[ 4];
      out[ 5] ^= dgst[ 5];
      out[ 6] ^= dgst[ 6];
      out[ 7] ^= dgst[ 7];
      out[ 8] ^= dgst[ 8];
      out[ 9] ^= dgst[ 9];
      out[10] ^= dgst[10];
      out[11] ^= dgst[11];
      out[12] ^= dgst[12];
      out[13] ^= dgst[13];
      out[14] ^= dgst[14];
      out[15] ^= dgst[15];
    }

    unpackv (tmps, dgst, gid, i +  0, dgst[ 0]);
    unpackv (tmps, dgst, gid, i +  1, dgst[ 1]);
    unpackv (tmps, dgst, gid, i +  2, dgst[ 2]);
    unpackv (tmps, dgst, gid, i +  3, dgst[ 3]);
    unpackv (tmps, dgst, gid, i +  4, dgst[ 4]);
    unpackv (tmps, dgst, gid, i +  5, dgst[ 5]);
    unpackv (tmps, dgst, gid, i +  6, dgst[ 6]);
    unpackv (tmps, dgst, gid, i +  7, dgst[ 7]);
    unpackv (tmps, dgst, gid, i +  8, dgst[ 8]);
    unpackv (tmps, dgst, gid, i +  9, dgst[ 9]);
    unpackv (tmps, dgst, gid, i + 10, dgst[10]);
    unpackv (tmps, dgst, gid, i + 11, dgst[11]);
    unpackv (tmps, dgst, gid, i + 12, dgst[12]);
    unpackv (tmps, dgst, gid, i + 13, dgst[13]);
    unpackv (tmps, dgst, gid, i + 14, dgst[14]);
    unpackv (tmps, dgst, gid, i + 15, dgst[15]);

    unpackv (tmps, out, gid, i +  0, out[ 0]);
    unpackv (tmps, out, gid, i +  1, out[ 1]);
    unpackv (tmps, out, gid, i +  2, out[ 2]);
    unpackv (tmps, out, gid, i +  3, out[ 3]);
    unpackv (tmps, out, gid, i +  4, out[ 4]);
    unpackv (tmps, out, gid, i +  5, out[ 5]);
    unpackv (tmps, out, gid, i +  6, out[ 6]);
    unpackv (tmps, out, gid, i +  7, out[ 7]);
    unpackv (tmps, out, gid, i +  8, out[ 8]);
    unpackv (tmps, out, gid, i +  9, out[ 9]);
    unpackv (tmps, out, gid, i + 10, out[10]);
    unpackv (tmps, out, gid, i + 11, out[11]);
    unpackv (tmps, out, gid, i + 12, out[12]);
    unpackv (tmps, out, gid, i + 13, out[13]);
    unpackv (tmps, out, gid, i + 14, out[14]);
    unpackv (tmps, out, gid, i + 15, out[15]);
  }
}

KERNEL_FQ void m06232_comp (KERN_ATTR_TMPS_ESALT (tc_tmp_t, tc_t))
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

  /**
   * Whirlpool shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_Ch[8][256];
  LOCAL_VK u32 s_Cl[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_Ch[0][i] = Ch[0][i];
    s_Ch[1][i] = Ch[1][i];
    s_Ch[2][i] = Ch[2][i];
    s_Ch[3][i] = Ch[3][i];
    s_Ch[4][i] = Ch[4][i];
    s_Ch[5][i] = Ch[5][i];
    s_Ch[6][i] = Ch[6][i];
    s_Ch[7][i] = Ch[7][i];

    s_Cl[0][i] = Cl[0][i];
    s_Cl[1][i] = Cl[1][i];
    s_Cl[2][i] = Cl[2][i];
    s_Cl[3][i] = Cl[3][i];
    s_Cl[4][i] = Cl[4][i];
    s_Cl[5][i] = Cl[5][i];
    s_Cl[6][i] = Cl[6][i];
    s_Cl[7][i] = Cl[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a (*s_Ch)[256] = Ch;
  CONSTANT_AS u32a (*s_Cl)[256] = Cl;

  #endif

  if (gid >= gid_max) return;

  u32 ukey1[8];

  ukey1[0] = hc_swap32_S (tmps[gid].out[ 0]);
  ukey1[1] = hc_swap32_S (tmps[gid].out[ 1]);
  ukey1[2] = hc_swap32_S (tmps[gid].out[ 2]);
  ukey1[3] = hc_swap32_S (tmps[gid].out[ 3]);
  ukey1[4] = hc_swap32_S (tmps[gid].out[ 4]);
  ukey1[5] = hc_swap32_S (tmps[gid].out[ 5]);
  ukey1[6] = hc_swap32_S (tmps[gid].out[ 6]);
  ukey1[7] = hc_swap32_S (tmps[gid].out[ 7]);

  u32 ukey2[8];

  ukey2[0] = hc_swap32_S (tmps[gid].out[ 8]);
  ukey2[1] = hc_swap32_S (tmps[gid].out[ 9]);
  ukey2[2] = hc_swap32_S (tmps[gid].out[10]);
  ukey2[3] = hc_swap32_S (tmps[gid].out[11]);
  ukey2[4] = hc_swap32_S (tmps[gid].out[12]);
  ukey2[5] = hc_swap32_S (tmps[gid].out[13]);
  ukey2[6] = hc_swap32_S (tmps[gid].out[14]);
  ukey2[7] = hc_swap32_S (tmps[gid].out[15]);

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

  ukey3[0] = hc_swap32_S (tmps[gid].out[16]);
  ukey3[1] = hc_swap32_S (tmps[gid].out[17]);
  ukey3[2] = hc_swap32_S (tmps[gid].out[18]);
  ukey3[3] = hc_swap32_S (tmps[gid].out[19]);
  ukey3[4] = hc_swap32_S (tmps[gid].out[20]);
  ukey3[5] = hc_swap32_S (tmps[gid].out[21]);
  ukey3[6] = hc_swap32_S (tmps[gid].out[22]);
  ukey3[7] = hc_swap32_S (tmps[gid].out[23]);

  u32 ukey4[8];

  ukey4[0] = hc_swap32_S (tmps[gid].out[24]);
  ukey4[1] = hc_swap32_S (tmps[gid].out[25]);
  ukey4[2] = hc_swap32_S (tmps[gid].out[26]);
  ukey4[3] = hc_swap32_S (tmps[gid].out[27]);
  ukey4[4] = hc_swap32_S (tmps[gid].out[28]);
  ukey4[5] = hc_swap32_S (tmps[gid].out[29]);
  ukey4[6] = hc_swap32_S (tmps[gid].out[30]);
  ukey4[7] = hc_swap32_S (tmps[gid].out[31]);

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
}
