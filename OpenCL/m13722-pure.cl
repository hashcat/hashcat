/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha512.cl"
#include "inc_cipher_aes.cl"
#include "inc_cipher_twofish.cl"
#include "inc_cipher_serpent.cl"
#include "inc_cipher_camellia.cl"
#include "inc_cipher_kuznyechik.cl"
#endif

typedef struct vc
{
  u32 salt_buf[32];
  u32 data_buf[112];
  u32 keyfile_buf[16];
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

  int pim_multi; // 2048 for boot (not SHA-512 or Whirlpool), 1000 for others
  int pim_start;
  int pim_stop;

} vc_t;

#ifdef KERNEL_STATIC
#include "inc_truecrypt_keyfile.cl"
#include "inc_truecrypt_crc32.cl"
#include "inc_truecrypt_xts.cl"
#include "inc_veracrypt_xts.cl"
#endif

typedef struct vc64_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

  u64 pim_key[32];
  int pim; // marker for cracked

} vc64_tmp_t;

DECLSPEC int check_header_0512 (GLOBAL_AS const vc_t *esalt_bufs, GLOBAL_AS u64 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 key1[8];
  u32 key2[8];

  key1[0] = hc_swap32_S (h32_from_64_S (key[0]));
  key1[1] = hc_swap32_S (l32_from_64_S (key[0]));
  key1[2] = hc_swap32_S (h32_from_64_S (key[1]));
  key1[3] = hc_swap32_S (l32_from_64_S (key[1]));
  key1[4] = hc_swap32_S (h32_from_64_S (key[2]));
  key1[5] = hc_swap32_S (l32_from_64_S (key[2]));
  key1[6] = hc_swap32_S (h32_from_64_S (key[3]));
  key1[7] = hc_swap32_S (l32_from_64_S (key[3]));
  key2[0] = hc_swap32_S (h32_from_64_S (key[4]));
  key2[1] = hc_swap32_S (l32_from_64_S (key[4]));
  key2[2] = hc_swap32_S (h32_from_64_S (key[5]));
  key2[3] = hc_swap32_S (l32_from_64_S (key[5]));
  key2[4] = hc_swap32_S (h32_from_64_S (key[6]));
  key2[5] = hc_swap32_S (l32_from_64_S (key[6]));
  key2[6] = hc_swap32_S (h32_from_64_S (key[7]));
  key2[7] = hc_swap32_S (l32_from_64_S (key[7]));

  if (verify_header_serpent    (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2) == 1) return 0;
  if (verify_header_twofish    (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2) == 1) return 0;
  if (verify_header_camellia   (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2) == 1) return 0;
  if (verify_header_kuznyechik (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2) == 1) return 0;
  if (verify_header_aes        (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;

  return -1;
}

DECLSPEC int check_header_1024 (GLOBAL_AS const vc_t *esalt_bufs, GLOBAL_AS u64 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 key1[8];
  u32 key2[8];
  u32 key3[8];
  u32 key4[8];

  key1[0] = hc_swap32_S (h32_from_64_S (key[ 0]));
  key1[1] = hc_swap32_S (l32_from_64_S (key[ 0]));
  key1[2] = hc_swap32_S (h32_from_64_S (key[ 1]));
  key1[3] = hc_swap32_S (l32_from_64_S (key[ 1]));
  key1[4] = hc_swap32_S (h32_from_64_S (key[ 2]));
  key1[5] = hc_swap32_S (l32_from_64_S (key[ 2]));
  key1[6] = hc_swap32_S (h32_from_64_S (key[ 3]));
  key1[7] = hc_swap32_S (l32_from_64_S (key[ 3]));
  key2[0] = hc_swap32_S (h32_from_64_S (key[ 4]));
  key2[1] = hc_swap32_S (l32_from_64_S (key[ 4]));
  key2[2] = hc_swap32_S (h32_from_64_S (key[ 5]));
  key2[3] = hc_swap32_S (l32_from_64_S (key[ 5]));
  key2[4] = hc_swap32_S (h32_from_64_S (key[ 6]));
  key2[5] = hc_swap32_S (l32_from_64_S (key[ 6]));
  key2[6] = hc_swap32_S (h32_from_64_S (key[ 7]));
  key2[7] = hc_swap32_S (l32_from_64_S (key[ 7]));
  key3[0] = hc_swap32_S (h32_from_64_S (key[ 8]));
  key3[1] = hc_swap32_S (l32_from_64_S (key[ 8]));
  key3[2] = hc_swap32_S (h32_from_64_S (key[ 9]));
  key3[3] = hc_swap32_S (l32_from_64_S (key[ 9]));
  key3[4] = hc_swap32_S (h32_from_64_S (key[10]));
  key3[5] = hc_swap32_S (l32_from_64_S (key[10]));
  key3[6] = hc_swap32_S (h32_from_64_S (key[11]));
  key3[7] = hc_swap32_S (l32_from_64_S (key[11]));
  key4[0] = hc_swap32_S (h32_from_64_S (key[12]));
  key4[1] = hc_swap32_S (l32_from_64_S (key[12]));
  key4[2] = hc_swap32_S (h32_from_64_S (key[13]));
  key4[3] = hc_swap32_S (l32_from_64_S (key[13]));
  key4[4] = hc_swap32_S (h32_from_64_S (key[14]));
  key4[5] = hc_swap32_S (l32_from_64_S (key[14]));
  key4[6] = hc_swap32_S (h32_from_64_S (key[15]));
  key4[7] = hc_swap32_S (l32_from_64_S (key[15]));

  if (verify_header_serpent_aes         (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2, key3, key4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;
  if (verify_header_twofish_serpent     (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2, key3, key4) == 1) return 0;
  if (verify_header_aes_twofish         (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2, key3, key4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;
  if (verify_header_camellia_kuznyechik (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2, key3, key4) == 1) return 0;
  if (verify_header_camellia_serpent    (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2, key3, key4) == 1) return 0;
  if (verify_header_kuznyechik_twofish  (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2, key3, key4) == 1) return 0;
  if (verify_header_kuznyechik_aes      (esalt_bufs[0].data_buf, esalt_bufs[0].signature, key1, key2, key3, key4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;

  return -1;
}

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

KERNEL_FQ void m13722_init (KERN_ATTR_TMPS_ESALT (vc64_tmp_t, vc_t))
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
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

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
  w4[0] = pws[gid].i[16];
  w4[1] = pws[gid].i[17];
  w4[2] = pws[gid].i[18];
  w4[3] = pws[gid].i[19];
  w5[0] = pws[gid].i[20];
  w5[1] = pws[gid].i[21];
  w5[2] = pws[gid].i[22];
  w5[3] = pws[gid].i[23];
  w6[0] = pws[gid].i[24];
  w6[1] = pws[gid].i[25];
  w6[2] = pws[gid].i[26];
  w6[3] = pws[gid].i[27];
  w7[0] = pws[gid].i[28];
  w7[1] = pws[gid].i[29];
  w7[2] = pws[gid].i[30];
  w7[3] = pws[gid].i[31];

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
  w4[0] = hc_swap32_S (w4[0]);
  w4[1] = hc_swap32_S (w4[1]);
  w4[2] = hc_swap32_S (w4[2]);
  w4[3] = hc_swap32_S (w4[3]);
  w5[0] = hc_swap32_S (w5[0]);
  w5[1] = hc_swap32_S (w5[1]);
  w5[2] = hc_swap32_S (w5[2]);
  w5[3] = hc_swap32_S (w5[3]);
  w6[0] = hc_swap32_S (w6[0]);
  w6[1] = hc_swap32_S (w6[1]);
  w6[2] = hc_swap32_S (w6[2]);
  w6[3] = hc_swap32_S (w6[3]);
  w7[0] = hc_swap32_S (w7[0]);
  w7[1] = hc_swap32_S (w7[1]);
  w7[2] = hc_swap32_S (w7[2]);
  w7[3] = hc_swap32_S (w7[3]);

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_128 (&sha512_hmac_ctx, w0, w1, w2, w3, w5, w5, w6, w7);

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

  sha512_hmac_update_global_swap (&sha512_hmac_ctx, esalt_bufs[digests_offset].salt_buf, 64);

  for (u32 i = 0, j = 1; i < 16; i += 8, j += 1)
  {
    sha512_hmac_ctx_t sha512_hmac_ctx2 = sha512_hmac_ctx;

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

KERNEL_FQ void m13722_loop (KERN_ATTR_TMPS_ESALT (vc64_tmp_t, vc_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
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

  // this is the pim range check
  // it is guaranteed that only 0 or 1 innerloops will match a "pim" mark (each 1000 iterations)
  // therefore the module limits the inner loop iteration count to 1000
  // if the key_pim is set, we know that we have to save and check the key for this pim

  const int pim_multi = esalt_bufs[digests_offset].pim_multi;
  const int pim_start = esalt_bufs[digests_offset].pim_start;
  const int pim_stop  = esalt_bufs[digests_offset].pim_stop;

  int pim    = 0;
  int pim_at = 0;

  for (u32 j = 0; j < loop_cnt; j++)
  {
    const int iter_abs = 1 + loop_pos + j;

    if ((iter_abs % pim_multi) == pim_multi - 1)
    {
      const int pim_cur = (iter_abs / pim_multi) + 1;

      if ((pim_cur >= pim_start) && (pim_cur <= pim_stop))
      {
        pim = pim_cur;

        pim_at = j;
      }
    }
  }

  // irregular pbkdf2 from here

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

  for (u32 i = 0; i < 16; i += 8)
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

      // this iteration creates a valid pim

      if (j == pim_at)
      {
        tmps[gid].pim_key[i + 0] = out[0];
        tmps[gid].pim_key[i + 1] = out[1];
        tmps[gid].pim_key[i + 2] = out[2];
        tmps[gid].pim_key[i + 3] = out[3];
        tmps[gid].pim_key[i + 4] = out[4];
        tmps[gid].pim_key[i + 5] = out[5];
        tmps[gid].pim_key[i + 6] = out[6];
        tmps[gid].pim_key[i + 7] = out[7];
      }
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

  if (pim == 0) return;

  if (check_header_0512 (esalt_bufs, tmps[gid].pim_key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1) tmps[gid].pim = pim;
  if (check_header_1024 (esalt_bufs, tmps[gid].pim_key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1) tmps[gid].pim = pim;
}

KERNEL_FQ void m13722_comp (KERN_ATTR_TMPS_ESALT (vc64_tmp_t, vc_t))
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

  if (tmps[gid].pim)
  {
    if (atomic_inc (&hashes_shown[0]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
    }
  }
  else
  {
    if (check_header_0512 (esalt_bufs, tmps[gid].out, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
    {
      if (atomic_inc (&hashes_shown[0]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
      }
    }

    if (check_header_1024 (esalt_bufs, tmps[gid].out, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
    {
      if (atomic_inc (&hashes_shown[0]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, 0, gid, 0, 0, 0);
      }
    }
  }
}
