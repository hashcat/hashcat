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
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_twofish.cl)
#include M2S(INCLUDE_PATH/inc_cipher_serpent.cl)
#include M2S(INCLUDE_PATH/inc_cipher_camellia.cl)
#include M2S(INCLUDE_PATH/inc_cipher_kuznyechik.cl)
#endif

typedef struct vc
{
  u32 data_buf[112];
  u32 keyfile_buf16[16];
  u32 keyfile_buf32[32];
  u32 keyfile_enabled;
  u32 signature;

  keyboard_layout_mapping_t keyboard_layout_mapping_buf[256];
  int                       keyboard_layout_mapping_cnt;

  int pim_multi; // 2048 for boot (not SHA-512 or Whirlpool), 1000 for others
  int pim_start;
  int pim_stop;

} vc_t;

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_truecrypt_crc32.cl)
#include M2S(INCLUDE_PATH/inc_truecrypt_xts.cl)
#include M2S(INCLUDE_PATH/inc_veracrypt_xts.cl)
#include M2S(INCLUDE_PATH/inc_veracrypt_keyfile.cl)
#endif

typedef struct vc64_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[32];
  u64  out[32];

  u64 pim_key[32];
  int pim; // marker for cracked
  int pim_check; // marker for _extended kernel

} vc64_tmp_t;

DECLSPEC int check_header_0512 (GLOBAL_AS const vc_t *esalt_bufs, GLOBAL_AS const kernel_param_t *kernel_param, GLOBAL_AS u64 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
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

  if (verify_header_serpent    (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2) == 1) return 0;
  if (verify_header_twofish    (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2) == 1) return 0;
  if (verify_header_camellia   (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2) == 1) return 0;
  if (verify_header_kuznyechik (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2) == 1) return 0;
  if (verify_header_aes        (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;

  return -1;
}

DECLSPEC int check_header_1024 (GLOBAL_AS const vc_t *esalt_bufs, GLOBAL_AS const kernel_param_t *kernel_param, GLOBAL_AS u64 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
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

  if (verify_header_serpent_aes         (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;
  if (verify_header_twofish_serpent     (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4) == 1) return 0;
  if (verify_header_aes_twofish         (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;
  if (verify_header_camellia_kuznyechik (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4) == 1) return 0;
  if (verify_header_camellia_serpent    (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4) == 1) return 0;
  if (verify_header_kuznyechik_twofish  (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4) == 1) return 0;
  if (verify_header_kuznyechik_aes      (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;

  return -1;
}

DECLSPEC int check_header_1536 (GLOBAL_AS const vc_t *esalt_bufs, GLOBAL_AS const kernel_param_t *kernel_param, GLOBAL_AS u64 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 key1[8];
  u32 key2[8];
  u32 key3[8];
  u32 key4[8];
  u32 key5[8];
  u32 key6[8];

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
  key5[0] = hc_swap32_S (h32_from_64_S (key[16]));
  key5[1] = hc_swap32_S (l32_from_64_S (key[16]));
  key5[2] = hc_swap32_S (h32_from_64_S (key[17]));
  key5[3] = hc_swap32_S (l32_from_64_S (key[17]));
  key5[4] = hc_swap32_S (h32_from_64_S (key[18]));
  key5[5] = hc_swap32_S (l32_from_64_S (key[18]));
  key5[6] = hc_swap32_S (h32_from_64_S (key[19]));
  key5[7] = hc_swap32_S (l32_from_64_S (key[19]));
  key6[0] = hc_swap32_S (h32_from_64_S (key[20]));
  key6[1] = hc_swap32_S (l32_from_64_S (key[20]));
  key6[2] = hc_swap32_S (h32_from_64_S (key[21]));
  key6[3] = hc_swap32_S (l32_from_64_S (key[21]));
  key6[4] = hc_swap32_S (h32_from_64_S (key[22]));
  key6[5] = hc_swap32_S (l32_from_64_S (key[22]));
  key6[6] = hc_swap32_S (h32_from_64_S (key[23]));
  key6[7] = hc_swap32_S (l32_from_64_S (key[23]));

  if (verify_header_serpent_twofish_aes         (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, key5, key6, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;
  if (verify_header_kuznyechik_serpent_camellia (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, key5, key6) == 1) return 0;
  if (verify_header_aes_twofish_serpent         (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, key3, key4, key5, key6, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;

  return -1;
}

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

KERNEL_FQ void m13723_init (KERN_ATTR_TMPS_ESALT (vc64_tmp_t, vc_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * keyboard layout shared
   */

  const int keyboard_layout_mapping_cnt = esalt_bufs[DIGESTS_OFFSET_HOST].keyboard_layout_mapping_cnt;

  LOCAL_VK keyboard_layout_mapping_t s_keyboard_layout_mapping_buf[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_keyboard_layout_mapping_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].keyboard_layout_mapping_buf[i];
  }

  SYNC_THREADS ();

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 w[32];

  w[ 0] = pws[gid].i[ 0];
  w[ 1] = pws[gid].i[ 1];
  w[ 2] = pws[gid].i[ 2];
  w[ 3] = pws[gid].i[ 3];
  w[ 4] = pws[gid].i[ 4];
  w[ 5] = pws[gid].i[ 5];
  w[ 6] = pws[gid].i[ 6];
  w[ 7] = pws[gid].i[ 7];
  w[ 8] = pws[gid].i[ 8];
  w[ 9] = pws[gid].i[ 9];
  w[10] = pws[gid].i[10];
  w[11] = pws[gid].i[11];
  w[12] = pws[gid].i[12];
  w[13] = pws[gid].i[13];
  w[14] = pws[gid].i[14];
  w[15] = pws[gid].i[15];
  w[16] = pws[gid].i[16];
  w[17] = pws[gid].i[17];
  w[18] = pws[gid].i[18];
  w[19] = pws[gid].i[19];
  w[20] = pws[gid].i[20];
  w[21] = pws[gid].i[21];
  w[22] = pws[gid].i[22];
  w[23] = pws[gid].i[23];
  w[24] = pws[gid].i[24];
  w[25] = pws[gid].i[25];
  w[26] = pws[gid].i[26];
  w[27] = pws[gid].i[27];
  w[28] = pws[gid].i[28];
  w[29] = pws[gid].i[29];
  w[30] = pws[gid].i[30];
  w[31] = pws[gid].i[31];

  u32 pw_len = pws[gid].pw_len;

  hc_execute_keyboard_layout_mapping (w, pw_len, s_keyboard_layout_mapping_buf, keyboard_layout_mapping_cnt);

  pw_len = hc_apply_keyfile_vc (w, pw_len, &esalt_bufs[DIGESTS_OFFSET_HOST]);

  sha512_hmac_ctx_t sha512_hmac_ctx;

  sha512_hmac_init_swap (&sha512_hmac_ctx, w, pw_len);

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

  sha512_hmac_update_global_swap (&sha512_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, 64);

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

KERNEL_FQ void m13723_loop (KERN_ATTR_TMPS_ESALT (vc64_tmp_t, vc_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= GID_CNT) return;

  // this is the pim range check
  // it is guaranteed that only 0 or 1 innerloops will match a "pim" mark (each 1000 iterations)
  // therefore the module limits the inner loop iteration count to 1000
  // if the key_pim is set, we know that we have to save and check the key for this pim

  const int pim_multi = esalt_bufs[DIGESTS_OFFSET_HOST].pim_multi;
  const int pim_start = esalt_bufs[DIGESTS_OFFSET_HOST].pim_start;
  const int pim_stop  = esalt_bufs[DIGESTS_OFFSET_HOST].pim_stop;

  int pim    = 0;
  int pim_at = 0;

  for (u32 j = 0; j < LOOP_CNT; j++)
  {
    const int iter_abs = 1 + LOOP_POS + j;

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

      // this iteration creates a valid pim

      if (j == pim_at)
      {
        unpack64v (tmps, pim_key, gid, i + 0, out[0]);
        unpack64v (tmps, pim_key, gid, i + 1, out[1]);
        unpack64v (tmps, pim_key, gid, i + 2, out[2]);
        unpack64v (tmps, pim_key, gid, i + 3, out[3]);
        unpack64v (tmps, pim_key, gid, i + 4, out[4]);
        unpack64v (tmps, pim_key, gid, i + 5, out[5]);
        unpack64v (tmps, pim_key, gid, i + 6, out[6]);
        unpack64v (tmps, pim_key, gid, i + 7, out[7]);

        const u32x pimx = make_u32x (pim);

        unpack (tmps, pim_check, gid, pimx);
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
}

KERNEL_FQ void m13723_loop_extended (KERN_ATTR_TMPS_ESALT (vc64_tmp_t, vc_t))
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

  if (gid >= GID_CNT) return;

  const u32 pim_check = tmps[gid].pim_check;

  if (pim_check)
  {
    if (check_header_0512 (esalt_bufs, kernel_param, tmps[gid].pim_key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
    {
      tmps[gid].pim = pim_check;
    }

    if (check_header_1024 (esalt_bufs, kernel_param, tmps[gid].pim_key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
    {
      tmps[gid].pim = pim_check;
    }

    if (check_header_1536 (esalt_bufs, kernel_param, tmps[gid].pim_key, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
    {
      tmps[gid].pim = pim_check;
    }

    tmps[gid].pim_check = 0;
  }
}

KERNEL_FQ void m13723_comp (KERN_ATTR_TMPS_ESALT (vc64_tmp_t, vc_t))
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

  if (gid >= GID_CNT) return;

  if (tmps[gid].pim)
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
  else
  {
    if (check_header_0512 (esalt_bufs, kernel_param, tmps[gid].out, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
      }
    }

    if (check_header_1024 (esalt_bufs, kernel_param, tmps[gid].out, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
      }
    }

    if (check_header_1536 (esalt_bufs, kernel_param, tmps[gid].out, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) != -1)
    {
      if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
      }
    }
  }
}
