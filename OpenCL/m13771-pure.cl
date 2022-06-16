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
#include M2S(INCLUDE_PATH/inc_hash_streebog512.cl)
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

typedef struct vc64_sbog_tmp
{
  u64  ipad_raw[8];
  u64  opad_raw[8];

  u64  ipad_hash[8];
  u64  opad_hash[8];

  u64  dgst[32];
  u64  out[32];

  u64 pim_key[32];
  int pim; // marker for cracked
  int pim_check; // marker for _extended kernel

} vc64_sbog_tmp_t;

DECLSPEC int check_header_0512 (GLOBAL_AS const vc_t *esalt_bufs, GLOBAL_AS const kernel_param_t *kernel_param, GLOBAL_AS u64 *key, SHM_TYPE u32 *s_te0, SHM_TYPE u32 *s_te1, SHM_TYPE u32 *s_te2, SHM_TYPE u32 *s_te3, SHM_TYPE u32 *s_te4, SHM_TYPE u32 *s_td0, SHM_TYPE u32 *s_td1, SHM_TYPE u32 *s_td2, SHM_TYPE u32 *s_td3, SHM_TYPE u32 *s_td4)
{
  u32 key1[8];
  u32 key2[8];

  key1[0] = hc_swap32_S (h32_from_64_S (key[7]));
  key1[1] = hc_swap32_S (l32_from_64_S (key[7]));
  key1[2] = hc_swap32_S (h32_from_64_S (key[6]));
  key1[3] = hc_swap32_S (l32_from_64_S (key[6]));
  key1[4] = hc_swap32_S (h32_from_64_S (key[5]));
  key1[5] = hc_swap32_S (l32_from_64_S (key[5]));
  key1[6] = hc_swap32_S (h32_from_64_S (key[4]));
  key1[7] = hc_swap32_S (l32_from_64_S (key[4]));
  key2[0] = hc_swap32_S (h32_from_64_S (key[3]));
  key2[1] = hc_swap32_S (l32_from_64_S (key[3]));
  key2[2] = hc_swap32_S (h32_from_64_S (key[2]));
  key2[3] = hc_swap32_S (l32_from_64_S (key[2]));
  key2[4] = hc_swap32_S (h32_from_64_S (key[1]));
  key2[5] = hc_swap32_S (l32_from_64_S (key[1]));
  key2[6] = hc_swap32_S (h32_from_64_S (key[0]));
  key2[7] = hc_swap32_S (l32_from_64_S (key[0]));

  if (verify_header_serpent    (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2) == 1) return 0;
  if (verify_header_twofish    (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2) == 1) return 0;
  if (verify_header_camellia   (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2) == 1) return 0;
  if (verify_header_kuznyechik (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2) == 1) return 0;
  if (verify_header_aes        (esalt_bufs[DIGESTS_OFFSET_HOST].data_buf, esalt_bufs[DIGESTS_OFFSET_HOST].signature, key1, key2, s_te0, s_te1, s_te2, s_te3, s_te4, s_td0, s_td1, s_td2, s_td3, s_td4) == 1) return 0;

  return -1;
}

DECLSPEC void hmac_streebog512_run_V (PRIVATE_AS u32x *w0, PRIVATE_AS u32x *w1, PRIVATE_AS u32x *w2, PRIVATE_AS u32x *w3, PRIVATE_AS u64x *ipad_hash, PRIVATE_AS u64x *opad_hash, PRIVATE_AS u64x *ipad_raw, PRIVATE_AS u64x *opad_raw, PRIVATE_AS u64x *digest, SHM_TYPE u64a (*s_sbob_sl64)[256])
{
  const u64x nullbuf[8] = { 0 };
  u64x counterbuf[8]    = { 0 };
  u64x padding[8]       = { 0 };
  u64x message[8];

  padding[7] = 0x0100000000000000UL;

  //inner HMAC: ipad + message

  //first transform: precalculated ipad hash
  counterbuf[7] = 0x0002000000000000UL;

  //second transform: message = previous HMAC digest
  message[7] = hl32_to_64 (w3[2], w3[3]);
  message[6] = hl32_to_64 (w3[0], w3[1]);
  message[5] = hl32_to_64 (w2[2], w2[3]);
  message[4] = hl32_to_64 (w2[0], w2[1]);
  message[3] = hl32_to_64 (w1[2], w1[3]);
  message[2] = hl32_to_64 (w1[0], w1[1]);
  message[1] = hl32_to_64 (w0[2], w0[3]);
  message[0] = hl32_to_64 (w0[0], w0[1]);

  digest[0] = ipad_hash[0];
  digest[1] = ipad_hash[1];
  digest[2] = ipad_hash[2];
  digest[3] = ipad_hash[3];
  digest[4] = ipad_hash[4];
  digest[5] = ipad_hash[5];
  digest[6] = ipad_hash[6];
  digest[7] = ipad_hash[7];

  streebog512_g_vector (digest, counterbuf, message, s_sbob_sl64);

  counterbuf[7] = 0x0004000000000000UL;

  //final: padding byte
  streebog512_g_vector (digest, counterbuf, padding, s_sbob_sl64);

  streebog512_add_vector (message, ipad_raw);
  streebog512_add_vector (message, padding);

  streebog512_g_vector (digest, nullbuf, counterbuf, s_sbob_sl64);

  streebog512_g_vector (digest, nullbuf, message, s_sbob_sl64);

  //outer HMAC: opad + digest

  //first transform: precalculated opad hash
  counterbuf[7] = 0x0002000000000000UL;

  //second transform: message = inner HMAC digest
  message[0] = digest[0];
  message[1] = digest[1];
  message[2] = digest[2];
  message[3] = digest[3];
  message[4] = digest[4];
  message[5] = digest[5];
  message[6] = digest[6];
  message[7] = digest[7];

  digest[0] = opad_hash[0];
  digest[1] = opad_hash[1];
  digest[2] = opad_hash[2];
  digest[3] = opad_hash[3];
  digest[4] = opad_hash[4];
  digest[5] = opad_hash[5];
  digest[6] = opad_hash[6];
  digest[7] = opad_hash[7];

  streebog512_g_vector (digest, counterbuf, message, s_sbob_sl64);

  counterbuf[7] = 0x0004000000000000UL;

  streebog512_g_vector (digest, counterbuf, padding, s_sbob_sl64);

  streebog512_add_vector (message, opad_raw);
  streebog512_add_vector (message, padding);

  streebog512_g_vector (digest, nullbuf, counterbuf, s_sbob_sl64);

  streebog512_g_vector (digest, nullbuf, message, s_sbob_sl64);
}

KERNEL_FQ void m13771_init (KERN_ATTR_TMPS_ESALT (vc64_sbog_tmp_t, vc_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  const int keyboard_layout_mapping_cnt = esalt_bufs[DIGESTS_OFFSET_HOST].keyboard_layout_mapping_cnt;

  LOCAL_VK keyboard_layout_mapping_t s_keyboard_layout_mapping_buf[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_keyboard_layout_mapping_buf[i] = esalt_bufs[DIGESTS_OFFSET_HOST].keyboard_layout_mapping_buf[i];
  }

  SYNC_THREADS ();

  #ifdef REAL_SHM

  LOCAL_VK u64a s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob512_sl64;

  #endif

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

  streebog512_hmac_ctx_t streebog512_hmac_ctx;

  streebog512_hmac_init_swap (&streebog512_hmac_ctx, w, pw_len, s_sbob_sl64);

  tmps[gid].ipad_hash[0] = streebog512_hmac_ctx.ipad.h[0];
  tmps[gid].ipad_hash[1] = streebog512_hmac_ctx.ipad.h[1];
  tmps[gid].ipad_hash[2] = streebog512_hmac_ctx.ipad.h[2];
  tmps[gid].ipad_hash[3] = streebog512_hmac_ctx.ipad.h[3];
  tmps[gid].ipad_hash[4] = streebog512_hmac_ctx.ipad.h[4];
  tmps[gid].ipad_hash[5] = streebog512_hmac_ctx.ipad.h[5];
  tmps[gid].ipad_hash[6] = streebog512_hmac_ctx.ipad.h[6];
  tmps[gid].ipad_hash[7] = streebog512_hmac_ctx.ipad.h[7];

  tmps[gid].opad_hash[0] = streebog512_hmac_ctx.opad.h[0];
  tmps[gid].opad_hash[1] = streebog512_hmac_ctx.opad.h[1];
  tmps[gid].opad_hash[2] = streebog512_hmac_ctx.opad.h[2];
  tmps[gid].opad_hash[3] = streebog512_hmac_ctx.opad.h[3];
  tmps[gid].opad_hash[4] = streebog512_hmac_ctx.opad.h[4];
  tmps[gid].opad_hash[5] = streebog512_hmac_ctx.opad.h[5];
  tmps[gid].opad_hash[6] = streebog512_hmac_ctx.opad.h[6];
  tmps[gid].opad_hash[7] = streebog512_hmac_ctx.opad.h[7];

  tmps[gid].ipad_raw[0] = streebog512_hmac_ctx.ipad.s[0];
  tmps[gid].ipad_raw[1] = streebog512_hmac_ctx.ipad.s[1];
  tmps[gid].ipad_raw[2] = streebog512_hmac_ctx.ipad.s[2];
  tmps[gid].ipad_raw[3] = streebog512_hmac_ctx.ipad.s[3];
  tmps[gid].ipad_raw[4] = streebog512_hmac_ctx.ipad.s[4];
  tmps[gid].ipad_raw[5] = streebog512_hmac_ctx.ipad.s[5];
  tmps[gid].ipad_raw[6] = streebog512_hmac_ctx.ipad.s[6];
  tmps[gid].ipad_raw[7] = streebog512_hmac_ctx.ipad.s[7];

  tmps[gid].opad_raw[0] = streebog512_hmac_ctx.opad.s[0];
  tmps[gid].opad_raw[1] = streebog512_hmac_ctx.opad.s[1];
  tmps[gid].opad_raw[2] = streebog512_hmac_ctx.opad.s[2];
  tmps[gid].opad_raw[3] = streebog512_hmac_ctx.opad.s[3];
  tmps[gid].opad_raw[4] = streebog512_hmac_ctx.opad.s[4];
  tmps[gid].opad_raw[5] = streebog512_hmac_ctx.opad.s[5];
  tmps[gid].opad_raw[6] = streebog512_hmac_ctx.opad.s[6];
  tmps[gid].opad_raw[7] = streebog512_hmac_ctx.opad.s[7];

  streebog512_hmac_update_global_swap (&streebog512_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, 64);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    streebog512_hmac_ctx_t streebog512_hmac_ctx2 = streebog512_hmac_ctx;

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

    streebog512_hmac_update_64 (&streebog512_hmac_ctx2, w0, w1, w2, w3, 4);

    streebog512_hmac_final (&streebog512_hmac_ctx2);

    tmps[gid].dgst[i + 0] = streebog512_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = streebog512_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = streebog512_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = streebog512_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = streebog512_hmac_ctx2.opad.h[4];
    tmps[gid].dgst[i + 5] = streebog512_hmac_ctx2.opad.h[5];
    tmps[gid].dgst[i + 6] = streebog512_hmac_ctx2.opad.h[6];
    tmps[gid].dgst[i + 7] = streebog512_hmac_ctx2.opad.h[7];

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

KERNEL_FQ void m13771_loop (KERN_ATTR_TMPS_ESALT (vc64_sbog_tmp_t, vc_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * shared lookup table
   */

  #ifdef REAL_SHM

  LOCAL_VK u64a s_sbob_sl64[8][256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_sbob_sl64[0][i] = sbob512_sl64[0][i];
    s_sbob_sl64[1][i] = sbob512_sl64[1][i];
    s_sbob_sl64[2][i] = sbob512_sl64[2][i];
    s_sbob_sl64[3][i] = sbob512_sl64[3][i];
    s_sbob_sl64[4][i] = sbob512_sl64[4][i];
    s_sbob_sl64[5][i] = sbob512_sl64[5][i];
    s_sbob_sl64[6][i] = sbob512_sl64[6][i];
    s_sbob_sl64[7][i] = sbob512_sl64[7][i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u64a (*s_sbob_sl64)[256] = sbob512_sl64;

  #endif

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

  u64x ipad_hash[8];
  u64x opad_hash[8];

  ipad_hash[0] = pack64v (tmps, ipad_hash, gid, 0);
  ipad_hash[1] = pack64v (tmps, ipad_hash, gid, 1);
  ipad_hash[2] = pack64v (tmps, ipad_hash, gid, 2);
  ipad_hash[3] = pack64v (tmps, ipad_hash, gid, 3);
  ipad_hash[4] = pack64v (tmps, ipad_hash, gid, 4);
  ipad_hash[5] = pack64v (tmps, ipad_hash, gid, 5);
  ipad_hash[6] = pack64v (tmps, ipad_hash, gid, 6);
  ipad_hash[7] = pack64v (tmps, ipad_hash, gid, 7);

  opad_hash[0] = pack64v (tmps, opad_hash, gid, 0);
  opad_hash[1] = pack64v (tmps, opad_hash, gid, 1);
  opad_hash[2] = pack64v (tmps, opad_hash, gid, 2);
  opad_hash[3] = pack64v (tmps, opad_hash, gid, 3);
  opad_hash[4] = pack64v (tmps, opad_hash, gid, 4);
  opad_hash[5] = pack64v (tmps, opad_hash, gid, 5);
  opad_hash[6] = pack64v (tmps, opad_hash, gid, 6);
  opad_hash[7] = pack64v (tmps, opad_hash, gid, 7);

  u64x ipad_raw[8];
  u64x opad_raw[8];

  ipad_raw[0] = pack64v (tmps, ipad_raw, gid, 0);
  ipad_raw[1] = pack64v (tmps, ipad_raw, gid, 1);
  ipad_raw[2] = pack64v (tmps, ipad_raw, gid, 2);
  ipad_raw[3] = pack64v (tmps, ipad_raw, gid, 3);
  ipad_raw[4] = pack64v (tmps, ipad_raw, gid, 4);
  ipad_raw[5] = pack64v (tmps, ipad_raw, gid, 5);
  ipad_raw[6] = pack64v (tmps, ipad_raw, gid, 6);
  ipad_raw[7] = pack64v (tmps, ipad_raw, gid, 7);

  opad_raw[0] = pack64v (tmps, opad_raw, gid, 0);
  opad_raw[1] = pack64v (tmps, opad_raw, gid, 1);
  opad_raw[2] = pack64v (tmps, opad_raw, gid, 2);
  opad_raw[3] = pack64v (tmps, opad_raw, gid, 3);
  opad_raw[4] = pack64v (tmps, opad_raw, gid, 4);
  opad_raw[5] = pack64v (tmps, opad_raw, gid, 5);
  opad_raw[6] = pack64v (tmps, opad_raw, gid, 6);
  opad_raw[7] = pack64v (tmps, opad_raw, gid, 7);

  for (u32 i = 0; i < 8; i += 8)
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

      hmac_streebog512_run_V (w0, w1, w2, w3, ipad_hash, opad_hash, ipad_raw, opad_raw, dgst, s_sbob_sl64);

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

KERNEL_FQ void m13771_loop_extended (KERN_ATTR_TMPS_ESALT (vc64_sbog_tmp_t, vc_t))
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

    tmps[gid].pim_check = 0;
  }
}

KERNEL_FQ void m13771_comp (KERN_ATTR_TMPS_ESALT (vc64_sbog_tmp_t, vc_t))
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
  }
}
