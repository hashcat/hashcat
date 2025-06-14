/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct
{
  #ifndef SCRYPT_TMP_ELEM
  #define SCRYPT_TMP_ELEM 1
  #endif

  uint4 P[SCRYPT_TMP_ELEM];

} scrypt_tmp_t;

KERNEL_FQ void HC_ATTR_SEQ m27700_init (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 w[128] = { 0 };

  hc_enc_t hc_enc;

  hc_enc_init (&hc_enc);

  const int w_len = hc_enc_next_global (&hc_enc, pws[gid].i, pws[gid].pw_len, 256, w, sizeof (w));

  if (w_len == -1) return;

  // utf16le to utf16be
  for (int i = 0, j = 0; i < w_len; i += 4, j += 1)
  {
    w[j] = ((w[j] >> 8) & 0x00ff00ff)
         | ((w[j] << 8) & 0xff00ff00);
  }

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_swap (&sha256_hmac_ctx, w, w_len);

  u32 x0[4] = { 0 };
  u32 x1[4] = { 0 };
  u32 x2[4] = { 0 };
  u32 x3[4] = { 0 };

  x0[0] = salt_bufs[SALT_POS_HOST].salt_buf[0];
  x0[1] = salt_bufs[SALT_POS_HOST].salt_buf[1];

  sha256_hmac_update_64 (&sha256_hmac_ctx, x0, x1, x2, x3, 8);

  scrypt_pbkdf2_body (&sha256_hmac_ctx, tmps[gid].P, SCRYPT_CNT * 4);

  scrypt_blockmix_in (tmps[gid].P, SCRYPT_CNT * 4);
}

KERNEL_FQ void HC_ATTR_SEQ m27700_loop_prepare (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  GLOBAL_AS uint4 *d_scrypt0_buf = (GLOBAL_AS uint4 *) d_extra0_buf;
  GLOBAL_AS uint4 *d_scrypt1_buf = (GLOBAL_AS uint4 *) d_extra1_buf;
  GLOBAL_AS uint4 *d_scrypt2_buf = (GLOBAL_AS uint4 *) d_extra2_buf;
  GLOBAL_AS uint4 *d_scrypt3_buf = (GLOBAL_AS uint4 *) d_extra3_buf;

  #ifdef IS_HIP
  LOCAL_VK uint4 X_s[MAX_THREADS_PER_BLOCK][STATE_CNT4];
  LOCAL_AS uint4 *X = X_s[lid];
  #else
  uint4 X[STATE_CNT4];
  #endif

  const u32 P_offset = SALT_REPEAT * STATE_CNT4;

  GLOBAL_AS uint4 *P = tmps[gid].P + P_offset;

  for (int z = 0; z < STATE_CNT4; z++) X[z] = P[z];

  scrypt_smix_init (X, d_scrypt0_buf, d_scrypt1_buf, d_scrypt2_buf, d_scrypt3_buf, gid);

  for (int z = 0; z < STATE_CNT4; z++) P[z] = X[z];
}

KERNEL_FQ void HC_ATTR_SEQ m27700_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  if (gid >= GID_CNT) return;

  GLOBAL_AS uint4 *d_scrypt0_buf = (GLOBAL_AS uint4 *) d_extra0_buf;
  GLOBAL_AS uint4 *d_scrypt1_buf = (GLOBAL_AS uint4 *) d_extra1_buf;
  GLOBAL_AS uint4 *d_scrypt2_buf = (GLOBAL_AS uint4 *) d_extra2_buf;
  GLOBAL_AS uint4 *d_scrypt3_buf = (GLOBAL_AS uint4 *) d_extra3_buf;

  uint4 X[STATE_CNT4];

  #ifdef IS_HIP
  LOCAL_VK uint4 T_s[MAX_THREADS_PER_BLOCK][STATE_CNT4];
  LOCAL_AS uint4 *T = T_s[lid];
  #else
  uint4 T[STATE_CNT4];
  #endif

  const u32 P_offset = SALT_REPEAT * STATE_CNT4;

  GLOBAL_AS uint4 *P = tmps[gid].P + P_offset;

  for (int z = 0; z < STATE_CNT4; z++) X[z] = P[z];

  scrypt_smix_loop (X, T, d_scrypt0_buf, d_scrypt1_buf, d_scrypt2_buf, d_scrypt3_buf, gid);

  for (int z = 0; z < STATE_CNT4; z++) P[z] = X[z];
}

KERNEL_FQ void HC_ATTR_SEQ m27700_comp (KERN_ATTR_TMPS (scrypt_tmp_t))
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

  /**
   * 2nd pbkdf2, creates B
   */

  u32 w[128] = { 0 };

  hc_enc_t hc_enc;

  hc_enc_init (&hc_enc);

  const int w_len = hc_enc_next_global (&hc_enc, pws[gid].i, pws[gid].pw_len, 256, w, sizeof (w));

  if (w_len == -1) return;

  // utf16le to utf16be
  for (int i = 0, j = 0; i < w_len; i += 4, j += 1)
  {
    w[j] = ((w[j] >> 8) & 0x00ff00ff)
         | ((w[j] << 8) & 0xff00ff00);
  }

  scrypt_blockmix_out (tmps[gid].P, SCRYPT_CNT * 4);

  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_swap (&ctx, w, w_len);

  sha256_hmac_update_global_swap (&ctx, (GLOBAL_AS const u32 *) tmps[gid].P, SCRYPT_CNT * 4);

  scrypt_pbkdf2_body (&ctx, tmps[gid].P, 16);

  // AES256-CBC decrypt

  u32 key[8];

  key[0] = tmps[gid].P[0].x;
  key[1] = tmps[gid].P[0].y;
  key[2] = tmps[gid].P[0].z;
  key[3] = tmps[gid].P[0].w;
  key[4] = tmps[gid].P[1].x;
  key[5] = tmps[gid].P[1].y;
  key[6] = tmps[gid].P[1].z;
  key[7] = tmps[gid].P[1].w;

  #define KEYLEN 60

  u32 ks[KEYLEN];

  aes256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 iv[4];

  iv[0] = salt_bufs[SALT_POS_HOST].salt_buf[2];
  iv[1] = salt_bufs[SALT_POS_HOST].salt_buf[3];
  iv[2] = salt_bufs[SALT_POS_HOST].salt_buf[4];
  iv[3] = salt_bufs[SALT_POS_HOST].salt_buf[5];

  u32 enc[4];

  enc[0] = salt_bufs[SALT_POS_HOST].salt_buf[6];
  enc[1] = salt_bufs[SALT_POS_HOST].salt_buf[7];
  enc[2] = salt_bufs[SALT_POS_HOST].salt_buf[8];
  enc[3] = salt_bufs[SALT_POS_HOST].salt_buf[9];

  u32 dec[4];

  aes256_decrypt (ks, enc, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

  dec[0] ^= iv[0];
  dec[1] ^= iv[1];
  dec[2] ^= iv[2];
  dec[3] ^= iv[3];

  if ((dec[0] == 0x10101010) &&
      (dec[1] == 0x10101010) &&
      (dec[2] == 0x10101010) &&
      (dec[3] == 0x10101010))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}
