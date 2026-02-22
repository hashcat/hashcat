/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Exodus Desktop Wallet - bridge-compatible kernel for scrypt-jane bridge
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes-gcm.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define SCRYPT_R_MAX 16
#define SCRYPT_P_MAX 16

#define SCRYPT_TMP_SIZE (128ULL * SCRYPT_R_MAX * SCRYPT_P_MAX)
#define SCRYPT_TMP_SIZE4 (SCRYPT_TMP_SIZE / 4)

typedef struct
{
  u32 P[SCRYPT_TMP_SIZE4];

} scrypt_tmp_t;

typedef struct exodus
{
  u32 iv[4];
  u32 data[8];
  u32 tag[4];

} exodus_t;

KERNEL_FQ KERNEL_FA void m70700_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, exodus_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  // 1st PBKDF2-SHA256: global password, global salt
  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  u32 r = salt_bufs[SALT_POS_HOST].scrypt_r;
  u32 p = salt_bufs[SALT_POS_HOST].scrypt_p;

  u32 chunk_bytes = 64 * r * 2;

  u32 x_bytes = chunk_bytes * p;

  for (u32 i = 0, j = 0, k = 1; i < x_bytes; i += 32, j += 8, k += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = k;
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

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    u32 digest[8];

    digest[0] = sha256_hmac_ctx2.opad.h[0];
    digest[1] = sha256_hmac_ctx2.opad.h[1];
    digest[2] = sha256_hmac_ctx2.opad.h[2];
    digest[3] = sha256_hmac_ctx2.opad.h[3];
    digest[4] = sha256_hmac_ctx2.opad.h[4];
    digest[5] = sha256_hmac_ctx2.opad.h[5];
    digest[6] = sha256_hmac_ctx2.opad.h[6];
    digest[7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].P[j + 0] = hc_swap32_S (digest[0]);
    tmps[gid].P[j + 1] = hc_swap32_S (digest[1]);
    tmps[gid].P[j + 2] = hc_swap32_S (digest[2]);
    tmps[gid].P[j + 3] = hc_swap32_S (digest[3]);
    tmps[gid].P[j + 4] = hc_swap32_S (digest[4]);
    tmps[gid].P[j + 5] = hc_swap32_S (digest[5]);
    tmps[gid].P[j + 6] = hc_swap32_S (digest[6]);
    tmps[gid].P[j + 7] = hc_swap32_S (digest[7]);
  }
}

KERNEL_FQ KERNEL_FA void m70700_loop (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, exodus_t))
{
  // EMPTY - The scrypt-jane bridge replaces this
}

KERNEL_FQ KERNEL_FA void m70700_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, exodus_t))
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
   * 2nd PBKDF2-SHA256
   * Key = global password, Salt = bridge output tmps[gid].P[] (global)
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  u32 r = salt_bufs[SALT_POS_HOST].scrypt_r;
  u32 p = salt_bufs[SALT_POS_HOST].scrypt_p;

  u32 chunk_bytes = 64 * r * 2;

  u32 x_bytes = chunk_bytes * p;

  for (u32 i = 0, j = 0; i < x_bytes; i += 64, j += 16)
  {
    w0[0] = hc_swap32_S (tmps[gid].P[j +  0]);
    w0[1] = hc_swap32_S (tmps[gid].P[j +  1]);
    w0[2] = hc_swap32_S (tmps[gid].P[j +  2]);
    w0[3] = hc_swap32_S (tmps[gid].P[j +  3]);
    w1[0] = hc_swap32_S (tmps[gid].P[j +  4]);
    w1[1] = hc_swap32_S (tmps[gid].P[j +  5]);
    w1[2] = hc_swap32_S (tmps[gid].P[j +  6]);
    w1[3] = hc_swap32_S (tmps[gid].P[j +  7]);
    w2[0] = hc_swap32_S (tmps[gid].P[j +  8]);
    w2[1] = hc_swap32_S (tmps[gid].P[j +  9]);
    w2[2] = hc_swap32_S (tmps[gid].P[j + 10]);
    w2[3] = hc_swap32_S (tmps[gid].P[j + 11]);
    w3[0] = hc_swap32_S (tmps[gid].P[j + 12]);
    w3[1] = hc_swap32_S (tmps[gid].P[j + 13]);
    w3[2] = hc_swap32_S (tmps[gid].P[j + 14]);
    w3[3] = hc_swap32_S (tmps[gid].P[j + 15]);

    sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = 1;
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

  sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 4);

  sha256_hmac_final (&ctx);

  u32 out[8];

  out[0] = hc_swap32_S (ctx.opad.h[0]);
  out[1] = hc_swap32_S (ctx.opad.h[1]);
  out[2] = hc_swap32_S (ctx.opad.h[2]);
  out[3] = hc_swap32_S (ctx.opad.h[3]);
  out[4] = hc_swap32_S (ctx.opad.h[4]);
  out[5] = hc_swap32_S (ctx.opad.h[5]);
  out[6] = hc_swap32_S (ctx.opad.h[6]);
  out[7] = hc_swap32_S (ctx.opad.h[7]);

  // GCM stuff

  u32 ukey[8];

  ukey[0] = hc_swap32_S (out[0]);
  ukey[1] = hc_swap32_S (out[1]);
  ukey[2] = hc_swap32_S (out[2]);
  ukey[3] = hc_swap32_S (out[3]);
  ukey[4] = hc_swap32_S (out[4]);
  ukey[5] = hc_swap32_S (out[5]);
  ukey[6] = hc_swap32_S (out[6]);
  ukey[7] = hc_swap32_S (out[7]);

  u32 key[60] = { 0 };
  u32 subKey[4] = { 0 };

  AES_GCM_Init (ukey, 256, key, subKey, s_te0, s_te1, s_te2, s_te3, s_te4);

  u32 iv[4];

  iv[0] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[0];
  iv[1] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[1];
  iv[2] = esalt_bufs[DIGESTS_OFFSET_HOST].iv[2];
  iv[3] = 0;

  u32 J0[4] = { 0 };

  AES_GCM_Prepare_J0 (iv, 12, subKey, J0);

  u32 T[4] = { 0 };
  u32 S[4] = { 0 };

  u32 S_len   = 16;
  u32 aad_buf[4] = { 0 };
  u32 aad_len = 0;

  AES_GCM_GHASH_GLOBAL (subKey, aad_buf, aad_len, esalt_bufs[DIGESTS_OFFSET_HOST].data, 32, S);

  AES_GCM_GCTR (key, J0, S, S_len, T, s_te0, s_te1, s_te2, s_te3, s_te4);

  const u32 r0 = T[0];
  const u32 r1 = T[1];
  const u32 r2 = T[2];
  const u32 r3 = T[3];

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
