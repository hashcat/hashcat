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
#include M2S(INCLUDE_PATH/inc_cipher_aes-gcm.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct exodus
{
  u32 iv[4];
  u32 data[8];
  u32 tag[4];

} exodus_t;

KERNEL_FQ KERNEL_FA void m28200_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, exodus_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m28200_loop_prepare (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, exodus_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_init (P, X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m28200_loop (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, exodus_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_loop (P, X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m28200_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, exodus_t))
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

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 out[8];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, out, 32);

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
