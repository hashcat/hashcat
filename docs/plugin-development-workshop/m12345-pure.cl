/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_md5.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

typedef struct workshop
{
  u32 encrypted_data[8];

} workshop_t;

typedef struct workshop_temp
{
  u32 digest_buf[4];

} workshop_temp_t;


KERNEL_FQ void m12345_init (KERN_ATTR_TMPS_ESALT (workshop_temp_t, workshop_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  md5_ctx_t ctx;
 
  md5_init (&ctx);
 
  md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
 
  md5_update_global (&ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);
 
  md5_final (&ctx);

  char *replace=(char*)&ctx.h[0];
  replace[0] = 0;
  replace[1] = 1;
  replace[2] = 2;
  replace[3] = 3;

  tmps[gid].digest_buf[0] = ctx.h[0];
  tmps[gid].digest_buf[1] = ctx.h[1];
  tmps[gid].digest_buf[2] = ctx.h[2];
  tmps[gid].digest_buf[3] = ctx.h[3];
}

KERNEL_FQ void m12345_loop (KERN_ATTR_TMPS_ESALT (workshop_temp_t, workshop_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  u32 digest[16] = { 0 };

  digest[0] = tmps[gid].digest_buf[0];
  digest[1] = tmps[gid].digest_buf[1];
  digest[2] = tmps[gid].digest_buf[2];
  digest[3] = tmps[gid].digest_buf[3];

  for (u32 index = 0; index < LOOP_CNT; index++)
  {
    md5_ctx_t ctx;

    md5_init (&ctx);
    
    md5_update (&ctx, digest, 16);

    md5_final (&ctx);

    digest[0] = ctx.h[0];
    digest[1] = ctx.h[1];
    digest[2] = ctx.h[2];
    digest[3] = ctx.h[3];
  }

  tmps[gid].digest_buf[0] = digest[0];
  tmps[gid].digest_buf[1] = digest[1];
  tmps[gid].digest_buf[2] = digest[2];
  tmps[gid].digest_buf[3] = digest[3];
}

KERNEL_FQ void m12345_comp (KERN_ATTR_TMPS_ESALT (workshop_temp_t, workshop_t))
{
  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * Copy the shared aes-tables
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

  // aeskey = first 16 bytes of decrypted_crypt_key
  u32 aes_key[4];
  aes_key[0] = tmps[gid].digest_buf[0];
  aes_key[1] = tmps[gid].digest_buf[1];
  aes_key[2] = tmps[gid].digest_buf[2];
  aes_key[3] = tmps[gid].digest_buf[3];

  // iv = only zeroes
  u32 iv[4] = { 0 };

  u32 local_encrypted_data[4];
  local_encrypted_data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data[0];
  local_encrypted_data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data[1];
  local_encrypted_data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data[2];
  local_encrypted_data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].encrypted_data[3];

  u32 decrypted_data[4] = {0}; // 16 bytes

  u32 ks[44];

  aes128_set_decrypt_key (ks, aes_key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  aes128_decrypt (ks, local_encrypted_data, decrypted_data, s_td0, s_td1, s_td2, s_td3, s_td4);

  if ((decrypted_data[0] == 0) && (decrypted_data[1] == 0) && (decrypted_data[2] == 0) && (decrypted_data[3] == 0))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
